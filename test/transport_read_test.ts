import { assertEquals } from '@std/assert';
import type { Transport } from '../src/adapters/types.ts';
import type { Channel } from '../src/Channel.ts';
import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext, type Session } from '../src/server.ts';
import { PACE_MIN, READ_BUFFER, transportChunks } from '../src/utils/transport-read.ts';
import { generateTestHostKeyEd25519 } from './integration_helpers.ts';

/** A transport whose reads come from a list of sizes, each filled with its index. */
function sizedTransport(sizes: number[]): Transport {
  let next = 0;
  return {
    readable: new ReadableStream(),
    writable: new WritableStream(),
    closed: false,
    close() {},
    read(buf: Uint8Array) {
      if (next === sizes.length) return Promise.resolve(null);
      const n = Math.min(sizes[next], buf.length);
      buf.fill(next++, 0, n);
      return Promise.resolve(n);
    },
  };
}

Deno.test('transportChunks reads into one buffer and reports a bulk transfer around its chunks', async () => {
  const sizes = [10, PACE_MIN, READ_BUFFER, 5];
  const events: string[] = [];
  const buffers = new Set<ArrayBufferLike>();
  for await (
    const chunk of transportChunks(sizedTransport(sizes), (busy) => events.push(`bulk ${busy}`))
  ) {
    buffers.add(chunk.buffer);
    events.push(`chunk ${chunk.length} of ${chunk[0]}`);
  }
  assertEquals(buffers.size, 1);
  assertEquals(events, [
    'chunk 10 of 0',
    'bulk true',
    `chunk ${PACE_MIN} of 1`,
    'bulk false',
    'bulk true',
    `chunk ${READ_BUFFER} of 2`,
    'bulk false',
    'chunk 5 of 3',
    'bulk false',
  ]);
});

Deno.test('transportChunks reads a transport without read() through its stream', async () => {
  const sent = [new Uint8Array([1, 2]), new Uint8Array([3])];
  const transport: Transport = {
    readable: ReadableStream.from(sent),
    writable: new WritableStream(),
    closed: false,
    close() {},
  };
  const chunks: Uint8Array[] = [];
  for await (const chunk of transportChunks(transport)) chunks.push(chunk);
  assertEquals(chunks, sent);
});

/** One end of an in-memory connection, read through read() as a socket is. */
class ReadingTransport implements Transport {
  closed = false;
  private _reader: ReadableStreamDefaultReader<Uint8Array>;
  private _left: Uint8Array = new Uint8Array(0);

  constructor(readable: ReadableStream<Uint8Array>, readonly writable: WritableStream<Uint8Array>) {
    this._reader = readable.getReader();
  }

  get readable(): ReadableStream<Uint8Array> {
    throw new Error('read through read()');
  }

  async read(buf: Uint8Array): Promise<number | null> {
    if (this._left.length === 0) {
      const { done, value } = await this._reader.read();
      if (done) return null;
      this._left = value;
    }
    const n = Math.min(buf.length, this._left.length);
    buf.set(this._left.subarray(0, n));
    this._left = this._left.subarray(n);
    return n;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.writable.close().catch(() => {});
    this._reader.cancel().catch(() => {});
  }
}

Deno.test({
  name: 'a client uploads through a server that reads into one buffer',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const toServer = new TransformStream<Uint8Array, Uint8Array>();
    const toClient = new TransformStream<Uint8Array, Uint8Array>();
    const clientEnd = new ReadingTransport(toClient.readable, toServer.writable);
    const serverEnd = new ReadingTransport(toServer.readable, toClient.writable);

    // Enough 32 KiB packets that reads bring several, and their decipher opens batches.
    const upload = new Uint8Array(4 * 1024 * 1024);
    for (let i = 0; i < upload.length; i++) upload[i] = (i * 7 + (i >> 12)) & 0xff;

    const hostKey = await generateTestHostKeyEd25519();
    const server = new Server({ hostKeys: [hostKey.parsedKey] });
    const received = Promise.withResolvers<Uint8Array>();
    server.on('connection', (conn: Connection) => {
      conn.on('authentication', (ctx: ServerAuthContext) => ctx.accept());
      conn.on('error', (err) => received.reject(err));
      conn.on('session', (accept: () => Session | undefined) => {
        accept()!.on('exec', (acceptExec: () => Channel | undefined) => {
          const stream = acceptExec()!;
          (async () => {
            const parts: Uint8Array[] = [];
            for await (const part of stream.readable) parts.push(new Uint8Array(part));
            const all = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
            let offset = 0;
            for (const part of parts) {
              all.set(part, offset);
              offset += part.length;
            }
            stream.exit(0);
            stream.end();
            received.resolve(all);
          })().catch(received.reject);
        });
      });
    });
    await server.injectTransport(serverEnd);

    const client = new Client();
    client.on('error', () => {});
    const ready = new Promise<void>((resolve) => client.on('ready', () => resolve()));
    await client.connect({
      transport: clientEnd,
      username: 'u',
      password: 'p',
      hostVerifier: () => true,
    });
    await ready;

    const stream = await client.exec('upload');
    const writer = stream.writable.getWriter();
    for (let offset = 0; offset < upload.length; offset += 65536) {
      await writer.write(upload.subarray(offset, offset + 65536));
    }
    await writer.close();

    const got = await received.promise;
    assertEquals(got.length, upload.length);
    assertEquals(got, upload);
    client.end();
    server.close();
  },
});
