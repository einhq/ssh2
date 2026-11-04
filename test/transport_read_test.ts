import { assertEquals } from '@std/assert';
import type { Transport } from '../src/adapters/types.ts';
import type { Channel } from '../src/Channel.ts';
import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext, type Session } from '../src/server.ts';
import { PACE_MIN, READ_BUFFER, transportChunks } from '../src/utils/transport-read.ts';
import { SFTP } from '../src/protocol/sftp/SFTP.ts';
import { STATUS_CODE } from '../src/protocol/sftp/constants.ts';
import type { SFTPHandle } from '../src/protocol/sftp/types.ts';
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

for (const cipher of ['chacha20-poly1305@openssh.com', 'aes128-gcm@openssh.com', 'aes128-ctr']) {
  Deno.test({
    name: `an SFTP WRITE's data is the listener's to keep (${cipher})`,
    sanitizeResources: false,
    sanitizeOps: false,
    async fn() {
      const toServer = new TransformStream<Uint8Array, Uint8Array>();
      const toClient = new TransformStream<Uint8Array, Uint8Array>();
      const clientEnd = new ReadingTransport(toClient.readable, toServer.writable);
      const serverEnd = new ReadingTransport(toServer.readable, toClient.writable);

      // Large writes that reads bring several of at once, and small ones between them.
      const upload = new Uint8Array(4 * 1024 * 1024);
      for (let i = 0; i < upload.length; i++) upload[i] = (i * 13 + (i >> 11)) & 0xff;
      const pieces: [number, number][] = [];
      for (let offset = 0; offset < upload.length;) {
        const size = Math.min(pieces.length % 5 === 4 ? 100 : 30000, upload.length - offset);
        pieces.push([offset, size]);
        offset += size;
      }

      const hostKey = await generateTestHostKeyEd25519();
      const server = new Server({
        hostKeys: [hostKey.parsedKey],
        algorithms: { cipher: [cipher] },
      });
      const kept: [bigint, Uint8Array][] = [];
      server.on('connection', (conn: Connection) => {
        conn.on('authentication', (ctx: ServerAuthContext) => ctx.accept());
        conn.on('error', () => {});
        conn.on('session', (accept: () => Session | undefined) => {
          accept()!.on('sftp', (acceptSftp: () => Channel | undefined) => {
            const channel = acceptSftp()!;
            const sftp = new SFTP(
              { protocol: conn.protocol },
              { type: 'session', incoming: channel.incoming, outgoing: channel.outgoing },
              { server: true },
            );
            (async () => {
              for await (const chunk of channel.readable) sftp.push(chunk);
              sftp.push(null);
            })().catch(() => {});
            sftp.on('OPEN', (id: number) => sftp.handle(id, new Uint8Array([1])));
            sftp.on(
              'WRITE',
              (id: number, _handle: SFTPHandle, offset: number | bigint, data: Uint8Array) => {
                kept.push([BigInt(offset), data]);
                sftp.status(id, STATUS_CODE.OK);
              },
            );
            sftp.on('CLOSE', (id: number) => sftp.status(id, STATUS_CODE.OK));
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
        algorithms: { cipher: [cipher] },
      });
      await ready;

      const sftp = await client.sftp();
      const handle = await sftp.open('/upload', 'w');
      await Promise.all(
        pieces.map(([offset, size]) => sftp.write(handle, upload, offset, size, offset)),
      );
      await sftp.close(handle);

      // Every WRITE's data, held since it arrived, still holds what was sent.
      const got = new Uint8Array(upload.length);
      for (const [offset, data] of kept) got.set(data, Number(offset));
      assertEquals(kept.length, pieces.length);
      assertEquals(got, upload);
      client.end();
      server.close();
    },
  });
}
