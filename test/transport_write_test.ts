import { assertEquals, assertStrictEquals, assertThrows } from '@std/assert';
import type { Transport } from '../src/adapters/types.ts';
import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext } from '../src/server.ts';
import { coalesceTransportWrite } from '../src/utils/transport-write.ts';
import { generateTestHostKeyEd25519 } from './integration_helpers.ts';

Deno.test('coalesceTransportWrite returns a lone record without copying', () => {
  const record = new Uint8Array([1, 2, 3]);
  const result = coalesceTransportWrite([record], 0, 8);

  assertStrictEquals(result.data, record);
  assertEquals(result.nextIndex, 1);
});

Deno.test('coalesceTransportWrite combines ordered records up to the bound', () => {
  const queue = [
    new Uint8Array([1, 2]),
    new Uint8Array([3, 4, 5]),
    new Uint8Array([6, 7]),
  ];

  const first = coalesceTransportWrite(queue, 0, 5);
  assertEquals(first.data, new Uint8Array([1, 2, 3, 4, 5]));
  assertEquals(first.nextIndex, 2);

  const second = coalesceTransportWrite(queue, first.nextIndex, 5);
  assertStrictEquals(second.data, queue[2]);
  assertEquals(second.nextIndex, 3);
});

Deno.test('coalesceTransportWrite permits one record larger than the bound', () => {
  const record = new Uint8Array(9);
  const result = coalesceTransportWrite([record, new Uint8Array([1])], 0, 8);

  assertStrictEquals(result.data, record);
  assertEquals(result.nextIndex, 1);
  assertThrows(() => coalesceTransportWrite([record], 1, 8), RangeError);
});

/** One end of an in-memory connection, counting the writers taken on its writable. */
class CountingTransport implements Transport {
  writers = 0;
  closed = false;

  constructor(
    readonly readable: ReadableStream<Uint8Array>,
    private _writable: WritableStream<Uint8Array>,
  ) {}

  get writable(): WritableStream<Uint8Array> {
    const writable = this._writable;
    return {
      getWriter: () => {
        this.writers++;
        return writable.getWriter();
      },
    } as WritableStream<Uint8Array>;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this._writable.close().catch(() => {});
  }
}

Deno.test({
  name:
    'client and server each take the transport writer once for a connection, injected on the server',
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const toServer = new TransformStream<Uint8Array, Uint8Array>();
    const toClient = new TransformStream<Uint8Array, Uint8Array>();
    const clientEnd = new CountingTransport(toClient.readable, toServer.writable);
    const serverEnd = new CountingTransport(toServer.readable, toClient.writable);

    const hostKey = await generateTestHostKeyEd25519();
    const server = new Server({ hostKeys: [hostKey.parsedKey] });
    server.on('connection', (conn: Connection) => {
      conn.on('authentication', (ctx: ServerAuthContext) => ctx.accept());
      conn.on('error', () => {});
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

    client.end();
    server.close();
    assertEquals([clientEnd.writers, serverEnd.writers], [1, 1]);
  },
});
