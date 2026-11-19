/**
 * Backpressure Tests
 *
 * A peer that sends past its channel window is cut off, and a server's SFTP
 * session holds no more than MAX_SERVER_BUFFERED of responses its client does
 * not read.
 */

import { assert, assertEquals } from '@std/assert';
import type { Channel } from '../src/Channel.ts';
import { MAX_WINDOW, PACKET_SIZE } from '../src/Channel.ts';
import { notifyWindowAdjust } from '../src/channel-window.ts';
import { Client } from '../src/client.ts';
import { MAX_SERVER_BUFFERED, SFTP } from '../src/protocol/sftp/SFTP.ts';
import { type Connection, Server, type ServerAuthContext, type Session } from '../src/server.ts';
import { generateTestHostKeyEd25519 } from './integration_helpers.ts';

/** A server's SFTP session whose client has a window of `window` bytes, and what it sent. */
function serverSftp(window: number) {
  const sent: number[] = [];
  let closed = false;
  const sftp = new SFTP(
    {
      protocol: {
        channelData(_id: number, data: Uint8Array) {
          sent.push(data.length);
        },
        channelClose() {
          closed = true;
        },
      },
    },
    {
      type: 'session',
      incoming: { id: 0, window: 1 << 21, packetSize: 32768, state: 'open' },
      outgoing: { id: 0, window: 1 << 21, packetSize: 32768, state: 'open' },
    },
    { server: true },
  );
  // INIT, version 3
  sftp.push(new Uint8Array([0, 0, 0, 5, 1, 0, 0, 0, 3]));
  sftp.outgoing.window = window;
  sent.length = 0;
  return { sftp, sent, isClosed: () => closed };
}

Deno.test('SFTP: responses past the window are counted, and drain when it opens', () => {
  const { sftp, sent } = serverSftp(0);
  let drains = 0;
  sftp.on('drain', () => drains++);

  sftp.data(1, new Uint8Array(1000));
  sftp.data(2, new Uint8Array(1000));
  assertEquals(sent.length, 0);
  assertEquals(sftp.bufferedAmount, 2 * (13 + 1000));

  sftp.outgoing.window = 1500;
  notifyWindowAdjust(sftp.outgoing);
  assertEquals(sftp.bufferedAmount, 2 * (13 + 1000) - 1500);
  assertEquals(drains, 0);

  sftp.outgoing.window = 1 << 20;
  notifyWindowAdjust(sftp.outgoing);
  assertEquals(sftp.bufferedAmount, 0);
  assertEquals(drains, 1);
});

Deno.test('SFTP: a server cuts off a client that never reads its responses', () => {
  const { sftp, isClosed } = serverSftp(0);
  const errors: Error[] = [];
  sftp.on('error', (err: Error) => errors.push(err));

  const chunk = new Uint8Array(256 * 1024);
  let reqid = 0;
  while (!isClosed() && reqid * chunk.length <= MAX_SERVER_BUFFERED + chunk.length) {
    sftp.data(reqid++, chunk);
  }

  assert(isClosed());
  assertEquals(errors.length, 1);
  assertEquals(sftp.bufferedAmount, 0);
});

Deno.test('server: a client that sends past its channel window is disconnected', async () => {
  const hostKey = await generateTestHostKeyEd25519();
  const server = new Server({ hostKeys: [hostKey.parsedKey] });
  const client = new Client();
  server.on('error', () => {});
  client.on('error', () => {});
  await server.listen(0, '127.0.0.1');

  try {
    const serverChannel = new Promise<Channel>((resolve) => {
      server.on('connection', (conn: Connection) => {
        conn.on('authentication', (ctx: ServerAuthContext) => ctx.accept());
        conn.on('session', (accept: () => Session | undefined) => {
          // The server never reads what the client sends, so its window is never refilled.
          accept()!.on('exec', (acceptExec: () => Channel | undefined) => resolve(acceptExec()!));
        });
      });
    });

    const addr = server.address()!;
    await new Promise<void>((resolve, reject) => {
      client.on('ready', () => resolve());
      client.connect({ host: addr.hostname, port: addr.port, username: 'test', password: 'x' })
        .catch(reject);
    });
    const closed = new Promise<void>((resolve) => client.on('close', () => resolve()));

    const channel = await client.exec('cat');
    await serverChannel;

    // Bypass the client's own window keeping: a packet more than the window allows.
    const protocol =
      (client as unknown as { _protocol: { channelData(id: number, d: Uint8Array): void } })
        ._protocol;
    const packet = new Uint8Array(PACKET_SIZE);
    for (let sent = 0; sent <= MAX_WINDOW; sent += packet.length) {
      protocol.channelData(channel.outgoing.id!, packet);
    }

    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('the client was not disconnected')), 10_000);
    });
    try {
      await Promise.race([closed, late]);
    } finally {
      clearTimeout(timer);
    }
  } finally {
    client.end();
    await server.close();
  }
});
