/**
 * Packets the server sends while a key exchange started by the client is in flight.
 */

import { assertEquals } from '@std/assert';
import type { Channel } from '../src/Channel.ts';
import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext } from '../src/server.ts';
import { generateTestHostKeyEd25519 } from './integration_helpers.ts';

const decoder = new TextDecoder();

async function readAll(stream: ReadableStream<Uint8Array>): Promise<string> {
  let text = '';
  for await (const chunk of stream) text += decoder.decode(chunk, { stream: true });
  return text;
}

Deno.test('rekey: data the server writes as its NEWKEYS goes out reaches the client', async () => {
  const hostKey = await generateTestHostKeyEd25519();
  let stream: Channel | undefined;
  let writeAtNewKeys = false;

  const server = new Server({
    hostKeys: [hostKey.parsedKey],
    // ChaCha20 encrypts NEWKEYS synchronously, so a microtask queued as it is
    // sent runs after NEWKEYS is out but before the outbound cipher changes.
    algorithms: { cipher: ['chacha20-poly1305@openssh.com'] },
    debug: (msg) => {
      if (writeAtNewKeys && msg.endsWith('Outbound: Sending NEWKEYS')) {
        writeAtNewKeys = false;
        queueMicrotask(() => stream!.write('during '));
      }
    },
  });
  server.on('error', () => {});

  const execStarted = Promise.withResolvers<void>();
  server.on('connection', (conn: Connection) => {
    conn.on('error', () => {});
    conn.on('authentication', (ctx: ServerAuthContext) => ctx.accept());
    conn.on('ready', () => {
      conn.on('session', (accept) => {
        accept()!.on('exec', (acceptExec) => {
          stream = acceptExec();
          execStarted.resolve();
        });
      });
    });
  });
  await server.listen(0, '127.0.0.1');

  const client = new Client();
  const failed = Promise.withResolvers<never>();
  client.on('error', (err) => failed.reject(err));

  try {
    const ready = new Promise<void>((resolve) => client.on('ready', () => resolve()));
    await client.connect({
      host: '127.0.0.1',
      port: server.address()!.port,
      username: 'test',
      password: 'test',
    });
    await Promise.race([ready, failed.promise]);

    const channel = await client.exec('stream');
    const stdout = readAll(channel.stdout);
    await Promise.race([execStarted.promise, failed.promise]);

    writeAtNewKeys = true;
    await Promise.race([client.rekey(), failed.promise]);

    stream!.write('after');
    stream!.exit(0);
    stream!.end();

    assertEquals(await Promise.race([stdout, failed.promise]), 'during after');
  } finally {
    client.end();
    server.close();
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
});
