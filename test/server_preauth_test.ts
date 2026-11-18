/**
 * Server Pre-authentication Limits Tests
 *
 * What a client that has not authenticated can hold: the header lines it
 * sends, how long it may take, and how many such connections there may be.
 */

import { assertEquals } from '@std/assert';
import { Server, type ServerConfig } from '../src/server.ts';
import { generateTestHostKeyEd25519 } from './integration_helpers.ts';

/** What one read finds: text, or null once the server has closed its side. */
async function readOnce(conn: Deno.Conn): Promise<string | null> {
  const buf = new Uint8Array(4096);
  const n = await conn.read(buf);
  return n === null ? null : new TextDecoder().decode(buf.subarray(0, n));
}

/** Reads until the server closes, failing past the deadline; what was read before. */
async function untilClosed(conn: Deno.Conn, ms: number): Promise<string> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`still open after ${ms} ms`)), ms);
  });
  let text = '';
  try {
    for (;;) {
      const got = await Promise.race([readOnce(conn), late]);
      if (got === null) return text;
      text += got;
    }
  } finally {
    clearTimeout(timer);
  }
}

async function withServer(
  config: Partial<ServerConfig>,
  fn: (port: number, errors: Error[]) => Promise<void>,
): Promise<void> {
  const hostKey = await generateTestHostKeyEd25519();
  const server = new Server({ hostKeys: [hostKey.parsedKey], ...config });
  const errors: Error[] = [];
  server.on('connection', (conn) => conn.on('error', (err) => errors.push(err)));
  server.on('error', (err) => errors.push(err));
  await server.listen(0, '127.0.0.1');
  try {
    await fn(server.address()!.port, errors);
  } finally {
    server.close();
  }
}

const connect = (port: number) => Deno.connect({ hostname: '127.0.0.1', port });

Deno.test('preauth: an identification line past 255 bytes closes the connection', async () => {
  await withServer({}, async (port) => {
    const conn = await connect(port);
    // No newline: the server must not wait for one for ever, buffering all of it
    await conn.write(new TextEncoder().encode('SSH-2.0-' + 'A'.repeat(4096)));
    assertEquals((await untilClosed(conn, 2000)).startsWith('SSH-2.0-'), true);
    conn.close();
  });
});

Deno.test('preauth: a client line that is not an identification closes the connection', async () => {
  await withServer({}, async (port) => {
    const conn = await connect(port);
    await conn.write(new TextEncoder().encode('hello\r\n'));
    await untilClosed(conn, 2000);
    conn.close();
  });
});

Deno.test('preauth: a connection that does not authenticate within the login grace time is closed', async () => {
  await withServer({ loginGraceTime: 200 }, async (port, errors) => {
    const conn = await connect(port);
    await conn.write(new TextEncoder().encode('SSH-2.0-test\r\n'));
    const started = performance.now();
    await untilClosed(conn, 3000);
    assertEquals(performance.now() - started >= 150, true);
    assertEquals(errors.map((err) => err.message), ['no authentication within 200 ms']);
    conn.close();
  });
});

Deno.test('preauth: connections past perSourceMaxStartups are closed unanswered, and a slot frees when one leaves', async () => {
  await withServer({ perSourceMaxStartups: 2 }, async (port) => {
    const held = [await connect(port), await connect(port)];
    for (const conn of held) assertEquals((await readOnce(conn))?.startsWith('SSH-2.0-'), true);

    const refused = await connect(port);
    assertEquals(await untilClosed(refused, 2000), '');
    refused.close();

    held.pop()!.close();
    // The server sees the end of the closed one before a new one takes its slot
    let next: Deno.Conn | undefined;
    for (let tries = 0; tries < 50 && !next; tries++) {
      await new Promise((resolve) => setTimeout(resolve, 20));
      const conn = await connect(port);
      if ((await readOnce(conn))?.startsWith('SSH-2.0-')) next = conn;
      else conn.close();
    }
    assertEquals(next !== undefined, true);
    next!.close();
    held[0].close();
  });
});

Deno.test('preauth: connections past maxStartups are closed unanswered', async () => {
  await withServer({ maxStartups: 3 }, async (port) => {
    const held = [await connect(port), await connect(port), await connect(port)];
    for (const conn of held) assertEquals((await readOnce(conn))?.startsWith('SSH-2.0-'), true);

    const refused = await connect(port);
    assertEquals(await untilClosed(refused, 2000), '');
    refused.close();
    for (const conn of held) conn.close();
  });
});
