/**
 * Server Accept Tests
 *
 * The listening side: a failed accept does not stop the server greeting the
 * clients after it, and a client that goes away gets its socket closed.
 */

import { assertEquals } from '@std/assert';
import type { DenoListener } from '../src/adapters/deno.ts';
import { Server } from '../src/server.ts';
import { generateTestHostKeyEd25519 } from './integration_helpers.ts';

/** What the server sends first, or what a read finds once it has nothing more. */
async function readBanner(conn: Deno.Conn): Promise<string | null> {
  const buf = new Uint8Array(256);
  const n = await conn.read(buf);
  return n === null ? null : new TextDecoder().decode(buf.subarray(0, n));
}

/** A read with a deadline, so a server that never answers fails the test instead of hanging it. */
async function within<T>(ms: number, what: string, promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what}: nothing within ${ms} ms`)), ms);
  });
  try {
    return await Promise.race([promise, late]);
  } finally {
    clearTimeout(timer);
  }
}

Deno.test('server: a failed accept is reported and the next client is greeted', async () => {
  const hostKey = await generateTestHostKeyEd25519();
  const server = new Server({ hostKeys: [hostKey.parsedKey] });
  const errors: Error[] = [];
  server.on('error', (err) => errors.push(err));
  await server.listen(0, '127.0.0.1');
  const { port } = server.address()!;

  // The accept already waiting is the real one; the next fails once, as one
  // does when the process is out of file descriptors
  const listener = (server as unknown as { _listener: DenoListener })._listener.listener;
  const accept = listener.accept.bind(listener);
  let failed = false;
  listener.accept = () => {
    if (failed) return accept();
    failed = true;
    return Promise.reject(new Error('Too many open files (os error 24)'));
  };

  try {
    const first = await Deno.connect({ hostname: '127.0.0.1', port });
    assertEquals(
      (await within(2000, 'first banner', readBanner(first)))?.startsWith('SSH-2.0-'),
      true,
    );
    first.close();

    const second = await Deno.connect({ hostname: '127.0.0.1', port });
    assertEquals(
      (await within(2000, 'banner after a failed accept', readBanner(second)))?.startsWith(
        'SSH-2.0-',
      ),
      true,
    );
    second.close();

    assertEquals(errors.map((err) => err.message), ['Too many open files (os error 24)']);
  } finally {
    server.close();
  }
});

Deno.test('server: a client that leaves before its identification has its socket closed', async () => {
  const hostKey = await generateTestHostKeyEd25519();
  const server = new Server({ hostKeys: [hostKey.parsedKey] });
  server.on('error', () => {});
  await server.listen(0, '127.0.0.1');
  const { port } = server.address()!;

  try {
    const conn = await Deno.connect({ hostname: '127.0.0.1', port });
    assertEquals((await within(2000, 'banner', readBanner(conn)))?.startsWith('SSH-2.0-'), true);
    // Half-close: the server reads the end of the stream, and its side
    // closing is what this end then reads
    await conn.closeWrite();
    assertEquals(await within(2000, 'the server closing its side', readBanner(conn)), null);
    conn.close();
  } finally {
    server.close();
  }
});
