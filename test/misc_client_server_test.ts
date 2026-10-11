/**
 * Miscellaneous Client-Server Tests
 *
 * Tests for various client-server interactions including:
 * - Host fingerprint verification
 * - Pipelined requests
 * - Rekeying
 * - Server greetings and banners
 * - Error handling
 *
 * Converted from test/test-misc-client-server.js
 */

import { assertEquals, assertExists, assertMatch } from '@std/assert';

import { fail } from '@std/assert';
import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext } from '../src/server.ts';
import {
  clearMustCallChecks,
  generateTestHostKeyEd25519,
  mustCall,
  verifyMustCallChecks,
} from './integration_helpers.ts';

/**
 * Create a function that should never be called
 */
function mustNotCall(msg?: string): (...args: unknown[]) => never {
  const stack = new Error().stack ?? '';
  return (...args: unknown[]) => {
    const argsInfo = args.length > 0 ? `\nCalled with arguments: ${JSON.stringify(args)}` : '';
    fail(`${msg || 'Function should not have been called'} at ${stack}${argsInfo}`);
  };
}

const DEBUG = false;
const FIXTURES_DIR = new URL('./fixtures/', import.meta.url).pathname;

// =============================================================================
// Helper functions
// =============================================================================

interface TestContext {
  client: Client;
  server: Server;
  conn?: Connection;
  cleanup: () => Promise<void>;
}

async function createTestContext(title: string): Promise<TestContext> {
  const hostKey = await generateTestHostKeyEd25519();

  const server = new Server({
    hostKeys: [hostKey.parsedKey],
    debug: DEBUG ? (msg: string) => console.log(`[${title}][SERVER]`, msg) : undefined,
  });

  const client = new Client();

  if (!DEBUG) {
    server.on('error', () => {});
    client.on('error', () => {});
  }

  await server.listen(0, '127.0.0.1');

  const cleanup = async () => {
    try {
      client.end();
    } catch { /* ignore */ }
    try {
      await server.close();
    } catch { /* ignore */ }
    verifyMustCallChecks();
  };

  return { client, server, cleanup };
}

async function connectWithPasswordAuth(
  ctx: TestContext,
  title: string,
): Promise<Connection> {
  const { client, server } = ctx;
  const addr = server.address()!;

  return new Promise<Connection>((resolve, reject) => {
    let connReady = false;
    let clientReady = false;
    let conn: Connection | undefined;

    const checkBothReady = () => {
      if (connReady && clientReady && conn) {
        resolve(conn);
      }
    };

    server.on(
      'connection',
      mustCall((c: Connection) => {
        conn = c;
        ctx.conn = c;
        c.on(
          'authentication',
          mustCall((authCtx: ServerAuthContext) => {
            authCtx.accept();
          }),
        );
        c.on(
          'ready',
          mustCall(() => {
            connReady = true;
            checkBothReady();
          }),
        );
      }),
    );

    client.on(
      'ready',
      mustCall(() => {
        clientReady = true;
        checkBothReady();
      }),
    );

    client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'test',
      password: 'test',
      debug: DEBUG ? (msg: string) => console.log(`[${title}][CLIENT]`, msg) : undefined,
    }).catch(reject);
  });
}

// =============================================================================
// Tests
// =============================================================================

// Host fingerprint verification tests
Deno.test('misc: Verify host fingerprint (sync success)', async () => {
  clearMustCallChecks();

  const privateKey = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
  const hostKey = await generateTestHostKeyEd25519();

  const server = new Server({
    hostKeys: [hostKey.parsedKey],
    debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
  });

  const client = new Client();

  if (!DEBUG) {
    server.on('error', () => {});
    client.on('error', () => {});
  }

  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;

  try {
    const serverDone = new Promise<void>((resolve) => {
      server.on(
        'connection',
        mustCall((conn: Connection) => {
          conn.on(
            'authentication',
            mustCall((authCtx: ServerAuthContext) => {
              authCtx.accept();
            }),
          );

          conn.on(
            'ready',
            mustCall(() => {
              conn.end();
              resolve();
            }),
          );
        }),
      );
    });

    const clientDone = new Promise<void>((resolve) => {
      client.on(
        'close',
        mustCall(() => {
          resolve();
        }),
      );
    });

    let hostKeyVerified = false;
    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'KeyUser',
      privateKey,
      hostVerifier: mustCall((key: Uint8Array | string) => {
        assertExists(key);
        // Key can be Uint8Array or string (if hostHash is set)
        assertEquals(key instanceof Uint8Array || typeof key === 'string', true);
        hostKeyVerified = true;
        return true;
      }),
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    });

    // Wait for connection to complete
    await Promise.all([serverDone, clientDone]);

    // Now verify the hostVerifier was called
    assertEquals(hostKeyVerified, true);
  } finally {
    try {
      client.end();
    } catch { /* ignore */ }
    try {
      await server.close();
    } catch { /* ignore */ }
    verifyMustCallChecks();
  }
});

Deno.test('misc: Verify host fingerprint (sync failure)', async () => {
  clearMustCallChecks();

  const privateKey = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
  const hostKey = await generateTestHostKeyEd25519();

  const server = new Server({
    hostKeys: [hostKey.parsedKey],
    debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
  });

  const client = new Client();

  // Expect errors
  server.on('error', () => {});

  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;

  try {
    const serverDone = new Promise<void>((resolve) => {
      server.on(
        'connection',
        mustCall((conn: Connection) => {
          conn.on('error', () => {}); // Expect error
          conn.on('authentication', mustNotCall());
          conn.on('ready', mustNotCall());
          conn.on('close', () => resolve());
        }),
      );
    });

    let clientError: Error | undefined;
    const clientDone = new Promise<void>((resolve) => {
      // Client may emit multiple errors, we only care about the first
      client.on('error', (err: Error) => {
        if (!clientError) clientError = err;
      });
      client.on('close', () => {
        resolve();
      });
    });

    let hostKeyRejected = false;
    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'KeyUser',
      privateKey,
      hostVerifier: mustCall((_key: Uint8Array | string) => {
        hostKeyRejected = true;
        return false; // Reject host key
      }),
      debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
    }).catch(() => {}); // Expect connection to fail

    // Wait for connection to complete
    await Promise.all([serverDone, clientDone]);

    // Now verify the assertions
    assertEquals(hostKeyRejected, true);
    assertExists(clientError);
    assertMatch(clientError!.message, /verification failed/i);
  } finally {
    try {
      client.end();
    } catch { /* ignore */ }
    try {
      await server.close();
    } catch { /* ignore */ }
    verifyMustCallChecks();
  }
});

Deno.test({
  name: 'misc: Server greeting',
  ignore: false,
  fn: async () => {
    clearMustCallChecks();

    const privateKey = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
    const hostKey = await generateTestHostKeyEd25519();
    const GREETING = 'Hello SSH client!';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      greeting: GREETING,
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    if (!DEBUG) {
      server.on('error', () => {});
      client.on('error', () => {});
    }

    await server.listen(0, '127.0.0.1');
    const addr = server.address()!;

    try {
      const serverDone = new Promise<void>((resolve) => {
        server.on(
          'connection',
          mustCall((conn: Connection) => {
            conn.on(
              'authentication',
              mustCall((authCtx: ServerAuthContext) => {
                authCtx.accept();
              }),
            );

            conn.on(
              'ready',
              mustCall(() => {
                conn.end();
                resolve();
              }),
            );
          }),
        );
      });

      let receivedGreeting: string | undefined;
      const clientDone = new Promise<void>((resolve) => {
        client.on(
          'greeting',
          mustCall((greeting: string) => {
            receivedGreeting = greeting;
          }),
        );

        client.on(
          'close',
          mustCall(() => {
            resolve();
          }),
        );
      });

      await client.connect({
        host: addr.hostname,
        port: addr.port,
        username: 'KeyUser',
        privateKey,
        debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
      });

      await Promise.all([serverDone, clientDone]);

      assertEquals(receivedGreeting, GREETING);
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      try {
        await server.close();
      } catch { /* ignore */ }
      verifyMustCallChecks();
    }
  },
});

Deno.test({
  name: 'misc: Server banner',
  ignore: false,
  fn: async () => {
    clearMustCallChecks();

    const privateKey = await Deno.readFile(`${FIXTURES_DIR}openssh_new_rsa`);
    const hostKey = await generateTestHostKeyEd25519();
    const BANNER = 'Welcome to the server!\nPlease follow the rules.\n';

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      banner: BANNER,
      debug: DEBUG ? (msg: string) => console.log('[SERVER]', msg) : undefined,
    });

    const client = new Client();

    if (!DEBUG) {
      server.on('error', () => {});
      client.on('error', () => {});
    }

    await server.listen(0, '127.0.0.1');
    const addr = server.address()!;

    try {
      const serverDone = new Promise<void>((resolve) => {
        server.on(
          'connection',
          mustCall((conn: Connection) => {
            conn.on(
              'authentication',
              mustCall((authCtx: ServerAuthContext) => {
                authCtx.accept();
              }),
            );

            conn.on(
              'ready',
              mustCall(() => {
                // Don't close immediately - let client receive banner first
              }),
            );

            conn.on('close', () => {
              resolve();
            });
          }),
        );
      });

      let receivedBanner: string | undefined;
      const clientDone = new Promise<void>((resolve) => {
        client.on(
          'banner',
          mustCall((banner: string) => {
            receivedBanner = banner;
          }),
        );

        // Close from client side after receiving ready event
        client.on(
          'ready',
          mustCall(() => {
            client.end();
          }),
        );

        client.on(
          'close',
          mustCall(() => {
            resolve();
          }),
        );
      });

      await client.connect({
        host: addr.hostname,
        port: addr.port,
        username: 'KeyUser',
        privateKey,
        debug: DEBUG ? (msg: string) => console.log('[CLIENT]', msg) : undefined,
      });

      await Promise.all([serverDone, clientDone]);

      assertEquals(receivedBanner, BANNER);
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      try {
        await server.close();
      } catch { /* ignore */ }
      verifyMustCallChecks();
    }
  },
});

Deno.test({
  name: 'misc: Outstanding callbacks called on disconnect',
  ignore: false,
  fn: async () => {
    clearMustCallChecks();
    const ctx = await createTestContext('Outstanding callbacks on disconnect');

    try {
      const conn = await connectWithPasswordAuth(ctx, 'Outstanding callbacks');

      // Server side: set up session handler but don't accept
      conn.on(
        'session',
        mustCall((_accept: () => void, _reject: () => void) => {
          // Don't call accept or reject - just disconnect
          conn.end();
        }),
      );

      // Client side: try to open a session (will fail when server disconnects)
      let execError: Error | undefined;
      try {
        await ctx.client.exec('test');
      } catch (err) {
        execError = err as Error;
      }
      assertExists(execError);
    } finally {
      await ctx.cleanup();
    }
  },
});

/** Records what a server connection emits from now until it closes. */
function connectionEvents(conn: Connection): Promise<string[]> {
  const events: string[] = [];
  return new Promise((resolve) => {
    conn.on('end', () => events.push('end'));
    conn.on('error', (err: Error) => events.push(`error: ${err.message}`));
    conn.on('close', () => {
      events.push('close');
      resolve(events);
    });
  });
}

Deno.test({
  name: 'misc: A client that disconnects ends the server connection without an error',
  fn: async () => {
    clearMustCallChecks();
    const ctx = await createTestContext('Client disconnects');

    try {
      const conn = await connectWithPasswordAuth(ctx, 'Client disconnects');
      const events = connectionEvents(conn);
      ctx.client.end();
      assertEquals(await events, ['end', 'close']);
    } finally {
      await ctx.cleanup();
    }
  },
});

Deno.test({
  name: 'misc: A server that ends the connection reports no error',
  fn: async () => {
    clearMustCallChecks();
    const ctx = await createTestContext('Server ends');

    try {
      const conn = await connectWithPasswordAuth(ctx, 'Server ends');
      const events = connectionEvents(conn);
      conn.end();
      assertEquals(await events, ['end', 'close']);
    } finally {
      await ctx.cleanup();
    }
  },
});

Deno.test({
  name: 'misc: Simple rekey test',
  ignore: false,
  fn: async () => {
    clearMustCallChecks();
    const hostKey = await generateTestHostKeyEd25519();

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      debug: DEBUG ? (msg: string) => console.log('[REKEY][SERVER]', msg) : undefined,
    });

    const client = new Client();

    server.on('error', () => {});
    client.on('error', () => {});

    await server.listen(0, '127.0.0.1');
    const addr = server.address()!;

    try {
      // Connect
      await new Promise<void>((resolve, reject) => {
        server.on('connection', (conn: Connection) => {
          conn.on('authentication', (ctx: ServerAuthContext) => {
            ctx.accept();
          });
          conn.on('ready', () => {});
        });

        client.on('ready', () => {
          resolve();
        });

        client.connect({
          host: addr.hostname,
          port: addr.port,
          username: 'test',
          password: 'test',
          debug: DEBUG ? (msg: string) => console.log('[REKEY][CLIENT]', msg) : undefined,
        }).catch(reject);
      });

      // Wait a bit for everything to settle
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Initiate rekey
      const rekeyTimeout = setTimeout(() => {
        throw new Error('Rekey timeout');
      }, 5000);
      await client.rekey();
      clearTimeout(rekeyTimeout);

      // Wait a moment for cleanup
      await new Promise((resolve) => setTimeout(resolve, 50));
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      try {
        await server.close();
      } catch { /* ignore */ }
    }
  },
});

Deno.test({
  name: 'misc: Compression (zlib@openssh.com)',
  ignore: false,
  async fn() {
    clearMustCallChecks();
    const hostKey = await generateTestHostKeyEd25519();

    const DEBUG_COMPRESS = true; // Enable debug for this test

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
      algorithms: {
        compress: ['zlib@openssh.com', 'none'],
      },
      debug: DEBUG_COMPRESS ? (msg: string) => console.log('[COMPRESS][SERVER]', msg) : undefined,
    });

    const client = new Client();
    let receivedData = '';

    server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on(
          'authentication',
          mustCall((ctx: ServerAuthContext) => {
            ctx.accept();
          }),
        );
        conn.on(
          'ready',
          mustCall(() => {
            // Server is ready
          }),
        );
        conn.on(
          'session',
          mustCall((accept) => {
            const session = accept();
            if (!session) return;
            session.on(
              'exec',
              mustCall((accept, _reject, info) => {
                const stream = accept();
                if (!stream) return;
                // Echo back the command with some extra data to test compression
                const response = `Compressed response to: ${info.command}\n${'A'.repeat(1000)}\n`;
                stream.write(new TextEncoder().encode(response));
                stream.exit(0);
                stream.close();
              }),
            );
          }),
        );
        conn.on('close', () => server.close());
      }),
    );

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'testuser',
      password: 'testpass',
      algorithms: {
        compress: ['zlib@openssh.com', 'none'],
      },
      debug: DEBUG_COMPRESS ? (msg: string) => console.log('[COMPRESS][CLIENT]', msg) : undefined,
    });

    // client.connect() already waits for 'ready', so proceed directly
    const stream = await client.exec('test command');

    // Use ReadableStream API to read data
    const reader = stream.stdout.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const decoded = new TextDecoder().decode(value);
        console.log('[TEST] Received data:', decoded.substring(0, 50) + '...');
        receivedData += decoded;
      }
    } finally {
      reader.releaseLock();
    }
    console.log('[TEST] Stream finished, receivedData length:', receivedData.length);

    const closeDone = new Promise<void>((resolve) => {
      client.on('close', () => resolve());
    });
    client.end();
    await closeDone;

    assertEquals(receivedData.includes('Compressed response to: test command'), true);
    assertEquals(receivedData.includes('A'.repeat(100)), true);
    server.close();
    await new Promise((r) => setTimeout(r, 50));
    verifyMustCallChecks();
  },
});
