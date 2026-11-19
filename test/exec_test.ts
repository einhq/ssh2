/**
 * Exec Tests
 *
 * Tests for exec command execution over SSH.
 * Converted from test/test-exec.js
 */

import { assertEquals, assertExists, assertThrows } from '@std/assert';
import type { Channel, StderrWritable } from '../src/Channel.ts';
import { Client } from '../src/client.ts';
import { type Connection, Server, type ServerAuthContext, type Session } from '../src/server.ts';
import {
  clearMustCallChecks,
  generateTestHostKeyEd25519,
  mustCall,
  verifyMustCallChecks,
} from './integration_helpers.ts';

const DEBUG = false;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface TestContext {
  client: Client;
  server: Server;
  conn?: Connection;
  cleanup: () => Promise<void>;
}

/**
 * Create a test context with client and server
 */
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

/**
 * Connect client to server with password auth
 * Returns when both client and server are ready
 */
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

    // Set up client ready BEFORE connecting
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

/**
 * Collect all data from a readable stream
 */
async function collectStream(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const total = new Uint8Array(chunks.reduce((acc, c) => acc + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    total.set(chunk, offset);
    offset += chunk.length;
  }

  return decoder.decode(total);
}

// =============================================================================
// Tests
// =============================================================================

Deno.test('exec: Simple exec()', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('Simple exec()');

  try {
    const COMMAND = 'foo --bar';
    const STDOUT_DATA = 'stdout data!\n';
    const STDERR_DATA = 'stderr data!\n';

    const conn = await connectWithPasswordAuth(ctx, 'Simple exec()');

    // Server side: handle session and exec
    const execDone = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((accept: () => Session | undefined) => {
          const session = accept();
          assertExists(session);

          session!.on(
            'exec',
            mustCall((
              acceptExec: () => Channel | undefined,
              _reject: (() => void) | undefined,
              info: { command: string },
            ) => {
              assertEquals(info.command, COMMAND);

              const stream = acceptExec();
              assertExists(stream);

              // Server sends stderr and stdout, then exits
              (stream!.stderr as StderrWritable).write(encoder.encode(STDERR_DATA));
              stream!.write(STDOUT_DATA);
              stream!.exit(100);
              stream!.end();
              // Wait for stream to close before ending connection
              stream!.on('close', () => {
                conn.end();
                resolve();
              });
            }),
          );
        }),
      );
    });

    // Client side: execute command (client is already ready from connectWithPasswordAuth)
    const clientDone = (async () => {
      const stream = await ctx.client.exec(COMMAND);

      let exitCode: number | undefined;

      stream.on(
        'exit-status',
        mustCall((code: number) => {
          exitCode = code;
        }),
      );

      const closedPromise = new Promise<void>((resolve) => {
        stream.on(
          'close',
          mustCall(() => {
            assertEquals(exitCode, 100);
            resolve();
          }),
        );
      });

      // Collect stdout and stderr
      const [stdout, stderr] = await Promise.all([
        collectStream(stream.stdout),
        collectStream(stream.stderr as ReadableStream<Uint8Array>),
      ]);
      assertEquals(stdout, STDOUT_DATA);
      assertEquals(stderr, STDERR_DATA);

      await closedPromise;
    })();

    await Promise.all([execDone, clientDone]);
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('exec: Simple exec() with exit signal', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('Simple exec() (exit signal)');

  try {
    const COMMAND = 'foo --bar';
    const STDOUT_DATA = 'stdout data!\n';
    const STDERR_DATA = 'stderr data!\n';

    const conn = await connectWithPasswordAuth(ctx, 'Simple exec() (exit signal)');

    const execDone = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((accept: () => Session | undefined) => {
          const session = accept();
          assertExists(session);

          session!.on(
            'exec',
            mustCall((
              acceptExec: () => Channel | undefined,
              _reject: (() => void) | undefined,
              info: { command: string },
            ) => {
              assertEquals(info.command, COMMAND);

              const stream = acceptExec();
              assertExists(stream);

              (stream!.stderr as StderrWritable).write(encoder.encode(STDERR_DATA));
              stream!.write(STDOUT_DATA);

              // Test that invalid signals throw
              assertThrows(() => stream!.exit('SIGFAKE'));
              assertThrows(() => stream!.exit('FAKE'));

              // Valid signal
              stream!.exit('SIGKILL');
              stream!.end();
              resolve();
            }),
          );
        }),
      );
    });

    const clientDone = (async () => {
      const stream = await ctx.client.exec(COMMAND);

      let exitSignal: string | undefined;

      stream.on(
        'exit-signal',
        mustCall((signal: string, _coreDumped: boolean, _desc: string) => {
          exitSignal = signal;
        }),
      );

      const closedPromise = new Promise<void>((resolve) => {
        stream.on(
          'close',
          mustCall(() => {
            assertEquals(exitSignal, 'SIGKILL');
            conn.end();
            resolve();
          }),
        );
      });

      // Consume streams
      collectStream(stream.stdout);
      collectStream(stream.stderr as ReadableStream<Uint8Array>);

      await closedPromise;
    })();

    await Promise.all([execDone, clientDone]);
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('exec: Simple exec() with exit signal (no "SIG" prefix)', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('Simple exec() (exit signal -- no SIG)');

  try {
    const COMMAND = 'foo --bar';

    const conn = await connectWithPasswordAuth(ctx, 'Simple exec() (exit signal -- no SIG)');

    const execDone = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((accept: () => Session | undefined) => {
          const session = accept();
          assertExists(session);

          session!.on(
            'exec',
            mustCall((
              acceptExec: () => Channel | undefined,
              _reject: (() => void) | undefined,
              info: { command: string },
            ) => {
              assertEquals(info.command, COMMAND);

              const stream = acceptExec();
              assertExists(stream);

              // Test without SIG prefix
              stream!.exit('KILL');
              stream!.end();
              resolve();
            }),
          );
        }),
      );
    });

    const clientDone = (async () => {
      const stream = await ctx.client.exec(COMMAND);

      let exitSignal: string | undefined;

      stream.on(
        'exit-signal',
        mustCall((signal: string) => {
          // Server sends 'KILL', client prepends 'SIG'
          exitSignal = signal;
        }),
      );

      const closedPromise = new Promise<void>((resolve) => {
        stream.on(
          'close',
          mustCall(() => {
            assertEquals(exitSignal, 'SIGKILL');
            conn.end();
            resolve();
          }),
        );
      });

      // Consume streams
      collectStream(stream.stdout);
      collectStream(stream.stderr as ReadableStream<Uint8Array>);

      await closedPromise;
    })();

    await Promise.all([execDone, clientDone]);
  } finally {
    await ctx.cleanup();
  }
});

Deno.test({
  name: 'exec: Exec with environment set',
  ignore: false,
  fn: async () => {
    // Test environment variable passing
    clearMustCallChecks();
    const ctx = await createTestContext('Exec with environment set');

    try {
      const env = { SSH2NODETEST: 'foo' };

      const conn = await connectWithPasswordAuth(ctx, 'Exec with environment set');

      const execDone = new Promise<void>((resolve) => {
        conn.on(
          'session',
          mustCall((accept: () => Session | undefined) => {
            const session = accept();
            assertExists(session);

            session!.on(
              'env',
              mustCall((
                acceptEnv: (() => void) | undefined,
                _reject: (() => void) | undefined,
                info: { key: string; val: string },
              ) => {
                assertEquals(info.key, 'SSH2NODETEST');
                assertEquals(info.val, 'foo');
                if (acceptEnv) acceptEnv();
              }),
            );

            session!.on(
              'exec',
              mustCall((
                acceptExec: () => Channel | undefined,
                _reject: (() => void) | undefined,
                _info: { command: string },
              ) => {
                const stream = acceptExec();
                assertExists(stream);

                stream!.exit(100);
                stream!.end();
                resolve();
              }),
            );
          }),
        );
      });

      const clientDone = (async () => {
        const stream = await ctx.client.exec('foo --bar', { env });

        const closedPromise = new Promise<void>((resolve) => {
          stream.on(
            'close',
            mustCall(() => {
              conn.end();
              resolve();
            }),
          );
        });

        // Consume stream
        collectStream(stream.stdout);

        await closedPromise;
      })();

      await Promise.all([execDone, clientDone]);
    } finally {
      await ctx.cleanup();
    }
  },
});

Deno.test({
  name: 'exec: Exec with setWindow()',
  ignore: false,
  fn: async () => {
    // Test window-change messages
    clearMustCallChecks();
    const ctx = await createTestContext('Exec with setWindow()');

    try {
      const dimensions = {
        rows: 60,
        cols: 115,
        height: 480,
        width: 640,
      };

      const conn = await connectWithPasswordAuth(ctx, 'Exec with setWindow()');

      const execDone = new Promise<void>((resolve) => {
        conn.on(
          'session',
          mustCall((accept: () => Session | undefined) => {
            const session = accept();
            assertExists(session);

            session!.on(
              'window-change',
              mustCall((
                acceptWc: (() => void) | undefined,
                _reject: (() => void) | undefined,
                info: { rows: number; cols: number; height: number; width: number },
              ) => {
                assertEquals(info.rows, dimensions.rows);
                assertEquals(info.cols, dimensions.cols);
                assertEquals(info.height, dimensions.height);
                assertEquals(info.width, dimensions.width);
                if (acceptWc) acceptWc();
              }),
            );

            session!.on(
              'exec',
              mustCall((
                acceptExec: () => Channel | undefined,
                _reject: (() => void) | undefined,
                _info: { command: string },
              ) => {
                const stream = acceptExec();
                assertExists(stream);

                stream!.exit(100);
                stream!.end();
                resolve();
              }),
            );
          }),
        );
      });

      const clientDone = (async () => {
        const stream = await ctx.client.exec('foo --bar');

        stream.setWindow(dimensions.rows, dimensions.cols, dimensions.height, dimensions.width);

        const closedPromise = new Promise<void>((resolve) => {
          stream.on(
            'close',
            mustCall(() => {
              conn.end();
              resolve();
            }),
          );
        });

        // Consume stream
        collectStream(stream.stdout);

        await closedPromise;
      })();

      await Promise.all([execDone, clientDone]);
    } finally {
      await ctx.cleanup();
    }
  },
});

Deno.test({
  name: 'exec: Exec with pty set',
  ignore: false,
  fn: async () => {
    // Test PTY request handling
    clearMustCallChecks();
    const ctx = await createTestContext('Exec with pty set');

    try {
      const pty = {
        rows: 2,
        cols: 4,
        width: 640, // Non-zero to avoid falsy || default in client.ts
        height: 480, // Non-zero to avoid falsy || default in client.ts
        term: 'vt220',
        modes: {},
      };

      const conn = await connectWithPasswordAuth(ctx, 'Exec with pty set');

      let sawPty = false;

      const execDone = new Promise<void>((resolve) => {
        conn.on(
          'session',
          mustCall((accept: () => Session | undefined) => {
            const session = accept();
            assertExists(session);

            session!.on(
              'pty',
              mustCall((
                acceptPty: (() => void) | undefined,
                _reject: (() => void) | undefined,
                info: {
                  rows: number;
                  cols: number;
                  height: number;
                  width: number;
                  term: string;
                  modes: Uint8Array;
                },
              ) => {
                assertEquals(info.rows, pty.rows);
                assertEquals(info.cols, pty.cols);
                assertEquals(info.height, pty.height);
                assertEquals(info.width, pty.width);
                assertEquals(info.term, pty.term);
                sawPty = true;
                if (acceptPty) acceptPty();
              }),
            );

            session!.on(
              'exec',
              mustCall((
                acceptExec: () => Channel | undefined,
                _reject: (() => void) | undefined,
                info: { command: string },
              ) => {
                assertEquals(sawPty, true, 'Expected pty to be set up before exec');
                assertEquals(info.command, 'foo --bar');

                const stream = acceptExec();
                assertExists(stream);

                stream!.exit(100);
                stream!.end();
                resolve();
              }),
            );
          }),
        );
      });

      const clientDone = (async () => {
        const stream = await ctx.client.exec('foo --bar', { pty });

        const closedPromise = new Promise<void>((resolve) => {
          stream.on(
            'close',
            mustCall(() => {
              conn.end();
              resolve();
            }),
          );
        });

        // Consume stream
        collectStream(stream.stdout);

        await closedPromise;
      })();

      await Promise.all([execDone, clientDone]);
    } finally {
      await ctx.cleanup();
    }
  },
});

Deno.test('exec: exec() immediately after connect() without separate ready listener', async () => {
  clearMustCallChecks();
  const title = 'exec after connect';
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
  const addr = server.address()!;

  try {
    const COMMAND = 'test-cmd';
    const STDOUT_DATA = 'hello from exec\n';

    // Server side: accept auth + handle session
    server.on('connection', (conn: Connection) => {
      conn.on('authentication', (authCtx: ServerAuthContext) => {
        authCtx.accept();
      });
      conn.on('ready', () => {
        conn.on('session', (accept: () => Session | undefined) => {
          const session = accept();
          if (!session) return;

          session.on('exec', (
            acceptExec: () => Channel | undefined,
            _reject: (() => void) | undefined,
            info: { command: string },
          ) => {
            assertEquals(info.command, COMMAND);
            const stream = acceptExec();
            if (!stream) return;
            stream.write(STDOUT_DATA);
            stream.exit(0);
            stream.end();
          });
        });
      });
    });

    // Client side: connect() then immediately exec() — no separate 'ready' listener
    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'test',
      password: 'test',
      debug: DEBUG ? (msg: string) => console.log(`[${title}][CLIENT]`, msg) : undefined,
    });

    // If connect() doesn't wait for auth, this would fail with channel open failure
    const stream = await client.exec(COMMAND);
    const stdout = await collectStream(stream.stdout);
    assertEquals(stdout, STDOUT_DATA);
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

Deno.test('exec: the exec channel closes when its client goes without closing it', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('client gone');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'client gone');

    // Server side: a command that runs until its channel closes, as one whose client was killed
    const closed = new Promise<void>((resolve) => {
      conn.on('session', (accept: () => Session | undefined) => {
        const session = accept();
        assertExists(session);
        session!.on('exec', (acceptExec: () => Channel | undefined) => {
          const stream = acceptExec();
          assertExists(stream);
          stream!.write('running\n');
          stream!.on('close', () => resolve());
        });
      });
    });

    // Client side: read the first output, then disconnect without closing the channel
    const stream = await ctx.client.exec('run-forever');
    const reader = stream.stdout.getReader();
    assertEquals(decoder.decode((await reader.read()).value), 'running\n');
    reader.releaseLock();
    ctx.client.end();

    await closed;
  } finally {
    await ctx.cleanup();
  }
});
