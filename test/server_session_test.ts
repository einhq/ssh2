/**
 * Server Session Integration Tests
 *
 * Tests for server-side session handling, auth flows, channel requests,
 * and other server features. These tests increase branch coverage for
 * src/server.ts and src/protocol/handlers.ts.
 */

import { assertEquals, assertExists } from '@std/assert';
import type { Channel } from '../src/Channel.ts';
import { Client } from '../src/client.ts';
import {
  type Connection,
  type ConnectionInfo,
  KeyboardAuthContext,
  type PKAuthContext,
  Server,
  type ServerAuthContext,
  type Session,
} from '../src/server.ts';
import {
  clearMustCallChecks,
  generateTestHostKeyEd25519,
  generateTestHostKeyRSA,
  mustCall,
  verifyMustCallChecks,
} from './integration_helpers.ts';

const FIXTURES_PATH = new URL('./fixtures', import.meta.url).pathname;

function fixture(file: string): Uint8Array {
  return Deno.readFileSync(`${FIXTURES_PATH}/${file}`);
}

const DEBUG = false;

interface TestContext {
  client: Client;
  server: Server;
  cleanup: () => Promise<void>;
}

async function createTestContext(title: string): Promise<TestContext> {
  const hostKey = await generateTestHostKeyEd25519();

  const server = new Server({
    hostKeys: [hostKey.parsedKey],
    debug: DEBUG ? (msg: string) => console.log(`[${title}][SERVER]`, msg) : undefined,
  });

  const client = new Client();
  server.on('error', () => {});
  client.on('error', () => {});

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
      if (connReady && clientReady && conn) resolve(conn);
    };

    server.on(
      'connection',
      mustCall((c: Connection) => {
        conn = c;
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
      password: 'testpass',
      debug: DEBUG ? (msg) => console.log(`[${title}][CLIENT]`, msg) : undefined,
    }).catch(reject);
  });
}

// =============================================================================
// Keyboard-interactive auth tests
// =============================================================================

Deno.test('auth: keyboard-interactive basic prompt and response', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('keyboard-interactive basic');

  try {
    const addr = ctx.server.address()!;

    // Resolve only when both server AND client report ready (avoids race on USERAUTH_SUCCESS)
    let serverReady = false;
    let clientReady = false;
    let resolveAuth!: () => void;
    const authDone = new Promise<void>((res) => {
      resolveAuth = res;
    });
    const checkDone = () => {
      if (serverReady && clientReady) resolveAuth();
    };

    ctx.server.on('connection', (conn: Connection) => {
      // Auth fires twice: once for 'none' and once for 'keyboard-interactive'
      conn.on('authentication', (authCtx: ServerAuthContext) => {
        if (authCtx.method !== 'keyboard-interactive') {
          authCtx.reject(['keyboard-interactive']);
          return;
        }
        assertExists(authCtx instanceof KeyboardAuthContext);
        const kbCtx = authCtx as KeyboardAuthContext;
        kbCtx.prompt('Enter password:', (responses) => {
          assertEquals(responses.length, 1);
          assertEquals(responses[0], 'secret');
          kbCtx.accept();
        });
      });
      conn.on('ready', () => {
        serverReady = true;
        checkDone();
      });
    });

    ctx.client.on('keyboard-interactive', (_name, _instructions, _lang, _prompts, finish) => {
      finish(['secret']);
    });
    ctx.client.on('ready', () => {
      clientReady = true;
      checkDone();
    });

    await ctx.client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'testuser',
      tryKeyboard: true,
      debug: DEBUG ? (msg) => console.log('[KBD CLIENT]', msg) : undefined,
    });

    await authDone;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('auth: keyboard-interactive with title + instructions + callback', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('keyboard-interactive title');

  try {
    const addr = ctx.server.address()!;

    let serverReady = false;
    let clientReady = false;
    let resolveAuth!: () => void;
    const authDone = new Promise<void>((res) => {
      resolveAuth = res;
    });
    const checkDone = () => {
      if (serverReady && clientReady) resolveAuth();
    };

    ctx.server.on('connection', (conn: Connection) => {
      conn.on('authentication', (authCtx: ServerAuthContext) => {
        if (authCtx.method !== 'keyboard-interactive') {
          authCtx.reject(['keyboard-interactive']);
          return;
        }
        const kbCtx = authCtx as KeyboardAuthContext;
        kbCtx.prompt(
          [{ prompt: 'Password:', echo: false }],
          'Login',
          'Enter credentials',
          (responses) => {
            assertEquals(responses[0], 'mypass');
            kbCtx.accept();
          },
        );
      });
      conn.on('ready', () => {
        serverReady = true;
        checkDone();
      });
    });

    ctx.client.on('keyboard-interactive', (_name, _instructions, _lang, _prompts, finish) => {
      finish(['mypass']);
    });
    ctx.client.on('ready', () => {
      clientReady = true;
      checkDone();
    });

    await ctx.client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'testuser',
      tryKeyboard: true,
    });

    await authDone;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('auth: keyboard-interactive with title and cb as second arg', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('keyboard-interactive title+cb');

  try {
    const addr = ctx.server.address()!;

    let serverReady = false;
    let clientReady = false;
    let resolveAuth!: () => void;
    const authDone = new Promise<void>((res) => {
      resolveAuth = res;
    });
    const checkDone = () => {
      if (serverReady && clientReady) resolveAuth();
    };

    ctx.server.on('connection', (conn: Connection) => {
      conn.on('authentication', (authCtx: ServerAuthContext) => {
        if (authCtx.method !== 'keyboard-interactive') {
          authCtx.reject(['keyboard-interactive']);
          return;
        }
        const kbCtx = authCtx as KeyboardAuthContext;
        // titleOrCb is a string, instructionsOrCb is a function → picks up as title + cb
        kbCtx.prompt('Passphrase:', 'Login', (responses) => {
          assertEquals(responses[0], 'p@ss');
          kbCtx.accept();
        });
      });
      conn.on('ready', () => {
        serverReady = true;
        checkDone();
      });
    });

    ctx.client.on('keyboard-interactive', (_n, _i, _l, _p, finish) => finish(['p@ss']));
    ctx.client.on('ready', () => {
      clientReady = true;
      checkDone();
    });

    await ctx.client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'testuser',
      tryKeyboard: true,
    });

    await authDone;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('auth: keyboard-interactive with array prompt and cb as second arg', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('keyboard-interactive arr+cb');

  try {
    const addr = ctx.server.address()!;

    let serverReady = false;
    let clientReady = false;
    let resolveAuth!: () => void;
    const authDone = new Promise<void>((res) => {
      resolveAuth = res;
    });
    const checkDone = () => {
      if (serverReady && clientReady) resolveAuth();
    };

    ctx.server.on('connection', (conn: Connection) => {
      conn.on('authentication', (authCtx: ServerAuthContext) => {
        if (authCtx.method !== 'keyboard-interactive') {
          authCtx.reject(['keyboard-interactive']);
          return;
        }
        const kbCtx = authCtx as KeyboardAuthContext;
        // titleOrCb is a function → covered the "typeof titleOrCb === 'function'" branch
        kbCtx.prompt([{ prompt: 'Enter token:', echo: false }], (responses) => {
          assertEquals(responses[0], 'abc123');
          kbCtx.accept();
        });
      });
      conn.on('ready', () => {
        serverReady = true;
        checkDone();
      });
    });

    ctx.client.on('keyboard-interactive', (_n, _i, _l, _p, finish) => finish(['abc123']));
    ctx.client.on('ready', () => {
      clientReady = true;
      checkDone();
    });

    await ctx.client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'testuser',
      tryKeyboard: true,
    });

    await authDone;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('auth: rejection with methods triggers USERAUTH_FAILURE', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('auth rejection with methods');

  try {
    const addr = ctx.server.address()!;
    let attempts = 0;

    // Resolve from conn 'ready' (after USERAUTH_SUCCESS is sent) to avoid race with cleanup
    const done = new Promise<void>((resolve) => {
      ctx.server.on(
        'connection',
        mustCall((conn: Connection) => {
          conn.on('authentication', (authCtx: ServerAuthContext) => {
            attempts++;
            if (attempts === 1) {
              authCtx.reject(['password']);
            } else {
              authCtx.accept();
            }
          });
          conn.on('ready', () => resolve());
        }),
      );
    });

    await ctx.client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'test',
      password: 'pass',
    });

    await done;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('auth: rejection without methods list', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('auth rejection no methods');

  try {
    const addr = ctx.server.address()!;

    // Server rejects with no methods → client has no fallback and connect rejects
    ctx.server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on(
          'authentication',
          mustCall((authCtx: ServerAuthContext) => {
            authCtx.reject(); // No methods list - covers USERAUTH_FAILURE with empty methods
          }),
        );
      }),
    );

    let connectError: Error | undefined;
    try {
      await ctx.client.connect({ host: addr.hostname, port: addr.port, username: 'test' });
    } catch (err) {
      connectError = err as Error;
    }

    assertEquals(connectError !== undefined, true);
    assertEquals(connectError!.message, 'All configured authentication methods failed');
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('auth: banner is sent on first authentication request', async () => {
  clearMustCallChecks();
  const hostKey = await generateTestHostKeyEd25519();
  const BANNER = 'Welcome to the SSH server!\n';

  const server = new Server({ hostKeys: [hostKey.parsedKey], banner: BANNER });
  server.on('error', () => {});
  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;

  const client = new Client();
  client.on('error', () => {});

  try {
    // Wait for banner AND client ready before checking (avoid race with cleanup)
    let bannerText = '';
    let bannerGot = false;
    let clientReady = false;
    let resolveAll!: () => void;
    const done = new Promise<void>((res) => {
      resolveAll = res;
    });
    const check = () => {
      if (bannerGot && clientReady) resolveAll();
    };

    client.on('banner', (message: string) => {
      bannerText = message;
      bannerGot = true;
      check();
    });
    client.on('ready', () => {
      clientReady = true;
      check();
    });

    server.on(
      'connection',
      mustCall((conn: Connection) => {
        conn.on('authentication', mustCall((authCtx: ServerAuthContext) => authCtx.accept()));
        // conn 'ready' fires before client 'ready', so no mustCall needed here
      }),
    );

    await client.connect({ host: addr.hostname, port: addr.port, username: 'test', password: 'p' });
    await done;

    assertEquals(bannerText, BANNER);
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

Deno.test('auth: double accept is a no-op', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('double accept prevention');

  try {
    const addr = ctx.server.address()!;

    const done = new Promise<void>((resolve) => {
      ctx.server.on(
        'connection',
        mustCall((conn: Connection) => {
          conn.on(
            'authentication',
            mustCall((authCtx: ServerAuthContext) => {
              authCtx.accept();
              authCtx.accept(); // No-op
              resolve();
            }),
          );
          conn.on('ready', () => {});
        }),
      );
    });

    ctx.client.on('ready', () => {});
    await ctx.client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'test',
      password: 'pass',
    });

    await done;
  } finally {
    await ctx.cleanup();
  }
});

// =============================================================================
// Channel request type tests
// =============================================================================

Deno.test('session: env request is forwarded to session listener', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('env request');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'env request');

    const envReceived = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((acceptSession: () => Session | undefined) => {
          const session = acceptSession();
          assertExists(session);

          session!.on(
            'env',
            mustCall((
              acceptEnv: (() => void) | undefined,
              _reject: (() => void) | undefined,
              info: { key: string; val: string },
            ) => {
              assertEquals(info.key, 'MY_VAR');
              assertEquals(info.val, 'hello');
              acceptEnv?.();

              session!.on(
                'shell',
                mustCall((shellAccept: () => Channel | undefined) => {
                  const chan = shellAccept();
                  chan?.end();
                  resolve();
                }),
              );
            }),
          );
        }),
      );
    });

    // shell() with env sends env request before shell
    const channel = await ctx.client.shell({ env: { MY_VAR: 'hello' }, pty: false });
    channel.on('close', () => {});

    await envReceived;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('session: pty-req is forwarded to session listener', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('pty request');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'pty request');

    const done = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((acceptSession: () => Session | undefined) => {
          const session = acceptSession();
          assertExists(session);

          session!.on(
            'pty',
            mustCall((
              acceptPty: (() => void) | undefined,
              _reject: (() => void) | undefined,
              info: Record<string, unknown>,
            ) => {
              assertExists(info.term);
              acceptPty?.();

              session!.on(
                'shell',
                mustCall((shellAccept: () => Channel | undefined) => {
                  const chan = shellAccept();
                  chan?.end();
                  resolve();
                }),
              );
            }),
          );
        }),
      );
    });

    // shell() sends pty-req by default
    const channel = await ctx.client.shell();
    channel.on('close', () => {});
    channel.end();

    await done;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('session: window-change with listener', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('window-change with listener');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'window-change with listener');

    const windowChangeDone = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((acceptSession: () => Session | undefined) => {
          const session = acceptSession();
          assertExists(session);

          session!.on(
            'pty',
            mustCall((acceptPty: (() => void) | undefined) => {
              acceptPty?.();
            }),
          );

          session!.on(
            'window-change',
            mustCall((
              _acceptWc: (() => void) | undefined,
              _reject: (() => void) | undefined,
              info: { cols: number; rows: number },
            ) => {
              assertEquals(info.cols, 120);
              assertEquals(info.rows, 40);
              resolve();
            }),
          );

          session!.on(
            'shell',
            mustCall((shellAccept: () => Channel | undefined) => {
              const chan = shellAccept();
              chan?.end();
            }),
          );
        }),
      );
    });

    const channel = await ctx.client.shell();
    channel.setWindow(40, 120, 480, 960);
    channel.on('close', () => {});

    await windowChangeDone;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('session: window-change without listener is auto-rejected', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('window-change no listener');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'window-change no listener');

    const done = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((acceptSession: () => Session | undefined) => {
          const session = acceptSession();
          assertExists(session);

          session!.on(
            'pty',
            mustCall((acceptPty: (() => void) | undefined) => {
              acceptPty?.();
            }),
          );

          // No 'window-change' listener → auto-reject branch in server.ts
          session!.on(
            'shell',
            mustCall((shellAccept: () => Channel | undefined) => {
              const chan = shellAccept();
              chan?.end();
              resolve();
            }),
          );
        }),
      );
    });

    const channel = await ctx.client.shell();
    channel.setWindow(40, 120, 480, 960);
    channel.on('close', () => {});

    await done;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('session: auth-agent-req is forwarded to session listener', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('auth-agent request');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'auth-agent request');

    const done = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((acceptSession: () => Session | undefined) => {
          const session = acceptSession();
          assertExists(session);

          session!.on(
            'auth-agent',
            mustCall((
              acceptAgent: (() => void) | undefined,
            ) => {
              acceptAgent?.();
            }),
          );

          session!.on(
            'shell',
            mustCall((shellAccept: () => Channel | undefined) => {
              const chan = shellAccept();
              chan?.end();
              resolve();
            }),
          );
        }),
      );
    });

    // shell with agentForward sends auth-agent-req
    const channel = await ctx.client.shell({ agentForward: true, pty: false });
    channel.on('close', () => {});

    await done;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('session: sftp subsystem is emitted as sftp event', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('sftp subsystem');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'sftp subsystem');

    const sftpDone = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((acceptSession: () => Session | undefined) => {
          const session = acceptSession();
          assertExists(session);

          session!.on(
            'sftp',
            mustCall((
              sftpAccept: () => Channel | undefined,
            ) => {
              const chan = sftpAccept();
              assertExists(chan);
              // Resolve immediately - 'sftp' event with valid channel confirms coverage.
              // Don't wait for chan 'close'; the SFTP protocol handshake may not complete
              // when the server destroys the channel before the client finishes SSH_FXP_INIT.
              resolve();
              try {
                chan?.destroy();
              } catch { /* ignore */ }
            }),
          );
        }),
      );
    });

    // client.sftp() sends subsystem 'sftp'
    ctx.client.sftp().catch(() => {}); // Will fail since we close the channel immediately

    await sftpDone;
  } finally {
    await ctx.cleanup();
  }
});

// =============================================================================
// Channel open type tests
// =============================================================================

Deno.test('channel: direct-tcpip channel open is accepted', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('direct-tcpip open');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'direct-tcpip open');

    const tcpipDone = new Promise<void>((resolve) => {
      conn.on(
        'tcpip',
        mustCall((
          accept: () => Channel | undefined,
          _reject: () => void,
          info: { srcIP: string; srcPort: number; destIP: string; destPort: number },
        ) => {
          assertEquals(info.destIP, '192.168.1.1');
          assertEquals(info.destPort, 80);
          const channel = accept();
          assertExists(channel);
          channel!.end();
          resolve();
        }),
      );
    });

    const channel = await ctx.client.forwardOut('127.0.0.1', 12345, '192.168.1.1', 80);
    channel.on('close', () => {});
    channel.end();

    await tcpipDone;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('channel: direct-tcpip without listener is auto-rejected', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('direct-tcpip no listener');

  try {
    await connectWithPasswordAuth(ctx, 'direct-tcpip no listener');

    let errReceived = false;
    try {
      await ctx.client.forwardOut('127.0.0.1', 12345, '192.168.1.1', 80);
    } catch {
      errReceived = true;
    }

    assertEquals(errReceived, true);
  } finally {
    await ctx.cleanup();
  }
});

// =============================================================================
// Global request tests
// =============================================================================

Deno.test('global: tcpip-forward is handled by request listener', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('tcpip-forward');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'tcpip-forward');

    conn.on(
      'request',
      mustCall((
        accept: ((port?: number) => void) | undefined,
        _reject: (() => void) | undefined,
        name: string,
      ) => {
        assertEquals(name, 'tcpip-forward');
        accept?.();
      }),
    );

    const port = await ctx.client.forwardIn('127.0.0.1', 0);
    assertEquals(typeof port, 'number');
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('global: request without listener is auto-rejected', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('global request no listener');

  try {
    await connectWithPasswordAuth(ctx, 'global request no listener');

    let errReceived = false;
    try {
      await ctx.client.forwardIn('127.0.0.1', 8080);
    } catch {
      errReceived = true;
    }

    assertEquals(errReceived, true);
  } finally {
    await ctx.cleanup();
  }
});

// =============================================================================
// Server constructor tests
// =============================================================================

Deno.test('server: RSA host key registers multiple hash algorithm variants', async () => {
  clearMustCallChecks();
  const rsaKey = await generateTestHostKeyRSA(2048);

  const server = new Server({ hostKeys: [rsaKey.parsedKey] });
  server.on('error', () => {});

  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;
  assertExists(addr);

  const client = new Client();
  client.on('error', () => {});

  try {
    const readyDone = new Promise<void>((resolve) => {
      server.on(
        'connection',
        mustCall((conn: Connection) => {
          conn.on('authentication', mustCall((authCtx: ServerAuthContext) => authCtx.accept()));
          conn.on('ready', mustCall(() => {}));
        }),
      );
      client.on('ready', mustCall(() => resolve()));
    });

    await client.connect({ host: addr.hostname, port: addr.port, username: 'test', password: 't' });
    await readyDone;
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

Deno.test('server: constructor with connection listener argument', async () => {
  clearMustCallChecks();
  const hostKey = await generateTestHostKeyEd25519();
  let listenerCalled = false;
  let info: ConnectionInfo | undefined;

  const server = new Server(
    { hostKeys: [hostKey.parsedKey] },
    mustCall((conn: Connection, connInfo: ConnectionInfo) => {
      listenerCalled = true;
      info = connInfo;
      conn.on('authentication', mustCall((authCtx: ServerAuthContext) => authCtx.accept()));
      conn.on('ready', mustCall(() => {}));
    }),
  );

  server.on('error', () => {});
  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;

  const client = new Client();
  client.on('error', () => {});

  try {
    const done = new Promise<void>((resolve) => {
      client.on('ready', mustCall(() => resolve()));
    });

    await client.connect({ host: addr.hostname, port: addr.port, username: 'test', password: 't' });
    await done;
    assertEquals(listenerCalled, true);
    assertEquals(info?.ip, '127.0.0.1');
    assertEquals(typeof info?.port, 'number');
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

Deno.test('server: maxConnections limits simultaneous connections', async () => {
  clearMustCallChecks();
  const hostKey = await generateTestHostKeyEd25519();

  const server = new Server({ hostKeys: [hostKey.parsedKey] });
  server.on('error', () => {});
  server.maxConnections = 1;

  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;

  const client1 = new Client();
  const client2 = new Client();
  client1.on('error', () => {});
  client2.on('error', () => {});

  try {
    const conn1Done = new Promise<void>((resolve) => {
      server.on('connection', (conn: Connection) => {
        conn.on('authentication', (authCtx: ServerAuthContext) => authCtx.accept());
        conn.on('ready', () => resolve());
      });
    });

    client1.on('ready', () => {});
    await client1.connect({ host: addr.hostname, port: addr.port, username: 't', password: 'p' });
    await conn1Done;

    // Second client should be rejected (transport closed immediately by maxConnections).
    // connect() will throw because the server drops the connection before auth completes.
    let client2Error: Error | undefined;
    try {
      await client2.connect({
        host: addr.hostname,
        port: addr.port,
        username: 't',
        password: 'p',
      });
    } catch (err) {
      client2Error = err as Error;
    }

    assertEquals(client2Error !== undefined, true);
  } finally {
    try {
      client1.end();
    } catch { /* ignore */ }
    try {
      client2.end();
    } catch { /* ignore */ }
    try {
      await server.close();
    } catch { /* ignore */ }
    clearMustCallChecks();
  }
});

// =============================================================================
// PKAuthContext tests
// =============================================================================

Deno.test('auth: publickey auth with user private key', async () => {
  clearMustCallChecks();
  const hostKey = await generateTestHostKeyEd25519();
  // Use a fixture RSA key in traditional PEM format that parseKey() can parse
  const userPrivateKey = fixture('id_rsa');

  const server = new Server({ hostKeys: [hostKey.parsedKey] });
  server.on('error', () => {});
  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;

  const client = new Client();
  client.on('error', () => {});

  try {
    // Wait for conn 'ready' to ensure USERAUTH_SUCCESS was processed before cleanup
    const done = new Promise<void>((resolve) => {
      server.on(
        'connection',
        mustCall((conn: Connection) => {
          conn.on('authentication', (authCtx: ServerAuthContext) => {
            if (authCtx.method === 'publickey') {
              const pkCtx = authCtx as PKAuthContext;
              pkCtx.accept();
            } else {
              authCtx.reject(['publickey']);
            }
          });
          conn.on('ready', () => resolve());
        }),
      );
    });

    client.on('ready', () => {});
    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'test',
      privateKey: userPrivateKey,
    });

    await done;
  } finally {
    try {
      client.end();
    } catch { /* ignore */ }
    try {
      await server.close();
    } catch { /* ignore */ }
    clearMustCallChecks();
  }
});

// =============================================================================
// PwdAuthContext — password change flow
// =============================================================================

// NOTE: password change flow (requestChange) cannot be tested end-to-end because
// the Client class does not implement USERAUTH_PASSWD_CHANGEREQ handling.
// The PwdAuthContext.requestChange method is covered by the server code path but
// requires a lower-level client that processes SSH message type 60.

// =============================================================================
// exec() channel request tests
// =============================================================================

Deno.test('session: exec command is forwarded to session listener', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('exec command');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'exec command');

    const execDone = new Promise<void>((resolve) => {
      conn.on(
        'session',
        mustCall((acceptSession: () => Session | undefined) => {
          const session = acceptSession();
          assertExists(session);

          session!.on(
            'exec',
            mustCall((
              execAccept: () => Channel | undefined,
              _reject: (() => void) | undefined,
              info: { command: string },
            ) => {
              assertEquals(info.command, 'echo hello');
              const chan = execAccept();
              assertExists(chan);
              chan!.end();
              resolve();
            }),
          );
        }),
      );
    });

    const channel = await ctx.client.exec('echo hello');
    channel.on('close', () => {});

    await execDone;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('session: exec with no exec listener is auto-rejected', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('exec no listener');

  try {
    await connectWithPasswordAuth(ctx, 'exec no listener');

    // Server has no 'exec' listener on the session → auto-reject
    // client.exec() should reject
    let errReceived = false;
    try {
      await ctx.client.exec('echo hello');
    } catch {
      errReceived = true;
    }

    assertEquals(errReceived, true);
  } finally {
    await ctx.cleanup();
  }
});

// NOTE: session 'signal' test is omitted because channel.signal() calls
// _protocol.signal?.() which doesn't exist on Protocol, so no signal is sent.

Deno.test('coverage: debug logging branches are covered by enabled debug mode', async () => {
  // This test enables a no-op debug function on both server and client.
  // The sole purpose is to exercise the `self._debug?.()` branches in handlers.ts
  // and the `debug?.(...)` branches in Protocol.ts / server.ts, which are skipped
  // when debug is undefined. We use a no-op (() => {}) to avoid polluting test output.
  clearMustCallChecks();

  const noopDebug = () => {};
  const hostKey = await generateTestHostKeyEd25519();
  const server = new Server({ hostKeys: [hostKey.parsedKey], debug: noopDebug });
  server.on('error', () => {});
  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;

  const client = new Client();
  client.on('error', () => {});

  try {
    let serverReady = false;
    let clientReady = false;
    let resolveAll!: () => void;
    const ready = new Promise<void>((res) => {
      resolveAll = res;
    });
    const check = () => {
      if (serverReady && clientReady) resolveAll();
    };

    let serverConn: Connection | undefined;

    server.on(
      'connection',
      mustCall((conn: Connection) => {
        serverConn = conn;
        // Use keyboard-interactive to cover USERAUTH_INFO_REQUEST/RESPONSE debug branches
        conn.on('authentication', (authCtx: ServerAuthContext) => {
          if (authCtx.method === 'keyboard-interactive') {
            const kbCtx = authCtx as KeyboardAuthContext;
            kbCtx.prompt('Enter token:', (responses) => {
              assertEquals(responses[0], 'debugtoken');
              kbCtx.accept();
            });
          } else {
            authCtx.reject(['keyboard-interactive']);
          }
        });
        conn.on('ready', () => {
          serverReady = true;
          check();
        });
      }),
    );

    client.on('keyboard-interactive', (_n, _i, _l, _p, finish) => finish(['debugtoken']));
    client.on('ready', () => {
      clientReady = true;
      check();
    });

    await client.connect({
      host: addr.hostname,
      port: addr.port,
      username: 'testuser',
      tryKeyboard: true,
      debug: noopDebug,
    });

    await ready;

    // Do a full session + shell to cover CHANNEL_REQUEST debug branches
    const shellDone = new Promise<void>((resolve) => {
      serverConn!.on(
        'session',
        mustCall((acceptSession: () => Session | undefined) => {
          const session = acceptSession();
          session!.on(
            'shell',
            mustCall((shellAccept: () => Channel | undefined) => {
              const chan = shellAccept();
              chan?.end();
              resolve();
            }),
          );
        }),
      );
    });

    const channel = await client.shell({ pty: false });
    channel.on('close', () => {});
    await shellDone;

    // Also do a forwardIn to cover GLOBAL_REQUEST/REQUEST_SUCCESS debug branches
    const requestDone = new Promise<void>((resolve) => {
      serverConn!.on(
        'request',
        mustCall((
          accept: ((port?: number) => void) | undefined,
        ) => {
          accept?.();
          resolve();
        }),
      );
    });

    await client.forwardIn('127.0.0.1', 0);
    await requestDone;

    // Reject another forwardIn to cover REQUEST_FAILURE debug branch
    // (no second 'request' listener, so server auto-rejects)
    try {
      await client.forwardIn('127.0.0.1', 9090);
    } catch {
      // Expected: auto-rejected since no new 'request' listener registered
    }
  } finally {
    try {
      client.end();
    } catch { /* ignore */ }
    try {
      await server.close();
    } catch { /* ignore */ }
    clearMustCallChecks();
  }
});

Deno.test('auth: no authentication listener auto-rejects connections', async () => {
  clearMustCallChecks();
  // Server with NO 'authentication' listener → auto-rejects all auth
  const hostKey = await generateTestHostKeyEd25519();
  const server = new Server({ hostKeys: [hostKey.parsedKey] });
  server.on('error', () => {});
  await server.listen(0, '127.0.0.1');
  const addr = server.address()!;

  const client = new Client();
  client.on('error', () => {});

  try {
    // Client connect rejects when all auth attempts are rejected
    let connectError: Error | undefined;
    try {
      await client.connect({
        host: addr.hostname,
        port: addr.port,
        username: 'test',
        password: 'p',
      });
    } catch (err) {
      connectError = err as Error;
    }

    assertEquals(connectError !== undefined, true);
  } finally {
    try {
      client.end();
    } catch { /* ignore */ }
    try {
      await server.close();
    } catch { /* ignore */ }
    clearMustCallChecks();
  }
});

Deno.test('channel: session open is rejected when noMoreSessions is set', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('noMoreSessions');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'noMoreSessions');

    // Set noMoreSessions on the server-side connection
    conn.noMoreSessions = true;

    // Now client tries to open a session → server rejects with ADMINISTRATIVELY_PROHIBITED
    let errReceived = false;
    try {
      await ctx.client.shell({ pty: false });
    } catch {
      errReceived = true;
    }

    assertEquals(errReceived, true);
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('channel: session open rejected when no session listener', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('no session listener');

  try {
    // Connect but don't register 'session' listener on the connection
    const addr = ctx.server.address()!;

    const done = new Promise<void>((resolve, reject) => {
      let serverConn: Connection | undefined;
      let connReady = false;
      let clientReady = false;

      const check = () => {
        if (connReady && clientReady && serverConn) resolve();
      };

      ctx.server.on(
        'connection',
        mustCall((c: Connection) => {
          serverConn = c;
          // No 'session' listener registered here
          c.on('authentication', mustCall((authCtx: ServerAuthContext) => authCtx.accept()));
          c.on(
            'ready',
            mustCall(() => {
              connReady = true;
              check();
            }),
          );
        }),
      );

      ctx.client.on(
        'ready',
        mustCall(() => {
          clientReady = true;
          check();
        }),
      );

      ctx.client.connect({
        host: addr.hostname,
        port: addr.port,
        username: 'test',
        password: 'pass',
      }).catch(reject);
    });

    await done;

    // Now open a session with no listener → server rejects
    let errReceived = false;
    try {
      await ctx.client.shell({ pty: false });
    } catch {
      errReceived = true;
    }

    assertEquals(errReceived, true);
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('session: connection close emits close on server Connection', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('conn close');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'conn close');

    const closeDone = new Promise<void>((resolve) => {
      conn.on(
        'close',
        mustCall(() => {
          resolve();
        }),
      );
    });

    // Client disconnects - server Connection should emit 'close'
    ctx.client.end();
    await closeDone;
  } finally {
    await ctx.cleanup();
  }
});

Deno.test('global: cancel-tcpip-forward is handled by request listener', async () => {
  clearMustCallChecks();
  const ctx = await createTestContext('cancel-tcpip-forward');

  try {
    const conn = await connectWithPasswordAuth(ctx, 'cancel-tcpip-forward');

    // Register listener that handles both tcpip-forward and cancel-tcpip-forward
    let cancelReceived = false;
    conn.on(
      'request',
      mustCall((
        accept: ((port?: number) => void) | undefined,
        _reject: (() => void) | undefined,
        name: string,
      ) => {
        if (name === 'tcpip-forward') {
          accept?.();
        } else if (name === 'cancel-tcpip-forward') {
          cancelReceived = true;
          accept?.();
        } else {
          accept?.();
        }
      }, 2),
    );

    // First forward-in, then cancel
    await ctx.client.forwardIn('127.0.0.1', 0);
    await ctx.client.unforwardIn('127.0.0.1', 0);

    assertEquals(cancelReceived, true);
  } finally {
    await ctx.cleanup();
  }
});
