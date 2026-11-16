/**
 * OpenSSH Integration Tests
 *
 * Tests the SSH server implementation against the real OpenSSH client.
 * This verifies compatibility with actual SSH clients.
 *
 * These tests require the `ssh` and `sshpass` commands to be available in PATH.
 * Install sshpass: sudo apt install sshpass
 */

import { assertEquals, assertGreater, assertStringIncludes } from '@std/assert';
import { OpenSSHAgent } from '../src/agent.ts';
import type { StderrWritable } from '../src/Channel.ts';
import { Client } from '../src/client.ts';
import {
  type Connection,
  type PKAuthContext,
  PwdAuthContext,
  Server,
  type ServerAuthContext,
} from '../src/server.ts';
import {
  generateTestHostKeyECDSA,
  generateTestHostKeyEd25519,
  generateTestHostKeyRSA,
} from './integration_helpers.ts';

/**
 * Run ssh command and get output
 */
async function runSsh(
  port: number,
  command: string,
  options: {
    user?: string;
    cipher?: string;
    keyExchange?: string;
    hostKeyAlg?: string;
    password?: string;
    timeout?: number;
  } = {},
): Promise<{ stdout: string; stderr: string; code: number }> {
  const args = [
    '-o',
    'StrictHostKeyChecking=no',
    '-o',
    'UserKnownHostsFile=/dev/null',
    '-o',
    'BatchMode=no',
    '-o',
    'LogLevel=ERROR',
    '-o',
    'PreferredAuthentications=password',
    '-o',
    'ConnectTimeout=10',
    '-p',
    port.toString(),
  ];

  if (options.cipher) {
    args.push('-c', options.cipher);
  }

  if (options.keyExchange) {
    args.push('-o', `KexAlgorithms=${options.keyExchange}`);
  }

  if (options.hostKeyAlg) {
    args.push('-o', `HostKeyAlgorithms=${options.hostKeyAlg}`);
  }

  const user = options.user ?? 'testuser';
  args.push(`${user}@localhost`, command);

  // Use sshpass if password is provided
  let cmd: Deno.Command;
  if (options.password) {
    cmd = new Deno.Command('sshpass', {
      args: ['-p', options.password, 'ssh', ...args],
      stdin: 'null',
      stdout: 'piped',
      stderr: 'piped',
    });
  } else {
    cmd = new Deno.Command('ssh', {
      args,
      stdin: 'null',
      stdout: 'piped',
      stderr: 'piped',
    });
  }

  // Use spawn + timeout to prevent hanging on stalled SSH handshakes
  const timeoutMs = options.timeout ?? 30_000;
  const proc = cmd.spawn();
  const timer = setTimeout(() => {
    try {
      proc.kill();
    } catch { /* already exited */ }
  }, timeoutMs);

  const { code, stdout, stderr } = await proc.output();
  clearTimeout(timer);

  return {
    code,
    stdout: new TextDecoder().decode(stdout),
    stderr: new TextDecoder().decode(stderr),
  };
}

/** `n` bytes of letters in 64 KiB chunks, each chunk a letter of its own. */
function largeOutput(n: number): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  for (let at = 0; at < n; at += 65536) {
    chunks.push(new Uint8Array(Math.min(65536, n - at)).fill(65 + chunks.length % 26));
  }
  return chunks;
}

/**
 * Create a test server with specific options
 */
async function createTestServer(options: {
  hostKey: Awaited<ReturnType<typeof generateTestHostKeyEd25519>>;
  acceptPassword?: string;
  cipherList?: string[];
}): Promise<{ server: Server; port: number; close: () => void }> {
  const { hostKey, acceptPassword = 'testpass', cipherList } = options;

  const server = new Server({
    hostKeys: [hostKey.parsedKey],
    algorithms: cipherList
      ? {
        cipher: cipherList,
      }
      : undefined,
  });

  server.on('connection', (conn: Connection) => {
    conn.on('authentication', (ctx: ServerAuthContext | PwdAuthContext) => {
      if (
        ctx.method === 'password' && ctx instanceof PwdAuthContext &&
        ctx.password === acceptPassword
      ) {
        ctx.accept();
      } else if (ctx.method === 'none') {
        ctx.reject(['password']);
      } else {
        ctx.reject();
      }
    });

    conn.on('ready', () => {
      conn.on('session', (accept) => {
        const session = accept();
        if (!session) return;

        session.on('exec', (accept, _reject, info) => {
          const stream = accept();
          if (!stream) return;
          // `bytes <n>`: n bytes in 64 KiB writes, none awaited, then a line on stderr and exit 3
          const bytes = /^bytes (\d+)$/.exec(info.command);
          if (bytes) {
            for (const chunk of largeOutput(Number(bytes[1]))) stream.write(chunk);
            (stream.stderr as StderrWritable).write('done\n');
            stream.exit(3);
            stream.end();
            return;
          }
          // Echo the command back
          const response = `Command received: ${info.command}\n`;
          stream.write(new TextEncoder().encode(response));
          stream.exit(0);
          stream.close();
        });

        session.on('shell', (accept) => {
          const stream = accept();
          if (!stream) return;
          stream.write(new TextEncoder().encode('Shell ready\n'));
        });
      });
    });

    conn.on('error', (err) => {
      console.error('Connection error:', err);
    });
  });

  await server.listen(0, 'localhost');
  const addr = server.address()!;

  return {
    server,
    port: addr.port,
    close: async () => {
      server.close();
      // Allow time for connections to fully close
      await new Promise((resolve) => setTimeout(resolve, 100));
    },
  };
}

/**
 * Check if sshpass is available
 */
async function hasSshpass(): Promise<boolean> {
  try {
    const cmd = new Deno.Command('which', { args: ['sshpass'], stdout: 'null', stderr: 'null' });
    const { code } = await cmd.output();
    return code === 0;
  } catch {
    return false;
  }
}

// Cache result
let sshpassAvailable: boolean | null = null;

async function checkSshpass(): Promise<boolean> {
  if (sshpassAvailable === null) {
    sshpassAvailable = await hasSshpass();
  }
  return sshpassAvailable;
}

// =============================================================================
// Tests
// =============================================================================

Deno.test({
  name: 'integration-openssh: Server with AES-GCM cipher',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyEd25519();
    const testServer = await createTestServer({
      hostKey,
      cipherList: ['aes128-gcm@openssh.com', 'aes256-gcm@openssh.com'],
    });

    try {
      const result = await runSsh(
        testServer.port,
        'echo hello',
        {
          cipher: 'aes128-gcm@openssh.com',
          password: 'testpass',
        },
      );

      assertEquals(result.code, 0, `SSH failed with stderr: ${result.stderr}`);
      assertStringIncludes(result.stdout, 'Command received: echo hello');
    } finally {
      await testServer.close();
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name:
    'integration-openssh: exec output past the client window arrives whole, before exit and EOF',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyEd25519();
    const testServer = await createTestServer({ hostKey });
    const size = 7 * 1024 * 1024 + 123;

    try {
      const result = await runSsh(testServer.port, `bytes ${size}`, { password: 'testpass' });

      assertEquals(result.code, 3, `SSH failed with stderr: ${result.stderr}`);
      assertEquals(result.stdout.length, size);
      assertEquals(
        result.stdout,
        largeOutput(size).map((chunk) => new TextDecoder().decode(chunk)).join(''),
      );
      assertEquals(result.stderr, 'done\n');
    } finally {
      await testServer.close();
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Server with Ed25519 host key',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyEd25519();
    const testServer = await createTestServer({
      hostKey,
      cipherList: ['aes128-gcm@openssh.com'],
    });

    try {
      const result = await runSsh(
        testServer.port,
        'echo test',
        {
          hostKeyAlg: 'ssh-ed25519',
          cipher: 'aes128-gcm@openssh.com',
          password: 'testpass',
        },
      );

      assertEquals(result.code, 0, `SSH failed with stderr: ${result.stderr}`);
      assertStringIncludes(result.stdout, 'Command received: echo test');
    } finally {
      await testServer.close();
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Server with ECDSA host key',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyECDSA();
    const testServer = await createTestServer({
      hostKey,
    });

    try {
      const result = await runSsh(
        testServer.port,
        'echo test',
        {
          hostKeyAlg: 'ecdsa-sha2-nistp256',
          password: 'testpass',
        },
      );

      assertEquals(result.code, 0, `SSH failed with stderr: ${result.stderr}`);
      assertStringIncludes(result.stdout, 'Command received: echo test');
    } finally {
      await testServer.close();
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Server with RSA host key',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyRSA();
    const testServer = await createTestServer({
      hostKey,
    });

    try {
      const result = await runSsh(
        testServer.port,
        'echo test',
        {
          hostKeyAlg: 'rsa-sha2-256',
          password: 'testpass',
        },
      );

      assertEquals(result.code, 0, `SSH failed with stderr: ${result.stderr}`);
      assertStringIncludes(result.stdout, 'Command received: echo test');
    } finally {
      await testServer.close();
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Server with AES-CTR cipher',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyEd25519();
    const testServer = await createTestServer({
      hostKey,
      cipherList: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr'],
    });

    try {
      const result = await runSsh(
        testServer.port,
        'echo hello',
        {
          cipher: 'aes128-ctr',
          password: 'testpass',
        },
      );

      assertEquals(result.code, 0, `SSH failed with stderr: ${result.stderr}`);
      assertStringIncludes(result.stdout, 'Command received: echo hello');
    } finally {
      await testServer.close();
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Password authentication failure',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyEd25519();
    const testServer = await createTestServer({
      hostKey,
      cipherList: ['aes128-gcm@openssh.com'],
    });

    try {
      const result = await runSsh(
        testServer.port,
        'echo hello',
        {
          cipher: 'aes128-gcm@openssh.com',
          password: 'wrongpassword',
        },
      );

      // Connection should fail due to wrong password
      assertEquals(result.code !== 0, true, 'Expected non-zero exit code for wrong password');
    } finally {
      await testServer.close();
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Server with ChaCha20-Poly1305 cipher',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyEd25519();
    const testServer = await createTestServer({
      hostKey,
      cipherList: ['chacha20-poly1305@openssh.com'],
    });

    try {
      const result = await runSsh(
        testServer.port,
        'echo hello',
        {
          cipher: 'chacha20-poly1305@openssh.com',
          password: 'testpass',
        },
      );

      assertEquals(result.code, 0, `SSH failed with stderr: ${result.stderr}`);
      assertStringIncludes(result.stdout, 'Command received: echo hello');
    } finally {
      await testServer.close();
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Rekey during session',
  ignore: !(await checkSshpass()),
  async fn() {
    const hostKey = await generateTestHostKeyEd25519();

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
    });

    let rekeyCompleted = false;

    server.on('connection', (conn: Connection) => {
      conn.on('authentication', (ctx: ServerAuthContext | PwdAuthContext) => {
        if (
          ctx.method === 'password' && ctx instanceof PwdAuthContext && ctx.password === 'testpass'
        ) {
          ctx.accept();
        } else if (ctx.method === 'none') {
          ctx.reject(['password']);
        } else {
          ctx.reject();
        }
      });

      conn.on('ready', () => {
        conn.on('session', (accept) => {
          const session = accept();
          if (!session) return;

          session.on('exec', (accept, _reject, info) => {
            const stream = accept();
            if (!stream) return;

            // Trigger rekey before responding
            conn.rekey(() => {
              rekeyCompleted = true;
              // After rekey completes, send response
              const response = `Command after rekey: ${info.command}\n`;
              stream.write(new TextEncoder().encode(response));
              stream.exit(0);
              stream.close();
            });
          });
        });
      });

      conn.on('error', (err) => {
        console.error('Connection error:', err);
      });

      conn.on('rekey', () => {
        // Server received rekey completion
      });
    });

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    try {
      const result = await runSsh(addr.port, 'hello world', { password: 'testpass' });
      assertEquals(result.code, 0);
      assertStringIncludes(result.stdout, 'Command after rekey: hello world');
      assertEquals(rekeyCompleted, true);
    } finally {
      server.close();
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

// =============================================================================
// Real SSH Agent Integration Test
// =============================================================================

/**
 * Check if SSH agent is running and has keys
 */
async function checkSshAgent(): Promise<boolean> {
  const socketPath = Deno.env.get('SSH_AUTH_SOCK');
  if (!socketPath) {
    return false;
  }

  try {
    const agent = new OpenSSHAgent(socketPath);
    const keys = await agent.getIdentities();
    return keys.length > 0;
  } catch {
    return false;
  }
}

// Cache result
let sshAgentAvailable: boolean | null = null;

async function hasSshAgent(): Promise<boolean> {
  if (sshAgentAvailable === null) {
    sshAgentAvailable = await checkSshAgent();
    if (!sshAgentAvailable) {
      console.log('SSH agent not available or has no keys - skipping ssh-agent tests');
    }
  }
  return sshAgentAvailable;
}

Deno.test({
  name: 'integration-openssh: Real SSH agent - list identities',
  ignore: !(await hasSshAgent()),
  async fn() {
    const socketPath = Deno.env.get('SSH_AUTH_SOCK')!;
    const agent = new OpenSSHAgent(socketPath);

    const keys = await agent.getIdentities();
    assertGreater(keys.length, 0, 'Should have at least one key in agent');

    // Log key info for debugging
    for (const key of keys) {
      console.log(`  Found key: ${key.type} (${key.comment || 'no comment'})`);
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Real SSH agent - authenticate to server',
  ignore: !(await hasSshAgent()),
  async fn() {
    const hostKey = await generateTestHostKeyEd25519();
    const socketPath = Deno.env.get('SSH_AUTH_SOCK')!;

    // Get the keys from the agent first to know what to expect
    const agent = new OpenSSHAgent(socketPath);
    const agentKeys = await agent.getIdentities();
    if (agentKeys.length === 0) {
      throw new Error('No keys in agent');
    }

    // Use the first key from the agent
    const expectedKey = agentKeys[0];
    const expectedPubSSH = expectedKey.getPublicSSH();

    const server = new Server({
      hostKeys: [hostKey.parsedKey],
    });

    let authSucceeded = false;
    let keyMatched = false;

    server.on('connection', (conn: Connection) => {
      conn.on('authentication', (ctx: ServerAuthContext) => {
        if (ctx.method === 'publickey') {
          const pkCtx = ctx as PKAuthContext;

          // Check if the offered key matches what we expect from the agent
          const offeredKey = pkCtx.key;

          // Compare the raw key data
          if (expectedPubSSH && offeredKey.data) {
            if (expectedPubSSH.length === offeredKey.data.length) {
              let match = true;
              for (let i = 0; i < expectedPubSSH.length; i++) {
                if (expectedPubSSH[i] !== offeredKey.data[i]) {
                  match = false;
                  break;
                }
              }
              if (match) {
                keyMatched = true;
              }
            }
          }

          // Accept the key
          ctx.accept();
          authSucceeded = true;
        } else if (ctx.method === 'none') {
          ctx.reject(['publickey']);
        } else {
          ctx.reject();
        }
      });

      conn.on('ready', () => {
        conn.on('session', (accept) => {
          const session = accept();
          if (!session) return;

          session.on('exec', (accept, _reject, info) => {
            const stream = accept();
            if (!stream) return;
            const response = `Command: ${info.command}\n`;
            stream.write(new TextEncoder().encode(response));
            stream.exit(0);
            stream.close();
          });
        });
      });

      conn.on('error', () => {
        // Ignore errors during cleanup
      });
    });

    await server.listen(0, 'localhost');
    const addr = server.address()!;

    // Create client with agent
    const client = new Client();

    try {
      await new Promise<void>((resolve, reject) => {
        client.on('ready', async () => {
          try {
            // Execute a command to verify the connection works
            const stream = await client.exec('test');
            stream.on('close', () => {
              client.end();
              resolve();
            });
          } catch (err) {
            reject(err);
          }
        });

        client.on('error', (err) => {
          reject(err);
        });

        client.connect({
          host: 'localhost',
          port: addr.port,
          username: 'testuser',
          agent: socketPath,
        }).catch(reject);
      });

      assertEquals(authSucceeded, true, 'Authentication should succeed');
      assertEquals(keyMatched, true, 'Key from agent should match');
    } finally {
      try {
        client.end();
      } catch { /* ignore */ }
      server.close();
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

// =============================================================================
// Stability Tests - detect hangs and race conditions
// =============================================================================

/**
 * Run a cipher test multiple times to detect intermittent hangs.
 * Each attempt has a short timeout; if any attempt hangs, the test fails
 * fast instead of blocking for minutes.
 */
async function runCipherStabilityTest(
  cipherName: string,
  iterations: number,
): Promise<void> {
  for (let i = 0; i < iterations; i++) {
    const hostKey = await generateTestHostKeyEd25519();
    const testServer = await createTestServer({
      hostKey,
      cipherList: [cipherName],
    });

    try {
      const result = await runSsh(
        testServer.port,
        `echo iteration-${i}`,
        {
          cipher: cipherName,
          password: 'testpass',
          timeout: 15_000,
        },
      );

      assertEquals(
        result.code,
        0,
        `Iteration ${
          i + 1
        }/${iterations} with ${cipherName} failed (code=${result.code}): ${result.stderr}`,
      );
      assertStringIncludes(result.stdout, `Command received: echo iteration-${i}`);
    } finally {
      await testServer.close();
    }
  }
}

Deno.test({
  name: 'integration-openssh: Stability - AES-CTR repeated connections',
  ignore: !(await checkSshpass()),
  async fn() {
    await runCipherStabilityTest('aes128-ctr', 5);
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Stability - AES-GCM repeated connections',
  ignore: !(await checkSshpass()),
  async fn() {
    await runCipherStabilityTest('aes128-gcm@openssh.com', 5);
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Stability - ChaCha20 repeated connections',
  ignore: !(await checkSshpass()),
  async fn() {
    await runCipherStabilityTest('chacha20-poly1305@openssh.com', 5);
  },
  sanitizeResources: false,
  sanitizeOps: false,
});

Deno.test({
  name: 'integration-openssh: Stability - rapid sequential connections',
  ignore: !(await checkSshpass()),
  async fn() {
    // Test rapid server create/connect/close cycles to detect resource leaks or race conditions
    const ciphers = [
      'aes128-ctr',
      'aes128-gcm@openssh.com',
      'chacha20-poly1305@openssh.com',
      'aes256-ctr',
      'aes256-gcm@openssh.com',
    ];

    for (const cipher of ciphers) {
      const hostKey = await generateTestHostKeyEd25519();
      const testServer = await createTestServer({
        hostKey,
        cipherList: [cipher],
      });

      try {
        const result = await runSsh(
          testServer.port,
          'echo ok',
          {
            cipher,
            password: 'testpass',
            timeout: 15_000,
          },
        );

        assertEquals(
          result.code,
          0,
          `Rapid test with ${cipher} failed (code=${result.code}): ${result.stderr}`,
        );
      } finally {
        await testServer.close();
      }
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});
