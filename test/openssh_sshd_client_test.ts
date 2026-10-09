/**
 * Client against a real OpenSSH sshd, started unprivileged on a random port for
 * the current user. Skipped when sshd, ssh-keygen or $USER is unavailable.
 */

import { assert, assertEquals, assertRejects } from '@std/assert';
import { Client } from '../src/client.ts';
import { generateKeyPair } from '../src/keygen.ts';

const SSHD = ['/usr/sbin/sshd', '/usr/bin/sshd'].find((p) => {
  try {
    return Deno.statSync(p).isFile;
  } catch {
    return false;
  }
});
const USER = Deno.env.get('USER');
// internal-sftp needs a privileged sshd; an unprivileged one refuses the subsystem
const SFTP_SERVER =
  ['/usr/lib/openssh/sftp-server', '/usr/libexec/openssh/sftp-server', '/usr/libexec/sftp-server']
    .find((p) => {
      try {
        return Deno.statSync(p).isFile;
      } catch {
        return false;
      }
    }) ?? 'internal-sftp';

async function haveKeygen(): Promise<boolean> {
  try {
    const out = await new Deno.Command('ssh-keygen', {
      args: ['-?'],
      stdout: 'null',
      stderr: 'null',
    })
      .output();
    return out.code !== 127;
  } catch {
    return false;
  }
}

const ignore = !SSHD || !USER || !(await haveKeygen());

interface Sshd {
  port: number;
  dir: string;
  stop(): Promise<void>;
}

async function freePort(): Promise<number> {
  const l = Deno.listen({ hostname: '127.0.0.1', port: 0 });
  const port = (l.addr as Deno.NetAddr).port;
  l.close();
  return port;
}

async function startSshd(authorizedKeys: string[]): Promise<Sshd> {
  const dir = await Deno.makeTempDir({ prefix: 'ssh2-sshd-' });
  const hostKey = `${dir}/host_ed25519`;
  await new Deno.Command('ssh-keygen', {
    args: ['-q', '-t', 'ed25519', '-N', '', '-f', hostKey],
    stdout: 'null',
    stderr: 'null',
  }).output();
  await Deno.writeTextFile(`${dir}/authorized_keys`, authorizedKeys.join('\n') + '\n');

  const port = await freePort();
  await Deno.writeTextFile(
    `${dir}/sshd_config`,
    [
      `Port ${port}`,
      'ListenAddress 127.0.0.1',
      `HostKey ${hostKey}`,
      `PidFile ${dir}/sshd.pid`,
      `AuthorizedKeysFile ${dir}/authorized_keys`,
      'StrictModes no',
      'UsePAM no',
      'PasswordAuthentication no',
      'KbdInteractiveAuthentication no',
      'PubkeyAuthentication yes',
      `Subsystem sftp ${SFTP_SERVER}`,
      'LogLevel ERROR',
    ].join('\n') + '\n',
  );

  const child = new Deno.Command(SSHD!, {
    args: ['-D', '-e', '-f', `${dir}/sshd_config`],
    stdout: 'null',
    stderr: 'piped',
  }).spawn();

  // Wait until it accepts connections
  const deadline = Date.now() + 5000;
  while (true) {
    try {
      const conn = await Deno.connect({ hostname: '127.0.0.1', port });
      conn.close();
      break;
    } catch {
      if (Date.now() > deadline) {
        child.kill();
        const err = new TextDecoder().decode((await child.output()).stderr);
        throw new Error(`sshd did not start: ${err}`);
      }
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  return {
    port,
    dir,
    async stop() {
      try {
        child.kill('SIGTERM');
      } catch { /* already gone */ }
      await child.stderr.cancel().catch(() => {});
      await child.status;
      await Deno.remove(dir, { recursive: true });
    },
  };
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<string> {
  let text = '';
  const decoder = new TextDecoder();
  for await (const chunk of stream) text += decoder.decode(chunk, { stream: true });
  return text + decoder.decode();
}

async function connect(port: number, privateKey: string): Promise<Client> {
  const client = new Client();
  await client.connect({
    host: '127.0.0.1',
    port,
    username: USER,
    privateKey,
    readyTimeout: 10000,
    hostVerifier: () => true,
    debug: Deno.env.get('DBG') ? (m: string) => console.log('[C]', m) : undefined,
  });
  return client;
}

Deno.test({
  name: 'openssh sshd: ed25519 key, exec with exit status',
  ignore,
  async fn() {
    const key = await generateKeyPair('ed25519');
    const sshd = await startSshd([key.public]);
    try {
      const client = await connect(sshd.port, key.private);
      const channel = await client.exec('echo hello; exit 3');
      const status = new Promise<number>((resolve) => channel.on('exit-status', resolve));
      assertEquals(await channel.accepted, true);
      assertEquals((await readAll(channel.readable)).trim(), 'hello');
      assertEquals(await status, 3);
      client.end();
    } finally {
      await sshd.stop();
    }
  },
});

Deno.test({
  name: 'openssh sshd: RSA key is accepted (signed with rsa-sha2, not ssh-rsa)',
  ignore,
  async fn() {
    const key = await generateKeyPair('rsa', { bits: 2048 });
    const sshd = await startSshd([key.public]);
    try {
      const client = await connect(sshd.port, key.private);
      const channel = await client.exec('echo rsa');
      assertEquals((await readAll(channel.readable)).trim(), 'rsa');
      client.end();
    } finally {
      await sshd.stop();
    }
  },
});

Deno.test({
  name: 'openssh sshd: an unknown key fails auth promptly',
  ignore,
  async fn() {
    const known = await generateKeyPair('ed25519');
    const unknown = await generateKeyPair('ed25519');
    const sshd = await startSshd([known.public]);
    try {
      const started = Date.now();
      const err = await assertRejects(() => connect(sshd.port, unknown.private));
      assertEquals((err as { level?: string }).level, 'client-authentication');
      assert(Date.now() - started < 5000);
    } finally {
      await sshd.stop();
    }
  },
});

Deno.test({
  name: 'openssh sshd: sftp write, stat, readdir, read, rename, posixRename, symlink, unlink',
  ignore,
  async fn() {
    const key = await generateKeyPair('ed25519');
    const sshd = await startSshd([key.public]);
    try {
      const client = await connect(sshd.port, key.private);
      const sftp = await client.sftp();
      const root = `${sshd.dir}/files`;
      await sftp.mkdir(root);

      await sftp.writeFile(`${root}/a.txt`, new TextEncoder().encode('sailboat'));
      const st = await sftp.stat(`${root}/a.txt`);
      assertEquals(st.size, 8);

      await sftp.rename(`${root}/a.txt`, `${root}/b.txt`);
      // posix-rename replaces an existing target, which RENAME refuses
      await sftp.writeFile(`${root}/c.txt`, new TextEncoder().encode('rowboat'));
      await assertRejects(() => sftp.rename(`${root}/c.txt`, `${root}/b.txt`));
      await sftp.posixRename(`${root}/c.txt`, `${root}/b.txt`);
      // An absolute target: with the arguments the wrong way round this fails
      // (b.txt exists) instead of creating a link in the sshd user's home
      await sftp.symlink(`${root}/b.txt`, `${root}/link`);
      assertEquals(await sftp.readlink(`${root}/link`), `${root}/b.txt`);

      const names = (await sftp.readdir(root)).map((e) => e.filename).sort();
      assertEquals(names, ['b.txt', 'link']);

      const data = await sftp.readFile(`${root}/b.txt`);
      assertEquals(new TextDecoder().decode(data), 'rowboat');

      await sftp.unlink(`${root}/link`);
      await sftp.unlink(`${root}/b.txt`);
      await sftp.rmdir(root);
      sftp.end();
      client.end();
    } finally {
      await sshd.stop();
    }
  },
});

Deno.test({
  name: 'openssh sshd: sftp moves more than one channel window each way',
  ignore,
  async fn() {
    const key = await generateKeyPair('ed25519');
    const sshd = await startSshd([key.public]);
    try {
      const client = await connect(sshd.port, key.private);
      const sftp = await client.sftp();
      const path = `${sshd.dir}/big.bin`;

      // 5 MiB: well past the 2 MiB window in both directions
      const data = new Uint8Array(5 * 1024 * 1024);
      for (let i = 0; i < data.length; i++) data[i] = (i * 31) & 0xff;

      await sftp.writeFile(path, data);
      assertEquals((await sftp.stat(path)).size, data.length);
      const back = await sftp.readFile(path);
      assertEquals(back.length, data.length);
      assertEquals(back, data);

      sftp.end();
      client.end();
    } finally {
      await sshd.stop();
    }
  },
});

Deno.test({
  name: 'openssh sshd: an interactive shell with a pty',
  ignore,
  async fn() {
    const key = await generateKeyPair('ed25519');
    const sshd = await startSshd([key.public]);
    try {
      const client = await connect(sshd.port, key.private);
      const channel = await client.shell({ pty: { rows: 30, cols: 100, term: 'xterm-256color' } });
      assertEquals(await channel.accepted, true);

      const status = new Promise<number>((resolve) => channel.on('exit-status', resolve));
      // A pty makes stdin a terminal; stty proves it and reports the size asked for
      channel.write('stty size; exit 7\n');
      const out = await readAll(channel.readable);
      assert(out.includes('30 100'), `stty size in: ${JSON.stringify(out)}`);
      assertEquals(await status, 7);
      client.end();
    } finally {
      await sshd.stop();
    }
  },
});
