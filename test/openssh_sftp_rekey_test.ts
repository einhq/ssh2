/**
 * OpenSSH's sftp client uploads through the server and starts a key exchange
 * every 256 KiB, while the server is still answering WRITEs that arrived before
 * it. Each STATUS reply follows an asynchronous disk write, as a real SFTP
 * server's does. The file arrives intact and the connection survives.
 *
 * Requires the `sftp` and `ssh-keygen` commands in PATH.
 */

import { assertEquals } from '@std/assert';
import { type Connection, Server, type ServerAuthContext } from '../src/server.ts';
import { SFTP } from '../src/protocol/sftp/SFTP.ts';
import { STATUS_CODE } from '../src/protocol/sftp/constants.ts';
import type { FileAttributes, SFTPHandle } from '../src/protocol/sftp/types.ts';
import { generateTestHostKeyEd25519 } from './integration_helpers.ts';

async function hasCommand(name: string): Promise<boolean> {
  try {
    const { code } = await new Deno.Command('which', {
      args: [name],
      stdout: 'null',
      stderr: 'null',
    }).output();
    return code === 0;
  } catch {
    return false;
  }
}

const available = await hasCommand('sftp') && await hasCommand('ssh-keygen');

const DIR_ATTRS: FileAttributes = { mode: 0o40755, size: 0, uid: 0, gid: 0, atime: 0, mtime: 0 };

/** Serves uploads into `root`, answering each WRITE once its bytes are on disk. */
function serveUploads(conn: Connection, root: string): void {
  conn.on('authentication', (ctx: ServerAuthContext) => {
    if (ctx.method === 'publickey') ctx.accept();
    else ctx.reject(['publickey']);
  });

  conn.on('ready', () => {
    conn.on('session', (accept) => {
      const session = accept();
      if (!session) return;

      session.on('sftp', (acceptSftp) => {
        const channel = acceptSftp();
        if (!channel) return;

        const sftp = new SFTP(
          { protocol: conn.protocol },
          { type: 'session', incoming: channel.incoming, outgoing: channel.outgoing },
          { server: true },
        );

        (async () => {
          const reader = channel.readable.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) sftp.push(value);
          }
          sftp.push(null);
          channel.end();
        })().catch(() => {});

        const files = new Map<number, { file: Deno.FsFile; tail: Promise<void> }>();
        let nextHandle = 0;
        const handleId = (handle: SFTPHandle) =>
          new DataView(handle.buffer, handle.byteOffset, handle.byteLength).getUint32(0);

        sftp.on('REALPATH', (id: number) => {
          sftp.name(id, { filename: '/', longname: '/', attrs: DIR_ATTRS });
        });
        sftp.on('STAT', (id: number, path: string) => {
          if (path === '/') sftp.attrs(id, DIR_ATTRS);
          else sftp.status(id, STATUS_CODE.NO_SUCH_FILE);
        });
        sftp.on('LSTAT', (id: number) => sftp.status(id, STATUS_CODE.NO_SUCH_FILE));
        sftp.on('OPEN', async (id: number, path: string) => {
          const file = await Deno.open(`${root}/${path.replace(/^\/+/, '')}`, {
            write: true,
            create: true,
            truncate: true,
          });
          const handle = new Uint8Array(4);
          new DataView(handle.buffer).setUint32(0, nextHandle);
          files.set(nextHandle++, { file, tail: Promise.resolve() });
          sftp.handle(id, handle);
        });
        sftp.on('WRITE', (id: number, handle: SFTPHandle, offset: number, data: Uint8Array) => {
          const open = files.get(handleId(handle))!;
          open.tail = open.tail.then(async () => {
            await open.file.seek(offset, Deno.SeekMode.Start);
            let written = 0;
            while (written < data.length) {
              written += await open.file.write(data.subarray(written));
            }
            sftp.status(id, STATUS_CODE.OK);
          });
        });
        sftp.on('CLOSE', async (id: number, handle: SFTPHandle) => {
          const key = handleId(handle);
          const open = files.get(key)!;
          files.delete(key);
          await open.tail;
          open.file.close();
          sftp.status(id, STATUS_CODE.OK);
        });
      });
    });
  });

  conn.on('error', () => {});
}

Deno.test({
  name: 'integration-openssh: sftp upload survives client rekeys',
  ignore: !available,
  async fn() {
    const dir = await Deno.makeTempDir({ prefix: 'ssh2-sftp-rekey-' });
    const root = `${dir}/root`;
    await Deno.mkdir(root);

    // Random in every 64 KiB block, so a misplaced write shows.
    const source = new Uint8Array(8 * 1024 * 1024);
    for (let i = 0; i < source.length; i += 65536) {
      crypto.getRandomValues(source.subarray(i, i + 65536));
    }
    await Deno.writeFile(`${dir}/upload.bin`, source);

    const keygen = await new Deno.Command('ssh-keygen', {
      args: ['-q', '-t', 'ed25519', '-N', '', '-f', `${dir}/id`],
      stdout: 'null',
      stderr: 'null',
    }).output();
    assertEquals(keygen.code, 0);
    await Deno.writeTextFile(`${dir}/batch`, `put ${dir}/upload.bin /upload.bin\n`);

    const hostKey = await generateTestHostKeyEd25519();
    const server = new Server({ hostKeys: [hostKey.parsedKey] });
    server.on('connection', (conn: Connection) => serveUploads(conn, root));
    await server.listen(0, 'localhost');

    try {
      const proc = new Deno.Command('sftp', {
        args: [
          '-o',
          'StrictHostKeyChecking=no',
          '-o',
          'UserKnownHostsFile=/dev/null',
          '-o',
          'IdentitiesOnly=yes',
          '-o',
          'IdentityAgent=none',
          '-o',
          'RekeyLimit=256K',
          '-c',
          'chacha20-poly1305@openssh.com',
          '-i',
          `${dir}/id`,
          '-P',
          String(server.address()!.port),
          '-b',
          `${dir}/batch`,
          'testuser@localhost',
        ],
        stdin: 'null',
        stdout: 'piped',
        stderr: 'piped',
      }).spawn();
      const timer = setTimeout(() => proc.kill(), 120_000);
      const { code, stderr } = await proc.output();
      clearTimeout(timer);

      assertEquals(code, 0, `sftp failed: ${new TextDecoder().decode(stderr)}`);
      const uploaded = await Deno.readFile(`${root}/upload.bin`);
      assertEquals(uploaded.length, source.length);
      assertEquals(uploaded, source);
    } finally {
      server.close();
      await new Promise((resolve) => setTimeout(resolve, 100));
      await Deno.remove(dir, { recursive: true });
    }
  },
  sanitizeResources: false,
  sanitizeOps: false,
});
