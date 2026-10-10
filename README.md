# ssh2-ts

SSH2 client and server modules written in TypeScript for [Deno](https://deno.land/).

This is a TypeScript port of [mscdex/ssh2](https://github.com/mscdex/ssh2), converted from Node.js
to Deno with Web Standard APIs. All callbacks have been replaced with async/await.

Development/testing is done against OpenSSH (9.x+).

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Key Differences from ssh2](#key-differences-from-ssh2)
- [Client Examples](#client-examples)
  - [Execute 'uptime' on a server](#execute-uptime-on-a-server)
  - [Start an interactive shell session](#start-an-interactive-shell-session)
  - [Send a raw HTTP request via port forwarding](#send-a-raw-http-request-via-port-forwarding)
  - [Forward remote connections to us](#forward-remote-connections-to-us)
  - [Get a directory listing via SFTP](#get-a-directory-listing-via-sftp)
  - [Connection hopping](#connection-hopping)
- [Server Examples](#server-examples)
  - [Password and public key authentication with exec](#password-and-public-key-authentication-with-exec)
  - [SFTP-only server](#sftp-only-server)
- [Other Examples](#other-examples)
  - [Generate an SSH key](#generate-an-ssh-key)
- [API](#api)
  - [Client](#client)
    - [Client events](#client-events)
    - [Client methods](#client-methods)
  - [Server](#server)
    - [Server events](#server-events)
    - [Server methods](#server-methods)
    - [Connection events](#connection-events)
    - [Connection methods](#connection-methods)
    - [Session events](#session-events)
  - [Channel](#channel)
  - [Pseudo-TTY settings](#pseudo-tty-settings)
  - [Utilities](#utilities)
- [Supported Algorithms](#supported-algorithms)

## Requirements

- [Deno](https://deno.land/) 2.9.4 or newer (the `chacha20-poly1305@openssh.com` cipher relies on
  the native `chacha20` from `node:crypto`, available in official Deno since 2.9.4)

## Installation

```ts
import { Client, Server } from 'jsr:@ein/ssh2-ts';
```

Or add to your `deno.json` imports:

```json
{
  "imports": {
    "ssh2": "jsr:@ein/ssh2-ts"
  }
}
```

## Key Differences from ssh2

This fork is a complete rewrite of ssh2 for the Deno ecosystem. The major changes are:

- **TypeScript-first**: Written entirely in TypeScript with complete type definitions.
- **Deno runtime**: Uses Deno's built-in APIs and test framework instead of Node.js.
- **Web Standard APIs**: Uses Web Crypto API, Web Compression API
  (CompressionStream/DecompressionStream), and other web standards instead of Node.js built-ins.
- **Promise/async-await only**: All client methods return Promises. No callback overloads.
- **No DSA support**: DSA keys are deprecated and not supported by Web Crypto API. All DSA code and
  tests have been removed.
- **No Windows agent support**: PageantAgent and CygwinAgent have been removed. Only OpenSSHAgent is
  supported.
- **No HTTPAgent/HTTPSAgent**: These Node.js-specific http.Agent wrappers have been removed.
- **No native bindings**: The `cpu-features` and C++ crypto bindings have been removed. All
  cryptography uses Deno's built-in Web Crypto API plus vendored pure-TypeScript code; see
  [Cryptography](#cryptography) for more information.
- **No encrypted old-style PEM keys**: Legacy PEM keys encrypted with `Proc-Type: 4,ENCRYPTED`
  (using MD5-based EVP_BytesToKey derivation) are not supported. Convert them to the modern OpenSSH
  format with: `ssh-keygen -p -o -f <keyfile>`. Encrypted new-format OpenSSH keys, PPK keys, and all
  unencrypted PEM keys are fully supported.
- **Strict KEX mode**: Implements RFC 9700 (strict key exchange) for OpenSSH 9.x compatibility.
- **Uint8Array instead of Buffer**: All binary data uses `Uint8Array` instead of Node.js `Buffer`.

## Client Examples

### Execute 'uptime' on a server

```ts
import { Client } from 'jsr:@ein/ssh2-ts';

const conn = new Client();

conn.on('ready', async () => {
  console.log('Client :: ready');
  const stream = await conn.exec('uptime');
  stream.on('close', (code: number, signal: string) => {
    console.log(`Stream :: close :: code: ${code}, signal: ${signal}`);
    conn.end();
  });
  stream.on('data', (data: Uint8Array) => {
    console.log('STDOUT: ' + new TextDecoder().decode(data));
  });
  stream.stderr.on('data', (data: Uint8Array) => {
    console.log('STDERR: ' + new TextDecoder().decode(data));
  });
});

await conn.connect({
  host: '192.168.100.100',
  port: 22,
  username: 'frylock',
  privateKey: await Deno.readTextFile('/path/to/my/key'),
});
```

### Start an interactive shell session

```ts
import { Client } from 'jsr:@ein/ssh2-ts';

const conn = new Client();

conn.on('ready', async () => {
  console.log('Client :: ready');
  const stream = await conn.shell();
  stream.on('close', () => {
    console.log('Stream :: close');
    conn.end();
  });
  stream.on('data', (data: Uint8Array) => {
    console.log('OUTPUT: ' + new TextDecoder().decode(data));
  });
  stream.end(new TextEncoder().encode('ls -l\nexit\n'));
});

await conn.connect({
  host: '192.168.100.100',
  port: 22,
  username: 'frylock',
  privateKey: await Deno.readTextFile('/path/to/my/key'),
});
```

### Send a raw HTTP request via port forwarding

```ts
import { Client } from 'jsr:@ein/ssh2-ts';

const conn = new Client();

conn.on('ready', async () => {
  console.log('Client :: ready');
  const stream = await conn.forwardOut('192.168.100.102', 8000, '127.0.0.1', 80);
  stream.on('close', () => {
    console.log('TCP :: CLOSED');
    conn.end();
  });
  stream.on('data', (data: Uint8Array) => {
    console.log('TCP :: DATA: ' + new TextDecoder().decode(data));
  });
  stream.end(new TextEncoder().encode([
    'HEAD / HTTP/1.1',
    'User-Agent: ssh2-ts',
    'Host: 127.0.0.1',
    'Accept: */*',
    'Connection: close',
    '',
    '',
  ].join('\r\n')));
});

await conn.connect({
  host: '192.168.100.100',
  port: 22,
  username: 'frylock',
  password: 'denorules',
});
```

### Forward remote connections to us

```ts
import { Client } from 'jsr:@ein/ssh2-ts';

const conn = new Client();

conn.on('ready', async () => {
  console.log('Client :: ready');
  const port = await conn.forwardIn('127.0.0.1', 8000);
  console.log(`Listening for connections on server on port ${port}!`);
});

conn.on('tcp connection', (info, accept, _reject) => {
  console.log('TCP :: INCOMING CONNECTION:');
  console.dir(info);
  const channel = accept();
  channel.on('close', () => {
    console.log('TCP :: CLOSED');
  });
  channel.on('data', (data: Uint8Array) => {
    console.log('TCP :: DATA: ' + new TextDecoder().decode(data));
  });
  channel.end(new TextEncoder().encode([
    'HTTP/1.1 404 Not Found',
    'Date: Thu, 15 Nov 2012 02:07:58 GMT',
    'Server: ForwardedConnection',
    'Content-Length: 0',
    'Connection: close',
    '',
    '',
  ].join('\r\n')));
});

await conn.connect({
  host: '192.168.100.100',
  port: 22,
  username: 'frylock',
  password: 'denorules',
});
```

### Get a directory listing via SFTP

```ts
import { Client } from 'jsr:@ein/ssh2-ts';

const conn = new Client();

conn.on('ready', async () => {
  console.log('Client :: ready');
  const sftp = await conn.sftp();
  const list = await sftp.readdir('foo');
  console.dir(list);
  conn.end();
});

await conn.connect({
  host: '192.168.100.100',
  port: 22,
  username: 'frylock',
  password: 'denorules',
});
```

### Connection hopping

```ts
import { Client } from 'jsr:@ein/ssh2-ts';

const conn1 = new Client();
const conn2 = new Client();

// Check uptime on 10.1.1.40 via 192.168.1.1
conn1.on('ready', async () => {
  console.log('FIRST :: connection ready');
  const stream = await conn1.forwardOut('127.0.0.1', 12345, '10.1.1.40', 22);
  await conn2.connect({
    sock: stream,
    username: 'user2',
    password: 'password2',
  });
});

conn2.on('ready', async () => {
  console.log('SECOND :: connection ready');
  const stream = await conn2.exec('uptime');
  stream.on('close', () => {
    conn1.end(); // close parent (and this) connection
  });
  stream.on('data', (data: Uint8Array) => {
    console.log(new TextDecoder().decode(data));
  });
});

await conn1.connect({
  host: '192.168.1.1',
  username: 'user1',
  password: 'password1',
});
```

## Server Examples

### Password and public key authentication with exec

```ts
import { parseKey, Server } from 'jsr:@ein/ssh2-ts';
import { timingSafeEqual } from 'jsr:@std/crypto/timing-safe-equal';

const allowedUser = new TextEncoder().encode('foo');
const allowedPassword = new TextEncoder().encode('bar');
const allowedPubKey = parseKey(await Deno.readTextFile('foo.pub'));

function checkValue(input: Uint8Array, allowed: Uint8Array): boolean {
  const autoReject = input.length !== allowed.length;
  if (autoReject) {
    allowed = input;
  }
  const isMatch = timingSafeEqual(input, allowed);
  return !autoReject && isMatch;
}

const server = new Server({
  hostKeys: [await Deno.readTextFile('host.key')],
}, (client) => {
  console.log('Client connected!');

  client.on('authentication', (ctx) => {
    const usernameMatch = checkValue(
      new TextEncoder().encode(ctx.username),
      allowedUser,
    );

    switch (ctx.method) {
      case 'password':
        if (
          !usernameMatch ||
          !checkValue(new TextEncoder().encode(ctx.password), allowedPassword)
        ) {
          return ctx.reject();
        }
        break;
      case 'publickey':
        if (
          !Array.isArray(allowedPubKey) &&
          ctx.key.algo === allowedPubKey.type &&
          checkValue(ctx.key.data, allowedPubKey.getPublicSSH()) &&
          (!ctx.signature || allowedPubKey.verify(ctx.blob!, ctx.signature, ctx.hashAlgo) === true)
        ) {
          break;
        }
        return ctx.reject();
      default:
        return ctx.reject();
    }

    if (usernameMatch) ctx.accept();
    else ctx.reject();
  });

  client.on('ready', () => {
    console.log('Client authenticated!');

    client.on('session', (accept, _reject) => {
      const session = accept();
      session.once('exec', (accept, _reject, info) => {
        console.log('Client wants to execute: ' + info.command);
        const stream = accept();
        stream.stderr.write(new TextEncoder().encode('Oh no, the dreaded errors!\n'));
        stream.write(new TextEncoder().encode('Just kidding about the errors!\n'));
        stream.exit(0);
        stream.end();
      });
    });
  });

  client.on('close', () => {
    console.log('Client disconnected');
  });
});

server.listen(0, '127.0.0.1', function (this: { address(): { port: number } }) {
  console.log('Listening on port ' + this.address().port);
});
```

### SFTP-only server

```ts
import { OPEN_MODE, Server, STATUS_CODE } from 'jsr:@ein/ssh2-ts';

const server = new Server({
  hostKeys: [await Deno.readTextFile('host.key')],
}, (client) => {
  console.log('Client connected!');

  client.on('authentication', (ctx) => {
    if (ctx.method === 'password' && ctx.username === 'foo' && ctx.password === 'bar') {
      ctx.accept();
    } else {
      ctx.reject();
    }
  });

  client.on('ready', () => {
    console.log('Client authenticated!');

    client.on('session', (accept, _reject) => {
      const session = accept();
      session.on('sftp', (accept, _reject) => {
        console.log('Client SFTP session');
        const openFiles = new Map<number, boolean>();
        let handleCount = 0;
        const sftp = accept();

        sftp.on('OPEN', (reqid, filename, flags, _attrs) => {
          if (filename !== '/tmp/foo.txt' || !(flags & OPEN_MODE.WRITE)) {
            return sftp.status(reqid, STATUS_CODE.FAILURE);
          }
          const handle = new Uint8Array(4);
          const view = new DataView(handle.buffer);
          openFiles.set(handleCount, true);
          view.setUint32(0, handleCount++);
          console.log('Opening file for write');
          sftp.handle(reqid, handle);
        });

        sftp.on('WRITE', (reqid, handle, offset, data) => {
          const view = new DataView(handle.buffer, handle.byteOffset);
          if (handle.length !== 4 || !openFiles.has(view.getUint32(0))) {
            return sftp.status(reqid, STATUS_CODE.FAILURE);
          }
          sftp.status(reqid, STATUS_CODE.OK);
          console.log(`Write to file at offset ${offset}: ${data.length} bytes`);
        });

        sftp.on('CLOSE', (reqid, handle) => {
          const view = new DataView(handle.buffer, handle.byteOffset);
          const fnum = view.getUint32(0);
          if (handle.length !== 4 || !openFiles.has(fnum)) {
            return sftp.status(reqid, STATUS_CODE.FAILURE);
          }
          console.log('Closing file');
          openFiles.delete(fnum);
          sftp.status(reqid, STATUS_CODE.OK);
        });
      });
    });
  });
});

server.listen(0, '127.0.0.1', function (this: { address(): { port: number } }) {
  console.log('Listening on port ' + this.address().port);
});
```

## Other Examples

### Generate an SSH key

```ts
import { generateKeyPair } from 'jsr:@ein/ssh2-ts';

// Generate unencrypted Ed25519 SSH key
const ed25519Keys = await generateKeyPair('ed25519');
console.log(ed25519Keys.public);
console.log(ed25519Keys.private);

// Generate ECDSA SSH key with a comment
const ecdsaKeys = await generateKeyPair('ecdsa', {
  bits: 256,
  comment: 'deno rules!',
});

// Generate encrypted RSA SSH key
const rsaKeys = await generateKeyPair('rsa', {
  bits: 2048,
  passphrase: 'foobarbaz',
  cipher: 'aes256-cbc',
});
```

## API

```ts
import { Client, generateKeyPair, parseKey, Server } from 'jsr:@ein/ssh2-ts';
```

### Client

#### Client events

- **banner**(message: string, language: string) - A notice was sent by the server upon connection.

- **change password**(prompt: string, done: (password: string) => void) - The server has requested
  that the user's password be changed.

- **close**() - The socket was closed.

- **end**() - The socket was disconnected.

- **error**(err: Error) - An error occurred. A `level` property indicates `'client-socket'` for
  socket-level errors, `'client-ssh'` for SSH disconnection messages, `'client-timeout'` when
  `readyTimeout` or keepalives expire, and `'client-authentication'` once every configured auth
  method has been tried once (and a password provider `passwordAttempts` times) and failed.

- **handshake**(negotiated: object) - Emitted when a handshake has completed (either initial or
  rekey). `negotiated` contains the negotiated algorithms:

  ```ts
  {
    kex: 'curve25519-sha256',
    srvHostKey: 'ssh-ed25519',
    cs: { cipher: 'aes128-gcm', mac: '', compress: 'none', lang: '' },
    sc: { cipher: 'aes128-gcm', mac: '', compress: 'none', lang: '' },
  }
  ```

- **hostkeys**(keys: ParsedKey[]) - Emitted when the server announces its available host keys.

- **keyboard-interactive**(name: string, instructions: string, instructionsLang: string, prompts:
  Array<{ prompt: string; echo: boolean }>, finish: (answers: string[]) => void) - The server is
  asking for keyboard-interactive authentication replies.

- **ready**() - Authentication was successful.

- **rekey**() - A rekeying operation has completed.

- **tcp connection**(details: object, accept: () => Channel, reject: () => void) - An incoming
  forwarded TCP connection is being requested. `details` contains `destIP`, `destPort`, `srcIP`,
  `srcPort`.

- **unix connection**(details: object, accept: () => Channel, reject: () => void) - An incoming
  forwarded UNIX socket connection. `details` contains `socketPath`.

- **x11**(details: object, accept: () => Channel, reject: () => void) - An incoming X11 connection.
  `details` contains `srcIP`, `srcPort`.

#### Client methods

- **connect**(config: ClientConfig): Promise\<void\> - Connects to an SSH server. Config properties:

  | Property            | Type                                                         | Default       | Description                                                                                                                                                                           |
  | ------------------- | ------------------------------------------------------------ | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `host`              | string                                                       | `'localhost'` | Hostname or IP address                                                                                                                                                                |
  | `port`              | number                                                       | `22`          | Port number                                                                                                                                                                           |
  | `username`          | string                                                       |               | Username for authentication                                                                                                                                                           |
  | `password`          | string \| (attempt: number) => string \| false \| Promise    |               | Password, or a provider asked each time password auth is tried (`false` skips it). A provider is asked again after a rejected password; the ready timeout waits for it                |
  | `passwordAttempts`  | number                                                       | `3`           | How many times a password provider is asked                                                                                                                                           |
  | `privateKey`        | string \| Uint8Array \| ParsedKey                            |               | Private key for key-based auth                                                                                                                                                        |
  | `passphrase`        | string                                                       |               | Passphrase for encrypted private key                                                                                                                                                  |
  | `agent`             | string                                                       |               | Path to ssh-agent UNIX socket                                                                                                                                                         |
  | `agentForward`      | boolean                                                      | `false`       | Enable agent forwarding                                                                                                                                                               |
  | `hostHash`          | string                                                       |               | Hash algorithm for hostVerifier (e.g. `'sha256'`)                                                                                                                                     |
  | `hostVerifier`      | (key: Uint8Array \| string) => boolean \| Promise\<boolean\> |               | Host key verification function. **If omitted, the server host key is accepted without verification, leaving the connection open to man-in-the-middle attacks** (a warning is logged). |
  | `algorithms`        | AlgorithmConfig                                              |               | Override default algorithms                                                                                                                                                           |
  | `readyTimeout`      | number                                                       | `20000`       | Time (ms) allowed for the TCP connect, handshake and authentication; the error has `level: 'client-timeout'`                                                                          |
  | `keepaliveInterval` | number                                                       | `0`           | Keepalive interval (ms)                                                                                                                                                               |
  | `keepaliveCountMax` | number                                                       | `3`           | Max unanswered keepalives                                                                                                                                                             |
  | `sock`              | Transport                                                    |               | Existing transport for connection hopping                                                                                                                                             |
  | `strictVendor`      | boolean                                                      | `true`        | Strict server vendor check                                                                                                                                                            |
  | `tryKeyboard`       | boolean                                                      | `false`       | Try keyboard-interactive auth                                                                                                                                                         |
  | `authHandler`       | AuthHandler                                                  |               | Custom authentication handler                                                                                                                                                         |
  | `debug`             | (msg: string) => void                                        |               | Debug logging function                                                                                                                                                                |

- **end**(): void - Disconnects the socket.

- **exec**(command: string, options?: ExecOptions): Promise\<Channel\> - Executes a command on the
  server. Options:

  | Property | Type                            | Description           |
  | -------- | ------------------------------- | --------------------- |
  | `env`    | object                          | Environment variables |
  | `pty`    | boolean \| PtyOptions           | Allocate a pseudo-TTY |
  | `x11`    | boolean \| number \| X11Options | X11 forwarding        |

- **shell**(options?: ShellOptions): Promise\<Channel\> - Starts an interactive shell session.
  Options support `window` (pseudo-TTY settings or `false`), `x11`, and `env`.

- **sftp**(): Promise\<SFTP\> - Starts an SFTP session.

- **forwardIn**(bindAddr: string, bindPort: number): Promise\<number\> - Bind on the server and
  forward incoming TCP connections. Returns the assigned port number.

- **unforwardIn**(bindAddr: string, bindPort: number): Promise\<void\> - Stop forwarding from a
  previously bound address/port.

- **forwardOut**(srcAddr: string, srcPort: number, dstAddr: string, dstPort: number):
  Promise\<Channel\> - Open an outbound TCP connection through the server.

- **rekey**(): Promise\<void\> - Initiates a rekey with the server.

- **openssh_forwardInStreamLocal**(socketPath: string): Promise\<void\> - OpenSSH extension: bind to
  a UNIX domain socket.

- **openssh_unforwardInStreamLocal**(socketPath: string): Promise\<void\> - OpenSSH extension:
  unbind from a UNIX domain socket.

- **openssh_forwardOutStreamLocal**(socketPath: string): Promise\<Channel\> - OpenSSH extension:
  open a UNIX domain socket connection.

### Server

#### Server events

- **connection**(client: Connection, info: ConnectionInfo) - A new client has connected. `info`
  contains the client's `header`, and its `ip` and `port` when the transport knows them.

#### Server methods

- **constructor**(config: ServerConfig, connectionListener?: function) - Creates a new Server
  instance. Config properties:

  | Property     | Type                                           | Required | Description                        |
  | ------------ | ---------------------------------------------- | -------- | ---------------------------------- |
  | `hostKeys`   | Array\<string \| Uint8Array \| HostKeyConfig\> | Yes      | Host private keys                  |
  | `algorithms` | AlgorithmConfig                                |          | Override default algorithms        |
  | `banner`     | string                                         |          | Message sent before authentication |
  | `greeting`   | string                                         |          | Message sent on connection         |
  | `ident`      | string                                         |          | Custom server software identifier  |
  | `debug`      | function                                       |          | Debug logging function             |

- **listen**(port: number, host?: string, callback?: function): void - Start listening for
  connections.

- **close**(callback?: function): void - Stop the server.

- **injectSocket**(socket: Transport): void - Inject an existing transport as a connection.

#### Connection events

- **authentication**(ctx: AuthContext) - Client has requested authentication. `ctx` provides
  `username`, `method`, `accept()`, and `reject()`. Depending on `ctx.method`:
  - `password`: `ctx.password` contains the password.
  - `publickey`: `ctx.key` contains `{ algo, data }`, plus `ctx.signature`, `ctx.blob`,
    `ctx.hashAlgo`.
  - `keyboard-interactive`: `ctx.prompt()` method for sending prompts.
  - `hostbased`: `ctx.key`, `ctx.localHostname`, `ctx.localUsername`, `ctx.signature`, `ctx.blob`.

- **ready**() - Client has been authenticated.

- **close**() - Client socket was closed.

- **error**(err: Error) - An error occurred.

- **session**(accept: () => Session, reject: () => void) - Client has requested a new session.

- **tcpip**(accept: () => Channel, reject: () => void, info: object) - Client requested an outbound
  TCP connection. `info` contains `destIP`, `destPort`, `srcIP`, `srcPort`.

- **request**(accept: function, reject: function, name: string, info: object) - Client sent a global
  request.

- **rekey**() - A rekeying operation has completed.

- **handshake**(negotiated: object) - Handshake completed.

#### Connection methods

- **end**(): void - Close the client connection.

- **forwardOut**(boundAddr: string, boundPort: number, remoteAddr: string, remotePort: number,
  callback: function): void - Alert client of incoming TCP connection.

- **openssh_forwardOutStreamLocal**(socketPath: string, callback: function): void - Alert client of
  incoming UNIX socket connection.

- **rekey**(callback?: function): void - Initiate a rekey.

- **x11**(originAddr: string, originPort: number, callback: function): void - Alert client of
  incoming X11 connection.

#### Session events

- **exec**(accept, reject, info: { command: string }) - Client wants to execute a command.

- **shell**(accept, reject) - Client wants an interactive shell.

- **sftp**(accept, reject) - Client wants an SFTP session.

- **pty**(accept, reject, info) - Client wants a pseudo-TTY. `info` contains `term`, `cols`, `rows`,
  `width`, `height`, `modes`.

- **env**(accept, reject, info: { key: string; value: string }) - Client wants to set an environment
  variable.

- **window-change**(accept, reject, info) - Client reports window dimension change.

- **signal**(accept, reject, info: { name: string }) - Client sent a signal.

- **auth-agent**(accept, reject) - Client wants agent forwarding.

- **subsystem**(accept, reject, info: { name: string }) - Client wants a subsystem.

- **close**() - Session was closed.

### Channel

Channel is a duplex stream used by both clients and servers.

- **allowHalfOpen**: boolean - When `true` (default), calling `end()` only sends EOF; the remote
  side can still send data.

- **close** event - Emitted when the channel is fully closed on both sides.

Client-specific (for exec/shell):

- The readable side represents stdout, the writable side represents stdin.
- **stderr** property contains a readable stream for stderr output.
- **exit** event - Emitted when the process finishes: `(code: number)` for normal exit, or
  `(null, signalName, didCoreDump, description)` for signal exit.
- **accepted**: Promise\<boolean\> - Settles with the server's answer to the exec/shell request.
  `exec()`/`shell()` resolve before that answer so no early output is missed; a refused request
  settles `false` and closes the channel.
- **setWindow**(rows, cols, height, width) - Notify server of terminal resize.
- **signal**(signalName: string) - Send a POSIX signal to the remote process.

Server-specific (for exec/shell):

- **exit**(exitCode: number) or **exit**(signalName, coreDumped?, errorMsg?) - Send exit status to
  the client.
- **stderr** property is a writable stream.

### Pseudo-TTY settings

| Property | Type   | Default   | Description       |
| -------- | ------ | --------- | ----------------- |
| `term`   | string | `'vt100'` | Terminal type     |
| `cols`   | number | `80`      | Number of columns |
| `rows`   | number | `24`      | Number of rows    |
| `width`  | number | `640`     | Width in pixels   |
| `height` | number | `480`     | Height in pixels  |
| `modes`  | object | `null`    | Terminal modes    |

### Utilities

- **parseKey**(keyData: string | Uint8Array, passphrase?: string) - Parses a private/public key in
  OpenSSH, RFC4716, or PPK format. Returns a `ParsedKey` object (or array for modern OpenSSH keys)
  with methods:
  - `type` - Key type string (e.g. `'ssh-ed25519'`)
  - `comment` - Key comment
  - `isPrivateKey()` - Whether this is a private key
  - `getPublicSSH()` - SSH-format public key as Uint8Array
  - `getPublicPEM()` - PEM-format public key as string
  - `getPrivatePEM()` - PEM-format private key as string
  - `sign(data)` - Sign data, returns signature Uint8Array
  - `verify(data, signature)` - Verify a signature
  - `equals(otherKey)` - Compare keys

- **generateKeyPair**(keyType: string, options?: KeyGenOptions): Promise\<KeyPair\> - Generate an
  SSH key pair. `keyType` must be `'rsa'`, `'ecdsa'`, or `'ed25519'`. Options:
  - `bits` - Key strength (ECDSA: 256/384/521; RSA: 2048+)
  - `cipher` - Cipher for encryption (e.g. `'aes256-cbc'`)
  - `passphrase` - Passphrase for key encryption
  - `comment` - Key comment
  - `rounds` - bcrypt rounds for encrypted keys (default: 16)

- **OPEN_MODE** - SFTP file open mode flags (`READ`, `WRITE`, `APPEND`, `CREAT`, `TRUNC`, `EXCL`).

- **STATUS_CODE** - SFTP status codes (`OK`, `EOF`, `NO_SUCH_FILE`, `PERMISSION_DENIED`, `FAILURE`,
  etc).

### Agent

- **OpenSSHAgent**(socketPath: string) - Communicates with an OpenSSH agent via UNIX socket.

- **BaseAgent** - Base class for creating custom agents. Implement `getIdentities(callback)` and
  `sign(pubKey, data, options, callback)`.

- **AgentProtocol**(isClient: boolean) - Duplex stream for OpenSSH agent protocol communication.

- **createAgent**(path: string) - Creates an OpenSSHAgent for the given socket path.

## Supported Algorithms

### Key Exchange

**Default** (in preference order):

- `curve25519-sha256`
- `curve25519-sha256@libssh.org`
- `ecdh-sha2-nistp256`
- `ecdh-sha2-nistp384`
- `ecdh-sha2-nistp521`
- `diffie-hellman-group14-sha256`
- `diffie-hellman-group16-sha512`
- `diffie-hellman-group18-sha512`

**Also supported:** `diffie-hellman-group14-sha1`

### Server Host Key

**Default:** `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`,
`rsa-sha2-512`, `rsa-sha2-256`

**Also supported:** `ssh-rsa` (SHA-1 RSA signatures; disabled by default like OpenSSH 8.8+, enable
via `algorithms.serverHostKey`)

### Cipher

**Default:** `chacha20-poly1305@openssh.com`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`,
`aes128-ctr`, `aes192-ctr`, `aes256-ctr`

**Also supported:** `aes256-cbc`, `aes192-cbc`, `aes128-cbc`, `aes128-gcm`, `aes256-gcm`

### HMAC

**Default:** `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256`,
`hmac-sha2-512`

**Also supported:** `hmac-sha1-etm@openssh.com`, `hmac-sha1`, `hmac-sha2-256-96`,
`hmac-sha2-512-96`, `hmac-sha1-96`

### Compression

**Default:** `none`, `zlib@openssh.com`, `zlib`

### Cryptography

Almost all cryptography runs on Deno's built-in
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (`crypto.subtle` /
`crypto.getRandomValues`):

- SHA-1/SHA-256/SHA-384/SHA-512 hashing and HMAC
- RSA and ECDSA key generation, signing, and verification
- Ed25519 key generation, signing, and verification
- Key exchange: X25519 (`curve25519-sha256`) and ECDH over P-256/P-384/P-521
- AES-CTR and AES-GCM (transport ciphers and private-key decryption)
- AES-CBC — Web Crypto only offers PKCS#7-padded CBC, so the raw (unpadded) CBC that SSH requires is
  implemented on top of it in `src/crypto/aes-cbc.ts`
- Random number generation

The two features Web Crypto does not cover are provided without any third-party dependency:

- **`chacha20-poly1305@openssh.com`** transport cipher — uses the runtime's native `chacha20` cipher
  from `node:crypto` (available in Deno 2.9.4+) together with a vendored Poly1305 implementation
  (`src/crypto/poly1305.ts`).
- **`bcrypt` KDF** — used when reading or writing passphrase-protected OpenSSH private keys
  (`src/keygen.ts`, `src/protocol/keyParser.ts`); provided by a vendored `bcrypt_pbkdf`
  implementation (`src/crypto/bcrypt-pbkdf.ts`).

ssh2-ts no longer depends on any third-party cryptography packages.

## License

See [LICENSE](LICENSE) for details.
