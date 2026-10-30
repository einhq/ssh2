/**
 * SFTP Protocol Handler
 *
 * Implements the SSH File Transfer Protocol (SFTP) version 3.
 * Supports both client and server modes.
 */

import { allocBytes, concatBytes, fromString, writeUInt32BE } from '../../utils/binary.ts';
import { EventEmitter } from '../../utils/events.ts';
import { onWindowAdjust } from '../../channel-window.ts';
import {
  DEFAULT_MAX_PKT_LEN,
  MAX_REQID,
  OPENSSH_MAX_PKT_LEN,
  PKT_RW_OVERHEAD,
  RE_OPENSSH,
  REQUEST,
  RESPONSE,
  STATUS_CODE,
  STATUS_CODE_STR,
} from './constants.ts';
import {
  attrsToBytes,
  CLIENT_VERSION_BUFFER,
  getAttrBytes,
  makePacketParser,
  type PacketParser,
  SERVER_VERSION_BUFFER,
  writeUInt64BE,
} from './packet.ts';
import { Stats } from './Stats.ts';
import { ReadStream, WriteStream } from './streams.ts';
import { fastGet as _fastGet, fastPut as _fastPut } from './transfer.ts';
import type {
  DirEntry,
  FileAttributes,
  InputAttributes,
  NameEntry,
  PendingRequest,
  ReaddirCallback,
  ReadStreamOptions,
  SFTPConfig,
  SFTPError,
  SFTPExtensions,
  SFTPHandle,
  StatusCallback,
  TransferOptions,
  WriteStreamOptions,
} from './types.ts';
import { stringToFlags } from './types.ts';

/**
 * Channel info for SFTP
 */
interface ChannelInfo {
  type: string;
  incoming: {
    id?: number;
    window: number;
    packetSize: number;
    state: string;
  };
  outgoing: {
    id?: number;
    window: number;
    packetSize: number;
    state: string;
  };
}

/**
 * Protocol interface for sending data
 */
export interface SFTPProtocol {
  channelData(id: number, data: Uint8Array): void;
  channelDataParts?(id: number, parts: readonly Uint8Array[]): void;
  channelClose(id: number): void;
}

type OutboundPayload = {
  length: number;
  offset: number;
  parts: readonly Uint8Array[];
};

function payloadParts(
  payload: OutboundPayload,
  start: number,
  length: number,
): Uint8Array[] {
  const result: Uint8Array[] = [];
  let partStart = 0;
  let remaining = length;

  for (const part of payload.parts) {
    const partEnd = partStart + part.length;
    if (start < partEnd && remaining > 0) {
      const offset = Math.max(0, start - partStart);
      const take = Math.min(part.length - offset, remaining);
      result.push(
        offset === 0 && take === part.length ? part : part.subarray(offset, offset + take),
      );
      start += take;
      remaining -= take;
    }
    partStart = partEnd;
    if (remaining === 0) break;
  }

  return result;
}

/**
 * Client interface for SFTP
 */
export interface SFTPClient {
  protocol: SFTPProtocol;
  remoteIdentRaw?: string;
}

/**
 * SFTP class - handles SFTP protocol for both client and server
 */
export class SFTP extends EventEmitter {
  /** Whether this is server mode */
  readonly server: boolean;

  /** Channel type */
  type: string;

  /** Incoming channel info */
  incoming: ChannelInfo['incoming'];

  /** Outgoing channel info */
  outgoing: ChannelInfo['outgoing'];

  /** Whether readable */
  readable = true;

  /** Maximum open handles (from server limits) */
  maxOpenHandles?: number;

  private _debug?: (msg: string) => void;
  private _isOpenSSH: boolean;
  private _isSsh2ts: boolean;
  private _version = -1;
  private _extensions: SFTPExtensions = {};
  private _biOpt?: boolean;

  // Packet parsing state
  private _pktLenBytes = 0;
  private _pktLen = 0;
  private _pktPos = 0;
  private _pkt?: Uint8Array;

  // Request tracking
  private _writeReqid = -1;
  private _requests: Record<number, PendingRequest> = {};

  // Packet size limits
  private _maxInPktLen: number;
  // @ts-ignore Used for future streaming functionality
  private _maxOutPktLen: number;
  private _maxReadLen: number;
  private _maxWriteLen: number;

  // Channel state
  // @ts-ignore Used for future streaming functionality
  private _client: SFTPClient;
  private _protocol: SFTPProtocol;
  // @ts-ignore Used for flow control
  private _waitWindow = false;
  // @ts-ignore Used for flow control
  private _chunkcb?: () => void;
  private _buffer: OutboundPayload[] = [];
  private _removeWindowAdjustListener?: () => void;

  // Parser instance
  private _parser: PacketParser;

  constructor(client: SFTPClient, chanInfo: ChannelInfo, cfg?: SFTPConfig) {
    super();

    const config = cfg || {};
    const remoteIdentRaw = client.remoteIdentRaw;

    this.server = !!config.server;
    this._debug = config.debug;
    this._isOpenSSH = !!(remoteIdentRaw && RE_OPENSSH.test(remoteIdentRaw));
    this._isSsh2ts = !!(remoteIdentRaw && /^SSH-2\.0-ssh2ts/.test(remoteIdentRaw));
    this._biOpt = config.biOpt;
    if (this.server) this._extensions = config.extensions ?? {};

    this._maxInPktLen = OPENSSH_MAX_PKT_LEN;
    this._maxOutPktLen = DEFAULT_MAX_PKT_LEN;
    this._maxReadLen = (this._isOpenSSH ? OPENSSH_MAX_PKT_LEN : DEFAULT_MAX_PKT_LEN) -
      PKT_RW_OVERHEAD;
    this._maxWriteLen = (this._isOpenSSH ? OPENSSH_MAX_PKT_LEN : DEFAULT_MAX_PKT_LEN) -
      PKT_RW_OVERHEAD;

    this._client = client;
    this._protocol = client.protocol;
    this._parser = makePacketParser();

    this.type = chanInfo.type;
    this.incoming = chanInfo.incoming;
    this.outgoing = chanInfo.outgoing;
    this._removeWindowAdjustListener = onWindowAdjust(this.outgoing, () => {
      if (this._waitWindow && this.outgoing.window > 0) {
        this._waitWindow = false;
        this._drainBuffer();
      }
    });
  }

  /**
   * Get SFTP version
   */
  get version(): number {
    return this._version;
  }

  /**
   * The extensions the server advertised; for a server, the ones it advertises
   */
  get extensions(): SFTPExtensions {
    return this._extensions;
  }

  /**
   * Initialize SFTP session
   */
  _init(): void {
    if (!this.server) {
      this._sendOrBuffer(CLIENT_VERSION_BUFFER);
    }
  }

  /**
   * Handle incoming data
   */
  push(data: Uint8Array | null): void {
    if (data === null) {
      this._cleanupRequests();
      if (!this.readable) return;
      this.readable = false;
      this.emit('end');
      return;
    }

    let p = 0;

    while (p < data.length) {
      // Read packet length (4 bytes)
      if (this._pktLenBytes < 4) {
        let nb = Math.min(4 - this._pktLenBytes, data.length - p);
        this._pktLenBytes += nb;

        while (nb--) {
          this._pktLen = (this._pktLen << 8) + data[p++];
        }

        if (this._pktLenBytes < 4) return;
        if (this._pktLen === 0) {
          this._doFatalError('Invalid packet length');
          return;
        }
        if (this._pktLen > this._maxInPktLen) {
          this._doFatalError(`Packet length ${this._pktLen} exceeds max ${this._maxInPktLen}`);
          return;
        }
        if (p >= data.length) return;
      }

      // Read packet data
      if (this._pktPos < this._pktLen) {
        const nb = Math.min(this._pktLen - this._pktPos, data.length - p);

        if (nb === this._pktLen && this._pktPos === 0) {
          // Full packet in single chunk
          this._pkt = data.subarray(p, p + nb);
        } else {
          // Fragmented packet
          if (!this._pkt) {
            this._pkt = new Uint8Array(this._pktLen);
          }
          this._pkt.set(data.subarray(p, p + nb), this._pktPos);
        }

        p += nb;
        this._pktPos += nb;

        if (this._pktPos < this._pktLen) return;
      }

      // Process complete packet
      const type = this._pkt![0];
      const payload = this._pkt!;

      // Reset for next packet
      this._pktLen = 0;
      this._pktLenBytes = 0;
      this._pkt = undefined;
      this._pktPos = 0;

      // Handle packet
      if (this._version === -1) {
        if (this.server) {
          if (type !== REQUEST.INIT) {
            this._doFatalError(`Expected INIT packet, got ${type}`);
            return;
          }
        } else if (type !== RESPONSE.VERSION) {
          this._doFatalError(`Expected VERSION packet, got ${type}`);
          return;
        }
      }

      if (this.server) {
        if (!this._handleServerPacket(type, payload)) return;
      } else {
        if (!this._handleClientPacket(type, payload)) return;
      }
    }
  }

  /**
   * End the SFTP session
   */
  end(): void {
    this.destroy();
  }

  /**
   * Destroy the SFTP session
   */
  destroy(): void {
    this._removeWindowAdjustListener?.();
    this._removeWindowAdjustListener = undefined;
    if (this.outgoing.state === 'open' || this.outgoing.state === 'eof') {
      this.outgoing.state = 'closing';
      this._protocol.channelClose(this.outgoing.id!);
    }
  }

  // ===========================================================================
  // Client Methods
  // ===========================================================================

  /**
   * Open a file
   */
  open(path: string, flags: string | number, attrs?: InputAttributes): Promise<SFTPHandle> {
    this._checkClient();

    const numFlags = typeof flags === 'number' ? flags : stringToFlags(flags as string);
    if (numFlags === null) {
      throw new Error(`Unknown flags string: ${flags}`);
    }

    let attrsFlags = 0;
    let attrsLen = 0;
    if (typeof attrs === 'string' || typeof attrs === 'number') {
      attrs = { mode: attrs as number | string };
    }
    if (typeof attrs === 'object' && attrs !== null) {
      const result = attrsToBytes(attrs);
      attrsFlags = result.flags;
      attrsLen = result.nb;
    }

    const pathBytes = fromString(path);
    const buf = allocBytes(4 + 1 + 4 + 4 + pathBytes.length + 4 + 4 + attrsLen);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = REQUEST.OPEN;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, pathBytes.length, p);
    p += 4;
    buf.set(pathBytes, p);
    p += pathBytes.length;
    writeUInt32BE(buf, numFlags, p);
    p += 4;
    writeUInt32BE(buf, attrsFlags, p);
    p += 4;

    if (attrsLen) {
      buf.set(getAttrBytes(attrsLen), p);
    }

    return new Promise((resolve, reject) => {
      this._requests[reqid] = {
        cb: (err: Error | null, handle?: SFTPHandle) => {
          if (err) reject(err);
          else resolve(handle!);
        },
      };
      this._sendOrBuffer(buf);
      this._debug?.(`SFTP: Outbound: Sending OPEN`);
    });
  }

  /**
   * Close a file handle
   */
  close(handle: SFTPHandle): Promise<void> {
    this._checkClient();
    this._checkHandle(handle);

    const buf = allocBytes(4 + 1 + 4 + 4 + handle.length);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = REQUEST.CLOSE;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, handle.length, p);
    p += 4;
    buf.set(handle, p);

    return new Promise((resolve, reject) => {
      this._requests[reqid] = {
        cb: (err: Error | null) => {
          if (err) reject(err);
          else resolve();
        },
      };
      this._sendOrBuffer(buf);
      this._debug?.(`SFTP: Outbound: Sending CLOSE`);
    });
  }

  /**
   * Read from a file
   * Returns the number of bytes read (0 means EOF)
   */
  read(
    handle: SFTPHandle,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | bigint,
  ): Promise<number> {
    this._checkClient();
    this._checkHandle(handle);

    if (offset >= buffer.length) throw new Error('offset out of bounds');
    if (offset + length > buffer.length) throw new Error('length extends past buffer');

    const readLen = Math.min(length, this._maxReadLen);

    const buf = allocBytes(4 + 1 + 4 + 4 + handle.length + 8 + 4);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = REQUEST.READ;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, handle.length, p);
    p += 4;
    buf.set(handle, p);
    p += handle.length;
    writeUInt64BE(buf, position, p);
    p += 8;
    writeUInt32BE(buf, readLen, p);

    return new Promise((resolve, reject) => {
      this._requests[reqid] = {
        cb: (err: Error | null, bytesRead?: number, data?: Uint8Array) => {
          if (err) {
            // EOF is returned as error, but we return 0 bytes read
            if ((err as Error & { code?: number }).code === STATUS_CODE.EOF) {
              resolve(0);
            } else {
              reject(err);
            }
          } else {
            if (data) {
              buffer.set(data, offset);
            }
            resolve(bytesRead ?? 0);
          }
        },
        buffer,
        type: REQUEST.READ,
      } as PendingRequest & { buffer: Uint8Array };
      this._sendOrBuffer(buf);
      this._debug?.(`SFTP: Outbound: Sending READ`);
    });
  }

  /**
   * Write to a file.
   *
   * Writes all `length` bytes, splitting into multiple WRITE packets when the
   * payload exceeds the negotiated max packet size. Resolves once every chunk
   * has been acknowledged. A zero `length` sends nothing.
   */
  write(
    handle: SFTPHandle,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | bigint,
  ): Promise<void> {
    this._checkClient();
    this._checkHandle(handle);

    if (offset > buffer.length) throw new Error('offset out of bounds');
    if (offset + length > buffer.length) throw new Error('length extends past buffer');

    return this._writeAll(handle, buffer, offset, length, position);
  }

  /** Write all `length` bytes, splitting into `_maxWriteLen`-sized WRITE packets. */
  private async _writeAll(
    handle: SFTPHandle,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | bigint,
  ): Promise<void> {
    let written = 0;
    let pos = BigInt(position);

    while (written < length) {
      const chunkLen = Math.min(length - written, this._maxWriteLen);
      await this._writeChunk(handle, buffer, offset + written, chunkLen, pos);
      written += chunkLen;
      pos += BigInt(chunkLen);
    }
  }

  /** Send a single WRITE packet (at most `_maxWriteLen` bytes). */
  private _writeChunk(
    handle: SFTPHandle,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: bigint,
  ): Promise<void> {
    const data = buffer.subarray(offset, offset + length);

    const buf = allocBytes(4 + 1 + 4 + 4 + handle.length + 8 + 4 + data.length);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = REQUEST.WRITE;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, handle.length, p);
    p += 4;
    buf.set(handle, p);
    p += handle.length;
    writeUInt64BE(buf, position, p);
    p += 8;
    writeUInt32BE(buf, data.length, p);
    p += 4;
    buf.set(data, p);

    return new Promise((resolve, reject) => {
      this._requests[reqid] = {
        cb: (err: Error | null) => {
          if (err) reject(err);
          else resolve();
        },
      };
      this._sendOrBuffer(buf);
      this._debug?.(`SFTP: Outbound: Sending WRITE`);
    });
  }

  /**
   * Get file stats (follows symlinks)
   */
  stat(path: string): Promise<FileAttributes> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._simplePath(REQUEST.STAT, path, (err, stats) => {
        if (err) reject(err);
        else resolve(stats!);
      }, 'STAT');
    });
  }

  /**
   * Get file stats (doesn't follow symlinks)
   */
  lstat(path: string): Promise<FileAttributes> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._simplePath(REQUEST.LSTAT, path, (err, stats) => {
        if (err) reject(err);
        else resolve(stats!);
      }, 'LSTAT');
    });
  }

  /**
   * Get file stats by handle
   */
  fstat(handle: SFTPHandle): Promise<FileAttributes> {
    this._checkClient();
    this._checkHandle(handle);
    return new Promise((resolve, reject) => {
      this._simpleHandle(REQUEST.FSTAT, handle, (err, stats) => {
        if (err) reject(err);
        else resolve(stats!);
      }, 'FSTAT');
    });
  }

  /**
   * Set file stats
   */
  setstat(path: string, attrs: InputAttributes): Promise<void> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._pathWithAttrs(REQUEST.SETSTAT, path, attrs, (err) => {
        if (err) reject(err);
        else resolve();
      }, 'SETSTAT');
    });
  }

  /**
   * Set file stats by handle
   */
  fsetstat(handle: SFTPHandle, attrs: InputAttributes): Promise<void> {
    this._checkClient();
    this._checkHandle(handle);

    const result = attrsToBytes(attrs);
    const buf = allocBytes(4 + 1 + 4 + 4 + handle.length + 4 + result.nb);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = REQUEST.FSETSTAT;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, handle.length, p);
    p += 4;
    buf.set(handle, p);
    p += handle.length;
    writeUInt32BE(buf, result.flags, p);
    p += 4;
    if (result.nb) {
      buf.set(getAttrBytes(result.nb), p);
    }

    return new Promise((resolve, reject) => {
      this._requests[reqid] = {
        cb: (err: Error | null) => {
          if (err) reject(err);
          else resolve();
        },
      };
      this._sendOrBuffer(buf);
      this._debug?.(`SFTP: Outbound: Sending FSETSTAT`);
    });
  }

  /**
   * Open a directory
   */
  opendir(path: string): Promise<SFTPHandle> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._simplePath(REQUEST.OPENDIR, path, (err, handle) => {
        if (err) reject(err);
        else resolve(handle!);
      }, 'OPENDIR');
    });
  }

  /**
   * Read directory entries
   */
  async readdir(
    handle: SFTPHandle | string,
    options?: { full?: boolean },
  ): Promise<DirEntry[]> {
    this._checkClient();

    const full = options?.full ?? false;

    // Filter out . and .. unless full option is true
    const filterEntries = (entries: DirEntry[]): DirEntry[] => {
      if (full) return entries;
      return entries.filter((e) => e.filename !== '.' && e.filename !== '..');
    };

    if (typeof handle === 'string') {
      // Path provided, open directory first
      const dirHandle = await this.opendir(handle);
      try {
        const entries: DirEntry[] = [];
        while (true) {
          let list: DirEntry[] | undefined;
          try {
            list = await this._readdirHandleAsync(dirHandle);
          } catch (err) {
            // Servers signal end-of-listing with an EOF status rather than an
            // empty NAME response; treat that as a clean terminator.
            if ((err as Error & { code?: number }).code === STATUS_CODE.EOF) break;
            throw err;
          }
          if (!list || list.length === 0) break;
          entries.push(...list);
        }
        return filterEntries(entries);
      } finally {
        await this.close(dirHandle);
      }
    } else {
      const list = await this._readdirHandleAsync(handle);
      return filterEntries(list ?? []);
    }
  }

  private _readdirHandleAsync(handle: SFTPHandle): Promise<DirEntry[] | undefined> {
    return new Promise((resolve, reject) => {
      this._readdirHandle(handle, (err, list) => {
        if (err) reject(err);
        else resolve(list);
      });
    });
  }

  private _readdirHandle(handle: SFTPHandle, cb: ReaddirCallback): void {
    this._checkHandle(handle);
    this._simpleHandle(REQUEST.READDIR, handle, cb, 'READDIR');
  }

  /**
   * Remove a file
   */
  unlink(path: string): Promise<void> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._simplePath(REQUEST.REMOVE, path, (err) => {
        if (err) reject(err);
        else resolve();
      }, 'REMOVE');
    });
  }

  /**
   * Alias for unlink
   */
  remove(path: string): Promise<void> {
    return this.unlink(path);
  }

  /**
   * Rename a file
   */
  rename(oldPath: string, newPath: string): Promise<void> {
    this._checkClient();

    const oldPathBytes = fromString(oldPath);
    const newPathBytes = fromString(newPath);
    const buf = allocBytes(4 + 1 + 4 + 4 + oldPathBytes.length + 4 + newPathBytes.length);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = REQUEST.RENAME;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, oldPathBytes.length, p);
    p += 4;
    buf.set(oldPathBytes, p);
    p += oldPathBytes.length;
    writeUInt32BE(buf, newPathBytes.length, p);
    p += 4;
    buf.set(newPathBytes, p);

    return new Promise((resolve, reject) => {
      this._requests[reqid] = {
        cb: (err: Error | null) => {
          if (err) reject(err);
          else resolve();
        },
      };
      this._sendOrBuffer(buf);
      this._debug?.(`SFTP: Outbound: Sending RENAME`);
    });
  }

  /**
   * Rename with POSIX semantics (`posix-rename@openssh.com`): an existing
   * `newPath` is replaced atomically, where RENAME refuses it. Rejects without
   * asking when the server does not advertise the extension.
   */
  posixRename(oldPath: string, newPath: string): Promise<void> {
    this._checkClient();

    const ext = 'posix-rename@openssh.com';
    if (this._extensions[ext] !== '1') {
      return Promise.reject(new Error(`server does not support ${ext}`));
    }

    const extBytes = fromString(ext);
    const oldPathBytes = fromString(oldPath);
    const newPathBytes = fromString(newPath);
    const buf = allocBytes(
      4 + 1 + 4 + 4 + extBytes.length + 4 + oldPathBytes.length + 4 + newPathBytes.length,
    );
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = REQUEST.EXTENDED;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    for (const bytes of [extBytes, oldPathBytes, newPathBytes]) {
      writeUInt32BE(buf, bytes.length, p);
      p += 4;
      buf.set(bytes, p);
      p += bytes.length;
    }

    return new Promise((resolve, reject) => {
      this._requests[reqid] = {
        cb: (err: Error | null) => {
          if (err) reject(err);
          else resolve();
        },
      };
      this._sendOrBuffer(buf);
      this._debug?.(`SFTP: Outbound: Sending ${ext}`);
    });
  }

  /**
   * Create a directory
   */
  mkdir(path: string, attrs?: InputAttributes): Promise<void> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._pathWithAttrs(REQUEST.MKDIR, path, attrs, (err) => {
        if (err) reject(err);
        else resolve();
      }, 'MKDIR');
    });
  }

  /**
   * Remove a directory
   */
  rmdir(path: string): Promise<void> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._simplePath(REQUEST.RMDIR, path, (err) => {
        if (err) reject(err);
        else resolve();
      }, 'RMDIR');
    });
  }

  /**
   * Get real path
   */
  realpath(path: string): Promise<string> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._simplePath(REQUEST.REALPATH, path, (err, result) => {
        if (err) reject(err);
        else resolve(result!);
      }, 'REALPATH');
    });
  }

  /**
   * Read symlink target
   */
  readlink(path: string): Promise<string> {
    this._checkClient();
    return new Promise((resolve, reject) => {
      this._simplePath(REQUEST.READLINK, path, (err, result) => {
        if (err) reject(err);
        else resolve(result!);
      }, 'READLINK');
    });
  }

  /**
   * Create a symlink
   */
  symlink(targetPath: string, linkPath: string): Promise<void> {
    this._checkClient();

    const targetBytes = fromString(targetPath);
    const linkBytes = fromString(linkPath);

    // The draft spec sends linkpath then targetpath; OpenSSH, dropbear and this
    // library's own server read them the other way round
    const targetFirst = this._isOpenSSH || this._isSsh2ts;
    const first = targetFirst ? targetBytes : linkBytes;
    const second = targetFirst ? linkBytes : targetBytes;

    const buf = allocBytes(4 + 1 + 4 + 4 + first.length + 4 + second.length);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = REQUEST.SYMLINK;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, first.length, p);
    p += 4;
    buf.set(first, p);
    p += first.length;
    writeUInt32BE(buf, second.length, p);
    p += 4;
    buf.set(second, p);

    return new Promise((resolve, reject) => {
      this._requests[reqid] = {
        cb: (err: Error | null) => {
          if (err) reject(err);
          else resolve();
        },
      };
      this._sendOrBuffer(buf);
      this._debug?.(`SFTP: Outbound: Sending SYMLINK`);
    });
  }

  /**
   * Check if file exists
   */
  async exists(path: string): Promise<boolean> {
    try {
      await this.stat(path);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Change file mode
   */
  chmod(path: string, mode: number | string): Promise<void> {
    return this.setstat(path, { mode });
  }

  /**
   * Change file mode by handle
   */
  fchmod(handle: SFTPHandle, mode: number | string): Promise<void> {
    return this.fsetstat(handle, { mode });
  }

  /**
   * Change file owner
   */
  chown(path: string, uid: number, gid: number): Promise<void> {
    return this.setstat(path, { uid, gid });
  }

  /**
   * Change file owner by handle
   */
  fchown(handle: SFTPHandle, uid: number, gid: number): Promise<void> {
    return this.fsetstat(handle, { uid, gid });
  }

  /**
   * Change file timestamps
   */
  utimes(path: string, atime: number | Date, mtime: number | Date): Promise<void> {
    return this.setstat(path, { atime, mtime });
  }

  /**
   * Change file timestamps by handle
   */
  futimes(handle: SFTPHandle, atime: number | Date, mtime: number | Date): Promise<void> {
    return this.fsetstat(handle, { atime, mtime });
  }

  /**
   * Read entire file contents
   */
  async readFile(path: string, _options?: { encoding?: null }): Promise<Uint8Array> {
    this._checkClient();

    const handle = await this.open(path, 'r');
    try {
      // Read until EOF regardless of the reported size: a single read() only
      // returns up to one packet, so loop and accumulate chunks.
      const chunks: Uint8Array[] = [];
      let offset = 0;
      const chunkSize = this._maxReadLen;

      while (true) {
        const buf = new Uint8Array(chunkSize);
        const bytesRead = await this.read(handle, buf, 0, chunkSize, offset);
        if (bytesRead === 0) break;
        chunks.push(buf.subarray(0, bytesRead));
        offset += bytesRead;
      }

      // Combine chunks
      const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
      const result = new Uint8Array(totalLength);
      let pos = 0;
      for (const chunk of chunks) {
        result.set(chunk, pos);
        pos += chunk.length;
      }
      return result;
    } finally {
      await this.close(handle);
    }
  }

  /**
   * Write data to a file
   */
  async writeFile(
    path: string,
    data: Uint8Array | string,
    options?: { mode?: number },
  ): Promise<void> {
    this._checkClient();

    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const handle = await this.open(path, 'w', { mode: options?.mode ?? 0o666 });

    try {
      await this.write(handle, buffer, 0, buffer.length, 0);
    } finally {
      await this.close(handle);
    }
  }

  /**
   * Append data to a file
   */
  async appendFile(
    path: string,
    data: Uint8Array | string,
    options?: { mode?: number },
  ): Promise<void> {
    this._checkClient();

    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const handle = await this.open(path, 'a', { mode: options?.mode ?? 0o666 });

    try {
      await this.write(handle, buffer, 0, buffer.length, 0);
    } finally {
      await this.close(handle);
    }
  }

  /**
   * Create a readable stream for a file
   */
  createReadStream(path: string, options?: ReadStreamOptions): ReadStream {
    this._checkClient();
    return new ReadStream(this, path, options);
  }

  /**
   * Create a writable stream for a file
   */
  createWriteStream(path: string, options?: WriteStreamOptions): WriteStream {
    this._checkClient();
    return new WriteStream(this, path, options);
  }

  /**
   * Fast download from remote to local file
   */
  fastGet(
    remotePath: string,
    localPath: string,
    opts?: TransferOptions | ((err: Error | null) => void),
    cb?: (err: Error | null) => void,
  ): void {
    this._checkClient();
    _fastGet(this, remotePath, localPath, opts, cb);
  }

  /**
   * Fast upload from local file to remote
   */
  fastPut(
    localPath: string,
    remotePath: string,
    opts?: TransferOptions | ((err: Error | null) => void),
    cb?: (err: Error | null) => void,
  ): void {
    this._checkClient();
    _fastPut(this, localPath, remotePath, opts, cb);
  }

  // ===========================================================================
  // Server Response Methods
  // ===========================================================================

  /**
   * Send STATUS response (server mode)
   */
  status(reqId: number, code: number, message?: string): void {
    this._checkServer();

    const msgBytes = fromString(
      message || STATUS_CODE_STR[code as keyof typeof STATUS_CODE_STR] || 'Unknown',
    );
    const langBytes = fromString('en');
    const buf = allocBytes(4 + 1 + 4 + 4 + 4 + msgBytes.length + 4 + langBytes.length);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = RESPONSE.STATUS;
    writeUInt32BE(buf, reqId, p);
    p += 4;
    writeUInt32BE(buf, code, p);
    p += 4;
    writeUInt32BE(buf, msgBytes.length, p);
    p += 4;
    buf.set(msgBytes, p);
    p += msgBytes.length;
    writeUInt32BE(buf, langBytes.length, p);
    p += 4;
    buf.set(langBytes, p);

    this._sendOrBuffer(buf);
  }

  /**
   * Send HANDLE response (server mode)
   */
  handle(reqId: number, handle: SFTPHandle): void {
    this._checkServer();

    const buf = allocBytes(4 + 1 + 4 + 4 + handle.length);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = RESPONSE.HANDLE;
    writeUInt32BE(buf, reqId, p);
    p += 4;
    writeUInt32BE(buf, handle.length, p);
    p += 4;
    buf.set(handle, p);

    this._sendOrBuffer(buf);
  }

  /**
   * Send DATA response (server mode)
   */
  data(reqId: number, data: Uint8Array): void {
    this._checkServer();

    const header = allocBytes(4 + 1 + 4 + 4);
    let p = 0;

    writeUInt32BE(header, header.length + data.length - 4, p);
    p += 4;
    header[p++] = RESPONSE.DATA;
    writeUInt32BE(header, reqId, p);
    p += 4;
    writeUInt32BE(header, data.length, p);

    this._sendOrBuffer([header, data]);
  }

  /**
   * Send ATTRS response (server mode)
   */
  attrs(reqId: number, attrs: FileAttributes): void {
    this._checkServer();

    const result = attrsToBytes(attrs);
    const buf = allocBytes(4 + 1 + 4 + 4 + result.nb);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = RESPONSE.ATTRS;
    writeUInt32BE(buf, reqId, p);
    p += 4;
    writeUInt32BE(buf, result.flags, p);
    p += 4;
    if (result.nb) {
      buf.set(getAttrBytes(result.nb), p);
    }

    this._sendOrBuffer(buf);
  }

  /**
   * Send NAME response (server mode)
   * Used for readdir, realpath, readlink responses
   */
  name(reqId: number, names: NameEntry | NameEntry[]): void {
    this._checkServer();

    const entries = Array.isArray(names) ? names : [names];
    const encoder = new TextEncoder();

    // Calculate total size needed
    let totalSize = 4 + 1 + 4 + 4; // packet length + type + reqId + count

    const encodedEntries: Array<{
      filename: Uint8Array;
      longname: Uint8Array;
      attrsFlags: number;
      attrsBytes: Uint8Array;
    }> = [];

    for (const entry of entries) {
      const filename = encoder.encode(entry.filename);
      const longname = encoder.encode(entry.longname ?? '');
      const attrsResult = attrsToBytes(entry.attrs);
      // attrsToBytes encodes into one shared buffer, so copy this entry's
      // bytes out before the next entry overwrites them.
      const attrsBytes = getAttrBytes(attrsResult.nb).slice();

      encodedEntries.push({ filename, longname, attrsFlags: attrsResult.flags, attrsBytes });

      totalSize += 4 + filename.length; // filename string
      totalSize += 4 + longname.length; // longname string
      totalSize += 4 + attrsBytes.length; // attrs flags + data
    }

    const buf = allocBytes(totalSize);
    let p = 0;

    writeUInt32BE(buf, totalSize - 4, p);
    p += 4;
    buf[p++] = RESPONSE.NAME;
    writeUInt32BE(buf, reqId, p);
    p += 4;
    writeUInt32BE(buf, entries.length, p);
    p += 4;

    for (const { filename, longname, attrsFlags, attrsBytes } of encodedEntries) {
      // Write filename
      writeUInt32BE(buf, filename.length, p);
      p += 4;
      buf.set(filename, p);
      p += filename.length;

      // Write longname
      writeUInt32BE(buf, longname.length, p);
      p += 4;
      buf.set(longname, p);
      p += longname.length;

      // Write attrs
      writeUInt32BE(buf, attrsFlags, p);
      p += 4;
      buf.set(attrsBytes, p);
      p += attrsBytes.length;
    }

    this._sendOrBuffer(buf);
  }

  // ===========================================================================
  // Private Helpers
  // ===========================================================================

  private _checkClient(): void {
    if (this.server) throw new Error('Client-only method called in server mode');
  }

  private _checkServer(): void {
    if (!this.server) throw new Error('Server-only method called in client mode');
  }

  private _checkHandle(handle: SFTPHandle): void {
    if (!(handle instanceof Uint8Array)) {
      throw new Error('handle is not a Uint8Array');
    }
  }

  private _nextReqId(): number {
    this._writeReqid = (this._writeReqid + 1) & MAX_REQID;
    return this._writeReqid;
  }

  // deno-lint-ignore no-explicit-any
  private _simplePath(
    type: number,
    path: string,
    cb: (...args: any[]) => void,
    name: string,
  ): void {
    const pathBytes = fromString(path);
    const buf = allocBytes(4 + 1 + 4 + 4 + pathBytes.length);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = type;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, pathBytes.length, p);
    p += 4;
    buf.set(pathBytes, p);

    this._requests[reqid] = { cb, type };
    this._sendOrBuffer(buf);
    this._debug?.(`SFTP: Outbound: Sending ${name}`);
  }

  // deno-lint-ignore no-explicit-any
  private _simpleHandle(
    type: number,
    handle: SFTPHandle,
    cb: (...args: any[]) => void,
    name: string,
  ): void {
    const buf = allocBytes(4 + 1 + 4 + 4 + handle.length);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = type;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, handle.length, p);
    p += 4;
    buf.set(handle, p);

    this._requests[reqid] = { cb, type };
    this._sendOrBuffer(buf);
    this._debug?.(`SFTP: Outbound: Sending ${name}`);
  }

  private _pathWithAttrs(
    type: number,
    path: string,
    attrs: InputAttributes | undefined,
    cb: StatusCallback | undefined,
    name: string,
  ): void {
    const result = attrsToBytes(attrs);
    const pathBytes = fromString(path);
    const buf = allocBytes(4 + 1 + 4 + 4 + pathBytes.length + 4 + result.nb);
    let p = 0;

    writeUInt32BE(buf, buf.length - 4, p);
    p += 4;
    buf[p++] = type;
    const reqid = this._nextReqId();
    writeUInt32BE(buf, reqid, p);
    p += 4;

    writeUInt32BE(buf, pathBytes.length, p);
    p += 4;
    buf.set(pathBytes, p);
    p += pathBytes.length;
    writeUInt32BE(buf, result.flags, p);
    p += 4;
    if (result.nb) {
      buf.set(getAttrBytes(result.nb), p);
    }

    this._requests[reqid] = { cb: cb || (() => {}) };
    this._sendOrBuffer(buf);
    this._debug?.(`SFTP: Outbound: Sending ${name}`);
  }

  private _sendOrBuffer(data: Uint8Array | readonly Uint8Array[]): boolean {
    const parts = data instanceof Uint8Array ? [data] : data;
    const payload: OutboundPayload = {
      length: parts.reduce((total, part) => total + part.length, 0),
      offset: 0,
      parts,
    };
    const ret = this._tryWritePayload(payload);
    if (ret !== undefined) {
      this._buffer.push(ret);
      return false;
    }
    return true;
  }

  private _tryWritePayload(payload: OutboundPayload): OutboundPayload | undefined {
    if (this.outgoing.state !== 'open') return undefined;

    if (this.outgoing.window === 0) {
      this._waitWindow = true;
      this._chunkcb = this._drainBuffer.bind(this);
      return payload;
    }

    let ret: OutboundPayload | undefined;
    let p = payload.offset;

    while (payload.length - p > 0 && this.outgoing.window > 0) {
      const actualLen = Math.min(
        payload.length - p,
        this.outgoing.window,
        this.outgoing.packetSize,
      );
      this.outgoing.window -= actualLen;

      if (this.outgoing.window === 0) {
        this._waitWindow = true;
        this._chunkcb = this._drainBuffer.bind(this);
      }

      const parts = payloadParts(payload, p, actualLen);
      if (this._protocol.channelDataParts) {
        this._protocol.channelDataParts(this.outgoing.id!, parts);
      } else if (parts.length === 1) {
        this._protocol.channelData(this.outgoing.id!, parts[0]);
      } else {
        this._protocol.channelData(this.outgoing.id!, concatBytes(parts));
      }

      p += actualLen;
    }

    if (payload.length - p > 0) {
      ret = p === payload.offset ? payload : { ...payload, offset: p };
    }

    return ret;
  }

  private _drainBuffer(): void {
    this._chunkcb = undefined;
    const buffer = this._buffer;
    let i = 0;

    while (i < buffer.length) {
      const payload = buffer[i];
      const ret = this._tryWritePayload(payload);
      if (ret !== undefined) {
        if (ret !== payload) buffer[i] = ret;
        if (i > 0) this._buffer = buffer.slice(i);
        return;
      }
      ++i;
    }

    if (i > 0) this._buffer = [];
  }

  private _doFatalError(msg: string): void {
    const err = new Error(msg) as Error & { level: string };
    err.level = 'sftp-protocol';
    this._debug?.(`SFTP: Inbound: ${msg}`);
    this.emit('error', err);
    this.destroy();
    this._cleanupRequests();
  }

  private _cleanupRequests(): void {
    const keys = Object.keys(this._requests);
    if (keys.length === 0) return;

    const reqs = this._requests;
    this._requests = {};
    const err = new Error('No response from server') as SFTPError;

    for (const key of keys) {
      const req = reqs[Number(key)];
      if (typeof req.cb === 'function') {
        req.cb(err);
      }
    }
  }

  // ===========================================================================
  // Client Packet Handlers
  // ===========================================================================

  private _handleClientPacket(type: number, payload: Uint8Array): boolean {
    switch (type) {
      case RESPONSE.VERSION:
        return this._handleVersion(payload);
      case RESPONSE.STATUS:
        return this._handleStatus(payload);
      case RESPONSE.HANDLE:
        return this._handleHandle(payload);
      case RESPONSE.DATA:
        return this._handleData(payload);
      case RESPONSE.NAME:
        return this._handleName(payload);
      case RESPONSE.ATTRS:
        return this._handleAttrs(payload);
      default:
        this._doFatalError(`Unknown packet type ${type}`);
        return false;
    }
  }

  private _handleVersion(payload: Uint8Array): boolean {
    if (this._version !== -1) {
      this._doFatalError('Duplicate VERSION packet');
      return false;
    }

    this._parser.init(payload, 1);
    const version = this._parser.readUInt32BE();

    const extensions: SFTPExtensions = {};
    while (this._parser.remaining > 0) {
      const extName = this._parser.readString(true) as string | undefined;
      const extData = this._parser.readString(true) as string | undefined;
      if (extData === undefined) break;
      extensions[extName!] = extData;
    }
    this._parser.clear();

    if (version === undefined) {
      this._doFatalError('Malformed VERSION packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received VERSION (v${version})`);

    this._version = version;
    this._extensions = extensions;
    this.emit('ready');
    return true;
  }

  private _handleStatus(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const errorCode = this._parser.readUInt32BE();
    const errorMsg = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    this._debug?.(`SFTP: Inbound: Received STATUS (id:${reqId}, ${errorCode})`);

    const req = this._requests[reqId!];
    delete this._requests[reqId!];

    if (req && typeof req.cb === 'function') {
      if (errorCode === STATUS_CODE.OK) {
        req.cb(null);
      } else {
        const err = new Error(
          errorMsg || STATUS_CODE_STR[errorCode as keyof typeof STATUS_CODE_STR] ||
            'Unknown status',
        ) as Error & { code: number };
        err.code = errorCode!;
        req.cb(err);
      }
    }
    return true;
  }

  private _handleHandle(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const handle = this._parser.readString(false) as Uint8Array | undefined;
    this._parser.clear();

    if (handle === undefined) {
      this._doFatalError('Malformed HANDLE packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received HANDLE (id:${reqId})`);

    const req = this._requests[reqId!];
    delete this._requests[reqId!];

    if (req && typeof req.cb === 'function') {
      req.cb(null, handle);
    }
    return true;
  }

  private _handleData(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const data = this._parser.readString(false) as Uint8Array | undefined;
    this._parser.clear();

    if (data === undefined) {
      this._doFatalError('Malformed DATA packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received DATA (id:${reqId}, ${data.length} bytes)`);

    const req = this._requests[reqId!] as PendingRequest & { buffer?: Uint8Array };
    delete this._requests[reqId!];

    if (req && typeof req.cb === 'function') {
      if (req.buffer) {
        req.buffer.set(data);
      }
      req.cb(null, data.length, data, 0);
    }
    return true;
  }

  private _handleName(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const count = this._parser.readUInt32BE();

    if (count === undefined) {
      this._parser.clear();
      this._doFatalError('Malformed NAME packet');
      return false;
    }

    const entries: DirEntry[] = [];
    for (let i = 0; i < count; i++) {
      const filename = this._parser.readString(true) as string | undefined;
      const longname = this._parser.readString(true) as string | undefined;
      const attrs = this._parser.readAttrs(this._biOpt);

      if (attrs === undefined) {
        this._parser.clear();
        this._doFatalError('Malformed NAME packet');
        return false;
      }

      entries.push({
        filename: filename!,
        longname: longname!,
        attrs,
      });
    }
    this._parser.clear();

    this._debug?.(`SFTP: Inbound: Received NAME (id:${reqId}, ${count} entries)`);

    const req = this._requests[reqId!];
    delete this._requests[reqId!];

    if (req && typeof req.cb === 'function') {
      // READDIR answers a list, however long; REALPATH and READLINK one path.
      // Deciding by the entry count instead handed readdir of a one-entry
      // directory the filename string.
      if (req.type === REQUEST.READDIR) {
        req.cb(null, entries);
      } else {
        req.cb(null, entries[0]?.filename, entries);
      }
    }
    return true;
  }

  private _handleAttrs(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const attrs = this._parser.readAttrs(this._biOpt);
    this._parser.clear();

    if (attrs === undefined) {
      this._doFatalError('Malformed ATTRS packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received ATTRS (id:${reqId})`);

    const req = this._requests[reqId!];
    delete this._requests[reqId!];

    if (req && typeof req.cb === 'function') {
      req.cb(null, new Stats(attrs));
    }
    return true;
  }

  // ===========================================================================
  // Server Packet Handlers
  // ===========================================================================

  private _handleServerPacket(type: number, payload: Uint8Array): boolean {
    switch (type) {
      case REQUEST.INIT:
        return this._handleInit(payload);
      case REQUEST.OPEN:
        return this._handleOpen(payload);
      case REQUEST.CLOSE:
        return this._handleClose(payload);
      case REQUEST.READ:
        return this._handleRead(payload);
      case REQUEST.WRITE:
        return this._handleWrite(payload);
      case REQUEST.LSTAT:
        return this._handleLstat(payload);
      case REQUEST.FSTAT:
        return this._handleFstat(payload);
      case REQUEST.SETSTAT:
        return this._handleSetstat(payload);
      case REQUEST.FSETSTAT:
        return this._handleFsetstat(payload);
      case REQUEST.OPENDIR:
        return this._handleOpendir(payload);
      case REQUEST.READDIR:
        return this._handleReaddir(payload);
      case REQUEST.REMOVE:
        return this._handleRemove(payload);
      case REQUEST.MKDIR:
        return this._handleMkdir(payload);
      case REQUEST.RMDIR:
        return this._handleRmdir(payload);
      case REQUEST.REALPATH:
        return this._handleRealpath(payload);
      case REQUEST.STAT:
        return this._handleStat(payload);
      case REQUEST.RENAME:
        return this._handleRename(payload);
      case REQUEST.READLINK:
        return this._handleReadlink(payload);
      case REQUEST.SYMLINK:
        return this._handleSymlink(payload);
      case REQUEST.EXTENDED:
        return this._handleExtended(payload);
      default:
        return this._handleUnknownRequest(type, payload);
    }
  }

  /**
   * EXTENDED carries its extension's name first; the rest of the payload is
   * the extension's own. Emitted as `EXTENDED(reqId, name, data)`, so with no
   * listener it is answered OP_UNSUPPORTED like any other unhandled request.
   */
  private _handleExtended(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const name = this._parser.readString(true) as string | undefined;
    const pos = this._parser.pos;
    this._parser.clear();

    if (name === undefined) {
      this._doFatalError('Malformed EXTENDED packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received EXTENDED ${name} (id:${reqId})`);
    return this._emitServerRequest('EXTENDED', reqId!, name, payload.subarray(pos));
  }

  /**
   * A request type this server does not know. Every request carries an id, so
   * it can be answered OP_UNSUPPORTED as the protocol draft asks, instead of
   * ending the whole session over one request.
   */
  private _handleUnknownRequest(type: number, payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    this._parser.clear();

    if (reqId === undefined) {
      this._doFatalError(`Unknown packet type ${type}`);
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received unknown request type ${type} (id:${reqId})`);
    this.status(reqId, STATUS_CODE.OP_UNSUPPORTED);
    return true;
  }

  private _handleInit(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const version = this._parser.readUInt32BE();
    this._parser.clear();

    if (version === undefined) {
      this._doFatalError('Malformed INIT packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received INIT (v${version})`);

    this._version = Math.min(version, 3); // We support up to version 3
    this._sendOrBuffer(this._versionPacket());
    this.emit('ready');
    return true;
  }

  /** VERSION v3, followed by the advertised extensions */
  private _versionPacket(): Uint8Array {
    const pairs = Object.entries(this._extensions).flat().map(fromString);
    if (!pairs.length) return SERVER_VERSION_BUFFER;

    const buf = allocBytes(
      SERVER_VERSION_BUFFER.length + pairs.reduce((n, b) => n + 4 + b.length, 0),
    );
    buf.set(SERVER_VERSION_BUFFER);
    writeUInt32BE(buf, buf.length - 4, 0);
    let p = SERVER_VERSION_BUFFER.length;
    for (const bytes of pairs) {
      writeUInt32BE(buf, bytes.length, p);
      p += 4;
      buf.set(bytes, p);
      p += bytes.length;
    }
    return buf;
  }

  private _emitServerRequest(name: string, reqId: number, ...args: unknown[]): boolean {
    // Nobody would ever answer a request without a listener, and the client
    // would wait for it forever.
    if (this.listenerCount(name) === 0) {
      this.status(reqId, STATUS_CODE.OP_UNSUPPORTED);
      return true;
    }
    this.emit(name, reqId, ...args);
    return true;
  }

  private _handleOpen(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const filename = this._parser.readString(true) as string | undefined;
    const flags = this._parser.readUInt32BE();
    const attrs = this._parser.readAttrs(this._biOpt);
    this._parser.clear();

    if (attrs === undefined) {
      this._doFatalError('Malformed OPEN packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received OPEN (id:${reqId})`);
    return this._emitServerRequest('OPEN', reqId!, filename, flags, attrs);
  }

  private _handleClose(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const handle = this._parser.readString(false) as Uint8Array | undefined;
    this._parser.clear();

    if (handle === undefined) {
      this._doFatalError('Malformed CLOSE packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received CLOSE (id:${reqId})`);
    return this._emitServerRequest('CLOSE', reqId!, handle);
  }

  private _handleRead(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const handle = this._parser.readString(false) as Uint8Array | undefined;
    const offset = this._parser.readUInt64BE(this._biOpt);
    const length = this._parser.readUInt32BE();
    this._parser.clear();

    if (length === undefined) {
      this._doFatalError('Malformed READ packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received READ (id:${reqId})`);
    return this._emitServerRequest('READ', reqId!, handle, offset, length);
  }

  private _handleWrite(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const handle = this._parser.readString(false) as Uint8Array | undefined;
    const offset = this._parser.readUInt64BE(this._biOpt);
    const data = this._parser.readString(false) as Uint8Array | undefined;
    this._parser.clear();

    if (data === undefined) {
      this._doFatalError('Malformed WRITE packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received WRITE (id:${reqId})`);
    return this._emitServerRequest('WRITE', reqId!, handle, offset, data);
  }

  private _handleLstat(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (path === undefined) {
      this._doFatalError('Malformed LSTAT packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received LSTAT (id:${reqId})`);
    return this._emitServerRequest('LSTAT', reqId!, path);
  }

  private _handleFstat(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const handle = this._parser.readString(false) as Uint8Array | undefined;
    this._parser.clear();

    if (handle === undefined) {
      this._doFatalError('Malformed FSTAT packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received FSTAT (id:${reqId})`);
    return this._emitServerRequest('FSTAT', reqId!, handle);
  }

  private _handleSetstat(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    const attrs = this._parser.readAttrs(this._biOpt);
    this._parser.clear();

    if (attrs === undefined) {
      this._doFatalError('Malformed SETSTAT packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received SETSTAT (id:${reqId})`);
    return this._emitServerRequest('SETSTAT', reqId!, path, attrs);
  }

  private _handleFsetstat(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const handle = this._parser.readString(false) as Uint8Array | undefined;
    const attrs = this._parser.readAttrs(this._biOpt);
    this._parser.clear();

    if (attrs === undefined) {
      this._doFatalError('Malformed FSETSTAT packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received FSETSTAT (id:${reqId})`);
    return this._emitServerRequest('FSETSTAT', reqId!, handle, attrs);
  }

  private _handleOpendir(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (path === undefined) {
      this._doFatalError('Malformed OPENDIR packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received OPENDIR (id:${reqId})`);
    return this._emitServerRequest('OPENDIR', reqId!, path);
  }

  private _handleReaddir(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const handle = this._parser.readString(false) as Uint8Array | undefined;
    this._parser.clear();

    if (handle === undefined) {
      this._doFatalError('Malformed READDIR packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received READDIR (id:${reqId})`);
    return this._emitServerRequest('READDIR', reqId!, handle);
  }

  private _handleRemove(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (path === undefined) {
      this._doFatalError('Malformed REMOVE packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received REMOVE (id:${reqId})`);
    return this._emitServerRequest('REMOVE', reqId!, path);
  }

  private _handleMkdir(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    const attrs = this._parser.readAttrs(this._biOpt);
    this._parser.clear();

    if (attrs === undefined) {
      this._doFatalError('Malformed MKDIR packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received MKDIR (id:${reqId})`);
    return this._emitServerRequest('MKDIR', reqId!, path, attrs);
  }

  private _handleRmdir(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (path === undefined) {
      this._doFatalError('Malformed RMDIR packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received RMDIR (id:${reqId})`);
    return this._emitServerRequest('RMDIR', reqId!, path);
  }

  private _handleRealpath(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (path === undefined) {
      this._doFatalError('Malformed REALPATH packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received REALPATH (id:${reqId})`);
    return this._emitServerRequest('REALPATH', reqId!, path);
  }

  private _handleStat(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (path === undefined) {
      this._doFatalError('Malformed STAT packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received STAT (id:${reqId})`);
    return this._emitServerRequest('STAT', reqId!, path);
  }

  private _handleRename(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const oldPath = this._parser.readString(true) as string | undefined;
    const newPath = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (newPath === undefined) {
      this._doFatalError('Malformed RENAME packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received RENAME (id:${reqId})`);
    return this._emitServerRequest('RENAME', reqId!, oldPath, newPath);
  }

  private _handleReadlink(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const path = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (path === undefined) {
      this._doFatalError('Malformed READLINK packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received READLINK (id:${reqId})`);
    return this._emitServerRequest('READLINK', reqId!, path);
  }

  private _handleSymlink(payload: Uint8Array): boolean {
    this._parser.init(payload, 1);
    const reqId = this._parser.readUInt32BE();
    const linkPath = this._parser.readString(true) as string | undefined;
    const targetPath = this._parser.readString(true) as string | undefined;
    this._parser.clear();

    if (targetPath === undefined) {
      this._doFatalError('Malformed SYMLINK packet');
      return false;
    }

    this._debug?.(`SFTP: Inbound: Received SYMLINK (id:${reqId})`);
    // Note: OpenSSH has arguments reversed
    return this._emitServerRequest('SYMLINK', reqId!, targetPath, linkPath);
  }
}
