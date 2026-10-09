/**
 * SFTP Type Definitions
 */

import type { StatusCode } from './constants.ts';

/**
 * Extended attribute for file metadata
 */
export interface ExtendedAttribute {
  type: string;
  data: Uint8Array;
}

/**
 * File attributes structure used in SFTP protocol
 */
export interface FileAttributes {
  mode?: number;
  uid?: number;
  gid?: number;
  size?: number | bigint;
  atime?: number | Date;
  mtime?: number | Date;
  extended?: ExtendedAttribute[];
}

/**
 * Input attributes - allows string mode (octal)
 */
export interface InputAttributes {
  mode?: number | string;
  uid?: number;
  gid?: number;
  size?: number | bigint;
  atime?: number | Date;
  mtime?: number | Date;
}

/**
 * Opaque file handle returned by open/opendir
 */
export type SFTPHandle = Uint8Array;

/**
 * Directory entry from readdir
 */
export interface DirEntry {
  filename: string;
  longname: string;
  attrs: FileAttributes;
}

/**
 * Name entry for server NAME response (fields optional for convenience)
 */
export interface NameEntry {
  filename: string;
  longname?: string;
  attrs?: FileAttributes;
}

/**
 * SFTP configuration options
 */
export interface SFTPConfig {
  /** Server mode (vs client mode) */
  server?: boolean;
  /** Debug logging function */
  debug?: (msg: string) => void;
  /** Use BigInt for 64-bit values */
  biOpt?: boolean;
  /**
   * Server mode: extensions advertised in VERSION, name to data (OpenSSH's
   * `posix-rename@openssh.com` is `'1'`). Their requests arrive as `EXTENDED`.
   */
  extensions?: SFTPExtensions;
}

/**
 * Transfer progress callback
 */
export interface TransferProgress {
  /** Total bytes to transfer */
  total: number | bigint;
  /** Bytes transferred so far */
  transferred: number | bigint;
  /** Current chunk size */
  chunk: number;
}

/**
 * Options for fastGet/fastPut
 */
export interface TransferOptions {
  /** Number of concurrent requests (default: 64) */
  concurrency?: number;
  /** Size of each chunk in bytes (default: 32768) */
  chunkSize?: number;
  /** Progress callback */
  step?: (progress: TransferProgress) => void;
  /** File mode for new files */
  mode?: number | string;
}

/**
 * Options for createReadStream
 */
export interface ReadStreamOptions {
  /** File flags (default: 'r') */
  flags?: string | number;
  /** File mode */
  mode?: number;
  /** Start position */
  start?: number;
  /** End position */
  end?: number;
  /** Auto close handle on end/error (default: true) */
  autoClose?: boolean;
  /** Existing file handle */
  handle?: SFTPHandle;
  /** High water mark for buffering */
  highWaterMark?: number;
}

/**
 * Options for createWriteStream
 */
export interface WriteStreamOptions {
  /** File flags (default: 'w') */
  flags?: string | number;
  /** File mode (default: 0o666) */
  mode?: number;
  /** Start position */
  start?: number;
  /** Auto close handle on end/error (default: true) */
  autoClose?: boolean;
  /** Existing file handle */
  handle?: SFTPHandle;
  /** High water mark for buffering */
  highWaterMark?: number;
}

/**
 * Callback for SFTP operations returning status
 */
export type StatusCallback = (err: SFTPError | null) => void;

/**
 * Callback for SFTP operations returning a handle
 */
export type HandleCallback = (err: SFTPError | null, handle?: SFTPHandle) => void;

/**
 * Callback for SFTP operations returning data
 */
export type DataCallback = (
  err: SFTPError | null,
  bytesRead?: number,
  buffer?: Uint8Array,
  position?: number | bigint,
) => void;

/**
 * Callback for SFTP write operations
 */
export type WriteCallback = (err: SFTPError | null) => void;

/**
 * Callback for SFTP stat operations
 */
export type StatsCallback = (err: SFTPError | null, stats?: FileAttributes) => void;

/**
 * Callback for SFTP readdir operations
 */
export type ReaddirCallback = (err: SFTPError | null, list?: DirEntry[]) => void;

/**
 * Callback for SFTP realpath/readlink operations
 */
export type PathCallback = (err: SFTPError | null, path?: string) => void;

/**
 * Callback for SFTP exists operation
 */
export type ExistsCallback = (exists: boolean) => void;

/**
 * SFTP Error with status code
 */
export class SFTPError extends Error {
  code: StatusCode;
  lang?: string;

  constructor(message: string, code: StatusCode, lang?: string) {
    super(message);
    this.name = 'SFTPError';
    this.code = code;
    this.lang = lang;
  }
}

/**
 * Pending request tracker
 */
export interface PendingRequest {
  // deno-lint-ignore no-explicit-any
  cb: (...args: any[]) => void;
  type?: number;
  buffer?: Uint8Array;
}

/**
 * SFTP protocol extensions
 */
export interface SFTPExtensions {
  [name: string]: string;
}

/**
 * Server request context for OPEN
 */
export interface OpenRequest {
  reqId: number;
  filename: string;
  flags: number;
  attrs: FileAttributes;
}

/**
 * Server request context for READ
 */
export interface ReadRequest {
  reqId: number;
  handle: SFTPHandle;
  offset: number | bigint;
  length: number;
}

/**
 * Server request context for WRITE
 */
export interface WriteRequest {
  reqId: number;
  handle: SFTPHandle;
  offset: number | bigint;
  data: Uint8Array;
}

/**
 * String flag to numeric flag mapping
 */
export const STRING_FLAG_MAP: Record<string, number> = {
  'r': 0x00000001, // READ
  'r+': 0x00000001 | 0x00000002, // READ | WRITE
  'w': 0x00000010 | 0x00000008 | 0x00000002, // TRUNC | CREAT | WRITE
  'wx': 0x00000010 | 0x00000008 | 0x00000002 | 0x00000020, // + EXCL
  'xw': 0x00000010 | 0x00000008 | 0x00000002 | 0x00000020,
  'w+': 0x00000010 | 0x00000008 | 0x00000001 | 0x00000002, // TRUNC | CREAT | READ | WRITE
  'wx+': 0x00000010 | 0x00000008 | 0x00000001 | 0x00000002 | 0x00000020,
  'xw+': 0x00000010 | 0x00000008 | 0x00000001 | 0x00000002 | 0x00000020,
  'a': 0x00000004 | 0x00000008 | 0x00000002, // APPEND | CREAT | WRITE
  'ax': 0x00000004 | 0x00000008 | 0x00000002 | 0x00000020,
  'xa': 0x00000004 | 0x00000008 | 0x00000002 | 0x00000020,
  'a+': 0x00000004 | 0x00000008 | 0x00000001 | 0x00000002, // APPEND | CREAT | READ | WRITE
  'ax+': 0x00000004 | 0x00000008 | 0x00000001 | 0x00000002 | 0x00000020,
  'xa+': 0x00000004 | 0x00000008 | 0x00000001 | 0x00000002 | 0x00000020,
};

/**
 * Convert string flags to numeric flags
 */
export function stringToFlags(str: string): number | null {
  const flags = STRING_FLAG_MAP[str];
  return flags !== undefined ? flags : null;
}

/**
 * Convert numeric flags to string flags
 */
export function flagsToString(flags: number): string | null {
  for (const [key, value] of Object.entries(STRING_FLAG_MAP)) {
    if (value === flags) return key;
  }
  return null;
}
