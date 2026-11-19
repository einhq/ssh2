/**
 * SSH2 - SSH2 client and server modules for Deno
 *
 * This is a TypeScript port of the ssh2 library, using Web-standard APIs.
 *
 * @module
 */

// ─── Core client / server ────────────────────────────────────────────────────
export * from './src/client.ts';
export * from './src/server.ts';

// ─── Key generation ──────────────────────────────────────────────────────────
export * from './src/keygen.ts';

// ─── SSH agent ───────────────────────────────────────────────────────────────
export * from './src/agent.ts';

// ─── Key parsing ─────────────────────────────────────────────────────────────
export {
  isParsedKey,
  isSupportedKeyType,
  parseDERKey,
  parseKey,
} from './src/protocol/keyParser.ts';
export type { ParsedKey } from './src/protocol/keyParser.ts';

// ─── Channel (public surface only) ───────────────────────────────────────────
// windowAdjust, MAX_WINDOW, PACKET_SIZE, WINDOW_THRESHOLD are internal.
export { Channel } from './src/Channel.ts';
export type {
  ChannelClient,
  ChannelEndpoint,
  ChannelEvents,
  ChannelInfo,
  ChannelOptions,
  ChannelProtocol,
  ChannelState,
  ExitInfo,
  StderrWritable,
} from './src/Channel.ts';

// ─── Algorithm helpers ───────────────────────────────────────────────────────
export { generateAlgorithmList } from './src/utils.ts';
export type { AlgorithmListOptions } from './src/utils.ts';

// ─── Protocol constants (user-facing) ────────────────────────────────────────
// Intentionally excludes internal details: MESSAGE, COMPAT/COMPAT_CHECKS,
// CIPHER_INFO/MAC_INFO, DISCONNECT_REASON_BY_VALUE.
export {
  CHANNEL_EXTENDED_DATATYPE,
  CHANNEL_OPEN_FAILURE,
  curve25519Supported,
  DEFAULT_CIPHER,
  DEFAULT_COMPRESSION,
  DEFAULT_KEX,
  DEFAULT_MAC,
  DEFAULT_SERVER_HOST_KEY,
  DISCONNECT_REASON,
  eddsaSupported,
  SIGNALS,
  SUPPORTED_CIPHER,
  SUPPORTED_COMPRESSION,
  SUPPORTED_KEX,
  SUPPORTED_MAC,
  SUPPORTED_SERVER_HOST_KEY,
  TERMINAL_MODE,
} from './src/protocol/constants.ts';
export type {
  ChannelOpenFailure,
  DisconnectReason,
  TerminalMode,
} from './src/protocol/constants.ts';

// ─── SFTP ─────────────────────────────────────────────────────────────────────
export { MAX_SERVER_BUFFERED, SFTP } from './src/protocol/sftp/SFTP.ts';
export type { SFTPClient } from './src/protocol/sftp/SFTP.ts';
export type { SFTPConfig } from './src/protocol/sftp/types.ts';
export { OPEN_MODE, STATUS_CODE, STATUS_CODE_STR } from './src/protocol/sftp/constants.ts';
export { Stats as SFTPStats } from './src/protocol/sftp/Stats.ts';
export type {
  FileAttributes,
  InputAttributes,
  SFTPExtensions,
  SFTPHandle,
} from './src/protocol/sftp/types.ts';
export { ReadStream, WriteStream } from './src/protocol/sftp/streams.ts';

// ─── Namespaced internals (for advanced / low-level use) ─────────────────────
export * as crypto from './src/crypto/mod.ts';
export * as adapters from './src/adapters/mod.ts';
