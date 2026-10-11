/**
 * SSH Protocol Handler
 *
 * Main protocol state machine for SSH communication.
 * Handles parsing, packet assembly, encryption, and message routing.
 */

import type { AgentContext } from '../agent.ts';
import {
  type Cipher as CipherType,
  createCipher,
  createDecipher,
  type Decipher as DecipherType,
  NullCipher as CipherNullCipher,
  NullDecipher as CipherNullDecipher,
} from '../crypto/ciphers.ts';
import { Ber, BerWriter } from '../utils/ber.ts';
import {
  allocBytes,
  concatBytes,
  fromString,
  readUInt32BE,
  toUtf8,
  writeUInt32BE,
} from '../utils/binary.ts';
import { EventEmitter } from '../utils/events.ts';
import {
  CIPHER_INFO,
  COMPAT_CHECKS,
  DISCONNECT_REASON,
  MAC_INFO,
  MESSAGE,
  SUPPORTED_SERVER_HOST_KEY,
} from './constants.ts';
import { type HandlerProtocol, MESSAGE_HANDLERS, type ProtocolHandlers } from './handlers.ts';
import {
  createDefaultOffer,
  type KexAlgorithms,
  KexHandler,
  type NegotiatedAlgorithms,
  type SessionKeys,
} from './kex.ts';
import type { ParsedKey } from './keyParser.ts';
import type { FatalErrorProtocol } from './utils.ts';
import { PacketReader, PacketWriter, ZlibCompressor, ZlibDecompressor } from './zlib.ts';

const MODULE_VER = '2.0.0';
const IDENT_RAW = fromString(`SSH-2.0-ssh2ts${MODULE_VER}`);
const PING_PAYLOAD = new Uint8Array([
  MESSAGE.GLOBAL_REQUEST,
  // "keepalive@openssh.com"
  0,
  0,
  0,
  21,
  107,
  101,
  101,
  112,
  97,
  108,
  105,
  118,
  101,
  64,
  111,
  112,
  101,
  110,
  115,
  115,
  104,
  46,
  99,
  111,
  109,
  // Request a reply
  1,
]);

const VALID_DISCONNECT_REASONS = new Set<number>(
  Object.values(DISCONNECT_REASON).filter((v) => typeof v === 'number') as number[],
);

/**
 * Protocol configuration
 */
export interface ProtocolConfig {
  server?: boolean;
  onWrite: (data: Uint8Array) => void;
  onError: (err: Error) => void;
  debug?: (msg: string) => void;
  onHeader?: (header: ProtocolHeader) => void;
  onPacket?: () => void;
  onHandshakeComplete?: (algorithms?: NegotiatedAlgorithms) => void;
  messageHandlers?: ProtocolHandlers;
  offer?: KexAlgorithms;
  ident?: string | Uint8Array;
  hostKeys?: HostKeyInfo[];
  hostVerifier?: (key: Uint8Array) => boolean | Promise<boolean>;
  greeting?: string;
  banner?: string;
}

/**
 * Host key information
 */
export interface HostKeyInfo {
  type: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Protocol header from version exchange
 */
export interface ProtocolHeader {
  identRaw: Uint8Array;
  greeting?: string;
  versions: {
    protocol: string;
    software: string;
  };
  comments?: string;
}

/**
 * Cipher interface for packet encryption (re-export from ciphers.ts)
 */
export type Cipher = CipherType;

/**
 * Decipher interface for packet decryption (re-export from ciphers.ts)
 */
export type Decipher = DecipherType;

type SegmentedPayload = {
  length: number;
  parts: readonly Uint8Array[];
};

type OutboundPayload = Uint8Array | SegmentedPayload;

/**
 * Main SSH Protocol class
 */
export class Protocol extends EventEmitter implements FatalErrorProtocol, HandlerProtocol {
  // Configuration
  private _server: boolean;
  _debug?: (msg: string) => void;
  private _onWrite: (data: Uint8Array) => void;
  _onError?: (err: Error) => void;
  private _onHeader?: (header: ProtocolHeader) => void;
  private _onPacket?: () => void;
  private _onHandshakeComplete?: (algorithms?: NegotiatedAlgorithms) => void;
  private _hostVerifier?: (key: Uint8Array) => boolean | Promise<boolean>;

  // State
  private _parse: (
    chunk: Uint8Array,
    i: number,
    len: number,
  ) => number;
  private _parseMode: 'header' | 'packet' = 'header';
  private _buffer: Uint8Array | undefined;
  private _identRaw: Uint8Array;
  private _remoteIdentRaw: Uint8Array | undefined;
  _authsQueue: string[] = [];
  _compatFlags = 0;
  // Packets held back from our KEXINIT until our NEWKEYS is out and the new
  // outbound cipher is in place
  private _queue: OutboundPayload[] | undefined;
  private _banner: string | undefined;
  private _hostKeys: HostKeyInfo[] | undefined;

  // Key exchange
  private _kexHandler: KexHandler;
  private _offer: KexAlgorithms;
  private _kexinit: Uint8Array | undefined;
  _kex: { sessionID: Uint8Array } = { sessionID: new Uint8Array(0) };
  private _strictKex = false; // RFC 9700 strict KEX mode
  private _firstKexComplete = false; // set once the first NEWKEYS is processed
  private _peerExtInfo = false; // peer offered ext-info-c/-s in its first KEXINIT (RFC 8308)
  private _extInfoSent = false;
  private _kexInitPromise: Promise<void> | undefined; // Promise for key exchange initialization

  // Encryption
  _cipher: Cipher;
  private _decipher: Decipher | undefined;
  private _sessionKeys: SessionKeys | undefined;

  // Async parsing state - ensures only one parse operation runs at a time
  private _parsingPromise: Promise<void> | undefined;

  // Compression is stateful and stays serialized here. Ciphers reserve their
  // own sequence/IV and ordered transport slots synchronously, so independent
  // async encryptions can remain in flight without reordering their writes.
  private _outboundPackets: OutboundPayload[] = [];
  private _sendingPacket = false;
  private _packetDrainPromise: Promise<void> = Promise.resolve();
  private _pendingEncryptions = new Set<Promise<void>>();

  // Packet read/write
  private _packetRW: {
    read: PacketReader;
    write: PacketWriter;
  };

  // Compression state
  private _compress = false;
  private _decompress = false;
  private _compressor: ZlibCompressor | undefined;
  private _decompressor: ZlibDecompressor | undefined;

  // Handler callbacks
  _handlers: ProtocolHandlers;

  // Greeting for server (outbound)
  private _greeting: string | undefined;
  // Collected greeting lines from remote (inbound)
  private _receivedGreeting: string[] = [];
  private _sentIdent: Uint8Array;

  // Public start function
  start: (() => void) | undefined;

  constructor(config: ProtocolConfig) {
    super();

    this._server = !!config.server;
    this._onWrite = config.onWrite;
    this._onError = config.onError;
    this._debug = config.debug;
    this._onHeader = config.onHeader;
    this._onPacket = config.onPacket;
    this._onHandshakeComplete = config.onHandshakeComplete;
    this._hostVerifier = config.hostVerifier;
    this._handlers = config.messageHandlers || {};

    // Set up identification string
    if (typeof config.ident === 'string') {
      this._identRaw = fromString(`SSH-2.0-${config.ident}`);
    } else if (config.ident instanceof Uint8Array) {
      this._identRaw = concatBytes([fromString('SSH-2.0-'), config.ident]);
    } else {
      this._identRaw = IDENT_RAW;
    }

    this._sentIdent = concatBytes([this._identRaw, fromString('\r\n')]);

    // Server configuration
    if (this._server) {
      this._hostKeys = config.hostKeys;
      if (config.greeting) {
        this._greeting = config.greeting.endsWith('\r\n')
          ? config.greeting
          : `${config.greeting}\r\n`;
      }
      if (config.banner) {
        this._banner = config.banner.endsWith('\r\n') ? config.banner : `${config.banner}\r\n`;
      }
    }

    // Initialize key exchange
    this._offer = config.offer || createDefaultOffer();
    this._kexHandler = new KexHandler(this._server, this._offer);

    // Initialize ciphers (null cipher for initial handshake)
    this._cipher = new CipherNullCipher(0, this._onWrite);
    this._decipher = new CipherNullDecipher(0, this._onPayload.bind(this));

    // Initialize packet reader/writer
    const protocolRef = {
      _kexinit: this._kexinit,
      _cipher: this._cipher,
    };
    this._packetRW = {
      read: new PacketReader(),
      write: new PacketWriter(protocolRef),
    };

    // Start in header parsing mode
    this._parse = this._parseHeader.bind(this);

    this._debug?.(`Local ident: ${toUtf8(this._identRaw)}`);

    // Set up start function
    this.start = () => {
      this.start = undefined;
      if (this._greeting) {
        this._onWrite(fromString(this._greeting));
      }
      this._onWrite(this._sentIdent);
    };
  }

  /**
   * Clean up resources
   */
  cleanup(): void {
    this._destruct();
  }

  /**
   * Destruct the protocol instance
   */
  _destruct(reason?: string): void {
    this._packetRW.read.cleanup();
    this._packetRW.write.cleanup();
    this._cipher?.free();
    this._decipher?.free();

    if (!reason || reason.length === 0) {
      reason = 'fatal error';
    }

    this.parse = () => {
      throw new Error(`Instance unusable after ${reason}`);
    };
    this._onWrite = () => {
      throw new Error(`Instance unusable after ${reason}`);
    };
  }

  /**
   * Parse incoming data
   * Returns a Promise that resolves when data has been processed
   */
  async parse(chunk: Uint8Array, i = 0, len = chunk.length): Promise<void> {
    this._debug?.(`parse: received ${len - i} bytes, parseMode=${this._parseMode}`);

    // Wait for any pending parsing to complete first
    while (this._parsingPromise) {
      this._debug?.(`parse: waiting for previous parse to complete`);
      await this._parsingPromise;
    }

    // Now process this chunk
    this._debug?.(`parse: starting to process chunk`);
    this._parsingPromise = this._processChunk(chunk, i, len);
    try {
      await this._parsingPromise;
    } finally {
      this._parsingPromise = undefined;
    }
  }

  /**
   * Process a single chunk of data
   */
  private async _processChunk(chunk: Uint8Array, i: number, len: number): Promise<void> {
    while (i < len) {
      const before = i;
      // Check if we're in packet parsing mode (which is async)
      if (this._parseMode === 'packet') {
        i = await this._parsePacketAsync(chunk, i, len);
      } else {
        i = this._parse(chunk, i, len);
      }
      this._debug?.(`parse: processed ${i - before} bytes, position ${before} -> ${i}`);
    }
  }

  /**
   * Parse the SSH identification header
   */
  private _parseHeader(
    chunk: Uint8Array,
    i: number,
    len: number,
  ): number {
    // Look for the SSH version line (SSH-2.0-...)
    let lineEnd = -1;
    for (let j = i; j < len; j++) {
      if (chunk[j] === 10) {
        // '\n'
        lineEnd = j;
        break;
      }
    }

    if (lineEnd === -1) {
      // Incomplete line, buffer it
      if (this._buffer) {
        this._buffer = concatBytes([this._buffer, chunk.subarray(i, len)]);
      } else {
        this._buffer = chunk.subarray(i, len);
      }
      return len;
    }

    let line: Uint8Array;
    if (this._buffer) {
      line = concatBytes([this._buffer, chunk.subarray(i, lineEnd)]);
      this._buffer = undefined;
    } else {
      line = chunk.subarray(i, lineEnd);
    }

    // Remove trailing \r if present
    if (line[line.length - 1] === 13) {
      line = line.subarray(0, line.length - 1);
    }

    const lineStr = toUtf8(line);

    // Check for SSH-2.0 identifier
    if (lineStr.startsWith('SSH-2.0-') || lineStr.startsWith('SSH-1.99-')) {
      this._remoteIdentRaw = line;
      this._debug?.(`Remote ident: ${lineStr}`);

      // Parse the header
      const parts = lineStr.split(' ');
      const protoSoft = parts[0].split('-');
      const header: ProtocolHeader = {
        identRaw: line,
        versions: {
          protocol: protoSoft[1],
          software: protoSoft.slice(2).join('-'),
        },
        comments: parts.slice(1).join(' ') || undefined,
        // Include any greeting lines received before the SSH ident
        greeting: this._receivedGreeting.length > 0 ? this._receivedGreeting.join('\n') : undefined,
      };

      // Check compatibility flags
      this._checkCompat(lineStr);

      // Set version strings for key exchange
      if (this._server) {
        this._kexHandler.setVersions(lineStr, toUtf8(this._identRaw));
      } else {
        this._kexHandler.setVersions(toUtf8(this._identRaw), lineStr);
      }

      // Notify header callback
      this._onHeader?.(header);

      // Switch to packet parsing mode
      this._parse = this._parsePacket.bind(this);
      this._parseMode = 'packet';

      // Start key exchange
      this._sendKexInit();

      return lineEnd + 1;
    }

    // Not the SSH header line - this is a greeting line, collect it
    this._receivedGreeting.push(lineStr);
    this._debug?.(`Received greeting line: ${lineStr}`);
    return lineEnd + 1;
  }

  /**
   * Check for SSH compatibility flags based on remote ident
   */
  private _checkCompat(ident: string): void {
    for (const [pattern, flags] of COMPAT_CHECKS) {
      let matches = false;
      if (pattern instanceof RegExp) {
        matches = pattern.test(ident);
      } else {
        matches = ident.includes(pattern);
      }
      if (matches) {
        this._compatFlags |= flags;
      }
    }
  }

  /**
   * Parse SSH packets (synchronous wrapper, kept for compatibility)
   */
  private _parsePacket(
    _chunk: Uint8Array,
    _i: number,
    len: number,
  ): number {
    // This should not be called directly anymore - use _parsePacketAsync
    this._debug?.(`_parsePacket: WARNING - sync version called, use _parsePacketAsync`);
    return len;
  }

  /**
   * Parse SSH packets asynchronously
   * This ensures we wait for decryption before processing more data
   */
  private async _parsePacketAsync(
    chunk: Uint8Array,
    i: number,
    len: number,
  ): Promise<number> {
    if (!this._decipher) {
      this._debug?.(`_parsePacketAsync: no decipher!`);
      return len;
    }

    this._debug?.(`_parsePacketAsync: decrypting ${len - i} bytes from position ${i}`);

    try {
      // Pass data to decipher for decryption and parsing
      // The decipher calls _onPayload internally for each complete packet
      // If decrypt returns a position (number), it means the decipher stopped early
      // (e.g., after NEWKEYS) and remaining bytes need the new cipher
      const result = await this._decipher.decrypt(chunk, i, len);

      if (typeof result === 'number' && result < len) {
        // Decipher stopped early, save remaining bytes for new decipher
        this._debug?.(
          `_parsePacketAsync: decipher stopped at position ${result}, saving ${
            len - result
          } remaining bytes`,
        );
        // Process remaining data with the new decipher
        await this._processPendingDataAsync(chunk, result, len);
      }
    } catch (err) {
      this._debug?.(`_parsePacketAsync: decrypt error: ${(err as Error).message}`);
      this._onError?.(err as Error);
    }

    return len;
  }

  /**
   * Process remaining data after cipher switch
   */
  private async _processPendingDataAsync(
    chunk: Uint8Array,
    start: number,
    end: number,
  ): Promise<void> {
    if (!this._decipher) {
      return;
    }
    this._debug?.(`_processPendingDataAsync: processing ${end - start} bytes with new decipher`);
    try {
      await this._decipher.decrypt(chunk, start, end);
    } catch (err) {
      this._debug?.(`_processPendingDataAsync: decrypt error: ${(err as Error).message}`);
      this._onError?.(err as Error);
    }
  }

  /**
   * Handle a decrypted payload
   * Returns false to signal the decipher to stop processing (used for cipher switch)
   */
  private async _onPayload(payload: Uint8Array): Promise<void | boolean> {
    if (payload.length === 0) {
      return;
    }

    // Decompress if enabled
    let data = payload;
    if (this._decompress && this._decompressor) {
      data = await this._decompressor.decompressAsync(payload);
    }

    const type = data[0];

    this._debug?.(`Inbound: Received packet type ${type}`);
    this._onPacket?.();

    // Handle key exchange messages
    if (type >= 20 && type <= 49) {
      const stopProcessing = await this._handleKexMessage(type, data);
      if (stopProcessing) {
        // Return false to signal the decipher to stop processing
        // This happens after NEWKEYS when we need to switch ciphers
        return false;
      }
      return;
    }

    // Strict KEX (RFC 9700 / Terrapin, CVE-2023-48795): during the initial key
    // exchange (before the first NEWKEYS) only KEX messages (20-49) are allowed.
    // Any other transport message here (IGNORE/DEBUG/UNIMPLEMENTED/EXT_INFO/...)
    // is an injection attempt and must abort the connection. Combined with the
    // post-NEWKEYS sequence-number reset, this closes the Terrapin attack.
    if (this._strictKex && !this._firstKexComplete) {
      this._debug?.(`Strict KEX violation: message type ${type} before first NEWKEYS`);
      this.disconnect(DISCONNECT_REASON.KEY_EXCHANGE_FAILED);
      this._onError?.(
        new Error(
          `Strict KEX violation: unexpected message type ${type} during initial key exchange`,
        ),
      );
      return;
    }

    // Look up message handler
    const handler = MESSAGE_HANDLERS[type];
    if (handler) {
      handler(this as unknown as HandlerProtocol, data);
    } else {
      this._debug?.(`Inbound: Unhandled message type ${type}`);
      // Send UNIMPLEMENTED for unknown messages
      this._sendUnimplemented(this._decipher?.inSeqno ?? 0);
    }
  }

  /**
   * Handle key exchange messages
   * Returns true if the decipher should stop processing (after NEWKEYS)
   */
  private async _handleKexMessage(type: number, payload: Uint8Array): Promise<boolean> {
    switch (type) {
      case MESSAGE.KEXINIT:
        this._handleKexInit(payload);
        return false;
      case MESSAGE.NEWKEYS:
        this._handleNewKeys();
        // Return true to signal that the decipher should stop processing
        // Any remaining bytes need to be decrypted with the new cipher
        return true;
      case MESSAGE.KEXECDH_INIT: // Also MESSAGE.KEXDH_INIT (same value: 30)
        // Must await to ensure cipher switch completes before processing more packets
        await this._handleKexEcdhInit(payload);
        return false;
      case MESSAGE.KEXECDH_REPLY: // Also MESSAGE.KEXDH_REPLY (same value: 31)
        // Must await to ensure cipher switch completes before processing more packets
        await this._handleKexEcdhReply(payload);
        return false;
      default:
        this._debug?.(`Inbound: KEX message type ${type} not yet implemented`);
        return false;
    }
  }

  /**
   * Handle KEXINIT message
   */
  private _handleKexInit(payload: Uint8Array): void {
    const result = this._kexHandler.handleKexInit(payload);
    if (result instanceof Error) {
      this._onError?.(result);
      return;
    }

    this._debug?.(`Negotiated algorithms: ${JSON.stringify(result.algorithms)}`);

    // RFC 8308 only honours ext-info-c/-s in the first KEXINIT
    if (!this._firstKexComplete && result.extInfo) {
      this._peerExtInfo = true;
    }

    // Track strict KEX mode (RFC 9700)
    if (result.strictKex) {
      this._strictKex = true;
      this._debug?.('Strict KEX mode enabled');
    }

    // If we haven't sent our KEXINIT yet, send it now
    if (!this._kexinit) {
      this._sendKexInit();
    }

    // Start the key exchange and store the promise so KEXECDH_INIT handler can wait for it
    this._kexInitPromise = this._startKeyExchange();
  }

  /**
   * Handle NEWKEYS message
   */
  private _handleNewKeys(): void {
    this._debug?.('Inbound: Received NEWKEYS');

    // Switch decipher for receiving
    this._switchInboundDecipher();

    // The initial key exchange is now complete; strict-KEX message filtering
    // (see _handlePacket) only applies up to this first NEWKEYS.
    this._firstKexComplete = true;

    // Key exchange is complete
    this._kexinit = undefined;

    // Notify handshake complete
    this._onHandshakeComplete?.(this._kexHandler.state.algorithms);
  }

  /**
   * Start key exchange process
   */
  private async _startKeyExchange(): Promise<void> {
    const result = await this._kexHandler.initKeyExchange();
    if (result instanceof Error) {
      this._onError?.(result);
      return;
    }

    this._debug?.('Key exchange initiated');

    // Client sends KEXECDH_INIT, server waits for it
    if (!this._server) {
      this._sendKexEcdhInit(result.publicKey);
    }
  }

  /**
   * Send KEXECDH_INIT message (client side)
   */
  private _sendKexEcdhInit(publicKey: Uint8Array): void {
    // Format: byte SSH_MSG_KEXECDH_INIT + string Q_C (client public key)
    const payload = allocBytes(1 + 4 + publicKey.length);
    payload[0] = MESSAGE.KEXECDH_INIT;
    writeUInt32BE(payload, publicKey.length, 1);
    payload.set(publicKey, 5);

    this._debug?.('Outbound: Sending KEXECDH_INIT');
    // Force send - key exchange packets must never be queued during rekey
    this._sendPacket(payload, true);
  }

  /**
   * Handle KEXECDH_INIT message (server side)
   */
  private async _handleKexEcdhInit(payload: Uint8Array): Promise<void> {
    if (!this._server) {
      this._onError?.(new Error('Received KEXECDH_INIT as client'));
      return;
    }

    this._debug?.('Inbound: Received KEXECDH_INIT');

    // Wait for key exchange initialization to complete
    // This is needed because KEXINIT and KEXECDH_INIT may arrive in the same TCP packet
    // and _startKeyExchange() from _handleKexInit is async
    if (this._kexInitPromise) {
      await this._kexInitPromise;
      this._kexInitPromise = undefined;
    }

    // Parse client's public key: byte + string Q_C
    if (payload.length < 5) {
      this._onError?.(new Error('Invalid KEXECDH_INIT message'));
      return;
    }

    const clientPubKeyLen = readUInt32BE(payload, 1);
    if (payload.length < 5 + clientPubKeyLen) {
      this._onError?.(new Error('Invalid KEXECDH_INIT: truncated public key'));
      return;
    }

    const clientPublicKey = payload.subarray(5, 5 + clientPubKeyLen);

    // Get our host key
    if (!this._hostKeys || this._hostKeys.length === 0) {
      this._onError?.(new Error('No host keys configured'));
      return;
    }

    const hostKeyInfo = this._hostKeys[0]; // Use first available host key

    // Complete key exchange with client's public key
    const sessionKeys = await this._kexHandler.completeKeyExchange(
      clientPublicKey,
      hostKeyInfo.publicKey,
    );

    if (sessionKeys instanceof Error) {
      this._onError?.(sessionKeys);
      return;
    }

    // Sign the exchange hash with our host key using the negotiated algorithm
    const exchangeHash = this._kexHandler.state.exchangeHash!;
    const negotiatedAlgo = this._kexHandler.state.algorithms!.serverHostKey;
    const signature = await this._signExchangeHash(hostKeyInfo, exchangeHash, negotiatedAlgo);
    if (signature instanceof Error) {
      this._onError?.(signature);
      return;
    }

    // Send KEXECDH_REPLY
    this._sendKexEcdhReply(
      hostKeyInfo.publicKey,
      this._kexHandler.state.exchangeResult!.publicKey,
      signature,
    );

    // Store session ID (first exchange hash)
    if (this._kex.sessionID.length === 0) {
      this._kex.sessionID = exchangeHash;
    }

    // Send NEWKEYS
    await this._sendNewKeys();

    // Store session keys for cipher switching
    this._sessionKeys = sessionKeys;

    // Switch cipher for sending (server to client)
    this._switchOutboundCipher();

    // RFC 8308: a server may send EXT_INFO as the next packet after its first
    // NEWKEYS. server-sig-algs tells the client which signature algorithms user
    // auth accepts, without which a client must sign an RSA key with SHA-1
    // (`ssh-rsa`).
    if (this._peerExtInfo && !this._extInfoSent) {
      this._extInfoSent = true;
      this.sendExtInfo([{ name: 'server-sig-algs', value: SUPPORTED_SERVER_HOST_KEY.join(',') }]);
    }

    this._flushQueue();

    this._debug?.('Server key exchange complete, waiting for client NEWKEYS');
  }

  /**
   * Send KEXECDH_REPLY message (server side)
   */
  private _sendKexEcdhReply(
    hostKey: Uint8Array,
    serverPublicKey: Uint8Array,
    signature: Uint8Array,
  ): void {
    // Format: byte SSH_MSG_KEXECDH_REPLY + string K_S + string Q_S + string sig
    const payloadLen = 1 + 4 + hostKey.length + 4 + serverPublicKey.length + 4 + signature.length;
    const payload = allocBytes(payloadLen);

    let offset = 0;
    payload[offset++] = MESSAGE.KEXECDH_REPLY;

    // K_S (host key)
    writeUInt32BE(payload, hostKey.length, offset);
    offset += 4;
    payload.set(hostKey, offset);
    offset += hostKey.length;

    // Q_S (server public key)
    writeUInt32BE(payload, serverPublicKey.length, offset);
    offset += 4;
    payload.set(serverPublicKey, offset);
    offset += serverPublicKey.length;

    // Signature
    writeUInt32BE(payload, signature.length, offset);
    offset += 4;
    payload.set(signature, offset);

    this._debug?.('Outbound: Sending KEXECDH_REPLY');
    // Force send - key exchange packets must never be queued during rekey
    this._sendPacket(payload, true);
  }

  /**
   * Handle KEXECDH_REPLY message (client side)
   */
  private async _handleKexEcdhReply(payload: Uint8Array): Promise<void> {
    if (this._server) {
      this._onError?.(new Error('Received KEXECDH_REPLY as server'));
      return;
    }

    this._debug?.('Inbound: Received KEXECDH_REPLY');

    // Parse: byte + string K_S + string Q_S + string sig
    let offset = 1;

    if (payload.length < offset + 4) {
      this._onError?.(new Error('Invalid KEXECDH_REPLY: truncated'));
      return;
    }

    // K_S (host key)
    const hostKeyLen = readUInt32BE(payload, offset);
    offset += 4;
    if (payload.length < offset + hostKeyLen) {
      this._onError?.(new Error('Invalid KEXECDH_REPLY: truncated host key'));
      return;
    }
    const hostKey = payload.subarray(offset, offset + hostKeyLen);
    offset += hostKeyLen;

    // Q_S (server public key)
    if (payload.length < offset + 4) {
      this._onError?.(new Error('Invalid KEXECDH_REPLY: truncated'));
      return;
    }
    const serverPubKeyLen = readUInt32BE(payload, offset);
    offset += 4;
    if (payload.length < offset + serverPubKeyLen) {
      this._onError?.(new Error('Invalid KEXECDH_REPLY: truncated server public key'));
      return;
    }
    const serverPublicKey = payload.subarray(offset, offset + serverPubKeyLen);
    offset += serverPubKeyLen;

    // Signature
    if (payload.length < offset + 4) {
      this._onError?.(new Error('Invalid KEXECDH_REPLY: truncated'));
      return;
    }
    const sigLen = readUInt32BE(payload, offset);
    offset += 4;
    if (payload.length < offset + sigLen) {
      this._onError?.(new Error('Invalid KEXECDH_REPLY: truncated signature'));
      return;
    }
    const signature = payload.subarray(offset, offset + sigLen);

    // Verify host key (if verifier is configured)
    if (this._hostVerifier) {
      const verified = await this._hostVerifier(hostKey);
      if (!verified) {
        this._onError?.(new Error('Host key verification failed'));
        return;
      }
    }

    // Complete key exchange with server's public key
    const sessionKeys = await this._kexHandler.completeKeyExchange(serverPublicKey, hostKey);
    if (sessionKeys instanceof Error) {
      this._onError?.(sessionKeys);
      return;
    }

    // Verify signature
    const exchangeHash = this._kexHandler.state.exchangeHash!;
    const negotiatedAlgo = this._kexHandler.state.algorithms?.serverHostKey;
    const verified = await this._verifyExchangeHash(
      hostKey,
      exchangeHash,
      signature,
      negotiatedAlgo,
    );
    if (verified instanceof Error) {
      this._onError?.(verified);
      return;
    }
    if (!verified) {
      this._onError?.(new Error('Exchange hash signature verification failed'));
      return;
    }

    // Store session ID (first exchange hash)
    if (this._kex.sessionID.length === 0) {
      this._kex.sessionID = exchangeHash;
    }

    // Send NEWKEYS
    await this._sendNewKeys();

    // Store session keys for cipher switching
    this._sessionKeys = sessionKeys;

    // Switch cipher for sending (client to server)
    this._switchOutboundCipher();

    this._flushQueue();

    this._debug?.('Client key exchange complete, waiting for server NEWKEYS');
  }

  /**
   * Sign exchange hash with host key
   */
  private async _signExchangeHash(
    hostKey: HostKeyInfo,
    exchangeHash: Uint8Array,
    algorithm: string,
  ): Promise<Uint8Array | Error> {
    try {
      // Import private key and sign
      const keyData = hostKey.privateKey;

      // Parse PEM to get raw key data
      const pemStr = new TextDecoder().decode(keyData);
      const pemMatch = pemStr.match(
        /-----BEGIN ([A-Z ]+) KEY-----\n?([\s\S]+?)\n?-----END ([A-Z ]+) KEY-----/,
      );
      if (!pemMatch) {
        return new Error('Invalid private key PEM format');
      }

      const keyType = pemMatch[1];
      const b64Data = pemMatch[2].replace(/\s/g, '');
      const rawKey = Uint8Array.from(atob(b64Data), (c) => c.charCodeAt(0));

      // Handle Ed25519 keys
      if (algorithm === 'ssh-ed25519' || hostKey.type === 'ssh-ed25519') {
        const privateKey = await crypto.subtle.importKey(
          'pkcs8',
          rawKey as BufferSource,
          { name: 'Ed25519' },
          false,
          ['sign'],
        );

        const sig = await crypto.subtle.sign(
          'Ed25519',
          privateKey,
          exchangeHash as BufferSource,
        );

        // Format signature as SSH string: algorithm name + raw signature
        const sigBytes = new Uint8Array(sig);
        const algoName = fromString('ssh-ed25519');
        const formatted = allocBytes(4 + algoName.length + 4 + sigBytes.length);
        let offset = 0;
        writeUInt32BE(formatted, algoName.length, offset);
        offset += 4;
        formatted.set(algoName, offset);
        offset += algoName.length;
        writeUInt32BE(formatted, sigBytes.length, offset);
        offset += 4;
        formatted.set(sigBytes, offset);

        return formatted;
      }

      // Handle ECDSA keys
      if (algorithm.startsWith('ecdsa-sha2-') || hostKey.type.startsWith('ecdsa-sha2-')) {
        // Determine curve and hash from algorithm
        let namedCurve = 'P-256';
        let hash: AlgorithmIdentifier = 'SHA-256';
        let sigAlgoName = 'ecdsa-sha2-nistp256';
        let sigSize = 32; // Size of r and s for P-256

        if (algorithm.includes('nistp384') || hostKey.type.includes('nistp384')) {
          namedCurve = 'P-384';
          hash = 'SHA-384';
          sigAlgoName = 'ecdsa-sha2-nistp384';
          sigSize = 48;
        } else if (algorithm.includes('nistp521') || hostKey.type.includes('nistp521')) {
          namedCurve = 'P-521';
          hash = 'SHA-512';
          sigAlgoName = 'ecdsa-sha2-nistp521';
          sigSize = 66; // 521 bits = 66 bytes
        }

        const privateKey = await crypto.subtle.importKey(
          'pkcs8',
          rawKey as BufferSource,
          { name: 'ECDSA', namedCurve },
          false,
          ['sign'],
        );

        const sig = await crypto.subtle.sign(
          { name: 'ECDSA', hash },
          privateKey,
          exchangeHash as BufferSource,
        );

        // Convert from WebCrypto format (r||s) to SSH format (mpint r + mpint s)
        const sigBytes = new Uint8Array(sig);
        const r = sigBytes.slice(0, sigSize);
        const s = sigBytes.slice(sigSize);

        // Add leading zero if MSB is set (to make it positive in SSH mpint format)
        const rPad = r[0] >= 0x80 ? 1 : 0;
        const sPad = s[0] >= 0x80 ? 1 : 0;

        const sshSig = allocBytes(4 + rPad + r.length + 4 + sPad + s.length);
        let soff = 0;

        writeUInt32BE(sshSig, rPad + r.length, soff);
        if (rPad) sshSig[soff + 4] = 0;
        sshSig.set(r, soff + 4 + rPad);
        soff += 4 + rPad + r.length;

        writeUInt32BE(sshSig, sPad + s.length, soff);
        if (sPad) sshSig[soff + 4] = 0;
        sshSig.set(s, soff + 4 + sPad);

        // Format outer signature: algorithm name + inner signature
        const algoName = fromString(sigAlgoName);
        const formatted = allocBytes(4 + algoName.length + 4 + sshSig.length);
        let offset = 0;
        writeUInt32BE(formatted, algoName.length, offset);
        offset += 4;
        formatted.set(algoName, offset);
        offset += algoName.length;
        writeUInt32BE(formatted, sshSig.length, offset);
        offset += 4;
        formatted.set(sshSig, offset);

        return formatted;
      }

      if (keyType === 'PRIVATE' || keyType.includes('RSA')) {
        // Determine hash algorithm from negotiated SSH algorithm
        let hash: AlgorithmIdentifier = 'SHA-256';
        let sigAlgoName = 'rsa-sha2-256';
        if (algorithm === 'rsa-sha2-512') {
          hash = 'SHA-512';
          sigAlgoName = 'rsa-sha2-512';
        } else if (algorithm === 'rsa-sha2-256') {
          hash = 'SHA-256';
          sigAlgoName = 'rsa-sha2-256';
        } else if (algorithm === 'ssh-rsa') {
          hash = 'SHA-1';
          sigAlgoName = 'ssh-rsa';
        }

        // RSA key
        const privateKey = await crypto.subtle.importKey(
          'pkcs8',
          rawKey as BufferSource,
          { name: 'RSASSA-PKCS1-v1_5', hash },
          false,
          ['sign'],
        );

        const sig = await crypto.subtle.sign(
          'RSASSA-PKCS1-v1_5',
          privateKey,
          exchangeHash as BufferSource,
        );

        // Format signature as SSH string: algorithm name + raw signature
        const sigBytes = new Uint8Array(sig);
        const algoName = fromString(sigAlgoName);
        const formatted = allocBytes(4 + algoName.length + 4 + sigBytes.length);
        let offset = 0;
        writeUInt32BE(formatted, algoName.length, offset);
        offset += 4;
        formatted.set(algoName, offset);
        offset += algoName.length;
        writeUInt32BE(formatted, sigBytes.length, offset);
        offset += 4;
        formatted.set(sigBytes, offset);

        return formatted;
      }

      return new Error(`Unsupported host key type: ${keyType}`);
    } catch (e) {
      return e as Error;
    }
  }

  /**
   * Verify exchange hash signature
   */
  private async _verifyExchangeHash(
    hostKey: Uint8Array,
    exchangeHash: Uint8Array,
    signature: Uint8Array,
    negotiatedAlgo?: string,
  ): Promise<boolean | Error> {
    try {
      // Parse host key to get type and public key data
      // Host key format: string type + type-specific data
      if (hostKey.length < 4) {
        return new Error('Invalid host key');
      }

      let offset = 0;
      const typeLen = readUInt32BE(hostKey, offset);
      offset += 4;
      const keyType = new TextDecoder().decode(hostKey.subarray(offset, offset + typeLen));
      offset += typeLen;

      // Parse signature: string algo + string sig
      let sigOffset = 0;
      const algoLen = readUInt32BE(signature, sigOffset);
      sigOffset += 4;
      const sigAlgo = new TextDecoder().decode(signature.subarray(sigOffset, sigOffset + algoLen));
      sigOffset += algoLen;

      const rawSigLen = readUInt32BE(signature, sigOffset);
      sigOffset += 4;
      const rawSig = signature.subarray(sigOffset, sigOffset + rawSigLen);

      this._debug?.(`Verifying signature with algo: ${sigAlgo}, key type: ${keyType}`);

      // Bind the signature algorithm to what was negotiated in KEXINIT. Without
      // this a MITM could present, e.g., an ssh-rsa (SHA-1) signature when
      // rsa-sha2-512 was negotiated, silently downgrading the hash.
      if (negotiatedAlgo && sigAlgo !== negotiatedAlgo) {
        return new Error(
          `Host key signature algorithm mismatch: negotiated '${negotiatedAlgo}', got '${sigAlgo}'`,
        );
      }

      if (keyType === 'ssh-rsa' || sigAlgo.startsWith('rsa-sha2')) {
        // Extract RSA public key components (e, n) from host key
        const eLen = readUInt32BE(hostKey, offset);
        offset += 4;
        let e = hostKey.subarray(offset, offset + eLen);
        offset += eLen;

        const nLen = readUInt32BE(hostKey, offset);
        offset += 4;
        let n = hostKey.subarray(offset, offset + nLen);

        // Strip leading zeros from e and n for JWK format
        // SSH format adds leading zeros for positive integers with high bit set,
        // but JWK expects integers without leading zeros
        while (e.length > 1 && e[0] === 0) {
          e = e.subarray(1);
        }
        while (n.length > 1 && n[0] === 0) {
          n = n.subarray(1);
        }

        // Determine hash algorithm
        let hash = 'SHA-1';
        if (sigAlgo === 'rsa-sha2-256') hash = 'SHA-256';
        else if (sigAlgo === 'rsa-sha2-512') hash = 'SHA-512';

        // Build JWK for RSA public key (using base64url encoding)
        const jwk = {
          kty: 'RSA',
          e: btoa(String.fromCharCode(...e)).replace(/\+/g, '-').replace(/\//g, '_').replace(
            /=/g,
            '',
          ),
          n: btoa(String.fromCharCode(...n)).replace(/\+/g, '-').replace(/\//g, '_').replace(
            /=/g,
            '',
          ),
        };

        const publicKey = await crypto.subtle.importKey(
          'jwk',
          jwk,
          { name: 'RSASSA-PKCS1-v1_5', hash },
          false,
          ['verify'],
        );

        return await crypto.subtle.verify(
          'RSASSA-PKCS1-v1_5',
          publicKey,
          rawSig as BufferSource,
          exchangeHash as BufferSource,
        );
      } else if (keyType === 'ssh-ed25519' || sigAlgo === 'ssh-ed25519') {
        // Extract Ed25519 public key (32 bytes) from host key
        const pubLen = readUInt32BE(hostKey, offset);
        offset += 4;
        const rawPub = hostKey.subarray(offset, offset + pubLen);

        if (rawPub.length !== 32) {
          return new Error(`Invalid Ed25519 public key length: ${rawPub.length}`);
        }

        // Build SPKI format for Ed25519:
        // SEQUENCE {
        //   SEQUENCE { OID 1.3.101.112 (Ed25519) }
        //   BIT STRING { 0x00 || raw_public_key }
        // }
        const asnWriter = new BerWriter();
        asnWriter.startSequence();
        // Algorithm identifier
        asnWriter.startSequence();
        asnWriter.writeOID('1.3.101.112'); // id-Ed25519
        asnWriter.endSequence();
        // Public key as BIT STRING
        asnWriter.startSequence(Ber.BitString);
        asnWriter.writeByte(0x00); // No unused bits
        asnWriter._ensure(rawPub.length);
        asnWriter._buf.set(rawPub, asnWriter._offset);
        asnWriter._offset += rawPub.length;
        asnWriter.endSequence();
        asnWriter.endSequence();

        const spkiKey = new Uint8Array(asnWriter.buffer);

        const publicKey = await crypto.subtle.importKey(
          'spki',
          spkiKey as BufferSource,
          { name: 'Ed25519' },
          false,
          ['verify'],
        );

        return await crypto.subtle.verify(
          'Ed25519',
          publicKey,
          rawSig as BufferSource,
          exchangeHash as BufferSource,
        );
      } else if (keyType.startsWith('ecdsa-sha2-')) {
        // Extract ECDSA public key from host key
        // Format: string curve_name + string Q (public point)
        const curveNameLen = readUInt32BE(hostKey, offset);
        offset += 4;
        const curveName = new TextDecoder().decode(hostKey.subarray(offset, offset + curveNameLen));
        offset += curveNameLen;

        const qLen = readUInt32BE(hostKey, offset);
        offset += 4;
        const q = hostKey.subarray(offset, offset + qLen);

        // Map SSH curve name to Web Crypto
        let namedCurve: string;
        let hashAlgo: string;
        if (curveName === 'nistp256') {
          namedCurve = 'P-256';
          hashAlgo = 'SHA-256';
        } else if (curveName === 'nistp384') {
          namedCurve = 'P-384';
          hashAlgo = 'SHA-384';
        } else if (curveName === 'nistp521') {
          namedCurve = 'P-521';
          hashAlgo = 'SHA-512';
        } else {
          return new Error(`Unsupported ECDSA curve: ${curveName}`);
        }

        // Q should be in uncompressed format (0x04 || x || y)
        if (q[0] !== 0x04) {
          return new Error('Only uncompressed ECDSA public keys are supported');
        }

        // Import raw public key
        const publicKey = await crypto.subtle.importKey(
          'raw',
          q as BufferSource,
          { name: 'ECDSA', namedCurve },
          false,
          ['verify'],
        );

        // SSH ECDSA signature format is: mpint r + mpint s (RFC 5656)
        // Web Crypto expects IEEE P1363 format (r || s as fixed-length)
        // Try SSH mpint format first, fall back to DER for compatibility
        let p1363Sig = this._sshMpintToP1363(rawSig, namedCurve);
        if (p1363Sig instanceof Error) {
          // Try DER format as fallback
          p1363Sig = this._derToP1363(rawSig, namedCurve);
          if (p1363Sig instanceof Error) {
            return p1363Sig;
          }
        }

        return await crypto.subtle.verify(
          { name: 'ECDSA', hash: hashAlgo },
          publicKey,
          p1363Sig as BufferSource,
          exchangeHash as BufferSource,
        );
      } else {
        return new Error(`Unsupported signature algorithm: ${sigAlgo}`);
      }
    } catch (e) {
      return e as Error;
    }
  }

  /**
   * Convert DER-encoded ECDSA signature to IEEE P1363 format
   * DER format: SEQUENCE { INTEGER r, INTEGER s }
   * P1363 format: r || s (fixed-length, no padding)
   */
  private _derToP1363(der: Uint8Array, namedCurve: string): Uint8Array | Error {
    // Determine component size based on curve
    let componentSize: number;
    if (namedCurve === 'P-256') componentSize = 32;
    else if (namedCurve === 'P-384') componentSize = 48;
    else if (namedCurve === 'P-521') componentSize = 66;
    else return new Error(`Unknown curve: ${namedCurve}`);

    // Parse DER
    if (der.length < 6 || der[0] !== 0x30) {
      return new Error('Invalid DER signature');
    }

    let offset = 2; // Skip SEQUENCE tag and length

    // Read r
    if (der[offset] !== 0x02) {
      return new Error('Invalid DER signature: expected INTEGER');
    }
    offset++;
    const rLen = der[offset++];
    let r = der.subarray(offset, offset + rLen);
    offset += rLen;

    // Strip leading zeros from r
    while (r.length > componentSize && r[0] === 0) {
      r = r.subarray(1);
    }

    // Read s
    if (der[offset] !== 0x02) {
      return new Error('Invalid DER signature: expected INTEGER');
    }
    offset++;
    const sLen = der[offset++];
    let s = der.subarray(offset, offset + sLen);

    // Strip leading zeros from s
    while (s.length > componentSize && s[0] === 0) {
      s = s.subarray(1);
    }

    // Create fixed-length output
    const result = new Uint8Array(componentSize * 2);

    // Pad r and s to component size and copy
    result.set(r, componentSize - r.length);
    result.set(s, componentSize * 2 - s.length);

    return result;
  }

  /**
   * Convert SSH mpint-encoded ECDSA signature to IEEE P1363 format
   * SSH format: uint32 r_len + r_bytes + uint32 s_len + s_bytes (with optional leading 0 for positive)
   * P1363 format: r || s (fixed-length, no padding byte)
   */
  private _sshMpintToP1363(sig: Uint8Array, namedCurve: string): Uint8Array | Error {
    // Determine component size based on curve
    let componentSize: number;
    if (namedCurve === 'P-256') componentSize = 32;
    else if (namedCurve === 'P-384') componentSize = 48;
    else if (namedCurve === 'P-521') componentSize = 66;
    else return new Error(`Unknown curve: ${namedCurve}`);

    if (sig.length < 8) {
      return new Error('Invalid SSH mpint signature: too short');
    }

    let offset = 0;

    // Read r length
    const rLen = readUInt32BE(sig, offset);
    offset += 4;

    if (sig.length < offset + rLen + 4) {
      return new Error('Invalid SSH mpint signature: truncated');
    }

    let r = sig.subarray(offset, offset + rLen);
    offset += rLen;

    // Read s length
    const sLen = readUInt32BE(sig, offset);
    offset += 4;

    if (sig.length < offset + sLen) {
      return new Error('Invalid SSH mpint signature: truncated');
    }

    let s = sig.subarray(offset, offset + sLen);

    // Strip leading zeros (SSH adds these for positive integers with high bit set)
    while (r.length > componentSize && r[0] === 0) {
      r = r.subarray(1);
    }
    while (s.length > componentSize && s[0] === 0) {
      s = s.subarray(1);
    }

    // Create fixed-length output
    const result = new Uint8Array(componentSize * 2);

    // Pad r and s to component size and copy
    result.set(r, componentSize - r.length);
    result.set(s, componentSize * 2 - s.length);

    return result;
  }

  /**
   * Send NEWKEYS message
   */
  private async _sendNewKeys(): Promise<void> {
    const payload = allocBytes(1);
    payload[0] = MESSAGE.NEWKEYS;

    this._debug?.('Outbound: Sending NEWKEYS');
    // Force send - key exchange packets must never be queued during rekey
    this._sendPacket(payload, true);
    // Packets still being compressed or encrypted under the old keys reach the
    // transport before the outbound cipher changes
    await this._waitForOutboundPackets();
  }

  /**
   * Switch outbound cipher after sending NEWKEYS
   */
  private _switchOutboundCipher(): void {
    if (!this._sessionKeys || !this._kexHandler.state.algorithms) {
      this._debug?.('Cannot switch outbound cipher: no session keys or algorithms');
      return;
    }

    const algorithms = this._kexHandler.state.algorithms;
    const isServer = this._server;

    // Server sends S->C, Client sends C->S
    const cipherName = isServer ? algorithms.sc.cipher : algorithms.cs.cipher;
    const macName = isServer ? algorithms.sc.mac : algorithms.cs.mac;
    const key = isServer ? this._sessionKeys.keyS2C : this._sessionKeys.keyC2S;
    const iv = isServer ? this._sessionKeys.ivS2C : this._sessionKeys.ivC2S;
    const macKey = isServer ? this._sessionKeys.macKeyS2C : this._sessionKeys.macKeyC2S;

    const cipherInfo = CIPHER_INFO[cipherName];
    if (!cipherInfo) {
      this._debug?.(`Unknown cipher: ${cipherName}, staying on NullCipher`);
      return;
    }

    const macInfo = MAC_INFO[macName];
    // Note: For AEAD ciphers (like GCM), macInfo may be undefined

    this._debug?.(`Switching outbound cipher to ${cipherName}`);

    // Free old cipher
    this._cipher?.free();

    // Create new cipher
    // In strict KEX mode (RFC 9700), sequence numbers reset to 0 after NEWKEYS
    const seqno = this._strictKex ? 0 : ((this._cipher as CipherType).outSeqno ?? 0);
    this._debug?.(`New outbound seqno: ${seqno} (strictKex=${this._strictKex})`);
    this._cipher = createCipher({
      outbound: {
        seqno,
        onWrite: this._onWrite,
        cipherInfo,
        cipherKey: key,
        cipherIV: iv,
        macInfo,
        macKey,
      },
    });

    // Update the packet writer's reference to the cipher
    // deno-lint-ignore no-explicit-any
    ((this._packetRW.write as unknown) as { _protocol: { _cipher: Cipher } })._protocol._cipher =
      this._cipher;
  }

  /**
   * Switch inbound decipher after receiving NEWKEYS
   */
  private _switchInboundDecipher(): void {
    if (!this._sessionKeys || !this._kexHandler.state.algorithms) {
      this._debug?.('Cannot switch inbound decipher: no session keys or algorithms');
      return;
    }

    const algorithms = this._kexHandler.state.algorithms;
    const isServer = this._server;

    // Server receives C->S, Client receives S->C
    const cipherName = isServer ? algorithms.cs.cipher : algorithms.sc.cipher;
    const macName = isServer ? algorithms.cs.mac : algorithms.sc.mac;
    const key = isServer ? this._sessionKeys.keyC2S : this._sessionKeys.keyS2C;
    const iv = isServer ? this._sessionKeys.ivC2S : this._sessionKeys.ivS2C;
    const macKey = isServer ? this._sessionKeys.macKeyC2S : this._sessionKeys.macKeyS2C;

    const cipherInfo = CIPHER_INFO[cipherName];
    if (!cipherInfo) {
      this._debug?.(`Unknown cipher: ${cipherName}, staying on NullDecipher`);
      return;
    }

    const macInfo = MAC_INFO[macName];
    // Note: For AEAD ciphers (like GCM), macInfo may be undefined

    this._debug?.(`Switching inbound decipher to ${cipherName}`);

    // Free old decipher
    // In strict KEX mode (RFC 9700), sequence numbers reset to 0 after NEWKEYS
    const seqno = this._strictKex ? 0 : (this._decipher?.inSeqno ?? 0);
    this._debug?.(`New inbound seqno: ${seqno} (strictKex=${this._strictKex})`);
    this._decipher?.free();
    this._decipher = createDecipher({
      inbound: {
        seqno,
        onPayload: this._onPayload.bind(this),
        decipherInfo: cipherInfo,
        decipherKey: key,
        decipherIV: iv,
        macInfo,
        macKey,
      },
    });
  }

  /**
   * Enable compression after authentication success
   * For 'zlib@openssh.com', compression starts after auth success
   */
  enableCompression(): void {
    const algorithms = this._kexHandler.state.algorithms;
    if (!algorithms) {
      this._debug?.('Cannot enable compression: no algorithms negotiated');
      return;
    }

    const isServer = this._server;
    // For server: outbound uses sc.compress, inbound uses cs.compress
    // For client: outbound uses cs.compress, inbound uses sc.compress
    const outboundCompress = isServer ? algorithms.sc.compress : algorithms.cs.compress;
    const inboundCompress = isServer ? algorithms.cs.compress : algorithms.sc.compress;

    // Enable outbound compression
    if (outboundCompress === 'zlib@openssh.com' || outboundCompress === 'zlib') {
      this._compress = true;
      this._compressor = new ZlibCompressor();
      this._debug?.(`Enabled outbound compression: ${outboundCompress}`);
    }

    // Enable inbound decompression
    if (inboundCompress === 'zlib@openssh.com' || inboundCompress === 'zlib') {
      this._decompress = true;
      this._decompressor = new ZlibDecompressor();
      this._debug?.(`Enabled inbound decompression: ${inboundCompress}`);
    }
  }

  /**
   * Send KEXINIT message
   */
  private _sendKexInit(): void {
    const kexinit = this._kexHandler.generateKexInit();
    this._kexinit = kexinit;

    this._debug?.('Outbound: Sending KEXINIT');
    this._sendPacket(kexinit, true);

    // RFC 4253 7.1: no service messages from KEXINIT until our NEWKEYS. Every
    // non-forced packet waits for the new keys, since one produced while
    // NEWKEYS is out but the old cipher still in place would be encrypted under
    // keys the peer has already dropped.
    this._queue ??= [];
  }

  /**
   * Send the packets held back during the key exchange, under the new keys
   */
  private _flushQueue(): void {
    const queue = this._queue;
    if (!queue) return;
    this._queue = undefined;
    this._debug?.(`Flushing ${queue.length} queued packets after key exchange`);
    for (const payload of queue) {
      this._sendPacket(payload);
    }
  }

  /**
   * Send a packet
   */
  private _sendPacket(payload: OutboundPayload, force = false): void {
    // During rekey, queue non-critical packets
    if (this._queue && !force) {
      this._queue.push(payload);
      return;
    }

    if (!this._compress || !this._compressor) {
      this._encryptPacket(payload);
      return;
    }

    this._outboundPackets.push(payload);
    if (!this._sendingPacket) {
      this._packetDrainPromise = this._drainOutboundPackets();
    }
  }

  private _encryptPacket(payload: OutboundPayload): void {
    try {
      const packet = this._cipher.allocPacket(payload.length);
      if (payload instanceof Uint8Array) {
        packet.set(payload, 5);
      } else {
        let packetOffset = 5;
        for (const part of payload.parts) {
          packet.set(part, packetOffset);
          packetOffset += part.length;
        }
      }

      const encrypted = this._cipher.encrypt(packet);
      if (!encrypted) return;

      const tracked = encrypted
        .catch((err) => this._onError?.(err as Error))
        .finally(() => this._pendingEncryptions.delete(tracked));
      this._pendingEncryptions.add(tracked);
    } catch (err) {
      this._onError?.(err as Error);
    }
  }

  private async _drainOutboundPackets(): Promise<void> {
    if (this._sendingPacket) return;
    this._sendingPacket = true;

    try {
      for (let i = 0; i < this._outboundPackets.length; i++) {
        const payload = this._outboundPackets[i];
        let data = payload instanceof Uint8Array ? payload : allocBytes(payload.length);
        if (!(payload instanceof Uint8Array)) {
          let dataOffset = 0;
          for (const part of payload.parts) {
            data.set(part, dataOffset);
            dataOffset += part.length;
          }
        }
        data = await this._compressor!.compressAsync(data);
        this._encryptPacket(data);
      }
      this._outboundPackets.length = 0;
    } catch (err) {
      this._outboundPackets.length = 0;
      this._onError?.(err as Error);
    } finally {
      this._sendingPacket = false;
      if (this._outboundPackets.length > 0) {
        this._packetDrainPromise = this._drainOutboundPackets();
      }
    }
  }

  private async _waitForOutboundPackets(): Promise<void> {
    while (
      this._sendingPacket || this._outboundPackets.length > 0 || this._pendingEncryptions.size > 0
    ) {
      await Promise.all([this._packetDrainPromise, ...this._pendingEncryptions]);
    }
  }

  /**
   * Send UNIMPLEMENTED message
   */
  private _sendUnimplemented(seqno: number): void {
    const payload = allocBytes(5);
    payload[0] = MESSAGE.UNIMPLEMENTED;
    writeUInt32BE(payload, seqno, 1);

    this._debug?.(`Outbound: Sending UNIMPLEMENTED for seqno ${seqno}`);
    this._sendPacket(payload);
  }

  // ============================================================================
  // Protocol message API
  // ============================================================================

  /**
   * Send DISCONNECT message
   */
  disconnect(reason?: number): void {
    if (reason === undefined || !VALID_DISCONNECT_REASONS.has(reason)) {
      reason = DISCONNECT_REASON.PROTOCOL_ERROR;
    }

    const payload = allocBytes(13); // 1 + 4 + 4 + 4
    payload[0] = MESSAGE.DISCONNECT;
    writeUInt32BE(payload, reason, 1);
    // description length = 0
    writeUInt32BE(payload, 0, 5);
    // language tag length = 0
    writeUInt32BE(payload, 0, 9);

    this._debug?.(`Outbound: Sending DISCONNECT (${reason})`);
    this._sendPacket(payload, true);
  }

  /**
   * Send ping (keepalive)
   */
  ping(): void {
    this._debug?.(
      'Outbound: Sending ping (GLOBAL_REQUEST: keepalive@openssh.com)',
    );
    this._sendPacket(PING_PAYLOAD);
  }

  /**
   * Initiate rekeying
   */
  rekey(): void {
    if (this._kexinit === undefined) {
      this._debug?.('Outbound: Initiated explicit rekey');
      this._sendKexInit();
    } else {
      this._debug?.('Outbound: Ignoring rekey during handshake');
    }
  }

  /**
   * Send REQUEST_SUCCESS
   */
  requestSuccess(data?: Uint8Array): void {
    let payload: Uint8Array;
    if (data) {
      payload = allocBytes(1 + data.length);
      payload[0] = MESSAGE.REQUEST_SUCCESS;
      payload.set(data, 1);
    } else {
      payload = allocBytes(1);
      payload[0] = MESSAGE.REQUEST_SUCCESS;
    }

    this._debug?.('Outbound: Sending REQUEST_SUCCESS');
    this._sendPacket(payload);
  }

  /**
   * Send REQUEST_FAILURE
   */
  requestFailure(): void {
    const payload = allocBytes(1);
    payload[0] = MESSAGE.REQUEST_FAILURE;

    this._debug?.('Outbound: Sending REQUEST_FAILURE');
    this._sendPacket(payload);
  }

  /**
   * Send CHANNEL_SUCCESS
   */
  channelSuccess(channel: number): void {
    const payload = allocBytes(5);
    payload[0] = MESSAGE.CHANNEL_SUCCESS;
    writeUInt32BE(payload, channel, 1);

    this._debug?.(`Outbound: Sending CHANNEL_SUCCESS (c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Send CHANNEL_FAILURE
   */
  channelFailure(channel: number): void {
    const payload = allocBytes(5);
    payload[0] = MESSAGE.CHANNEL_FAILURE;
    writeUInt32BE(payload, channel, 1);

    this._debug?.(`Outbound: Sending CHANNEL_FAILURE (c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Send CHANNEL_OPEN_FAILURE
   */
  channelOpenFail(
    recipient: number,
    reason: number,
    description: string,
    lang: string,
  ): void {
    const descBytes = fromString(description);
    const langBytes = fromString(lang);
    const payload = allocBytes(17 + descBytes.length + langBytes.length);

    let offset = 0;
    payload[offset++] = MESSAGE.CHANNEL_OPEN_FAILURE;
    writeUInt32BE(payload, recipient, offset);
    offset += 4;
    writeUInt32BE(payload, reason, offset);
    offset += 4;
    writeUInt32BE(payload, descBytes.length, offset);
    offset += 4;
    payload.set(descBytes, offset);
    offset += descBytes.length;
    writeUInt32BE(payload, langBytes.length, offset);
    offset += 4;
    payload.set(langBytes, offset);

    this._debug?.(
      `Outbound: Sending CHANNEL_OPEN_FAILURE (r:${recipient}, reason:${reason})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Send CHANNEL_DATA
   */
  channelData(channel: number, data: Uint8Array): void {
    this.channelDataParts(channel, [data]);
  }

  /**
   * Send CHANNEL_DATA assembled directly into the cipher packet.
   *
   * Keeping the application payload segmented avoids a complete data-sized
   * copy here. Compression still materializes it because zlib needs one input.
   */
  channelDataParts(channel: number, parts: readonly Uint8Array[]): void {
    const dataLength = parts.reduce((total, part) => total + part.length, 0);
    const header = allocBytes(9);
    let offset = 0;
    header[offset++] = MESSAGE.CHANNEL_DATA;
    writeUInt32BE(header, channel, offset);
    offset += 4;
    writeUInt32BE(header, dataLength, offset);

    this._debug?.(
      `Outbound: Sending CHANNEL_DATA (c:${channel}, ${dataLength} bytes)`,
    );
    this._sendPacket({ length: header.length + dataLength, parts: [header, ...parts] });
  }

  /**
   * Send CHANNEL_EXTENDED_DATA
   */
  channelExtData(channel: number, data: Uint8Array, type: number): void {
    const payload = allocBytes(13 + data.length);
    let offset = 0;
    payload[offset++] = MESSAGE.CHANNEL_EXTENDED_DATA;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, type, offset);
    offset += 4;
    writeUInt32BE(payload, data.length, offset);
    offset += 4;
    payload.set(data, offset);

    this._debug?.(
      `Outbound: Sending CHANNEL_EXTENDED_DATA (c:${channel}, type:${type}, ${data.length} bytes)`,
    );
    this._sendPacket(payload);
  }

  /**
   * Send CHANNEL_WINDOW_ADJUST
   */
  channelWindowAdjust(channel: number, amount: number): void {
    const payload = allocBytes(9);
    payload[0] = MESSAGE.CHANNEL_WINDOW_ADJUST;
    writeUInt32BE(payload, channel, 1);
    writeUInt32BE(payload, amount, 5);

    this._debug?.(
      `Outbound: Sending CHANNEL_WINDOW_ADJUST (c:${channel}, amount:${amount})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Send CHANNEL_EOF
   */
  channelEOF(channel: number): void {
    const payload = allocBytes(5);
    payload[0] = MESSAGE.CHANNEL_EOF;
    writeUInt32BE(payload, channel, 1);

    this._debug?.(`Outbound: Sending CHANNEL_EOF (c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Send CHANNEL_CLOSE
   */
  channelClose(channel: number): void {
    const payload = allocBytes(5);
    payload[0] = MESSAGE.CHANNEL_CLOSE;
    writeUInt32BE(payload, channel, 1);

    this._debug?.(`Outbound: Sending CHANNEL_CLOSE (c:${channel})`);
    this._sendPacket(payload);
  }

  // ============================================================================
  // Accessors for future use
  // ============================================================================

  /** Get the remote identification string */
  get remoteIdent(): Uint8Array | undefined {
    return this._remoteIdentRaw;
  }

  /** Get the server host keys */
  get hostKeys(): HostKeyInfo[] | undefined {
    return this._hostKeys;
  }

  /** Get the server banner */
  get banner(): string | undefined {
    return this._banner;
  }

  /** Get the host verifier function */
  get hostVerifier(): ((key: Uint8Array) => boolean | Promise<boolean>) | undefined {
    return this._hostVerifier;
  }

  // ============================================================================
  // Service and Authentication Methods
  // ============================================================================

  /**
   * Request a service
   */
  service(name: string): void {
    const nameBytes = fromString(name);
    const payload = allocBytes(1 + 4 + nameBytes.length);
    payload[0] = MESSAGE.SERVICE_REQUEST;
    writeUInt32BE(payload, nameBytes.length, 1);
    payload.set(nameBytes, 5);

    this._debug?.(`Outbound: Sending SERVICE_REQUEST (${name})`);
    this._sendPacket(payload);
  }

  /**
   * Send auth none request
   */
  authNone(username: string): void {
    const userBytes = fromString(username);
    const serviceBytes = fromString('ssh-connection');
    const methodBytes = fromString('none');

    const payload = allocBytes(
      1 + 4 + userBytes.length + 4 + serviceBytes.length + 4 + methodBytes.length,
    );
    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(payload, userBytes.length, offset);
    offset += 4;
    payload.set(userBytes, offset);
    offset += userBytes.length;

    writeUInt32BE(payload, serviceBytes.length, offset);
    offset += 4;
    payload.set(serviceBytes, offset);
    offset += serviceBytes.length;

    writeUInt32BE(payload, methodBytes.length, offset);
    offset += 4;
    payload.set(methodBytes, offset);

    this._debug?.(`Outbound: Sending USERAUTH_REQUEST (none)`);
    this._sendPacket(payload);
  }

  /**
   * Send password auth request
   */
  authPassword(username: string, password: string): void {
    const userBytes = fromString(username);
    const serviceBytes = fromString('ssh-connection');
    const methodBytes = fromString('password');
    const passBytes = fromString(password);

    const payload = allocBytes(
      1 + 4 + userBytes.length + 4 + serviceBytes.length + 4 + methodBytes.length + 1 + 4 +
        passBytes.length,
    );
    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(payload, userBytes.length, offset);
    offset += 4;
    payload.set(userBytes, offset);
    offset += userBytes.length;

    writeUInt32BE(payload, serviceBytes.length, offset);
    offset += 4;
    payload.set(serviceBytes, offset);
    offset += serviceBytes.length;

    writeUInt32BE(payload, methodBytes.length, offset);
    offset += 4;
    payload.set(methodBytes, offset);
    offset += methodBytes.length;

    payload[offset++] = 0; // FALSE - not changing password

    writeUInt32BE(payload, passBytes.length, offset);
    offset += 4;
    payload.set(passBytes, offset);

    this._debug?.(`Outbound: Sending USERAUTH_REQUEST (password)`);
    this._sendPacket(payload);
  }

  /**
   * Send SSH_MSG_EXT_INFO (RFC 8308)
   */
  sendExtInfo(exts: Array<{ name: string; value: string }>): void {
    const encoded = exts.map((ext) => ({
      name: fromString(ext.name),
      value: fromString(ext.value),
    }));
    let len = 1 + 4;
    for (const ext of encoded) len += 4 + ext.name.length + 4 + ext.value.length;

    const payload = allocBytes(len);
    let offset = 0;
    payload[offset++] = MESSAGE.EXT_INFO;
    writeUInt32BE(payload, encoded.length, offset);
    offset += 4;
    for (const ext of encoded) {
      writeUInt32BE(payload, ext.name.length, offset);
      offset += 4;
      payload.set(ext.name, offset);
      offset += ext.name.length;
      writeUInt32BE(payload, ext.value.length, offset);
      offset += 4;
      payload.set(ext.value, offset);
      offset += ext.value.length;
    }

    this._debug?.('Outbound: Sending EXT_INFO');
    // Only valid directly after NEWKEYS, so it must not wait in the rekey queue
    this._sendPacket(payload, true);
  }

  /**
   * Send public key auth query (without signature)
   * Server will respond with USERAUTH_PK_OK if key is acceptable
   */
  authPK(username: string, key: ParsedKey, keyAlgo?: string): void {
    const userBytes = fromString(username);
    const serviceBytes = fromString('ssh-connection');
    const methodBytes = fromString('publickey');
    const algo = keyAlgo || key.type;
    const algoBytes = fromString(algo);
    const pubKeySSH = key.getPublicSSH();

    if (!pubKeySSH) {
      throw new Error('Cannot get public key SSH blob');
    }

    const payload = allocBytes(
      1 + 4 + userBytes.length + 4 + serviceBytes.length + 4 + methodBytes.length +
        1 + 4 + algoBytes.length + 4 + pubKeySSH.length,
    );
    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(payload, userBytes.length, offset);
    offset += 4;
    payload.set(userBytes, offset);
    offset += userBytes.length;

    writeUInt32BE(payload, serviceBytes.length, offset);
    offset += 4;
    payload.set(serviceBytes, offset);
    offset += serviceBytes.length;

    writeUInt32BE(payload, methodBytes.length, offset);
    offset += 4;
    payload.set(methodBytes, offset);
    offset += methodBytes.length;

    payload[offset++] = 0; // FALSE - this is just a query

    writeUInt32BE(payload, algoBytes.length, offset);
    offset += 4;
    payload.set(algoBytes, offset);
    offset += algoBytes.length;

    writeUInt32BE(payload, pubKeySSH.length, offset);
    offset += 4;
    payload.set(pubKeySSH, offset);

    this._debug?.(`Outbound: Sending USERAUTH_REQUEST (publickey query, algo=${algo})`);
    this._authsQueue.push('publickey');
    this._sendPacket(payload);
  }

  /**
   * Send public key auth request with signature
   * Called after receiving USERAUTH_PK_OK
   */
  async authPKSign(username: string, key: ParsedKey, keyAlgo?: string): Promise<void> {
    const userBytes = fromString(username);
    const serviceBytes = fromString('ssh-connection');
    const methodBytes = fromString('publickey');
    const algo = keyAlgo || key.type;
    const algoBytes = fromString(algo);
    const pubKeySSH = key.getPublicSSH();

    if (!pubKeySSH) {
      throw new Error('Cannot get public key SSH blob');
    }

    // Build the data to be signed
    // string    session identifier
    // byte      SSH_MSG_USERAUTH_REQUEST
    // string    user name
    // string    service name
    // string    "publickey"
    // boolean   TRUE
    // string    public key algorithm name
    // string    public key blob
    const sessionId = this._kex.sessionID;
    const dataToSign = allocBytes(
      4 + sessionId.length + 1 + 4 + userBytes.length + 4 + serviceBytes.length +
        4 + methodBytes.length + 1 + 4 + algoBytes.length + 4 + pubKeySSH.length,
    );

    let signOffset = 0;
    writeUInt32BE(dataToSign, sessionId.length, signOffset);
    signOffset += 4;
    dataToSign.set(sessionId, signOffset);
    signOffset += sessionId.length;

    dataToSign[signOffset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(dataToSign, userBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(userBytes, signOffset);
    signOffset += userBytes.length;

    writeUInt32BE(dataToSign, serviceBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(serviceBytes, signOffset);
    signOffset += serviceBytes.length;

    writeUInt32BE(dataToSign, methodBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(methodBytes, signOffset);
    signOffset += methodBytes.length;

    dataToSign[signOffset++] = 1; // TRUE

    writeUInt32BE(dataToSign, algoBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(algoBytes, signOffset);
    signOffset += algoBytes.length;

    writeUInt32BE(dataToSign, pubKeySSH.length, signOffset);
    signOffset += 4;
    dataToSign.set(pubKeySSH, signOffset);

    // Sign the data
    const signResult = await key.sign(dataToSign, algo);
    if (signResult instanceof Error) {
      throw signResult;
    }

    // Build signature blob: string algorithm + string signature
    const sigAlgoBytes = fromString(algo);
    const signatureBlob = allocBytes(4 + sigAlgoBytes.length + 4 + signResult.length);
    let sigBlobOffset = 0;
    writeUInt32BE(signatureBlob, sigAlgoBytes.length, sigBlobOffset);
    sigBlobOffset += 4;
    signatureBlob.set(sigAlgoBytes, sigBlobOffset);
    sigBlobOffset += sigAlgoBytes.length;
    writeUInt32BE(signatureBlob, signResult.length, sigBlobOffset);
    sigBlobOffset += 4;
    signatureBlob.set(signResult, sigBlobOffset);

    // Build final packet
    const payload = allocBytes(
      1 + 4 + userBytes.length + 4 + serviceBytes.length + 4 + methodBytes.length +
        1 + 4 + algoBytes.length + 4 + pubKeySSH.length + 4 + signatureBlob.length,
    );
    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(payload, userBytes.length, offset);
    offset += 4;
    payload.set(userBytes, offset);
    offset += userBytes.length;

    writeUInt32BE(payload, serviceBytes.length, offset);
    offset += 4;
    payload.set(serviceBytes, offset);
    offset += serviceBytes.length;

    writeUInt32BE(payload, methodBytes.length, offset);
    offset += 4;
    payload.set(methodBytes, offset);
    offset += methodBytes.length;

    payload[offset++] = 1; // TRUE - this has a signature

    writeUInt32BE(payload, algoBytes.length, offset);
    offset += 4;
    payload.set(algoBytes, offset);
    offset += algoBytes.length;

    writeUInt32BE(payload, pubKeySSH.length, offset);
    offset += 4;
    payload.set(pubKeySSH, offset);
    offset += pubKeySSH.length;

    writeUInt32BE(payload, signatureBlob.length, offset);
    offset += 4;
    payload.set(signatureBlob, offset);

    this._debug?.(`Outbound: Sending USERAUTH_REQUEST (publickey with signature, algo=${algo})`);
    this._sendPacket(payload);
  }

  /**
   * Send public key auth request with signature using agent
   * Called after receiving USERAUTH_PK_OK when using agent authentication
   */
  async authPKSignWithAgent(
    username: string,
    key: ParsedKey,
    agentCtx: AgentContext,
    keyAlgo?: string,
  ): Promise<void> {
    const userBytes = fromString(username);
    const serviceBytes = fromString('ssh-connection');
    const methodBytes = fromString('publickey');
    const algo = keyAlgo || key.type;
    const algoBytes = fromString(algo);
    const pubKeySSH = key.getPublicSSH();

    if (!pubKeySSH) {
      throw new Error('Cannot get public key SSH blob');
    }

    // Build the data to be signed
    const sessionId = this._kex.sessionID;
    const dataToSign = allocBytes(
      4 + sessionId.length + 1 + 4 + userBytes.length + 4 + serviceBytes.length +
        4 + methodBytes.length + 1 + 4 + algoBytes.length + 4 + pubKeySSH.length,
    );

    let signOffset = 0;
    writeUInt32BE(dataToSign, sessionId.length, signOffset);
    signOffset += 4;
    dataToSign.set(sessionId, signOffset);
    signOffset += sessionId.length;

    dataToSign[signOffset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(dataToSign, userBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(userBytes, signOffset);
    signOffset += userBytes.length;

    writeUInt32BE(dataToSign, serviceBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(serviceBytes, signOffset);
    signOffset += serviceBytes.length;

    writeUInt32BE(dataToSign, methodBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(methodBytes, signOffset);
    signOffset += methodBytes.length;

    dataToSign[signOffset++] = 1; // TRUE

    writeUInt32BE(dataToSign, algoBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(algoBytes, signOffset);
    signOffset += algoBytes.length;

    writeUInt32BE(dataToSign, pubKeySSH.length, signOffset);
    signOffset += 4;
    dataToSign.set(pubKeySSH, signOffset);

    // Sign the data using agent
    // Determine hash algorithm for RSA
    let hashAlgo: 'sha256' | 'sha512' | undefined;
    if (algo === 'rsa-sha2-256') {
      hashAlgo = 'sha256';
    } else if (algo === 'rsa-sha2-512') {
      hashAlgo = 'sha512';
    }

    const signResult = await agentCtx.sign(
      key,
      dataToSign,
      hashAlgo ? { hash: hashAlgo } : undefined,
    );

    // Build signature blob: string algorithm + string signature
    const sigAlgoBytes = fromString(algo);
    const signatureBlob = allocBytes(4 + sigAlgoBytes.length + 4 + signResult.length);
    let sigBlobOffset = 0;
    writeUInt32BE(signatureBlob, sigAlgoBytes.length, sigBlobOffset);
    sigBlobOffset += 4;
    signatureBlob.set(sigAlgoBytes, sigBlobOffset);
    sigBlobOffset += sigAlgoBytes.length;
    writeUInt32BE(signatureBlob, signResult.length, sigBlobOffset);
    sigBlobOffset += 4;
    signatureBlob.set(signResult, sigBlobOffset);

    // Build final packet
    const payload = allocBytes(
      1 + 4 + userBytes.length + 4 + serviceBytes.length + 4 + methodBytes.length +
        1 + 4 + algoBytes.length + 4 + pubKeySSH.length + 4 + signatureBlob.length,
    );
    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(payload, userBytes.length, offset);
    offset += 4;
    payload.set(userBytes, offset);
    offset += userBytes.length;

    writeUInt32BE(payload, serviceBytes.length, offset);
    offset += 4;
    payload.set(serviceBytes, offset);
    offset += serviceBytes.length;

    writeUInt32BE(payload, methodBytes.length, offset);
    offset += 4;
    payload.set(methodBytes, offset);
    offset += methodBytes.length;

    payload[offset++] = 1; // TRUE - this has a signature

    writeUInt32BE(payload, algoBytes.length, offset);
    offset += 4;
    payload.set(algoBytes, offset);
    offset += algoBytes.length;

    writeUInt32BE(payload, pubKeySSH.length, offset);
    offset += 4;
    payload.set(pubKeySSH, offset);
    offset += pubKeySSH.length;

    writeUInt32BE(payload, signatureBlob.length, offset);
    offset += 4;
    payload.set(signatureBlob, offset);

    this._debug?.(
      `Outbound: Sending USERAUTH_REQUEST (publickey with agent signature, algo=${algo})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Send hostbased auth request
   * Hostbased authentication uses the client host's identity to authenticate
   */
  async authHostbased(
    username: string,
    key: ParsedKey,
    localHostname: string,
    localUsername: string,
    keyAlgo?: string,
  ): Promise<void> {
    const userBytes = fromString(username);
    const serviceBytes = fromString('ssh-connection');
    const methodBytes = fromString('hostbased');
    const algo = keyAlgo || key.type;
    const algoBytes = fromString(algo);
    const pubKeySSH = key.getPublicSSH();
    const localHostnameBytes = fromString(localHostname);
    const localUsernameBytes = fromString(localUsername);

    if (!pubKeySSH) {
      throw new Error('Cannot get public key SSH blob');
    }

    // Build the data to be signed (RFC 4252 Section 9)
    // string    session identifier
    // byte      SSH_MSG_USERAUTH_REQUEST
    // string    user name
    // string    service name
    // string    "hostbased"
    // string    public key algorithm name
    // string    public key blob
    // string    client host name
    // string    client user name
    const sessionId = this._kex.sessionID;
    const dataToSign = allocBytes(
      4 + sessionId.length + 1 + 4 + userBytes.length + 4 + serviceBytes.length +
        4 + methodBytes.length + 4 + algoBytes.length + 4 + pubKeySSH.length +
        4 + localHostnameBytes.length + 4 + localUsernameBytes.length,
    );

    let signOffset = 0;
    writeUInt32BE(dataToSign, sessionId.length, signOffset);
    signOffset += 4;
    dataToSign.set(sessionId, signOffset);
    signOffset += sessionId.length;

    dataToSign[signOffset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(dataToSign, userBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(userBytes, signOffset);
    signOffset += userBytes.length;

    writeUInt32BE(dataToSign, serviceBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(serviceBytes, signOffset);
    signOffset += serviceBytes.length;

    writeUInt32BE(dataToSign, methodBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(methodBytes, signOffset);
    signOffset += methodBytes.length;

    writeUInt32BE(dataToSign, algoBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(algoBytes, signOffset);
    signOffset += algoBytes.length;

    writeUInt32BE(dataToSign, pubKeySSH.length, signOffset);
    signOffset += 4;
    dataToSign.set(pubKeySSH, signOffset);
    signOffset += pubKeySSH.length;

    writeUInt32BE(dataToSign, localHostnameBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(localHostnameBytes, signOffset);
    signOffset += localHostnameBytes.length;

    writeUInt32BE(dataToSign, localUsernameBytes.length, signOffset);
    signOffset += 4;
    dataToSign.set(localUsernameBytes, signOffset);

    // Sign the data
    const signResult = await key.sign(dataToSign, algo);
    if (signResult instanceof Error) {
      throw signResult;
    }

    // Build signature blob: string algorithm + string signature
    const sigAlgoBytes = fromString(algo);
    const signatureBlob = allocBytes(4 + sigAlgoBytes.length + 4 + signResult.length);
    let sigBlobOffset = 0;
    writeUInt32BE(signatureBlob, sigAlgoBytes.length, sigBlobOffset);
    sigBlobOffset += 4;
    signatureBlob.set(sigAlgoBytes, sigBlobOffset);
    sigBlobOffset += sigAlgoBytes.length;
    writeUInt32BE(signatureBlob, signResult.length, sigBlobOffset);
    sigBlobOffset += 4;
    signatureBlob.set(signResult, sigBlobOffset);

    // Build final packet
    const payload = allocBytes(
      1 + 4 + userBytes.length + 4 + serviceBytes.length + 4 + methodBytes.length +
        4 + algoBytes.length + 4 + pubKeySSH.length +
        4 + localHostnameBytes.length + 4 + localUsernameBytes.length +
        4 + signatureBlob.length,
    );
    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(payload, userBytes.length, offset);
    offset += 4;
    payload.set(userBytes, offset);
    offset += userBytes.length;

    writeUInt32BE(payload, serviceBytes.length, offset);
    offset += 4;
    payload.set(serviceBytes, offset);
    offset += serviceBytes.length;

    writeUInt32BE(payload, methodBytes.length, offset);
    offset += 4;
    payload.set(methodBytes, offset);
    offset += methodBytes.length;

    writeUInt32BE(payload, algoBytes.length, offset);
    offset += 4;
    payload.set(algoBytes, offset);
    offset += algoBytes.length;

    writeUInt32BE(payload, pubKeySSH.length, offset);
    offset += 4;
    payload.set(pubKeySSH, offset);
    offset += pubKeySSH.length;

    writeUInt32BE(payload, localHostnameBytes.length, offset);
    offset += 4;
    payload.set(localHostnameBytes, offset);
    offset += localHostnameBytes.length;

    writeUInt32BE(payload, localUsernameBytes.length, offset);
    offset += 4;
    payload.set(localUsernameBytes, offset);
    offset += localUsernameBytes.length;

    writeUInt32BE(payload, signatureBlob.length, offset);
    offset += 4;
    payload.set(signatureBlob, offset);

    this._debug?.(
      `Outbound: Sending USERAUTH_REQUEST (hostbased, algo=${algo}, host=${localHostname})`,
    );
    this._authsQueue.push('hostbased');
    this._sendPacket(payload);
  }

  /**
   * Send keyboard-interactive auth request
   */
  authKeyboard(username: string): void {
    const userBytes = fromString(username);
    const serviceBytes = fromString('ssh-connection');
    const methodBytes = fromString('keyboard-interactive');
    const langBytes = fromString('');
    const subMethodBytes = fromString('');

    const payload = allocBytes(
      1 + 4 + userBytes.length + 4 + serviceBytes.length + 4 + methodBytes.length +
        4 + langBytes.length + 4 + subMethodBytes.length,
    );
    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_REQUEST;

    writeUInt32BE(payload, userBytes.length, offset);
    offset += 4;
    payload.set(userBytes, offset);
    offset += userBytes.length;

    writeUInt32BE(payload, serviceBytes.length, offset);
    offset += 4;
    payload.set(serviceBytes, offset);
    offset += serviceBytes.length;

    writeUInt32BE(payload, methodBytes.length, offset);
    offset += 4;
    payload.set(methodBytes, offset);
    offset += methodBytes.length;

    writeUInt32BE(payload, langBytes.length, offset);
    offset += 4;

    writeUInt32BE(payload, subMethodBytes.length, offset);

    this._debug?.(`Outbound: Sending USERAUTH_REQUEST (keyboard-interactive)`);
    this._authsQueue.push('keyboard-interactive');
    this._sendPacket(payload);
  }

  /**
   * Send keyboard-interactive info response (SSH_MSG_USERAUTH_INFO_RESPONSE)
   */
  authInfoResponse(responses: string[]): void {
    // Calculate total length
    let totalLen = 1 + 4; // message type + num-responses
    const responseBytes: Uint8Array[] = [];
    for (const resp of responses) {
      const bytes = fromString(resp);
      responseBytes.push(bytes);
      totalLen += 4 + bytes.length;
    }

    const payload = allocBytes(totalLen);
    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_INFO_RESPONSE;

    writeUInt32BE(payload, responses.length, offset);
    offset += 4;

    for (const bytes of responseBytes) {
      writeUInt32BE(payload, bytes.length, offset);
      offset += 4;
      payload.set(bytes, offset);
      offset += bytes.length;
    }

    this._debug?.(`Outbound: Sending USERAUTH_INFO_RESPONSE (${responses.length} responses)`);
    this._sendPacket(payload);
  }

  // ============================================================================
  // Server-side Authentication Methods
  // ============================================================================

  /**
   * Accept service request (server-side)
   */
  serviceAccept(service: string): void {
    const serviceBytes = fromString(service);
    const payload = allocBytes(1 + 4 + serviceBytes.length);

    payload[0] = MESSAGE.SERVICE_ACCEPT;
    writeUInt32BE(payload, serviceBytes.length, 1);
    payload.set(serviceBytes, 5);

    this._debug?.(`Outbound: Sending SERVICE_ACCEPT (${service})`);
    this._sendPacket(payload);
  }

  /**
   * Send auth banner (server-side) - shown to user during authentication
   */
  authBanner(message: string, language = ''): void {
    const msgBytes = fromString(message);
    const langBytes = fromString(language);
    const payload = allocBytes(1 + 4 + msgBytes.length + 4 + langBytes.length);

    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_BANNER;
    writeUInt32BE(payload, msgBytes.length, offset);
    offset += 4;
    payload.set(msgBytes, offset);
    offset += msgBytes.length;
    writeUInt32BE(payload, langBytes.length, offset);
    offset += 4;
    payload.set(langBytes, offset);

    this._debug?.('Outbound: Sending USERAUTH_BANNER');
    this._sendPacket(payload);
  }

  /**
   * Send auth success (server-side)
   */
  authSuccess(): void {
    const payload = allocBytes(1);
    payload[0] = MESSAGE.USERAUTH_SUCCESS;

    this._debug?.('Outbound: Sending USERAUTH_SUCCESS');
    this._sendPacket(payload);

    // Enable compression after auth success (for 'zlib@openssh.com')
    this.enableCompression();
  }

  /**
   * Send auth failure (server-side)
   */
  authFailure(methodsLeft?: string[], isPartial?: boolean): void {
    const methods = methodsLeft?.join(',') ?? '';
    const methodsBytes = fromString(methods);
    const payload = allocBytes(1 + 4 + methodsBytes.length + 1);

    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_FAILURE;
    writeUInt32BE(payload, methodsBytes.length, offset);
    offset += 4;
    payload.set(methodsBytes, offset);
    offset += methodsBytes.length;
    payload[offset] = isPartial ? 1 : 0;

    this._debug?.(`Outbound: Sending USERAUTH_FAILURE (methods: ${methods})`);
    this._sendPacket(payload);
  }

  /**
   * Send public key OK (server-side) - client should now send signature
   */
  authPKOK(keyAlgo: string, keyData: Uint8Array): void {
    const algoBytes = fromString(keyAlgo);
    const payload = allocBytes(1 + 4 + algoBytes.length + 4 + keyData.length);

    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_PK_OK;
    writeUInt32BE(payload, algoBytes.length, offset);
    offset += 4;
    payload.set(algoBytes, offset);
    offset += algoBytes.length;
    writeUInt32BE(payload, keyData.length, offset);
    offset += 4;
    payload.set(keyData, offset);

    this._debug?.(`Outbound: Sending USERAUTH_PK_OK (${keyAlgo})`);
    this._sendPacket(payload);
  }

  /**
   * Request password change (server-side)
   */
  authPasswdChg(prompt: string): void {
    const promptBytes = fromString(prompt);
    const langBytes = fromString('');
    const payload = allocBytes(1 + 4 + promptBytes.length + 4 + langBytes.length);

    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_PASSWD_CHANGEREQ;
    writeUInt32BE(payload, promptBytes.length, offset);
    offset += 4;
    payload.set(promptBytes, offset);
    offset += promptBytes.length;
    writeUInt32BE(payload, langBytes.length, offset);

    this._debug?.('Outbound: Sending USERAUTH_PASSWD_CHANGEREQ');
    this._sendPacket(payload);
  }

  /**
   * Send keyboard-interactive info request (server-side)
   */
  authInfoReq(
    title: string,
    instructions: string,
    prompts: Array<{ prompt: string; echo: boolean }>,
  ): void {
    const titleBytes = fromString(title);
    const instrBytes = fromString(instructions);
    const langBytes = fromString('');

    let promptsSize = 0;
    const promptData: Array<{ prompt: Uint8Array; echo: boolean }> = [];
    for (const p of prompts) {
      const promptBytes = fromString(p.prompt);
      promptsSize += 4 + promptBytes.length + 1;
      promptData.push({ prompt: promptBytes, echo: p.echo });
    }

    const payload = allocBytes(
      1 + 4 + titleBytes.length + 4 + instrBytes.length + 4 + langBytes.length + 4 + promptsSize,
    );

    let offset = 0;
    payload[offset++] = MESSAGE.USERAUTH_INFO_REQUEST;

    writeUInt32BE(payload, titleBytes.length, offset);
    offset += 4;
    payload.set(titleBytes, offset);
    offset += titleBytes.length;

    writeUInt32BE(payload, instrBytes.length, offset);
    offset += 4;
    payload.set(instrBytes, offset);
    offset += instrBytes.length;

    writeUInt32BE(payload, langBytes.length, offset);
    offset += 4;
    payload.set(langBytes, offset);
    offset += langBytes.length;

    writeUInt32BE(payload, prompts.length, offset);
    offset += 4;

    for (const p of promptData) {
      writeUInt32BE(payload, p.prompt.length, offset);
      offset += 4;
      payload.set(p.prompt, offset);
      offset += p.prompt.length;
      payload[offset++] = p.echo ? 1 : 0;
    }

    this._debug?.(`Outbound: Sending USERAUTH_INFO_REQUEST (${prompts.length} prompts)`);
    this._sendPacket(payload);
  }

  // ============================================================================
  // Channel Request Methods
  // ============================================================================

  /**
   * Open a channel
   */
  channelOpen(type: string, localId: number, window: number, packetSize: number): void {
    const typeBytes = fromString(type);
    const payload = allocBytes(1 + 4 + typeBytes.length + 4 + 4 + 4);
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_OPEN;
    writeUInt32BE(payload, typeBytes.length, offset);
    offset += 4;
    payload.set(typeBytes, offset);
    offset += typeBytes.length;
    writeUInt32BE(payload, localId, offset);
    offset += 4;
    writeUInt32BE(payload, window, offset);
    offset += 4;
    writeUInt32BE(payload, packetSize, offset);

    this._debug?.(`Outbound: Sending CHANNEL_OPEN (${type}, l:${localId})`);
    this._sendPacket(payload);
  }

  /**
   * Confirm channel open
   */
  channelOpenConfirm(recipient: number, sender: number, window: number, packetSize: number): void {
    const payload = allocBytes(17);
    payload[0] = MESSAGE.CHANNEL_OPEN_CONFIRMATION;
    writeUInt32BE(payload, recipient, 1);
    writeUInt32BE(payload, sender, 5);
    writeUInt32BE(payload, window, 9);
    writeUInt32BE(payload, packetSize, 13);

    this._debug?.(`Outbound: Sending CHANNEL_OPEN_CONFIRMATION (r:${recipient})`);
    this._sendPacket(payload);
  }

  /**
   * Request PTY
   */
  pty(
    channel: number,
    rows: number,
    cols: number,
    height: number,
    width: number,
    term: string,
    _modes: Record<string, number> | null,
  ): void {
    const termBytes = fromString(term);
    // Simplified - no terminal modes for now
    const modesBytes = new Uint8Array([0]); // TTY_OP_END
    const reqType = fromString('pty-req');

    // Sized from the request name: a byte too many here is trailing garbage
    // that OpenSSH refuses ("unexpected bytes remain"), closing the session
    const payload = allocBytes(
      1 + 4 + 4 + reqType.length + 1 + 4 + termBytes.length + 4 + 4 + 4 + 4 + 4 + modesBytes.length,
    );
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;

    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;

    payload[offset++] = 0; // want reply = false

    writeUInt32BE(payload, termBytes.length, offset);
    offset += 4;
    payload.set(termBytes, offset);
    offset += termBytes.length;

    writeUInt32BE(payload, cols, offset);
    offset += 4;
    writeUInt32BE(payload, rows, offset);
    offset += 4;
    writeUInt32BE(payload, width, offset);
    offset += 4;
    writeUInt32BE(payload, height, offset);
    offset += 4;
    writeUInt32BE(payload, modesBytes.length, offset);
    offset += 4;
    payload.set(modesBytes, offset);

    this._debug?.(`Outbound: Sending CHANNEL_REQUEST (pty-req, c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Execute a command
   */
  exec(channel: number, command: string, wantReply: boolean): void {
    const cmdBytes = fromString(command);
    const reqType = fromString('exec');

    const payload = allocBytes(1 + 4 + 4 + reqType.length + 1 + 4 + cmdBytes.length);
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;
    writeUInt32BE(payload, cmdBytes.length, offset);
    offset += 4;
    payload.set(cmdBytes, offset);

    this._debug?.(`Outbound: Sending CHANNEL_REQUEST (exec, c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Start a shell
   */
  shell(channel: number, wantReply: boolean): void {
    const reqType = fromString('shell');

    const payload = allocBytes(1 + 4 + 4 + reqType.length + 1);
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;

    this._debug?.(`Outbound: Sending CHANNEL_REQUEST (shell, c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Request agent forwarding (auth-agent-req@openssh.com)
   */
  authAgentRequest(channel: number, wantReply = true): void {
    const reqType = fromString('auth-agent-req@openssh.com');

    const payload = allocBytes(1 + 4 + 4 + reqType.length + 1);
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;

    this._debug?.(`Outbound: Sending CHANNEL_REQUEST (auth-agent-req@openssh.com, c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Set environment variable
   */
  env(channel: number, name: string, value: string, wantReply = false): void {
    const reqType = fromString('env');
    const nameBytes = fromString(name);
    const valueBytes = fromString(value);

    const payload = allocBytes(
      1 + 4 + 4 + reqType.length + 1 + 4 + nameBytes.length + 4 + valueBytes.length,
    );
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;
    writeUInt32BE(payload, nameBytes.length, offset);
    offset += 4;
    payload.set(nameBytes, offset);
    offset += nameBytes.length;
    writeUInt32BE(payload, valueBytes.length, offset);
    offset += 4;
    payload.set(valueBytes, offset);

    this._debug?.(`Outbound: Sending CHANNEL_REQUEST (env: ${name}=${value}, c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Request a subsystem
   */
  subsystem(channel: number, name: string, wantReply: boolean): void {
    const reqType = fromString('subsystem');
    const nameBytes = fromString(name);

    const payload = allocBytes(1 + 4 + 4 + reqType.length + 1 + 4 + nameBytes.length);
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;
    writeUInt32BE(payload, nameBytes.length, offset);
    offset += 4;
    payload.set(nameBytes, offset);

    this._debug?.(`Outbound: Sending CHANNEL_REQUEST (subsystem:${name}, c:${channel})`);
    this._sendPacket(payload);
  }

  /**
   * Send window-change request (client only)
   */
  windowChange(channel: number, rows: number, cols: number, height: number, width: number): void {
    const reqType = fromString('window-change');

    // window-change format: cols, rows, width, height (all uint32)
    const payload = allocBytes(1 + 4 + 4 + reqType.length + 1 + 4 + 4 + 4 + 4);
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = 0; // want_reply = false
    writeUInt32BE(payload, cols, offset);
    offset += 4;
    writeUInt32BE(payload, rows, offset);
    offset += 4;
    writeUInt32BE(payload, width, offset);
    offset += 4;
    writeUInt32BE(payload, height, offset);

    this._debug?.(
      `Outbound: Sending CHANNEL_REQUEST (window-change, c:${channel}, rows:${rows}, cols:${cols})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Send exit-status (server only)
   */
  exitStatus(channel: number, status: number): void {
    const reqType = fromString('exit-status');

    const payload = allocBytes(1 + 4 + 4 + reqType.length + 1 + 4);
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = 0; // want_reply = false
    writeUInt32BE(payload, status, offset);

    this._debug?.(
      `Outbound: Sending CHANNEL_REQUEST (exit-status, c:${channel}, status:${status})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Send exit-signal (server only)
   */
  exitSignal(channel: number, signal: string, coreDumped: boolean, message: string): void {
    const reqType = fromString('exit-signal');
    const sigBytes = fromString(signal);
    const msgBytes = fromString(message);
    const langBytes = fromString(''); // empty language tag

    const payload = allocBytes(
      1 + 4 + 4 + reqType.length + 1 + 4 + sigBytes.length + 1 + 4 + msgBytes.length + 4 +
        langBytes.length,
    );
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_REQUEST;
    writeUInt32BE(payload, channel, offset);
    offset += 4;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = 0; // want_reply = false
    writeUInt32BE(payload, sigBytes.length, offset);
    offset += 4;
    payload.set(sigBytes, offset);
    offset += sigBytes.length;
    payload[offset++] = coreDumped ? 1 : 0;
    writeUInt32BE(payload, msgBytes.length, offset);
    offset += 4;
    payload.set(msgBytes, offset);
    offset += msgBytes.length;
    writeUInt32BE(payload, langBytes.length, offset);
    offset += 4;
    payload.set(langBytes, offset);

    this._debug?.(
      `Outbound: Sending CHANNEL_REQUEST (exit-signal, c:${channel}, signal:${signal})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Request TCP/IP forwarding
   */
  tcpipForward(bindAddr: string, bindPort: number, wantReply: boolean): void {
    const reqType = fromString('tcpip-forward');
    const addrBytes = fromString(bindAddr);

    const payload = allocBytes(1 + 4 + reqType.length + 1 + 4 + addrBytes.length + 4);
    let offset = 0;

    payload[offset++] = MESSAGE.GLOBAL_REQUEST;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;
    writeUInt32BE(payload, addrBytes.length, offset);
    offset += 4;
    payload.set(addrBytes, offset);
    offset += addrBytes.length;
    writeUInt32BE(payload, bindPort, offset);

    this._debug?.(`Outbound: Sending GLOBAL_REQUEST (tcpip-forward)`);
    this._sendPacket(payload);
  }

  /**
   * Cancel TCP/IP forwarding
   */
  cancelTcpipForward(bindAddr: string, bindPort: number, wantReply: boolean): void {
    const reqType = fromString('cancel-tcpip-forward');
    const addrBytes = fromString(bindAddr);

    const payload = allocBytes(1 + 4 + reqType.length + 1 + 4 + addrBytes.length + 4);
    let offset = 0;

    payload[offset++] = MESSAGE.GLOBAL_REQUEST;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;
    writeUInt32BE(payload, addrBytes.length, offset);
    offset += 4;
    payload.set(addrBytes, offset);
    offset += addrBytes.length;
    writeUInt32BE(payload, bindPort, offset);

    this._debug?.(`Outbound: Sending GLOBAL_REQUEST (cancel-tcpip-forward)`);
    this._sendPacket(payload);
  }

  /**
   * Request streamlocal forwarding (OpenSSH extension)
   */
  streamlocalForward(socketPath: string, wantReply: boolean): void {
    const reqType = fromString('streamlocal-forward@openssh.com');
    const pathBytes = fromString(socketPath);

    const payload = allocBytes(1 + 4 + reqType.length + 1 + 4 + pathBytes.length);
    let offset = 0;

    payload[offset++] = MESSAGE.GLOBAL_REQUEST;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;
    writeUInt32BE(payload, pathBytes.length, offset);
    offset += 4;
    payload.set(pathBytes, offset);

    this._debug?.(
      `Outbound: Sending GLOBAL_REQUEST (streamlocal-forward@openssh.com, path:${socketPath})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Cancel streamlocal forwarding (OpenSSH extension)
   */
  cancelStreamlocalForward(socketPath: string, wantReply: boolean): void {
    const reqType = fromString('cancel-streamlocal-forward@openssh.com');
    const pathBytes = fromString(socketPath);

    const payload = allocBytes(1 + 4 + reqType.length + 1 + 4 + pathBytes.length);
    let offset = 0;

    payload[offset++] = MESSAGE.GLOBAL_REQUEST;
    writeUInt32BE(payload, reqType.length, offset);
    offset += 4;
    payload.set(reqType, offset);
    offset += reqType.length;
    payload[offset++] = wantReply ? 1 : 0;
    writeUInt32BE(payload, pathBytes.length, offset);
    offset += 4;
    payload.set(pathBytes, offset);

    this._debug?.(
      `Outbound: Sending GLOBAL_REQUEST (cancel-streamlocal-forward@openssh.com, path:${socketPath})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Open direct streamlocal connection (OpenSSH extension)
   */
  directStreamlocal(
    localId: number,
    window: number,
    packetSize: number,
    socketPath: string,
  ): void {
    const typeBytes = fromString('direct-streamlocal@openssh.com');
    const pathBytes = fromString(socketPath);

    const payload = allocBytes(
      1 + 4 + typeBytes.length + 4 + 4 + 4 +
        4 + pathBytes.length + 4,
    );
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_OPEN;
    writeUInt32BE(payload, typeBytes.length, offset);
    offset += 4;
    payload.set(typeBytes, offset);
    offset += typeBytes.length;
    writeUInt32BE(payload, localId, offset);
    offset += 4;
    writeUInt32BE(payload, window, offset);
    offset += 4;
    writeUInt32BE(payload, packetSize, offset);
    offset += 4;
    writeUInt32BE(payload, pathBytes.length, offset);
    offset += 4;
    payload.set(pathBytes, offset);
    offset += pathBytes.length;
    // Reserved string (empty)
    writeUInt32BE(payload, 0, offset);

    this._debug?.(
      `Outbound: Sending CHANNEL_OPEN (direct-streamlocal@openssh.com, l:${localId}, path:${socketPath})`,
    );
    this._sendPacket(payload);
  }

  /**
   * Open direct TCP/IP connection
   */
  directTcpip(
    localId: number,
    window: number,
    packetSize: number,
    dstAddr: string,
    dstPort: number,
    srcAddr: string,
    srcPort: number,
  ): void {
    const typeBytes = fromString('direct-tcpip');
    const dstAddrBytes = fromString(dstAddr);
    const srcAddrBytes = fromString(srcAddr);

    const payload = allocBytes(
      1 + 4 + typeBytes.length + 4 + 4 + 4 +
        4 + dstAddrBytes.length + 4 +
        4 + srcAddrBytes.length + 4,
    );
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_OPEN;
    writeUInt32BE(payload, typeBytes.length, offset);
    offset += 4;
    payload.set(typeBytes, offset);
    offset += typeBytes.length;
    writeUInt32BE(payload, localId, offset);
    offset += 4;
    writeUInt32BE(payload, window, offset);
    offset += 4;
    writeUInt32BE(payload, packetSize, offset);
    offset += 4;
    writeUInt32BE(payload, dstAddrBytes.length, offset);
    offset += 4;
    payload.set(dstAddrBytes, offset);
    offset += dstAddrBytes.length;
    writeUInt32BE(payload, dstPort, offset);
    offset += 4;
    writeUInt32BE(payload, srcAddrBytes.length, offset);
    offset += 4;
    payload.set(srcAddrBytes, offset);
    offset += srcAddrBytes.length;
    writeUInt32BE(payload, srcPort, offset);

    this._debug?.(`Outbound: Sending CHANNEL_OPEN (direct-tcpip, l:${localId})`);
    this._sendPacket(payload);
  }

  /**
   * Open forwarded TCP/IP channel (server-side, to notify client of incoming connection)
   */
  forwardedTcpip(
    localId: number,
    window: number,
    packetSize: number,
    opts: { boundAddr: string; boundPort: number; remoteAddr: string; remotePort: number },
  ): void {
    const typeBytes = fromString('forwarded-tcpip');
    const boundAddrBytes = fromString(opts.boundAddr);
    const remoteAddrBytes = fromString(opts.remoteAddr);

    const payload = allocBytes(
      1 + 4 + typeBytes.length + 4 + 4 + 4 +
        4 + boundAddrBytes.length + 4 +
        4 + remoteAddrBytes.length + 4,
    );
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_OPEN;
    writeUInt32BE(payload, typeBytes.length, offset);
    offset += 4;
    payload.set(typeBytes, offset);
    offset += typeBytes.length;
    writeUInt32BE(payload, localId, offset);
    offset += 4;
    writeUInt32BE(payload, window, offset);
    offset += 4;
    writeUInt32BE(payload, packetSize, offset);
    offset += 4;
    writeUInt32BE(payload, boundAddrBytes.length, offset);
    offset += 4;
    payload.set(boundAddrBytes, offset);
    offset += boundAddrBytes.length;
    writeUInt32BE(payload, opts.boundPort, offset);
    offset += 4;
    writeUInt32BE(payload, remoteAddrBytes.length, offset);
    offset += 4;
    payload.set(remoteAddrBytes, offset);
    offset += remoteAddrBytes.length;
    writeUInt32BE(payload, opts.remotePort, offset);

    this._debug?.(`Outbound: Sending CHANNEL_OPEN (forwarded-tcpip, l:${localId})`);
    this._sendPacket(payload);
  }

  /**
   * Open X11 channel (server-side)
   */
  x11(
    localId: number,
    window: number,
    packetSize: number,
    opts: { originAddr: string; originPort: number },
  ): void {
    const typeBytes = fromString('x11');
    const addrBytes = fromString(opts.originAddr);

    const payload = allocBytes(
      1 + 4 + typeBytes.length + 4 + 4 + 4 +
        4 + addrBytes.length + 4,
    );
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_OPEN;
    writeUInt32BE(payload, typeBytes.length, offset);
    offset += 4;
    payload.set(typeBytes, offset);
    offset += typeBytes.length;
    writeUInt32BE(payload, localId, offset);
    offset += 4;
    writeUInt32BE(payload, window, offset);
    offset += 4;
    writeUInt32BE(payload, packetSize, offset);
    offset += 4;
    writeUInt32BE(payload, addrBytes.length, offset);
    offset += 4;
    payload.set(addrBytes, offset);
    offset += addrBytes.length;
    writeUInt32BE(payload, opts.originPort, offset);

    this._debug?.(`Outbound: Sending CHANNEL_OPEN (x11, l:${localId})`);
    this._sendPacket(payload);
  }

  /**
   * Open forwarded stream local channel (server-side, OpenSSH extension)
   */
  openssh_forwardedStreamLocal(
    localId: number,
    window: number,
    packetSize: number,
    opts: { socketPath: string },
  ): void {
    const typeBytes = fromString('forwarded-streamlocal@openssh.com');
    const pathBytes = fromString(opts.socketPath);

    const payload = allocBytes(
      1 + 4 + typeBytes.length + 4 + 4 + 4 +
        4 + pathBytes.length + 4,
    );
    let offset = 0;

    payload[offset++] = MESSAGE.CHANNEL_OPEN;
    writeUInt32BE(payload, typeBytes.length, offset);
    offset += 4;
    payload.set(typeBytes, offset);
    offset += typeBytes.length;
    writeUInt32BE(payload, localId, offset);
    offset += 4;
    writeUInt32BE(payload, window, offset);
    offset += 4;
    writeUInt32BE(payload, packetSize, offset);
    offset += 4;
    writeUInt32BE(payload, pathBytes.length, offset);
    offset += 4;
    payload.set(pathBytes, offset);
    offset += pathBytes.length;
    // Reserved field
    writeUInt32BE(payload, 0, offset);

    this._debug?.(
      `Outbound: Sending CHANNEL_OPEN (forwarded-streamlocal@openssh.com, l:${localId})`,
    );
    this._sendPacket(payload);
  }
}
