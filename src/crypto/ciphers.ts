/**
 * SSH Cipher implementations using Web Crypto API
 *
 * Implements AES-GCM, AES-CTR, AES-CBC, and ChaCha20-Poly1305 ciphers for SSH protocol.
 */

import { decryptNoPad, encryptNoPad } from './aes-cbc.ts';
import type { CipherInfo, MACInfo } from '../protocol/constants.ts';
import { allocBytes, concatBytes, readUInt32BE, writeUInt32BE } from '../utils/binary.ts';
import { ChaChaPolyCipher, ChaChaPolyDecipher } from './chacha20.ts';
import { hmac } from './hash.ts';
import { randomFill } from './random.ts';
import { incrementCounter, timingSafeEqual } from './utils.ts';

const MAX_PACKET_SIZE = 35000;

/** Configuration for outbound (encryption) */
export interface OutboundConfig {
  seqno: number;
  onWrite: (data: Uint8Array) => void;
  cipherInfo: CipherInfo;
  cipherKey: Uint8Array;
  cipherIV: Uint8Array;
  macInfo?: MACInfo;
  macKey?: Uint8Array;
}

/** Configuration for inbound (decryption) */
export interface InboundConfig {
  seqno: number;
  onPayload: (payload: Uint8Array) => void | boolean | number | Promise<void | boolean | number>;
  decipherInfo: CipherInfo;
  decipherKey: Uint8Array;
  decipherIV: Uint8Array;
  macInfo?: MACInfo;
  macKey?: Uint8Array;
}

/** Cipher configuration */
export interface CipherConfig {
  outbound: OutboundConfig;
}

/** Decipher configuration */
export interface DecipherConfig {
  inbound: InboundConfig;
}

/** Base cipher interface */
export interface Cipher {
  outSeqno: number;
  free(): void;
  allocPacket(payloadLen: number): Uint8Array;
  /** Reserve sequence/IV state and transport write order before the first await. */
  encrypt(packet: Uint8Array): void | Promise<void>;
}

/** Base decipher interface */
export interface Decipher {
  inSeqno: number;
  free(): void;
  decrypt(data: Uint8Array, p: number, dataLen: number): Promise<void | boolean | number>;
}

/**
 * Null cipher - used during initial handshake (no encryption)
 */
export class NullCipher implements Cipher {
  outSeqno: number;
  private _onWrite: (data: Uint8Array) => void;
  private _dead = false;

  constructor(seqno: number, onWrite: (data: Uint8Array) => void) {
    this.outSeqno = seqno;
    this._onWrite = onWrite;
  }

  free(): void {
    this._dead = true;
  }

  allocPacket(payloadLen: number): Uint8Array {
    let pktLen = 4 + 1 + payloadLen;
    let padLen = 8 - (pktLen & (8 - 1));
    if (padLen < 4) padLen += 8;
    pktLen += padLen;

    const packet = allocBytes(pktLen);
    writeUInt32BE(packet, pktLen - 4, 0);
    packet[4] = padLen;
    randomFill(packet, 5 + payloadLen, padLen);

    return packet;
  }

  encrypt(packet: Uint8Array): void {
    if (this._dead) return;
    this._onWrite(packet);
    this.outSeqno = (this.outSeqno + 1) >>> 0;
  }
}

/** Payload callback type that supports both sync and async returns */
type PayloadCallback = (
  payload: Uint8Array,
) => void | boolean | number | Promise<void | boolean | number>;

/**
 * Null decipher - used during initial handshake (no decryption)
 */
export class NullDecipher implements Decipher {
  inSeqno: number;
  private _onPayload: PayloadCallback;
  private _len = 0;
  private _lenBytes = 0;
  private _packet: Uint8Array | null = null;
  private _packetPos = 0;

  constructor(seqno: number, onPayload: PayloadCallback) {
    this.inSeqno = seqno;
    this._onPayload = onPayload;
  }

  free(): void {}

  async decrypt(
    data: Uint8Array,
    p: number,
    dataLen: number,
  ): Promise<void | boolean | number> {
    while (p < dataLen) {
      // Read packet length (4 bytes, big-endian)
      if (this._lenBytes < 4) {
        let nb = Math.min(4 - this._lenBytes, dataLen - p);
        this._lenBytes += nb;
        while (nb--) {
          this._len = (this._len << 8) + data[p++];
        }
        if (this._lenBytes < 4) return;

        if (this._len > MAX_PACKET_SIZE || this._len < 8 || ((4 + this._len) & 7) !== 0) {
          throw new Error('Bad packet length');
        }
        if (p >= dataLen) return;
      }

      // Read padding length, payload, and padding
      if (this._packetPos < this._len) {
        const nb = Math.min(this._len - this._packetPos, dataLen - p);
        const chunk = data.subarray(p, p + nb);
        if (nb === this._len) {
          // A copy: the payload may be kept (KEXINIT), and the caller reuses data.
          this._packet = chunk.slice();
        } else {
          if (!this._packet) {
            this._packet = allocBytes(this._len);
          }
          this._packet.set(chunk, this._packetPos);
        }
        p += nb;
        this._packetPos += nb;
        if (this._packetPos < this._len) return;
      }

      const packet = this._packet!;
      const padLen = packet[0];
      const payload = packet.subarray(1, packet.length - padLen);

      // Prepare for next packet
      this.inSeqno = (this.inSeqno + 1) >>> 0;
      this._len = 0;
      this._lenBytes = 0;
      this._packet = null;
      this._packetPos = 0;

      const ret = await this._onPayload(payload);
      if (ret !== undefined) {
        return ret === false ? p : ret;
      }
    }
  }
}

/**
 * AES-GCM Cipher
 * Seals with Web Crypto: Deno's node:crypto AES-GCM is about a third as fast.
 * Uses a write queue to ensure packets are sent in order, even when
 * multiple encrypt() calls happen concurrently.
 */
export class AESGCMCipher implements Cipher {
  outSeqno: number;
  private _onWrite: (data: Uint8Array) => void;
  private _encKey: CryptoKey | null = null;
  private _encKeyPending: Promise<CryptoKey> | null = null;
  private _encKeyRaw: Uint8Array;
  private _encIV: Uint8Array;
  private _dead = false;
  // Queue to serialize writes
  private _writeQueue: Promise<void> = Promise.resolve();

  constructor(config: CipherConfig) {
    const enc = config.outbound;
    this.outSeqno = enc.seqno;
    this._onWrite = enc.onWrite;
    this._encKeyRaw = enc.cipherKey;
    // Make a copy of the IV to avoid sharing with other components
    this._encIV = new Uint8Array(enc.cipherIV);
  }

  private _getKey(): Promise<CryptoKey> {
    if (this._encKey) {
      return Promise.resolve(this._encKey);
    }
    if (this._encKeyPending) {
      return this._encKeyPending;
    }
    this._encKeyPending = crypto.subtle.importKey(
      'raw',
      this._encKeyRaw as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['encrypt'],
    ).then((key) => {
      this._encKey = key;
      this._encKeyPending = null;
      return key;
    });
    return this._encKeyPending;
  }

  free(): void {
    this._dead = true;
    this._encKey = null;
  }

  allocPacket(payloadLen: number): Uint8Array {
    let pktLen = 4 + 1 + payloadLen;
    let padLen = 16 - ((pktLen - 4) & (16 - 1));
    if (padLen < 4) padLen += 16;
    pktLen += padLen;

    const packet = allocBytes(pktLen);
    writeUInt32BE(packet, pktLen - 4, 0);
    packet[4] = padLen;
    randomFill(packet, 5 + payloadLen, padLen);

    return packet;
  }

  async encrypt(packet: Uint8Array): Promise<void> {
    if (this._dead) return;

    // Capture IV and increment synchronously BEFORE any await
    // to prevent race conditions when multiple packets are encrypted concurrently
    const iv = new Uint8Array(this._encIV);
    incrementCounter(this._encIV);
    this.outSeqno = (this.outSeqno + 1) >>> 0;

    // Length bytes are Additional Authenticated Data (AAD)
    const lenData = packet.subarray(0, 4);
    const plaintext = packet.subarray(4);

    // Reserve our position in the write queue BEFORE any async operations
    // This ensures packets are written in the same order as IV assignment
    const { resolve, promise: myTurn } = Promise.withResolvers<void>();
    const previousWrite = this._writeQueue;
    this._writeQueue = myTurn;

    // Now do the async encryption
    const key = await this._getKey();

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        additionalData: lenData as BufferSource,
        tagLength: 128,
      },
      key,
      plaintext as BufferSource,
    );

    // Wait for previous writes to complete before writing ours
    await previousWrite;

    if (!this._dead) {
      // Write: length (unencrypted) + ciphertext + tag as a single buffer
      const ciphertextBytes = new Uint8Array(ciphertext);
      const combined = allocBytes(lenData.length + ciphertextBytes.length);
      combined.set(lenData, 0);
      combined.set(ciphertextBytes, lenData.length);
      this._onWrite(combined);
    }

    // Signal that our write is done
    resolve();
  }
}

/**
 * AES-GCM Decipher
 */
export class AESGCMDecipher implements Decipher {
  inSeqno: number;
  private _onPayload: PayloadCallback;
  private _decKey: CryptoKey | null = null;
  private _decKeyRaw: Uint8Array;
  private _decIV: Uint8Array;
  private _len = 0;
  private _lenBuf = allocBytes(4);
  private _lenPos = 0;
  private _packet: Uint8Array | null = null;
  private _pktLen = 0;
  private _tag = allocBytes(16);
  private _tagPos = 0;

  constructor(config: DecipherConfig) {
    const dec = config.inbound;
    this.inSeqno = dec.seqno;
    this._onPayload = dec.onPayload;
    this._decKeyRaw = dec.decipherKey;
    // Make a copy of the IV to avoid sharing with other components
    this._decIV = new Uint8Array(dec.decipherIV);
  }

  private async _getKey(): Promise<CryptoKey> {
    if (!this._decKey) {
      this._decKey = await crypto.subtle.importKey(
        'raw',
        this._decKeyRaw as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['decrypt'],
      );
    }
    return this._decKey;
  }

  free(): void {
    this._decKey = null;
  }

  async decrypt(
    data: Uint8Array,
    p: number,
    dataLen: number,
  ): Promise<void | boolean | number> {
    while (p < dataLen) {
      // Read packet length (4 bytes, unencrypted)
      if (this._lenPos < 4) {
        const nb = Math.min(4 - this._lenPos, dataLen - p);
        for (let i = 0; i < nb; i++) {
          this._lenBuf[this._lenPos++] = data[p++];
        }
        if (this._lenPos < 4) return;

        this._len = readUInt32BE(this._lenBuf, 0);

        if (this._len > MAX_PACKET_SIZE || this._len < 8 || (this._len & 15) !== 0) {
          throw new Error('Bad packet length');
        }
      }

      // Read encrypted payload
      if (this._pktLen < this._len) {
        if (p >= dataLen) return;
        const nb = Math.min(this._len - this._pktLen, dataLen - p);
        const chunk = data.subarray(p, p + nb);
        if (nb === this._len) {
          this._packet = new Uint8Array(chunk);
        } else {
          if (!this._packet) {
            this._packet = allocBytes(this._len);
          }
          this._packet.set(chunk, this._pktLen);
        }
        p += nb;
        this._pktLen += nb;
        if (this._pktLen < this._len || p >= dataLen) return;
      }

      // Read authentication tag (16 bytes)
      {
        const nb = Math.min(16 - this._tagPos, dataLen - p);
        for (let i = 0; i < nb; i++) {
          this._tag[this._tagPos++] = data[p++];
        }
        if (this._tagPos < 16) return;
      }

      const key = await this._getKey();

      // Combine ciphertext and tag for Web Crypto
      const ciphertextWithTag = concatBytes([this._packet!, this._tag]);

      // Decrypt with AES-GCM
      let plaintext: Uint8Array;
      try {
        const decrypted = await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: this._decIV as BufferSource,
            additionalData: this._lenBuf as BufferSource,
            tagLength: 128,
          },
          key,
          ciphertextWithTag as BufferSource,
        );
        plaintext = new Uint8Array(decrypted);
      } catch {
        // Do not leak the IV, sequence number, or lengths in the thrown error;
        // authentication failure is all the caller needs to know.
        throw new Error('Invalid MAC');
      }

      const padLen = plaintext[0];
      if (padLen > plaintext.length - 1) {
        throw new Error('Invalid padding length');
      }
      const payload = plaintext.subarray(1, plaintext.length - padLen);

      // Increment IV for next packet
      incrementCounter(this._decIV);

      // Prepare for next packet
      this.inSeqno = (this.inSeqno + 1) >>> 0;
      this._len = 0;
      this._lenPos = 0;
      this._packet = null;
      this._pktLen = 0;
      this._tagPos = 0;

      const ret = await this._onPayload(payload);
      if (ret !== undefined) {
        return ret === false ? p : ret;
      }
    }
  }
}

/**
 * Generic Cipher with HMAC (for AES-CTR, AES-CBC)
 * Uses a write queue to ensure packets are sent in order, even when
 * multiple encrypt() calls happen concurrently.
 */
export class GenericCipher implements Cipher {
  outSeqno: number;
  private _onWrite: (data: Uint8Array) => void;
  private _encKey: CryptoKey | null = null;
  private _encKeyPending: Promise<CryptoKey> | null = null;
  private _encKeyRaw: Uint8Array;
  private _encIV: Uint8Array;
  private _macKey: Uint8Array;
  private _macAlgorithm: string;
  private _macActualLen: number;
  private _macETM: boolean;
  private _blockLen: number;
  private _aadLen: number;
  private _cipherMode: 'AES-CTR' | 'AES-CBC';
  private _dead = false;
  // Queue to serialize writes
  private _writeQueue: Promise<void> = Promise.resolve();
  // Queue to serialize CBC encryption (next IV = last ciphertext block)
  private _cbcQueue: Promise<void> = Promise.resolve();

  constructor(config: CipherConfig) {
    const enc = config.outbound;
    this.outSeqno = enc.seqno;
    this._onWrite = enc.onWrite;
    this._encKeyRaw = enc.cipherKey;
    this._encIV = new Uint8Array(enc.cipherIV); // Copy to allow modification
    this._macKey = enc.macKey!;
    this._macAlgorithm = enc.macInfo!.sslName;
    this._macActualLen = enc.macInfo!.actualLen;
    this._macETM = enc.macInfo!.isETM;
    this._blockLen = enc.cipherInfo.blockLen;
    this._aadLen = this._macETM ? 4 : 0;

    // Determine cipher mode from sslName
    if (enc.cipherInfo.sslName.includes('ctr')) {
      this._cipherMode = 'AES-CTR';
    } else {
      this._cipherMode = 'AES-CBC';
    }
  }

  private _getKey(): Promise<CryptoKey> {
    if (this._encKey) {
      return Promise.resolve(this._encKey);
    }
    if (this._encKeyPending) {
      return this._encKeyPending;
    }
    this._encKeyPending = crypto.subtle.importKey(
      'raw',
      this._encKeyRaw as BufferSource,
      { name: this._cipherMode },
      false,
      ['encrypt'],
    ).then((key) => {
      this._encKey = key;
      this._encKeyPending = null;
      return key;
    });
    return this._encKeyPending;
  }

  free(): void {
    this._dead = true;
    this._encKey = null;
  }

  allocPacket(payloadLen: number): Uint8Array {
    const blockLen = this._blockLen;
    let pktLen = 4 + 1 + payloadLen;
    let padLen = blockLen - ((pktLen - this._aadLen) & (blockLen - 1));
    if (padLen < 4) padLen += blockLen;
    pktLen += padLen;

    const packet = allocBytes(pktLen);
    writeUInt32BE(packet, pktLen - 4, 0);
    packet[4] = padLen;
    randomFill(packet, 5 + payloadLen, padLen);

    return packet;
  }

  async encrypt(packet: Uint8Array): Promise<void> {
    if (this._dead) return;

    // Capture seqno synchronously BEFORE any await
    // to prevent race conditions when multiple packets are encrypted concurrently
    const seqnoBuf = allocBytes(4);
    writeUInt32BE(seqnoBuf, this.outSeqno, 0);
    this.outSeqno = (this.outSeqno + 1) >>> 0;

    // Reserve our position in the write queue BEFORE any async operations
    const { resolve, promise: myTurn } = Promise.withResolvers<void>();
    const previousWrite = this._writeQueue;
    this._writeQueue = myTurn;

    let encrypted: Uint8Array;
    let mac: Uint8Array;
    let lenBytes: Uint8Array | undefined;

    if (this._cipherMode === 'AES-CBC') {
      // Raw AES-CBC (no PKCS#7 padding) via Web Crypto. Each packet's IV is
      // the previous packet's last ciphertext block and Web Crypto is async,
      // so encryption is serialized through its own queue to preserve IV
      // ordering when encrypt() is called concurrently.
      const previousEncrypt = this._cbcQueue;
      const { resolve: encryptDone, promise: encryptTurn } = Promise.withResolvers<void>();
      this._cbcQueue = encryptTurn;
      await previousEncrypt;
      try {
        const key = await this._getKey();
        if (this._macETM) {
          lenBytes = packet.subarray(0, 4);
          const toEncrypt = packet.subarray(4);
          encrypted = await encryptNoPad(key, this._encIV, toEncrypt);
          // Update IV to last ciphertext block for next packet
          this._encIV.set(encrypted.subarray(encrypted.length - this._blockLen));
          mac = await hmac(
            this._macAlgorithm,
            this._macKey,
            concatBytes([seqnoBuf, lenBytes, encrypted]),
          );
        } else {
          // MAC-then-Encrypt: MAC is over plaintext, then encrypt
          encrypted = await encryptNoPad(key, this._encIV, packet);
          // Update IV to last ciphertext block for next packet
          this._encIV.set(encrypted.subarray(encrypted.length - this._blockLen));
          mac = await hmac(this._macAlgorithm, this._macKey, concatBytes([seqnoBuf, packet]));
        }
      } finally {
        encryptDone();
      }
    } else {
      // AES-CTR: use Web Crypto.
      // Capture IV and increment synchronously BEFORE any await.
      const iv = new Uint8Array(this._encIV);
      const dataLen = this._macETM ? packet.length - 4 : packet.length;
      const blocks = Math.ceil(dataLen / this._blockLen);
      for (let i = 0; i < blocks; i++) {
        incrementCounter(this._encIV);
      }

      const key = await this._getKey();

      if (this._macETM) {
        lenBytes = packet.subarray(0, 4);
        const toEncrypt = packet.subarray(4);
        const ciphertext = await crypto.subtle.encrypt(
          { name: 'AES-CTR', counter: iv as BufferSource, length: 128 },
          key,
          toEncrypt as BufferSource,
        );
        encrypted = new Uint8Array(ciphertext);
        mac = await hmac(
          this._macAlgorithm,
          this._macKey,
          concatBytes([seqnoBuf, lenBytes, encrypted]),
        );
      } else {
        // MAC-then-Encrypt
        const macInput = concatBytes([seqnoBuf, packet]);
        mac = await hmac(this._macAlgorithm, this._macKey, macInput);
        const ciphertext = await crypto.subtle.encrypt(
          { name: 'AES-CTR', counter: iv as BufferSource, length: 128 },
          key,
          packet as BufferSource,
        );
        encrypted = new Uint8Array(ciphertext);
      }
    }

    // Truncate MAC if needed
    if (mac.length > this._macActualLen) {
      mac = mac.subarray(0, this._macActualLen);
    }

    // Wait for previous writes to complete before writing ours
    await previousWrite;

    if (!this._dead) {
      // Combine all parts into a single write to prevent TCP fragmentation
      if (this._macETM && lenBytes) {
        const combined = allocBytes(lenBytes.length + encrypted.length + mac.length);
        combined.set(lenBytes, 0);
        combined.set(encrypted, lenBytes.length);
        combined.set(mac, lenBytes.length + encrypted.length);
        this._onWrite(combined);
      } else {
        const combined = allocBytes(encrypted.length + mac.length);
        combined.set(encrypted, 0);
        combined.set(mac, encrypted.length);
        this._onWrite(combined);
      }
    }

    // Signal that our write is done
    resolve();
  }
}

/**
 * Generic Decipher with HMAC (for AES-CTR, AES-CBC)
 */
export class GenericDecipher implements Decipher {
  inSeqno: number;
  private _onPayload: PayloadCallback;
  private _decKey: CryptoKey | null = null;
  private _decKeyRaw: Uint8Array;
  private _decIV: Uint8Array;
  private _macKey: Uint8Array;
  private _macAlgorithm: string;
  private _macActualLen: number;
  private _macETM: boolean;
  private _blockLen: number;
  private _cipherMode: 'AES-CTR' | 'AES-CBC';

  // State for incremental decryption
  private _len = 0;
  private _lenBuf = allocBytes(4);
  private _lenPos = 0;
  private _packet: Uint8Array | null = null;
  private _pktLen = 0;
  private _mac: Uint8Array;
  private _macPos = 0;
  private _firstBlock: Uint8Array | null = null;
  private _firstBlockDecrypted = false;

  constructor(config: DecipherConfig) {
    const dec = config.inbound;
    this.inSeqno = dec.seqno;
    this._onPayload = dec.onPayload;
    this._decKeyRaw = dec.decipherKey;
    this._decIV = new Uint8Array(dec.decipherIV);
    this._macKey = dec.macKey!;
    this._macAlgorithm = dec.macInfo!.sslName;
    this._macActualLen = dec.macInfo!.actualLen;
    this._macETM = dec.macInfo!.isETM;
    this._blockLen = dec.decipherInfo.blockLen;
    this._mac = allocBytes(this._macActualLen);

    if (dec.decipherInfo.sslName.includes('ctr')) {
      this._cipherMode = 'AES-CTR';
    } else {
      this._cipherMode = 'AES-CBC';
    }
  }

  private async _getKey(): Promise<CryptoKey> {
    if (!this._decKey) {
      // CBC also needs 'encrypt': decryptNoPad crafts a trailer block with
      // a single-block encryption to bypass Web Crypto's PKCS#7 handling
      const usages: KeyUsage[] = this._cipherMode === 'AES-CBC'
        ? ['encrypt', 'decrypt']
        : ['decrypt'];
      this._decKey = await crypto.subtle.importKey(
        'raw',
        this._decKeyRaw as BufferSource,
        { name: this._cipherMode },
        false,
        usages,
      );
    }
    return this._decKey;
  }

  free(): void {
    this._decKey = null;
  }

  async decrypt(
    data: Uint8Array,
    p: number,
    dataLen: number,
  ): Promise<void | boolean | number> {
    while (p < dataLen) {
      if (this._macETM) {
        // Encrypt-then-MAC: length is unencrypted
        if (this._lenPos < 4) {
          const nb = Math.min(4 - this._lenPos, dataLen - p);
          for (let i = 0; i < nb; i++) {
            this._lenBuf[this._lenPos++] = data[p++];
          }
          if (this._lenPos < 4) return;

          this._len = readUInt32BE(this._lenBuf, 0);
          if (this._len > MAX_PACKET_SIZE || this._len < 8) {
            throw new Error('Bad packet length');
          }
        }
      } else {
        // MAC-then-Encrypt: need to decrypt first block to get length
        if (!this._firstBlockDecrypted) {
          if (this._lenPos < this._blockLen) {
            const nb = Math.min(this._blockLen - this._lenPos, dataLen - p);
            if (!this._firstBlock) {
              this._firstBlock = allocBytes(this._blockLen);
            }
            for (let i = 0; i < nb; i++) {
              this._firstBlock[this._lenPos++] = data[p++];
            }
            if (this._lenPos < this._blockLen) return;
          }

          // Decrypt first block to get length
          let decryptedBlock: Uint8Array;
          if (this._cipherMode === 'AES-CBC') {
            decryptedBlock = await decryptNoPad(
              await this._getKey(),
              this._decIV,
              this._firstBlock!,
            );
          } else {
            const key = await this._getKey();
            const decrypted = await crypto.subtle.decrypt(
              { name: 'AES-CTR', counter: this._decIV as BufferSource, length: 128 },
              key,
              this._firstBlock as BufferSource,
            );
            decryptedBlock = new Uint8Array(decrypted);
          }

          this._len = readUInt32BE(decryptedBlock, 0);
          if (this._len > MAX_PACKET_SIZE || this._len < 8) {
            throw new Error('Bad packet length');
          }

          // Store decrypted first block
          this._packet = allocBytes(4 + this._len);
          this._packet.set(decryptedBlock, 0);
          this._pktLen = this._blockLen;
          this._firstBlockDecrypted = true;

          // Update IV: for CBC, next IV = the ciphertext block we just decrypted
          if (this._cipherMode === 'AES-CBC') {
            this._decIV.set(this._firstBlock!);
          } else {
            incrementCounter(this._decIV);
          }
        }
      }

      // Read encrypted payload
      const totalLen = this._macETM ? this._len : 4 + this._len;
      if (this._pktLen < totalLen) {
        if (p >= dataLen) return;
        const nb = Math.min(totalLen - this._pktLen, dataLen - p);
        const chunk = data.subarray(p, p + nb);

        if (!this._packet) {
          this._packet = allocBytes(totalLen);
        }
        this._packet.set(chunk, this._pktLen);
        p += nb;
        this._pktLen += nb;
        if (this._pktLen < totalLen) return;
      }

      // Read MAC
      {
        const nb = Math.min(this._macActualLen - this._macPos, dataLen - p);
        for (let i = 0; i < nb; i++) {
          this._mac[this._macPos++] = data[p++];
        }
        if (this._macPos < this._macActualLen) return;
      }

      const seqnoBuf = allocBytes(4);
      writeUInt32BE(seqnoBuf, this.inSeqno, 0);

      let payload: Uint8Array;

      if (this._macETM) {
        // Verify MAC first (over seqno + length + encrypted)
        const macInput = concatBytes([seqnoBuf, this._lenBuf, this._packet!]);
        const expectedMac = await hmac(this._macAlgorithm, this._macKey, macInput);
        const expectedMacTruncated = expectedMac.subarray(0, this._macActualLen);

        if (!timingSafeEqual(expectedMacTruncated, this._mac)) {
          throw new Error('Invalid MAC');
        }

        // Decrypt
        let plaintext: Uint8Array;
        if (this._cipherMode === 'AES-CBC') {
          // Save last ciphertext block for IV update before decryption overwrites _packet
          const lastCiphertextBlock = new Uint8Array(
            this._packet!.subarray(this._packet!.length - this._blockLen),
          );
          plaintext = await decryptNoPad(await this._getKey(), this._decIV, this._packet!);
          this._decIV.set(lastCiphertextBlock);
        } else {
          const key = await this._getKey();
          const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CTR', counter: this._decIV as BufferSource, length: 128 },
            key,
            this._packet as BufferSource,
          );
          plaintext = new Uint8Array(decrypted);
          const blocks = Math.ceil(this._packet!.length / this._blockLen);
          for (let i = 0; i < blocks; i++) {
            incrementCounter(this._decIV);
          }
        }

        const padLen = plaintext[0];
        payload = plaintext.subarray(1, plaintext.length - padLen);
      } else {
        // Decrypt remaining blocks (first block already decrypted)
        if (this._pktLen > this._blockLen) {
          // _packet[0..blockLen-1] = already-decrypted first block
          // _packet[blockLen..] = raw ciphertext for remaining blocks
          const remaining = this._packet!.subarray(this._blockLen);
          if (this._cipherMode === 'AES-CBC') {
            // Save last ciphertext block for IV update before we overwrite _packet
            const lastCiphertextBlock = new Uint8Array(
              remaining.subarray(remaining.length - this._blockLen),
            );
            const decrypted = await decryptNoPad(await this._getKey(), this._decIV, remaining);
            this._packet!.set(decrypted, this._blockLen);
            // Update IV to last ciphertext block for next packet
            this._decIV.set(lastCiphertextBlock);
          } else {
            const key = await this._getKey();
            const decrypted = await crypto.subtle.decrypt(
              { name: 'AES-CTR', counter: this._decIV as BufferSource, length: 128 },
              key,
              remaining as BufferSource,
            );
            this._packet!.set(new Uint8Array(decrypted), this._blockLen);
            const remainingBlocks = Math.ceil(remaining.length / this._blockLen);
            for (let i = 0; i < remainingBlocks; i++) {
              incrementCounter(this._decIV);
            }
          }
        }

        // Verify MAC (over seqno + decrypted packet)
        const macInput = concatBytes([seqnoBuf, this._packet!]);
        const expectedMac = await hmac(this._macAlgorithm, this._macKey, macInput);
        const expectedMacTruncated = expectedMac.subarray(0, this._macActualLen);

        if (!timingSafeEqual(expectedMacTruncated, this._mac)) {
          throw new Error('Invalid MAC');
        }

        const padLen = this._packet![4];
        payload = this._packet!.subarray(5, 4 + this._len - padLen);
      }

      // Prepare for next packet
      this.inSeqno = (this.inSeqno + 1) >>> 0;
      this._len = 0;
      this._lenPos = 0;
      this._packet = null;
      this._pktLen = 0;
      this._macPos = 0;
      this._firstBlock = null;
      this._firstBlockDecrypted = false;

      const ret = await this._onPayload(payload);
      if (ret !== undefined) {
        return ret === false ? p : ret;
      }
    }
  }
}

/**
 * Create appropriate cipher based on cipher info
 */
export function createCipher(config: CipherConfig): Cipher {
  const cipherName = config.outbound.cipherInfo.sslName;

  if (cipherName === 'chacha20') {
    return new ChaChaPolyCipher(config);
  } else if (cipherName.includes('gcm')) {
    return new AESGCMCipher(config);
  } else if (cipherName.includes('ctr') || cipherName.includes('cbc')) {
    return new GenericCipher(config);
  }

  throw new Error(`Unsupported cipher: ${cipherName}`);
}

/**
 * Create appropriate decipher based on cipher info
 */
export function createDecipher(config: DecipherConfig): Decipher {
  const cipherName = config.inbound.decipherInfo.sslName;

  if (cipherName === 'chacha20') {
    return new ChaChaPolyDecipher(config);
  } else if (cipherName.includes('gcm')) {
    return new AESGCMDecipher(config);
  } else if (cipherName.includes('ctr') || cipherName.includes('cbc')) {
    return new GenericDecipher(config);
  }

  throw new Error(`Unsupported cipher: ${cipherName}`);
}
