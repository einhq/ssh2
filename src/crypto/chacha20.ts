/**
 * ChaCha20-Poly1305 Cipher implementation for SSH
 *
 * SSH's chacha20-poly1305@openssh.com uses a custom construction different from
 * standard AEAD ChaCha20-Poly1305 (RFC 8439): the original DJB ChaCha20 variant
 * (8-byte nonce, explicit block counter) plus a detached Poly1305 MAC.
 *
 * Poly1305, the length and Poly1305-key blocks, and small payloads run in
 * WebAssembly (chachapoly.wat), one instance per direction, with the packet
 * assembled in its memory. Payloads from NATIVE_MIN bytes on use the runtime's
 * native node:crypto ChaCha20 (requires a Deno version whose node:crypto
 * supports the raw "chacha20" cipher), which is faster once its per-call setup
 * is paid off.
 */

import { createCipheriv } from 'node:crypto';
import { readUInt32BE, writeUInt32BE } from '../utils/binary.ts';
import type { Cipher, CipherConfig, Decipher, DecipherConfig } from './ciphers.ts';
import { CHACHAPOLY_WASM } from './chachapoly-wasm.ts';
import { randomFill } from './random.ts';
import { timingSafeEqual } from './utils.ts';

const MAX_PACKET_SIZE = 35000;

/** Payload size from which the native ChaCha20 beats the WebAssembly one. */
const NATIVE_MIN = 2048;

// Layout of an instance's memory. Bytes 0-63 are the module's own scratch.
const KEY_MAIN = 64; // 32-byte payload key
const KEY_LEN = 96; // 32-byte packet-length key
const NONCE = 128; // 8 bytes: the sequence number, big-endian
const LEN = 136; // 4 bytes: the decrypted packet length
const POLY_KEY = 144; // 32 bytes
const TAG = 176; // 16 bytes: the received MAC
const EXPECTED_TAG = 192; // 16 bytes
const PACKET = 208; // encrypted length, then the packet, then (outbound) its MAC

const PAGE = 65536;
const MODULE = new WebAssembly.Module(CHACHAPOLY_WASM as BufferSource);

interface ChaChaPolyExports {
  memory: WebAssembly.Memory;
  chacha20(key: number, nonce: number, counter: number, data: number, len: number): void;
  poly1305(key: number, msg: number, len: number, out: number): void;
}

/**
 * One direction's ChaCha20-Poly1305 state: a WebAssembly instance holding the
 * 64-byte SSH key (payload key, then length key) and the packet being sealed
 * or opened.
 */
class ChaChaPoly {
  readonly wasm: ChaChaPolyExports;
  mem: Uint8Array;
  private _keyMain: Uint8Array;
  private _iv = new Uint8Array(16);

  constructor(key: Uint8Array) {
    this.wasm = new WebAssembly.Instance(MODULE).exports as unknown as ChaChaPolyExports;
    this.mem = new Uint8Array(this.wasm.memory.buffer);
    this._keyMain = key.slice(0, 32);
    this.mem.set(key.subarray(0, 64), KEY_MAIN);
    // Payloads start at block 1.
    this._iv[0] = 1;
  }

  /** Grows memory so that PACKET + size bytes fit. */
  reserve(size: number): void {
    const need = PACKET + size - this.mem.length;
    if (need > 0) {
      this.wasm.memory.grow(Math.ceil(need / PAGE));
      this.mem = new Uint8Array(this.wasm.memory.buffer);
    }
  }

  /** Sets the nonce for seqno and derives the packet's Poly1305 key. */
  begin(seqno: number): void {
    writeUInt32BE(this.mem, seqno, NONCE + 4);
    this.mem.fill(0, POLY_KEY, POLY_KEY + 32);
    this.wasm.chacha20(KEY_MAIN, NONCE, 0, POLY_KEY, 32);
  }

  /** XORs the 4 bytes at offset with the length keystream. */
  length(offset: number): void {
    this.wasm.chacha20(KEY_LEN, NONCE, 0, offset, 4);
  }

  /** Encrypts or decrypts len payload bytes at PACKET + 4 in place. */
  payload(len: number): void {
    const start = PACKET + 4;
    if (len < NATIVE_MIN) {
      this.wasm.chacha20(KEY_MAIN, NONCE, 1, start, len);
      return;
    }
    this._iv.set(this.mem.subarray(NONCE, NONCE + 8), 8);
    // The native counter is 32-bit little-endian, then a 96-bit nonce:
    // counter(4) || 0x00000000 || nonce(8) is the DJB counter-and-nonce block.
    const cipher = createCipheriv('chacha20', this._keyMain, this._iv);
    this.mem.set(cipher.update(this.mem.subarray(start, start + len)), start);
    // Deno keeps the native cipher context in its resource table until final(),
    // so a stream cipher is finalized although it has nothing left to emit.
    cipher.final();
  }

  /** Writes the Poly1305 tag of the len bytes at PACKET to out. */
  mac(len: number, out: number): void {
    this.wasm.poly1305(POLY_KEY, PACKET, len, out);
  }
}

/**
 * ChaCha20-Poly1305 Cipher for SSH
 *
 * SSH's chacha20-poly1305@openssh.com uses:
 * - Two 256-bit keys: one for packet length encryption, one for payload
 * - Custom nonce construction using sequence number
 * - Poly1305 MAC over encrypted length + encrypted payload
 */
export class ChaChaPolyCipher implements Cipher {
  outSeqno: number;
  private _onWrite: (data: Uint8Array) => void;
  private _state: ChaChaPoly;
  private _dead = false;

  constructor(config: CipherConfig) {
    const enc = config.outbound;
    this.outSeqno = enc.seqno;
    this._onWrite = enc.onWrite;
    this._state = new ChaChaPoly(enc.cipherKey);
  }

  free(): void {
    this._dead = true;
  }

  allocPacket(payloadLen: number): Uint8Array {
    let pktLen = 4 + 1 + payloadLen;
    let padLen = 8 - ((pktLen - 4) & (8 - 1));
    if (padLen < 4) padLen += 8;
    pktLen += padLen;

    const packet = new Uint8Array(pktLen);
    writeUInt32BE(packet, pktLen - 4, 0);
    packet[4] = padLen;
    randomFill(packet, 5 + payloadLen, padLen);

    return packet;
  }

  encrypt(packet: Uint8Array): void {
    if (this._dead) return;

    const state = this._state;
    const len = packet.length;
    state.reserve(len + 16);
    state.mem.set(packet, PACKET);
    state.begin(this.outSeqno);
    state.length(PACKET);
    state.payload(len - 4);
    state.mac(len, PACKET + len);
    this._onWrite(state.mem.slice(PACKET, PACKET + len + 16));

    this.outSeqno = (this.outSeqno + 1) >>> 0;
  }
}

/** Payload callback type that supports both sync and async returns */
type PayloadCallback = (
  payload: Uint8Array,
) => void | boolean | number | Promise<void | boolean | number>;

/**
 * ChaCha20-Poly1305 Decipher for SSH
 *
 * A packet's bytes are gathered at PACKET in the instance's memory as they
 * arrive: the encrypted length, the encrypted packet, then the MAC at TAG.
 */
export class ChaChaPolyDecipher implements Decipher {
  inSeqno: number;
  private _onPayload: PayloadCallback;
  private _state: ChaChaPoly;

  // State for incremental decryption
  private _len = 0;
  private _lenPos = 0;
  private _pktLen = 0;
  private _macPos = 0;

  constructor(config: DecipherConfig) {
    const dec = config.inbound;
    this.inSeqno = dec.seqno;
    this._onPayload = dec.onPayload;
    this._state = new ChaChaPoly(dec.decipherKey);
    this._state.reserve(4 + MAX_PACKET_SIZE);
  }

  free(): void {}

  async decrypt(
    data: Uint8Array,
    p: number,
    dataLen: number,
  ): Promise<void | boolean | number> {
    const state = this._state;
    const mem = state.mem;
    while (p < dataLen) {
      // Read encrypted packet length (4 bytes)
      if (this._lenPos < 4) {
        const nb = Math.min(4 - this._lenPos, dataLen - p);
        mem.set(data.subarray(p, p + nb), PACKET + this._lenPos);
        p += nb;
        this._lenPos += nb;
        if (this._lenPos < 4) return;

        // The MAC covers the encrypted length, so decrypt a copy.
        state.begin(this.inSeqno);
        mem.copyWithin(LEN, PACKET, PACKET + 4);
        state.length(LEN);
        this._len = readUInt32BE(mem, LEN);

        if (this._len > MAX_PACKET_SIZE || this._len < 8 || (this._len & 7) !== 0) {
          throw new Error('Bad packet length');
        }
      }

      // Read encrypted payload
      if (this._pktLen < this._len) {
        if (p >= dataLen) return;
        const nb = Math.min(this._len - this._pktLen, dataLen - p);
        mem.set(data.subarray(p, p + nb), PACKET + 4 + this._pktLen);
        p += nb;
        this._pktLen += nb;
        if (this._pktLen < this._len || p >= dataLen) return;
      }

      // Read Poly1305 MAC (16 bytes)
      {
        const nb = Math.min(16 - this._macPos, dataLen - p);
        mem.set(data.subarray(p, p + nb), TAG + this._macPos);
        p += nb;
        this._macPos += nb;
        if (this._macPos < 16) return;
      }

      const len = this._len;
      state.mac(4 + len, EXPECTED_TAG);
      if (
        !timingSafeEqual(
          mem.subarray(EXPECTED_TAG, EXPECTED_TAG + 16),
          mem.subarray(TAG, TAG + 16),
        )
      ) {
        throw new Error('Invalid MAC');
      }

      state.payload(len);

      const padLen = mem[PACKET + 4];
      if (padLen > len - 1) {
        throw new Error('Invalid padding length');
      }
      const payload = mem.slice(PACKET + 5, PACKET + 4 + len - padLen);

      // Prepare for next packet
      this.inSeqno = (this.inSeqno + 1) >>> 0;
      this._len = 0;
      this._lenPos = 0;
      this._pktLen = 0;
      this._macPos = 0;

      const ret = await this._onPayload(payload);
      if (ret !== undefined) {
        return ret === false ? p : ret;
      }
    }
  }
}
