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
 *
 * A packet is copied as little as it can be: an outbound one is filled where
 * it is encrypted, and an inbound payload that went through the native
 * cipher is handed on as a view of the native output.
 *
 * Outbound packets with a payload of THREAD_MIN bytes or more, and those that
 * queue behind them, are sealed on a worker thread instead
 * (chachapoly-thread.ts), in batches, so that a download's cipher work leaves
 * the calling thread. Inbound packets are opened here: a message per socket
 * read costs about as much main-thread time as opening its packets saves.
 */

import { createCipheriv } from 'node:crypto';
import { readUInt32BE, writeUInt32BE } from '../utils/binary.ts';
import type { Cipher, CipherConfig, Decipher, DecipherConfig } from './ciphers.ts';
import { CHACHAPOLY_WASM } from './chachapoly-wasm.ts';
import { batchBuffer, sealOnThread } from './chachapoly-thread.ts';
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
    this.mem.set(this.native(len), start);
  }

  /**
   * The len payload bytes at PACKET + 4 encrypted or decrypted by the native
   * ChaCha20, as a buffer of their own; memory is left as it was.
   */
  native(len: number): Uint8Array {
    const start = PACKET + 4;
    this._iv.set(this.mem.subarray(NONCE, NONCE + 8), 8);
    // The native counter is 32-bit little-endian, then a 96-bit nonce:
    // counter(4) || 0x00000000 || nonce(8) is the DJB counter-and-nonce block.
    const cipher = createCipheriv('chacha20', this._keyMain, this._iv);
    const out = cipher.update(this.mem.subarray(start, start + len));
    // Deno keeps the native cipher context in its resource table until final(),
    // so a stream cipher is finalized although it has nothing left to emit.
    cipher.final();
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
  }

  /** Writes the Poly1305 tag of the len bytes at PACKET to out. */
  mac(len: number, out: number): void {
    this.wasm.poly1305(POLY_KEY, PACKET, len, out);
  }
}

/**
 * Payload size from which an outbound packet is sealed on the worker thread
 * even when none of its connection's packets wait there. Smaller ones are
 * sealed here, where they cost less than a message.
 */
const THREAD_MIN = 2048;

/** Outbound packets on their way to the worker thread, back to back in `buf`. */
interface OutBatch {
  buf: ArrayBuffer;
  bytes: Uint8Array;
  used: number;
  /** Sequence number of the first packet. */
  seqno: number;
  /** Settles once the batch's records are written. */
  done: PromiseWithResolvers<void>;
}

/**
 * ChaCha20-Poly1305 Cipher for SSH
 *
 * SSH's chacha20-poly1305@openssh.com uses:
 * - Two 256-bit keys: one for packet length encryption, one for payload
 * - Custom nonce construction using sequence number
 * - Poly1305 MAC over encrypted length + encrypted payload
 *
 * A packet with a payload of THREAD_MIN bytes or more, and every packet after
 * it until the worker thread's batches are written, is sealed on the thread.
 * Its packets are gathered in a batch while an earlier one is out, so that a
 * busy connection sends many per message. Records are written in packet order.
 */
export class ChaChaPolyCipher implements Cipher {
  outSeqno: number;
  private _onWrite: (data: Uint8Array) => void;
  private _state: ChaChaPoly;
  private _key: Uint8Array;
  private _dead = false;
  /** The batch packets are added to, until it is sent. */
  private _batch: OutBatch | undefined;
  /** Batches sent to the thread whose records are not yet written. */
  private _sending = 0;
  /** Settles once the last batch sent is written; each batch writes after the one before. */
  private _written: Promise<void> = Promise.resolve();
  private _flushQueued = false;

  constructor(config: CipherConfig) {
    const enc = config.outbound;
    this.outSeqno = enc.seqno;
    this._onWrite = enc.onWrite;
    this._state = new ChaChaPoly(enc.cipherKey);
    this._key = enc.cipherKey.slice(0, 64);
  }

  free(): void {
    this._dead = true;
    // A batch not yet sent is dropped; those sent are not written.
    this._batch?.done.resolve();
    this._batch = undefined;
  }

  /**
   * The packet is laid out where encrypt() works on it, in the instance's
   * memory or in the batch for the thread, so filling it is the payload's only
   * copy. It is valid until the next allocPacket() or encrypt().
   */
  allocPacket(payloadLen: number): Uint8Array {
    let pktLen = 4 + 1 + payloadLen;
    let padLen = 8 - ((pktLen - 4) & (8 - 1));
    if (padLen < 4) padLen += 8;
    pktLen += padLen;

    let packet: Uint8Array;
    if (payloadLen >= THREAD_MIN || this._busy()) {
      const batch = this._room(pktLen);
      packet = batch.bytes.subarray(batch.used, batch.used + pktLen);
    } else {
      const state = this._state;
      state.reserve(pktLen + 16);
      packet = state.mem.subarray(PACKET, PACKET + pktLen);
    }
    writeUInt32BE(packet, pktLen - 4, 0);
    packet[4] = padLen;
    randomFill(packet, 5 + payloadLen, padLen);

    return packet;
  }

  /**
   * A packet sealed here is written before this returns. One that goes to the
   * thread returns a promise if it starts a batch, settled once the batch is
   * written; one that joins a batch returns nothing, as the batch's promise
   * covers it.
   */
  encrypt(packet: Uint8Array): void | Promise<void> {
    if (this._dead) return;

    const len = packet.length;
    let batch = this._batch;
    const allocated = batch !== undefined && packet.buffer === batch.buf &&
      packet.byteOffset === batch.used;
    if (!allocated && (this._busy() || len >= THREAD_MIN)) {
      batch = this._room(len);
      batch.bytes.set(packet, batch.used);
    } else if (!allocated) {
      this._seal(packet);
      return;
    }

    const first = batch!.used === 0;
    batch!.used += len;
    this.outSeqno = (this.outSeqno + 1) >>> 0;
    if (!this._flushQueued) {
      // Packets encrypted in the same turn go together.
      this._flushQueued = true;
      queueMicrotask(() => {
        this._flushQueued = false;
        if (this._sending === 0) this._sendBatch();
      });
    }
    return first ? batch!.done.promise : undefined;
  }

  /** Whether packets wait on the thread, so that the next one must follow them there. */
  private _busy(): boolean {
    return this._sending > 0 || (this._batch !== undefined && this._batch.used > 0);
  }

  /** The batch with room for a packet of pktLen bytes; a full one is sent. */
  private _room(pktLen: number): OutBatch {
    let batch = this._batch;
    if (batch && batch.used + pktLen > batch.bytes.length) {
      this._sendBatch();
      batch = undefined;
    }
    if (!batch) {
      const buf = batchBuffer(pktLen);
      batch = {
        buf,
        bytes: new Uint8Array(buf),
        used: 0,
        seqno: this.outSeqno,
        done: Promise.withResolvers<void>(),
      };
      this._batch = batch;
    }
    return batch;
  }

  /** Sends the batch being filled to the thread and queues the write of its records. */
  private _sendBatch(): void {
    const batch = this._batch;
    if (!batch || batch.used === 0) return;
    this._batch = undefined;
    this._sending++;
    const sealed = sealOnThread(this._key, batch.seqno, batch.buf, batch.used);
    const previous = this._written;
    this._written = (async () => {
      try {
        const records = await sealed;
        await previous;
        if (!this._dead) this._onWrite(records);
        batch.done.resolve();
      } catch (err) {
        batch.done.reject(err);
      } finally {
        this._sending--;
        if (this._sending === 0) this._sendBatch();
      }
    })();
  }

  /** Seals a packet here and writes its record. */
  private _seal(packet: Uint8Array): void {
    const state = this._state;
    const len = packet.length;
    if (packet.buffer !== state.mem.buffer || packet.byteOffset !== PACKET) {
      state.reserve(len + 16);
      state.mem.set(packet, PACKET);
    }
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

      let payload: Uint8Array;
      if (len < NATIVE_MIN) {
        state.payload(len);
        const padLen = mem[PACKET + 4];
        if (padLen > len - 1) {
          throw new Error('Invalid padding length');
        }
        payload = mem.slice(PACKET + 5, PACKET + 4 + len - padLen);
      } else {
        // The native output is a buffer of its own: the payload is a view of it.
        const plain = state.native(len);
        const padLen = plain[0];
        if (padLen > len - 1) {
          throw new Error('Invalid padding length');
        }
        payload = new Uint8Array(plain.buffer, plain.byteOffset + 1, len - 1 - padLen);
      }

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
