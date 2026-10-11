/**
 * Tests for chacha20-poly1305@openssh.com: the WebAssembly ChaCha20 and
 * Poly1305 primitives in src/crypto/chachapoly.wat, and the cipher built on
 * them in src/crypto/chacha20.ts.
 *
 * ChaCha20 known-answer vectors were generated with Node.js v24 (OpenSSL) for
 * the DJB 8-byte-nonce variant via the counter(4 LE) || 0x00000000 || nonce(8)
 * IV mapping. Poly1305 vectors are from RFC 8439. The sealed-record vectors
 * were produced by the TypeScript Poly1305 and native ChaCha20 that ssh2-ts
 * used before, which interoperated with OpenSSH.
 */

import { assertEquals, assertRejects } from '@std/assert';
import { createCipheriv } from 'node:crypto';
import { generate } from '../scripts/build-wasm.ts';
import { CHACHAPOLY_WASM } from '../src/crypto/chachapoly-wasm.ts';
import { ChaChaPolyCipher, ChaChaPolyDecipher } from '../src/crypto/chacha20.ts';
import { CIPHER_INFO } from '../src/protocol/constants.ts';
import { fromHex, toHex } from '../src/utils/binary.ts';

interface Primitives {
  memory: WebAssembly.Memory;
  chacha20(key: number, nonce: number, counter: number, data: number, len: number): void;
  poly1305(key: number, msg: number, len: number, out: number): void;
}

const wasm = new WebAssembly.Instance(new WebAssembly.Module(CHACHAPOLY_WASM as BufferSource))
  .exports as unknown as Primitives;
const mem = new Uint8Array(wasm.memory.buffer);
const KEY = 64;
const NONCE = 96;
const OUT = 112;
const DATA = 128;

function chacha20(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, counter = 0): Uint8Array {
  mem.set(key, KEY);
  mem.set(nonce, NONCE);
  mem.set(data, DATA);
  wasm.chacha20(KEY, NONCE, counter, DATA, data.length);
  return mem.slice(DATA, DATA + data.length);
}

function poly1305(msg: Uint8Array, key: Uint8Array): Uint8Array {
  mem.set(key, KEY);
  mem.set(msg, DATA);
  wasm.poly1305(KEY, DATA, msg.length, OUT);
  return mem.slice(OUT, OUT + 16);
}

function nativeChacha20(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  counter: number,
): Uint8Array {
  const iv = new Uint8Array(16);
  iv[0] = counter;
  iv.set(nonce, 8);
  return new Uint8Array(createCipheriv('chacha20', key, iv).update(data));
}

Deno.test('chachapoly-wasm.ts is assembled from chachapoly.wat', async () => {
  const current = await Deno.readTextFile(
    new URL('../src/crypto/chachapoly-wasm.ts', import.meta.url),
  );
  assertEquals(current, await generate(), 'run `deno task build:wasm`');
});

Deno.test('chacha20 DJB variant known-answer vectors', () => {
  const key = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const nonce = fromHex('0000000000000001');
  const data = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223');

  assertEquals(
    toHex(chacha20(key, nonce, data, 0)),
    '0122bbe21eff8fa1a1402169fd5cf4e42ab2fe48fde9a867a841a54886ea65f368661c5a',
  );
  assertEquals(
    toHex(chacha20(key, nonce, data, 1)),
    '695d7eda350fbe7d25787424bf19191d00e02d53daa4ea625d23af3335f38115f30cce29',
  );
});

Deno.test('chacha20 zero key/nonce keystream', () => {
  // Counter 0: first ChaCha20 block, matches RFC 8439 A.1 test vector #1
  assertEquals(
    toHex(chacha20(new Uint8Array(32), new Uint8Array(8), new Uint8Array(16))),
    '76b8e0ada0f13d90405d6ae55386bd28',
  );
  // Counter 1: second block
  assertEquals(
    toHex(chacha20(new Uint8Array(32), new Uint8Array(8), new Uint8Array(16), 1)),
    '9f07e7be5551387a98ba977c732d080d',
  );
});

Deno.test('chacha20 matches the native cipher across block boundaries', () => {
  const key = fromHex('ff'.repeat(16) + '0123456789abcdef'.repeat(2));
  const nonce = fromHex('0102030405060708');
  for (const len of [1, 4, 63, 64, 65, 127, 128, 129, 1000, 4096 + 17]) {
    const data = Uint8Array.from({ length: len }, (_, i) => (i * 7) & 0xff);
    for (const counter of [0, 1, 2]) {
      assertEquals(
        toHex(chacha20(key, nonce, data, counter)),
        toHex(nativeChacha20(key, nonce, data, counter)),
        `len ${len}, counter ${counter}`,
      );
    }
  }
});

Deno.test('poly1305 RFC 8439 §2.5.2 test vector', () => {
  const key = fromHex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
  const msg = new TextEncoder().encode('Cryptographic Forum Research Group');
  assertEquals(toHex(poly1305(msg, key)), 'a8061dc1305136c6c22b8baf0c0127a9');
});

Deno.test('poly1305 RFC 8439 §A.3 test vectors', () => {
  // Vector #1: zero key, zero message
  assertEquals(
    toHex(poly1305(new Uint8Array(64), new Uint8Array(32))),
    '00000000000000000000000000000000',
  );

  // Vector #2: r = 0, s = key of the IETF submission text
  const text = new TextEncoder().encode(
    'Any submission to the IETF intended by the Contributor for publication as all or part of an ' +
      'IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is ' +
      'considered an "IETF Contribution". Such statements include oral statements in IETF sessions, ' +
      'as well as written and electronic communications made at any time or place, which are addressed to',
  );
  const key2 = fromHex('0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e');
  assertEquals(toHex(poly1305(text, key2)), '36e5f6b5c5e06070f0efca96227a863e');

  // Vector #3: s = 0
  const key3 = fromHex('36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000');
  assertEquals(toHex(poly1305(text, key3)), 'f3477e7cd95417af89a6b8794c310cf0');

  // Vectors #4-#11 exercise the final carry and reduction mod 2^130 - 5.
  const cases: [string, string, string][] = [
    [
      '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0',
      '2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e',
      '4541669a7eaaee61e708dc7cbcc5eb62',
    ],
    [
      '0200000000000000000000000000000000000000000000000000000000000000',
      'ffffffffffffffffffffffffffffffff',
      '03000000000000000000000000000000',
    ],
    [
      '02000000000000000000000000000000ffffffffffffffffffffffffffffffff',
      '02000000000000000000000000000000',
      '03000000000000000000000000000000',
    ],
    [
      '0100000000000000000000000000000000000000000000000000000000000000',
      'fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000',
      '05000000000000000000000000000000',
    ],
    [
      '0100000000000000000000000000000000000000000000000000000000000000',
      'fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101',
      '00000000000000000000000000000000',
    ],
    [
      '0200000000000000000000000000000000000000000000000000000000000000',
      'fdffffffffffffffffffffffffffffff',
      'faffffffffffffffffffffffffffffff',
    ],
    [
      '0100000000000000040000000000000000000000000000000000000000000000',
      'e33594d7505e43b900000000000000003394d7505e4379cd01000000000000000000000000000000000000000000000001000000000000000000000000000000',
      '14000000000000005500000000000000',
    ],
    [
      '0100000000000000040000000000000000000000000000000000000000000000',
      'e33594d7505e43b900000000000000003394d7505e4379cd010000000000000000000000000000000000000000000000',
      '13000000000000000000000000000000',
    ],
  ];
  for (const [key, msg, tag] of cases) {
    assertEquals(toHex(poly1305(fromHex(msg), fromHex(key))), tag);
  }
});

Deno.test('poly1305 leaves the bytes after the message alone', () => {
  const key = fromHex('1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0');
  for (const len of [1, 4, 15, 16, 17, 40, 100]) {
    mem.fill(0xee, DATA, DATA + len + 32);
    poly1305(new Uint8Array(len).fill(0xab), key);
    assertEquals(toHex(mem.subarray(DATA + len, DATA + len + 32)), 'ee'.repeat(32));
  }
});

/** Seals a packet of payloadLen bytes whose padding is filled in deterministically. */
function seal(seqno: number, payloadLen: number): Uint8Array {
  const key = Uint8Array.from({ length: 64 }, (_, i) => i);
  const records: Uint8Array[] = [];
  const cipher = new ChaChaPolyCipher({
    outbound: {
      seqno,
      onWrite: (data) => records.push(data),
      cipherInfo: CIPHER_INFO['chacha20-poly1305@openssh.com'],
      cipherKey: key,
      cipherIV: new Uint8Array(0),
    },
  });
  const packet = cipher.allocPacket(payloadLen);
  for (let i = 4; i < packet.length; i++) packet[i] = (i * 31) & 0xff;
  packet[4] = packet.length - 5 - payloadLen;
  cipher.encrypt(packet);
  assertEquals(records.length, 1);
  assertEquals(records[0].length, packet.length + 16);
  return records[0];
}

async function sha256(data: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', data as BufferSource)));
}

Deno.test('ChaChaPolyCipher seals records as before, small and large', async () => {
  assertEquals(
    toHex(seal(7, 20)),
    'a39afc8a23ddaf9ab6941c0b18fe09212780fd6158399aff96e41bc624e9b91e' +
      '60ac1d69da71e2e86b8a2ec3aadb797eae1214f6',
  );
  assertEquals(
    await sha256(seal(0xfffffffe, 3000)),
    '16354c7899d22a7fd521ba5a9be49a3c1dd80368e4da6677cf2d3f82095d996a',
  );
  assertEquals(
    await sha256(seal(3, 32781)),
    'f6841e0dadedf8a86076b5aa5b876cb1e04b5009863ec57142f27996c3761158',
  );
});

function decipher(seqno: number, payloads: Uint8Array[]): ChaChaPolyDecipher {
  return new ChaChaPolyDecipher({
    inbound: {
      seqno,
      onPayload: (payload) => {
        payloads.push(payload);
      },
      decipherInfo: CIPHER_INFO['chacha20-poly1305@openssh.com'],
      decipherKey: Uint8Array.from({ length: 64 }, (_, i) => i),
      decipherIV: new Uint8Array(0),
    },
  });
}

Deno.test('ChaChaPolyDecipher opens records fed whole, in pieces, and back to back', async () => {
  const sizes = [20, 3000, 32781];
  const records = sizes.map((size, i) => seal(100 + i, size));
  const expected = sizes.map((size) => {
    const packet = new Uint8Array(4 + 1 + size + 64);
    for (let i = 4; i < packet.length; i++) packet[i] = (i * 31) & 0xff;
    return toHex(packet.subarray(5, 5 + size));
  });

  for (const piece of [Infinity, 1, 3, 4, 7, 4097]) {
    const all = new Uint8Array(records.reduce((n, r) => n + r.length, 0));
    let offset = 0;
    for (const record of records) {
      all.set(record, offset);
      offset += record.length;
    }
    const payloads: Uint8Array[] = [];
    const d = decipher(100, payloads);
    for (let p = 0; p < all.length; p += piece) {
      const chunk = all.subarray(p, Math.min(all.length, p + piece));
      await d.decrypt(chunk, 0, chunk.length);
    }
    assertEquals(payloads.map(toHex), expected, `pieces of ${piece}`);
    assertEquals(d.inSeqno, 103);
  }
});

Deno.test('ChaChaPolyDecipher hands out payloads that later packets do not overwrite', async () => {
  const payloads: Uint8Array[] = [];
  const d = decipher(7, payloads);
  const first = seal(7, 20);
  const second = seal(8, 20);
  await d.decrypt(first, 0, first.length);
  const copy = toHex(payloads[0]);
  await d.decrypt(second, 0, second.length);
  assertEquals(toHex(payloads[0]), copy);
});

Deno.test('ChaChaPolyDecipher rejects a record with a flipped bit', async () => {
  const cases: [number, string][] = [[0, 'Bad packet length'], [10, 'Invalid MAC'], [
    3020,
    'Invalid MAC',
  ]];
  for (const [at, message] of cases) {
    const record = seal(0xfffffffe, 3000);
    record[at] ^= 1;
    await assertRejects(
      () => decipher(0xfffffffe, []).decrypt(record, 0, record.length),
      Error,
      message,
    );
  }
});

Deno.test('ChaChaPolyCipher leaves no native cipher context behind', () => {
  // An unfinalized node:crypto cipher shows only in the runtime's internal
  // resource table; the test sanitizers do not see it.
  type Internal = { core: { resources(): Record<string, string> } };
  const denoInternal = Deno as unknown as { internal: symbol } & Record<symbol, Internal>;
  const { core } = denoInternal[denoInternal.internal];
  const ciphers = () =>
    Object.values(core.resources()).filter((name) => name === 'cryptoCipher').length;

  const before = ciphers();
  for (let i = 0; i < 10; i++) seal(i, 32781);
  assertEquals(ciphers(), before);
});
