/**
 * Unit tests for src/crypto/kex.ts
 *
 * Tests toMpint, X25519Exchange, ECDHExchange, DHExchange, and createKeyExchange
 * covering edge cases and error paths.
 */

import {
  assertEquals,
  assertInstanceOf,
  assertNotEquals,
  assertRejects,
  assertThrows,
} from '@std/assert';
import {
  createKeyExchange,
  DHExchange,
  ECDHExchange,
  toMpint,
  X25519Exchange,
} from '../src/crypto/kex.ts';
import { DEFAULT_KEX, SUPPORTED_KEX } from '../src/protocol/constants.ts';

// =============================================================================
// Advertised algorithms must be implemented (regression guard for S2:
// advertising an unimplemented KEX makes a peer that selects it fail the handshake)
// =============================================================================

Deno.test('every advertised KEX algorithm is constructible', () => {
  for (const algo of SUPPORTED_KEX) {
    // Must not throw "Unsupported key exchange algorithm".
    const kex = createKeyExchange(algo);
    assertEquals(kex.name, algo);
  }
  // DEFAULT_KEX is a subset of SUPPORTED_KEX; verify explicitly too.
  for (const algo of DEFAULT_KEX) {
    assertEquals(SUPPORTED_KEX.includes(algo), true);
  }
});

// =============================================================================
// toMpint
// =============================================================================

Deno.test('toMpint: single zero byte → [0]', () => {
  const result = toMpint(new Uint8Array([0]));
  assertEquals(result, new Uint8Array([0]));
});

Deno.test('toMpint: all-zero bytes → [0]', () => {
  const result = toMpint(new Uint8Array([0, 0, 0, 0]));
  assertEquals(result, new Uint8Array([0]));
});

Deno.test('toMpint: empty buffer → [0]', () => {
  const result = toMpint(new Uint8Array(0));
  assertEquals(result, new Uint8Array([0]));
});

Deno.test('toMpint: MSB not set, no leading zeros → returns same buffer', () => {
  const input = new Uint8Array([0x01, 0x02, 0x03]);
  const result = toMpint(input);
  assertEquals(result, input);
  // Should be the exact same reference (no copy needed)
  assertEquals(result === input, true);
});

Deno.test('toMpint: MSB set → prepends zero byte', () => {
  const input = new Uint8Array([0x80, 0x01]);
  const result = toMpint(input);
  assertEquals(result[0], 0x00);
  assertEquals(result[1], 0x80);
  assertEquals(result[2], 0x01);
  assertEquals(result.length, 3);
});

Deno.test('toMpint: MSB set on 0xFF → prepends zero byte', () => {
  const input = new Uint8Array([0xff, 0xff]);
  const result = toMpint(input);
  assertEquals(result[0], 0x00);
  assertEquals(result[1], 0xff);
  assertEquals(result[2], 0xff);
  assertEquals(result.length, 3);
});

Deno.test('toMpint: leading zeros stripped, MSB not set → subarray', () => {
  const input = new Uint8Array([0x00, 0x00, 0x01, 0x02]);
  const result = toMpint(input);
  assertEquals(result, new Uint8Array([0x01, 0x02]));
  assertEquals(result.length, 2);
});

Deno.test('toMpint: leading zeros stripped, MSB set → subarray + zero prefix', () => {
  const input = new Uint8Array([0x00, 0x00, 0x80, 0x01]);
  const result = toMpint(input);
  assertEquals(result[0], 0x00);
  assertEquals(result[1], 0x80);
  assertEquals(result[2], 0x01);
  assertEquals(result.length, 3);
});

// =============================================================================
// X25519Exchange
// =============================================================================

Deno.test('X25519Exchange: default name is curve25519-sha256', () => {
  const kex = new X25519Exchange();
  assertEquals(kex.name, 'curve25519-sha256');
  assertEquals(kex.hashName, 'sha256');
});

Deno.test('X25519Exchange: custom name', () => {
  const kex = new X25519Exchange('curve25519-sha256@libssh.org');
  assertEquals(kex.name, 'curve25519-sha256@libssh.org');
});

Deno.test('X25519Exchange: generateKeyPair returns 32-byte public key', async () => {
  const kex = new X25519Exchange();
  const result = await kex.generateKeyPair();
  assertEquals(result.publicKey.length, 32);
});

Deno.test('X25519Exchange: generateKeyPair produces different keys each call', async () => {
  const kex = new X25519Exchange();
  const r1 = await kex.generateKeyPair();
  const r2 = await kex.generateKeyPair();
  assertNotEquals(r1.publicKey, r2.publicKey);
});

Deno.test('X25519Exchange: computeSecret with valid peer key returns 32 bytes', async () => {
  const kex1 = new X25519Exchange();
  const kex2 = new X25519Exchange();
  const r1 = await kex1.generateKeyPair();
  const r2 = await kex2.generateKeyPair();

  const secret1 = await r1.computeSecret(r2.publicKey);
  const secret2 = await r2.computeSecret(r1.publicKey);

  assertEquals(secret1.length, 32);
  assertEquals(secret2.length, 32);
  // Shared secrets should match
  assertEquals(secret1, secret2);
});

Deno.test('X25519Exchange: computeSecret with invalid key throws', async () => {
  const kex = new X25519Exchange();
  const result = await kex.generateKeyPair();

  // Wrong length key (e.g., 16 bytes) should throw
  await assertRejects(
    () => result.computeSecret(new Uint8Array(16)),
    Error,
    'X25519 key exchange failed',
  );
});

// =============================================================================
// ECDHExchange constructor — curve name mapping
// =============================================================================

Deno.test('ECDHExchange: nistp256 is accepted', () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp256', 'nistp256', 'sha256');
  assertEquals(kex.name, 'ecdh-sha2-nistp256');
  assertEquals(kex.hashName, 'sha256');
});

Deno.test('ECDHExchange: prime256v1 is accepted (alternate name)', () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp256', 'prime256v1', 'sha256');
  assertEquals(kex.name, 'ecdh-sha2-nistp256');
});

Deno.test('ECDHExchange: nistp384 is accepted', () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp384', 'nistp384', 'sha384');
  assertEquals(kex.name, 'ecdh-sha2-nistp384');
  assertEquals(kex.hashName, 'sha384');
});

Deno.test('ECDHExchange: secp384r1 is accepted (alternate name)', () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp384', 'secp384r1', 'sha384');
  assertEquals(kex.name, 'ecdh-sha2-nistp384');
});

Deno.test('ECDHExchange: nistp521 is accepted', () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp521', 'nistp521', 'sha512');
  assertEquals(kex.name, 'ecdh-sha2-nistp521');
  assertEquals(kex.hashName, 'sha512');
});

Deno.test('ECDHExchange: secp521r1 is accepted (alternate name)', () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp521', 'secp521r1', 'sha512');
  assertEquals(kex.name, 'ecdh-sha2-nistp521');
});

Deno.test('ECDHExchange: unsupported curve throws', () => {
  assertThrows(
    () => new ECDHExchange('ecdh-sha2-bogus', 'boguscurve', 'sha256'),
    Error,
    'Unsupported ECDH curve',
  );
});

// =============================================================================
// ECDHExchange generateKeyPair and computeSecret
// =============================================================================

Deno.test('ECDHExchange P-256: generateKeyPair returns uncompressed point', async () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp256', 'nistp256', 'sha256');
  const result = await kex.generateKeyPair();
  // Uncompressed point: 0x04 + 32 + 32 = 65 bytes
  assertEquals(result.publicKey.length, 65);
  assertEquals(result.publicKey[0], 0x04);
});

Deno.test('ECDHExchange P-384: generateKeyPair returns uncompressed point', async () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp384', 'nistp384', 'sha384');
  const result = await kex.generateKeyPair();
  // Uncompressed point: 0x04 + 48 + 48 = 97 bytes
  assertEquals(result.publicKey.length, 97);
  assertEquals(result.publicKey[0], 0x04);
});

Deno.test('ECDHExchange P-521: generateKeyPair returns uncompressed point', async () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp521', 'nistp521', 'sha512');
  const result = await kex.generateKeyPair();
  // Uncompressed point: 0x04 + 66 + 66 = 133 bytes
  assertEquals(result.publicKey.length, 133);
  assertEquals(result.publicKey[0], 0x04);
});

Deno.test('ECDHExchange P-256: computeSecret with valid peer key returns 32 bytes', async () => {
  const kex1 = new ECDHExchange('ecdh-sha2-nistp256', 'nistp256', 'sha256');
  const kex2 = new ECDHExchange('ecdh-sha2-nistp256', 'nistp256', 'sha256');
  const r1 = await kex1.generateKeyPair();
  const r2 = await kex2.generateKeyPair();

  const secret1 = await r1.computeSecret(r2.publicKey);
  const secret2 = await r2.computeSecret(r1.publicKey);

  assertEquals(secret1.length, 32);
  assertEquals(secret2.length, 32);
  assertEquals(secret1, secret2);
});

Deno.test('ECDHExchange P-384: computeSecret returns 48 bytes', async () => {
  const kex1 = new ECDHExchange('ecdh-sha2-nistp384', 'nistp384', 'sha384');
  const kex2 = new ECDHExchange('ecdh-sha2-nistp384', 'nistp384', 'sha384');
  const r1 = await kex1.generateKeyPair();
  const r2 = await kex2.generateKeyPair();

  const secret = await r1.computeSecret(r2.publicKey);
  assertEquals(secret.length, 48);
});

Deno.test('ECDHExchange P-521: computeSecret returns 66 bytes', async () => {
  const kex1 = new ECDHExchange('ecdh-sha2-nistp521', 'nistp521', 'sha512');
  const kex2 = new ECDHExchange('ecdh-sha2-nistp521', 'nistp521', 'sha512');
  const r1 = await kex1.generateKeyPair();
  const r2 = await kex2.generateKeyPair();

  const secret = await r1.computeSecret(r2.publicKey);
  assertEquals(secret.length, 66);
});

Deno.test('ECDHExchange: computeSecret with malformed peer key throws', async () => {
  const kex = new ECDHExchange('ecdh-sha2-nistp256', 'nistp256', 'sha256');
  const result = await kex.generateKeyPair();

  // Pass a junk key — too short to be a valid point
  await assertRejects(
    () => result.computeSecret(new Uint8Array(10)),
    Error,
    'ECDH key exchange failed',
  );
});

// =============================================================================
// DHExchange
// =============================================================================

Deno.test('DHExchange: unsupported group throws', () => {
  assertThrows(
    () => new DHExchange('diffie-hellman-group99', 'modp99', 'sha256'),
    Error,
    'Unsupported DH group',
  );
});

Deno.test('DHExchange modp14: generates key pair', async () => {
  const kex = new DHExchange('diffie-hellman-group14-sha256', 'modp14', 'sha256');
  assertEquals(kex.name, 'diffie-hellman-group14-sha256');
  assertEquals(kex.hashName, 'sha256');

  const result = await kex.generateKeyPair();
  // Public key in mpint format — at least 1 byte
  assertEquals(result.publicKey.length > 0, true);
});

Deno.test('DHExchange modp14: computeSecret with value = 1 throws (invalid peer key)', async () => {
  const kex = new DHExchange('diffie-hellman-group14-sha256', 'modp14', 'sha256');
  const result = await kex.generateKeyPair();

  // Peer public key of value 1 — invalid (≤ 1)
  const invalidKey = new Uint8Array(256); // all zeros = value 0
  invalidKey[255] = 1; // last byte = 1, so value = 1

  await assertRejects(
    () => result.computeSecret(invalidKey),
    Error,
    'DH key exchange failed',
  );
});

Deno.test('DHExchange modp14: computeSecret between two valid keys produces shared secret', async () => {
  const kex1 = new DHExchange('diffie-hellman-group14-sha256', 'modp14', 'sha256');
  const kex2 = new DHExchange('diffie-hellman-group14-sha256', 'modp14', 'sha256');

  const r1 = await kex1.generateKeyPair();
  const r2 = await kex2.generateKeyPair();

  // computeSecret expects raw bytes from peer mpint (strip the leading 0x00 padding if any)
  // Both should produce the same secret
  const s1 = await r1.computeSecret(r2.publicKey);
  const s2 = await r2.computeSecret(r1.publicKey);

  assertEquals(s1.length, 256); // 2048 bits = 256 bytes
  assertEquals(s1, s2);
});

Deno.test('DHExchange modp18: two sides agree, with an exponent short enough not to stall the event loop', async () => {
  const kex = new DHExchange('diffie-hellman-group18-sha512', 'modp18', 'sha512');
  const started = performance.now();
  const r1 = await kex.generateKeyPair();
  const r2 = await kex.generateKeyPair();
  const s1 = await r1.computeSecret(r2.publicKey);
  const s2 = await r2.computeSecret(r1.publicKey);
  const took = performance.now() - started;

  assertEquals(s1.length, 1024);
  assertEquals(s1, s2);
  // Both sides with a full 8192-bit exponent took about 1.4 s; with 1024 bits, about 0.16 s
  assertEquals(took < 700, true, `took ${took.toFixed(0)} ms`);
});

// =============================================================================
// createKeyExchange factory
// =============================================================================

Deno.test('createKeyExchange: curve25519-sha256 → X25519Exchange', () => {
  const kex = createKeyExchange('curve25519-sha256');
  assertInstanceOf(kex, X25519Exchange);
  assertEquals(kex.name, 'curve25519-sha256');
});

Deno.test('createKeyExchange: curve25519-sha256@libssh.org → X25519Exchange', () => {
  const kex = createKeyExchange('curve25519-sha256@libssh.org');
  assertInstanceOf(kex, X25519Exchange);
  assertEquals(kex.name, 'curve25519-sha256@libssh.org');
});

Deno.test('createKeyExchange: ecdh-sha2-nistp256 → ECDHExchange', () => {
  const kex = createKeyExchange('ecdh-sha2-nistp256');
  assertInstanceOf(kex, ECDHExchange);
  assertEquals(kex.hashName, 'sha256');
});

Deno.test('createKeyExchange: ecdh-sha2-nistp384 → ECDHExchange with sha384', () => {
  const kex = createKeyExchange('ecdh-sha2-nistp384');
  assertInstanceOf(kex, ECDHExchange);
  assertEquals(kex.hashName, 'sha384');
});

Deno.test('createKeyExchange: ecdh-sha2-nistp521 → ECDHExchange with sha512', () => {
  const kex = createKeyExchange('ecdh-sha2-nistp521');
  assertInstanceOf(kex, ECDHExchange);
  assertEquals(kex.hashName, 'sha512');
});

Deno.test('createKeyExchange: diffie-hellman-group14-sha1 → DHExchange', () => {
  const kex = createKeyExchange('diffie-hellman-group14-sha1');
  assertInstanceOf(kex, DHExchange);
  assertEquals(kex.hashName, 'sha1');
});

Deno.test('createKeyExchange: diffie-hellman-group14-sha256 → DHExchange', () => {
  const kex = createKeyExchange('diffie-hellman-group14-sha256');
  assertInstanceOf(kex, DHExchange);
  assertEquals(kex.hashName, 'sha256');
});

Deno.test('createKeyExchange: diffie-hellman-group16-sha512 → DHExchange', () => {
  const kex = createKeyExchange('diffie-hellman-group16-sha512');
  assertInstanceOf(kex, DHExchange);
  assertEquals(kex.hashName, 'sha512');
});

Deno.test('createKeyExchange: diffie-hellman-group18-sha512 → DHExchange', () => {
  const kex = createKeyExchange('diffie-hellman-group18-sha512');
  assertInstanceOf(kex, DHExchange);
  assertEquals(kex.hashName, 'sha512');
});

Deno.test('createKeyExchange: unsupported algorithm throws', () => {
  assertThrows(
    () => createKeyExchange('super-quantum-sha9999'),
    Error,
    'Unsupported key exchange algorithm',
  );
});
