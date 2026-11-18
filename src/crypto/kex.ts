/**
 * Key Exchange Primitives for SSH
 *
 * Implements ECDH (P-256, P-384, P-521), X25519, and DH key exchange
 * using the Web Crypto API.
 */

import { allocBytes } from '../utils/binary.ts';
import { randomBytes } from './random.ts';

/**
 * Key exchange result with public key and shared secret computation
 */
export interface KeyExchangeResult {
  /** Our public key to send to peer */
  publicKey: Uint8Array;
  /** Compute shared secret from peer's public key */
  computeSecret(peerPublicKey: Uint8Array): Promise<Uint8Array>;
}

/**
 * Key exchange algorithm interface
 */
export interface KeyExchange {
  /** Algorithm name (e.g., 'curve25519-sha256') */
  name: string;
  /** Hash algorithm to use (e.g., 'sha256') */
  hashName: string;
  /** Generate key pair and return exchange result */
  generateKeyPair(): Promise<KeyExchangeResult>;
}

/**
 * Convert a byte array to mpint format (SSH's multiple-precision integer)
 * Strips leading zeros and adds a zero byte if MSB is set
 */
export function toMpint(buf: Uint8Array): Uint8Array {
  let idx = 0;
  let length = buf.length;

  // Strip leading zeros
  while (idx < buf.length && buf[idx] === 0x00) {
    ++idx;
    --length;
  }

  // If empty after stripping, return single zero byte
  if (length === 0) {
    return new Uint8Array([0]);
  }

  // Check if MSB is set (number would be interpreted as negative)
  if (buf[idx] & 0x80) {
    const result = allocBytes(1 + length);
    result[0] = 0;
    result.set(buf.subarray(idx), 1);
    return result;
  }

  // No leading zero needed
  if (idx === 0 && length === buf.length) {
    return buf;
  }

  return buf.subarray(idx, idx + length);
}

/**
 * X25519 (Curve25519) key exchange
 */
export class X25519Exchange implements KeyExchange {
  readonly name: string;
  readonly hashName: string = 'sha256';

  constructor(name: string = 'curve25519-sha256') {
    this.name = name;
  }

  async generateKeyPair(): Promise<KeyExchangeResult> {
    const keyPair = await crypto.subtle.generateKey('X25519', true, [
      'deriveBits',
    ]) as CryptoKeyPair;
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));

    return {
      publicKey,
      computeSecret: async (peerPublicKey: Uint8Array): Promise<Uint8Array> => {
        try {
          const peerKey = await crypto.subtle.importKey(
            'raw',
            peerPublicKey as Uint8Array<ArrayBuffer>,
            'X25519',
            false,
            [],
          );
          // deriveBits throws on an all-zero shared secret (low-order peer point)
          const sharedSecret = await crypto.subtle.deriveBits(
            { name: 'X25519', public: peerKey },
            keyPair.privateKey,
            256,
          );
          // OpenSSH uses the X25519 output bytes directly (without byte-order reversal)
          // despite RFC 8731's description suggesting little-to-big-endian conversion.
          // Return raw bytes; mpint encoding happens in buildExchangeHashInput
          return new Uint8Array(sharedSecret);
        } catch (e) {
          throw new Error(`X25519 key exchange failed: ${(e as Error).message}`);
        }
      },
    };
  }
}

/**
 * ECDH key exchange using Web Crypto
 * Supports P-256, P-384, P-521 curves
 */
export class ECDHExchange implements KeyExchange {
  readonly name: string;
  readonly hashName: string;
  private readonly namedCurve: 'P-256' | 'P-384' | 'P-521';
  private readonly fieldSize: number;

  constructor(name: string, curveName: string, hashName: string) {
    this.name = name;
    this.hashName = hashName;

    switch (curveName) {
      case 'nistp256':
      case 'prime256v1':
        this.namedCurve = 'P-256';
        this.fieldSize = 32;
        break;
      case 'nistp384':
      case 'secp384r1':
        this.namedCurve = 'P-384';
        this.fieldSize = 48;
        break;
      case 'nistp521':
      case 'secp521r1':
        this.namedCurve = 'P-521';
        this.fieldSize = 66;
        break;
      default:
        throw new Error(`Unsupported ECDH curve: ${curveName}`);
    }
  }

  async generateKeyPair(): Promise<KeyExchangeResult> {
    const algorithm = { name: 'ECDH', namedCurve: this.namedCurve };
    const keyPair = await crypto.subtle.generateKey(algorithm, true, ['deriveBits']);
    // Uncompressed point: 0x04 + x + y
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));

    return {
      publicKey,
      computeSecret: async (peerPublicKey: Uint8Array): Promise<Uint8Array> => {
        try {
          // importKey validates that the peer point is on the curve
          const peerKey = await crypto.subtle.importKey(
            'raw',
            peerPublicKey as Uint8Array<ArrayBuffer>,
            algorithm,
            false,
            [],
          );
          // deriveBits at full field width returns the x-coordinate,
          // which is the SSH ECDH shared secret format
          const sharedSecret = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: peerKey },
            keyPair.privateKey,
            this.fieldSize * 8,
          );
          return new Uint8Array(sharedSecret);
        } catch (e) {
          throw new Error(`ECDH key exchange failed: ${(e as Error).message}`);
        }
      },
    };
  }
}

/**
 * Standard Diffie-Hellman groups (MODP groups from RFC 3526)
 * Uses bigint for arbitrary precision arithmetic
 */

// MODP Group 14 (2048-bit) - RFC 3526
const MODP14_PRIME = BigInt(
  '0x' +
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AACAA68FFFFFFFFFFFFFFFF',
);

// MODP Group 16 (4096-bit) - RFC 3526
const MODP16_PRIME = BigInt(
  '0x' +
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7' +
    '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA' +
    '2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6' +
    '287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED' +
    '1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9' +
    '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199' +
    'FFFFFFFFFFFFFFFF',
);

// MODP Group 18 (8192-bit) - RFC 3526
const MODP18_PRIME = BigInt(
  '0x' +
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
    'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
    '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' +
    'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' +
    'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' +
    '43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7' +
    '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA' +
    '2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6' +
    '287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED' +
    '1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9' +
    '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492' +
    '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD' +
    'F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831' +
    '179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B' +
    'DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF' +
    '5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6' +
    'D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3' +
    '23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' +
    'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328' +
    '06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C' +
    'DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE' +
    '12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4' +
    '38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300' +
    '741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568' +
    '3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9' +
    '22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B' +
    '4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A' +
    '062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36' +
    '4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1' +
    'B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92' +
    '4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47' +
    '9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71' +
    '60C980DD98EDD3DFFFFFFFFFFFFFFFFF',
);

const DH_GENERATOR = BigInt(2);

/**
 * DH group parameters
 */
interface DHGroup {
  prime: bigint;
  generator: bigint;
  primeByteLength: number;
}

const DH_GROUPS: Record<string, DHGroup> = {
  modp14: { prime: MODP14_PRIME, generator: DH_GENERATOR, primeByteLength: 256 },
  modp16: { prime: MODP16_PRIME, generator: DH_GENERATOR, primeByteLength: 512 },
  modp18: { prime: MODP18_PRIME, generator: DH_GENERATOR, primeByteLength: 1024 },
};

/**
 * Convert bigint to Uint8Array (big-endian, unsigned)
 */
function bigintToBytes(n: bigint, length: number): Uint8Array {
  const hex = n.toString(16).padStart(length * 2, '0');
  const bytes = allocBytes(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to bigint (big-endian, unsigned)
 */
function bytesToBigint(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return BigInt(hex);
}

/**
 * Modular exponentiation: (base^exp) mod mod
 * Uses square-and-multiply algorithm
 */
function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = BigInt(1);
  base = base % mod;

  while (exp > 0) {
    if (exp % BigInt(2) === BigInt(1)) {
      result = (result * base) % mod;
    }
    exp = exp / BigInt(2);
    base = (base * base) % mod;
  }

  return result;
}

/** Digest length in bytes of each hash a MODP exchange uses. */
const HASH_BYTES: Record<string, number> = { sha1: 20, sha256: 32, sha512: 64 };

/**
 * Traditional Diffie-Hellman key exchange using MODP groups
 */
export class DHExchange implements KeyExchange {
  readonly name: string;
  readonly hashName: string;
  private readonly group: DHGroup;

  constructor(name: string, groupName: string, hashName: string) {
    this.name = name;
    this.hashName = hashName;

    const group = DH_GROUPS[groupName];
    if (!group) {
      throw new Error(`Unsupported DH group: ${groupName}`);
    }
    this.group = group;
  }

  async generateKeyPair(): Promise<KeyExchangeResult> {
    // The private exponent has twice the bits of the hash (512 at least), as
    // OpenSSH's has, not the prime's: that is the strength the exchange needs,
    // and a full-length exponent makes group18 about ten times as slow, all of
    // it on the event loop and at a client's choosing
    const exponentBytes = 2 * Math.max(32, HASH_BYTES[this.hashName] ?? 64);
    const privateKey = bytesToBigint(randomBytes(exponentBytes)) |
      BigInt(1) << BigInt(exponentBytes * 8 - 1);

    // Compute public key: g^x mod p
    const publicKeyBigint = modPow(this.group.generator, privateKey, this.group.prime);
    const publicKey = bigintToBytes(publicKeyBigint, this.group.primeByteLength);

    return {
      publicKey: toMpint(publicKey),
      computeSecret: async (peerPublicKey: Uint8Array): Promise<Uint8Array> => {
        try {
          // Convert peer's public key to bigint
          const peerPubBigint = bytesToBigint(peerPublicKey);

          // Validate peer's public key (basic checks)
          if (peerPubBigint <= BigInt(1) || peerPubBigint >= this.group.prime - BigInt(1)) {
            throw new Error('Invalid peer public key');
          }

          // Compute shared secret: peer_pub^x mod p
          const sharedSecretBigint = modPow(peerPubBigint, privateKey, this.group.prime);
          const sharedSecret = bigintToBytes(sharedSecretBigint, this.group.primeByteLength);

          // Return raw bytes; mpint encoding happens in buildExchangeHashInput
          return sharedSecret;
        } catch (e) {
          throw new Error(`DH key exchange failed: ${(e as Error).message}`);
        }
      },
    };
  }
}

/**
 * Create a key exchange instance for the given algorithm name
 */
export function createKeyExchange(algorithm: string): KeyExchange {
  switch (algorithm) {
    // X25519 (Curve25519)
    case 'curve25519-sha256':
    case 'curve25519-sha256@libssh.org':
      return new X25519Exchange(algorithm);

    // ECDH with NIST curves
    case 'ecdh-sha2-nistp256':
      return new ECDHExchange(algorithm, 'nistp256', 'sha256');
    case 'ecdh-sha2-nistp384':
      return new ECDHExchange(algorithm, 'nistp384', 'sha384');
    case 'ecdh-sha2-nistp521':
      return new ECDHExchange(algorithm, 'nistp521', 'sha512');

    // Traditional DH groups
    case 'diffie-hellman-group14-sha1':
      return new DHExchange(algorithm, 'modp14', 'sha1');
    case 'diffie-hellman-group14-sha256':
      return new DHExchange(algorithm, 'modp14', 'sha256');
    case 'diffie-hellman-group16-sha512':
      return new DHExchange(algorithm, 'modp16', 'sha512');
    case 'diffie-hellman-group18-sha512':
      return new DHExchange(algorithm, 'modp18', 'sha512');

    default:
      throw new Error(`Unsupported key exchange algorithm: ${algorithm}`);
  }
}

/**
 * List of supported key exchange algorithms (in preference order)
 */
export const SUPPORTED_KEX_ALGORITHMS = [
  'curve25519-sha256',
  'curve25519-sha256@libssh.org',
  'ecdh-sha2-nistp256',
  'ecdh-sha2-nistp384',
  'ecdh-sha2-nistp521',
  'diffie-hellman-group18-sha512',
  'diffie-hellman-group16-sha512',
  'diffie-hellman-group14-sha256',
  'diffie-hellman-group14-sha1',
];
