/**
 * SFTP Packet Tests
 *
 * Unit tests for PacketParser, attrsToBytes, toUnixTimestamp, modeNum, writeString
 * in src/protocol/sftp/packet.ts, and how SFTP.push assembles a WRITE.
 */

import { assertEquals, assertThrows } from '@std/assert';
import { ATTR } from '../src/protocol/sftp/constants.ts';
import {
  attrsToBytes,
  getAttrBytes,
  makePacketParser,
  modeNum,
  stringByteLength,
  toUnixTimestamp,
  writeString,
  writeUInt64BE,
} from '../src/protocol/sftp/mod.ts';
import { SFTP } from '../src/protocol/sftp/SFTP.ts';

// =============================================================================
// toUnixTimestamp
// =============================================================================

Deno.test('toUnixTimestamp: number returns floor(n)', () => {
  assertEquals(toUnixTimestamp(1234567890.9), 1234567890);
});

Deno.test('toUnixTimestamp: Date object returns seconds since epoch', () => {
  const d = new Date(1234567890000);
  assertEquals(toUnixTimestamp(d), 1234567890);
});

Deno.test('toUnixTimestamp: invalid value throws', () => {
  assertThrows(
    () => toUnixTimestamp(NaN as unknown as number),
    Error,
    'Cannot parse time',
  );
});

// =============================================================================
// modeNum
// =============================================================================

Deno.test('modeNum: number returns as-is', () => {
  assertEquals(modeNum(0o644), 0o644);
});

Deno.test('modeNum: string parses as octal', () => {
  assertEquals(modeNum('0644'), 0o644);
});

Deno.test('modeNum: NaN throws', () => {
  assertThrows(
    () => modeNum(NaN as unknown as number),
    Error,
    'Cannot parse mode',
  );
});

// =============================================================================
// attrsToBytes
// =============================================================================

Deno.test('attrsToBytes: undefined returns flags=0, nb=0', () => {
  const { flags, nb } = attrsToBytes(undefined);
  assertEquals(flags, 0);
  assertEquals(nb, 0);
});

Deno.test('attrsToBytes: bigint size sets SIZE flag (8 bytes)', () => {
  const { flags, nb } = attrsToBytes({ size: 256n });
  assertEquals(flags & ATTR.SIZE, ATTR.SIZE);
  assertEquals(nb, 8);
  // Check byte layout: 256 = 0x0000000000000100
  const bytes = getAttrBytes(nb);
  assertEquals(bytes[6], 0x01);
  assertEquals(bytes[7], 0x00);
});

Deno.test('attrsToBytes: number size sets SIZE flag', () => {
  const { flags, nb } = attrsToBytes({ size: 1024 });
  assertEquals(flags & ATTR.SIZE, ATTR.SIZE);
  assertEquals(nb, 8);
});

Deno.test('attrsToBytes: uid/gid sets UIDGID flag', () => {
  const { flags, nb } = attrsToBytes({ uid: 1000, gid: 1001 });
  assertEquals(flags & ATTR.UIDGID, ATTR.UIDGID);
  assertEquals(nb, 8);
});

Deno.test('attrsToBytes: mode string sets PERMISSIONS flag', () => {
  const { flags, nb } = attrsToBytes({ mode: '0644' });
  assertEquals(flags & ATTR.PERMISSIONS, ATTR.PERMISSIONS);
  assertEquals(nb, 4);
});

Deno.test('attrsToBytes: atime/mtime sets ACMODTIME flag', () => {
  const { flags, nb } = attrsToBytes({ atime: 100, mtime: 200 });
  assertEquals(flags & ATTR.ACMODTIME, ATTR.ACMODTIME);
  assertEquals(nb, 8);
});

// =============================================================================
// writeString + stringByteLength
// =============================================================================

Deno.test('writeString: writes string with 4-byte length prefix', () => {
  const buf = new Uint8Array(4 + 5);
  const end = writeString(buf, 'hello', 0);
  assertEquals(end, 9);
  // Length prefix
  assertEquals(buf[0], 0);
  assertEquals(buf[1], 0);
  assertEquals(buf[2], 0);
  assertEquals(buf[3], 5);
  // 'hello'
  assertEquals(buf[4], 0x68);
  assertEquals(buf[5], 0x65);
  assertEquals(buf[6], 0x6c);
  assertEquals(buf[7], 0x6c);
  assertEquals(buf[8], 0x6f);
});

Deno.test('writeString: writes Uint8Array data', () => {
  const data = new Uint8Array([0x01, 0x02, 0x03]);
  const buf = new Uint8Array(4 + 3);
  const end = writeString(buf, data, 0);
  assertEquals(end, 7);
  assertEquals(buf[3], 3);
  assertEquals(buf[4], 0x01);
});

Deno.test('writeString: writes at non-zero offset', () => {
  // 'abc' needs 4+3=7 bytes, 'xy' needs 4+2=6 bytes; total 13
  const buf = new Uint8Array(13);
  // Write 'abc' at offset 0
  writeString(buf, 'abc', 0);
  // Write 'xy' at offset 7
  writeString(buf, 'xy', 7);
  // Check offset 7: length prefix=2
  assertEquals(buf[7], 0);
  assertEquals(buf[8], 0);
  assertEquals(buf[9], 0);
  assertEquals(buf[10], 2);
  // 'x' and 'y'
  assertEquals(buf[11], 0x78);
  assertEquals(buf[12], 0x79);
});

Deno.test('stringByteLength: string counts UTF-8 bytes', () => {
  assertEquals(stringByteLength('hello'), 4 + 5);
});

Deno.test('stringByteLength: Uint8Array uses byteLength', () => {
  assertEquals(stringByteLength(new Uint8Array(10)), 4 + 10);
});

// =============================================================================
// writeUInt64BE
// =============================================================================

Deno.test('writeUInt64BE: writes number as 8-byte big-endian', () => {
  const buf = new Uint8Array(8);
  // Use small number to avoid JS precision issues: 0x0000000001020304 = 16909060
  writeUInt64BE(buf, 16909060, 0);
  assertEquals(buf[0], 0x00);
  assertEquals(buf[4], 0x01);
  assertEquals(buf[5], 0x02);
  assertEquals(buf[6], 0x03);
  assertEquals(buf[7], 0x04);
});

Deno.test('writeUInt64BE: writes bigint', () => {
  const buf = new Uint8Array(8);
  writeUInt64BE(buf, 0xdeadbeefn, 0);
  // 0xDEADBEEF = 3735928559
  assertEquals(buf[4], 0xde);
  assertEquals(buf[5], 0xad);
  assertEquals(buf[6], 0xbe);
  assertEquals(buf[7], 0xef);
});

// =============================================================================
// PacketParser — basic methods
// =============================================================================

Deno.test('PacketParser: pos getter returns current position', () => {
  const p = makePacketParser();
  const buf = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
  p.init(buf, 2);
  assertEquals(p.pos, 2);
  p.readByte();
  assertEquals(p.pos, 3);
});

Deno.test('PacketParser: remaining decrements after reads', () => {
  const p = makePacketParser();
  const buf = new Uint8Array([0x01, 0x02, 0x03]);
  p.init(buf);
  assertEquals(p.remaining, 3);
  p.readByte();
  assertEquals(p.remaining, 2);
});

Deno.test('PacketParser: skip advances position', () => {
  const p = makePacketParser();
  const buf = new Uint8Array([0, 0, 0, 0, 0x42]);
  p.init(buf);
  const ok = p.skip(4);
  assertEquals(ok, true);
  assertEquals(p.readByte(), 0x42);
});

Deno.test('PacketParser: skip beyond end returns false', () => {
  const p = makePacketParser();
  p.init(new Uint8Array([0x01, 0x02]));
  assertEquals(p.skip(10), false);
});

Deno.test('PacketParser: readByte returns byte', () => {
  const p = makePacketParser();
  p.init(new Uint8Array([0xAB]));
  assertEquals(p.readByte(), 0xAB);
});

Deno.test('PacketParser: readByte returns undefined at end', () => {
  const p = makePacketParser();
  p.init(new Uint8Array([]));
  assertEquals(p.readByte(), undefined);
});

Deno.test('PacketParser: readUInt32BE returns value', () => {
  const p = makePacketParser();
  const buf = new Uint8Array([0x00, 0x00, 0x00, 0x2A]);
  p.init(buf);
  assertEquals(p.readUInt32BE(), 42);
});

Deno.test('PacketParser: readUInt32BE returns undefined when buffer too short', () => {
  const p = makePacketParser();
  p.init(new Uint8Array([0x00, 0x00, 0x00])); // only 3 bytes
  assertEquals(p.readUInt32BE(), undefined);
});

Deno.test('PacketParser: readUInt64BE returns number by default', () => {
  const p = makePacketParser();
  const buf = new Uint8Array(8);
  buf[7] = 42;
  p.init(buf);
  assertEquals(p.readUInt64BE(), 42);
});

Deno.test('PacketParser: readUInt64BE returns bigint when asBigInt=true', () => {
  const p = makePacketParser();
  const buf = new Uint8Array(8);
  buf[7] = 0xAB;
  p.init(buf);
  assertEquals(p.readUInt64BE(true), 0xABn);
});

Deno.test('PacketParser: readUInt64BE returns undefined when buffer too short', () => {
  const p = makePacketParser();
  p.init(new Uint8Array(7)); // only 7 bytes
  assertEquals(p.readUInt64BE(), undefined);
});

Deno.test('PacketParser: readString returns Uint8Array', () => {
  const p = makePacketParser();
  const str = new TextEncoder().encode('abc');
  const buf = new Uint8Array(4 + 3);
  buf[3] = 3;
  buf.set(str, 4);
  p.init(buf);
  const result = p.readString();
  assertEquals(result instanceof Uint8Array, true);
  assertEquals(result, str);
});

Deno.test('PacketParser: readString(true) returns string', () => {
  const p = makePacketParser();
  const str = new TextEncoder().encode('hello');
  const buf = new Uint8Array(4 + 5);
  buf[3] = 5;
  buf.set(str, 4);
  p.init(buf);
  assertEquals(p.readString(true), 'hello');
});

Deno.test('PacketParser: readString returns undefined when length prefix missing', () => {
  const p = makePacketParser();
  p.init(new Uint8Array([0, 0, 0])); // only 3 bytes, need 4 for length prefix
  assertEquals(p.readString(), undefined);
});

Deno.test('PacketParser: readString returns undefined when data missing', () => {
  const p = makePacketParser();
  const buf = new Uint8Array(4 + 2);
  buf[3] = 10; // claims 10 bytes but only 2 available
  p.init(buf);
  assertEquals(p.readString(), undefined);
});

Deno.test('PacketParser: clear resets state', () => {
  const p = makePacketParser();
  p.init(new Uint8Array([1, 2, 3, 4, 5]));
  p.readByte();
  p.clear();
  assertEquals(p.pos, 0);
  assertEquals(p.remaining, 0);
  assertEquals(p.readByte(), undefined);
});

// =============================================================================
// PacketParser.readAttrs — EXTENDED attributes
// =============================================================================

function buildAttrsBuffer(flags: number, extra: Uint8Array): Uint8Array {
  const buf = new Uint8Array(4 + extra.length);
  buf[0] = (flags >>> 24) & 0xff;
  buf[1] = (flags >>> 16) & 0xff;
  buf[2] = (flags >>> 8) & 0xff;
  buf[3] = flags & 0xff;
  buf.set(extra, 4);
  return buf;
}

function writeU32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

function sshString(s: string): Uint8Array {
  const enc = new TextEncoder().encode(s);
  const buf = new Uint8Array(4 + enc.length);
  buf[3] = enc.length;
  buf.set(enc, 4);
  return buf;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, b) => a + b.length, 0);
  const result = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    result.set(p, off);
    off += p.length;
  }
  return result;
}

Deno.test('PacketParser: readAttrs empty flags returns empty attrs', () => {
  const p = makePacketParser();
  p.init(buildAttrsBuffer(0, new Uint8Array(0)));
  const attrs = p.readAttrs();
  assertEquals(attrs, {});
});

Deno.test('PacketParser: readAttrs SIZE flag reads 8 bytes', () => {
  const p = makePacketParser();
  const extra = new Uint8Array(8);
  extra[7] = 42; // size = 42
  p.init(buildAttrsBuffer(ATTR.SIZE, extra));
  const attrs = p.readAttrs();
  assertEquals(attrs!.size, 42);
});

Deno.test('PacketParser: readAttrs SIZE flag with bigint', () => {
  const p = makePacketParser();
  const extra = new Uint8Array(8);
  extra[7] = 42;
  p.init(buildAttrsBuffer(ATTR.SIZE, extra));
  const attrs = p.readAttrs(true);
  assertEquals(attrs!.size, 42n);
});

Deno.test('PacketParser: readAttrs UIDGID flag reads uid+gid', () => {
  const p = makePacketParser();
  const uid = writeU32(1000);
  const gid = writeU32(2000);
  p.init(buildAttrsBuffer(ATTR.UIDGID, concat(uid, gid)));
  const attrs = p.readAttrs();
  assertEquals(attrs!.uid, 1000);
  assertEquals(attrs!.gid, 2000);
});

Deno.test('PacketParser: readAttrs PERMISSIONS flag reads mode', () => {
  const p = makePacketParser();
  p.init(buildAttrsBuffer(ATTR.PERMISSIONS, writeU32(0o644)));
  const attrs = p.readAttrs();
  assertEquals(attrs!.mode, 0o644);
});

Deno.test('PacketParser: readAttrs ACMODTIME flag reads atime+mtime', () => {
  const p = makePacketParser();
  const extra = concat(writeU32(111), writeU32(222));
  p.init(buildAttrsBuffer(ATTR.ACMODTIME, extra));
  const attrs = p.readAttrs();
  assertEquals(attrs!.atime, 111);
  assertEquals(attrs!.mtime, 222);
});

Deno.test('PacketParser: readAttrs EXTENDED flag reads extended attrs', () => {
  const p = makePacketParser();
  // EXTENDED flag: count=1, then type string + data string
  const count = writeU32(1);
  const typeName = sshString('my-ext@example.com');
  const typeData = sshString('some-value');
  const extra = concat(count, typeName, typeData);
  p.init(buildAttrsBuffer(ATTR.EXTENDED, extra));
  const attrs = p.readAttrs();
  assertEquals(attrs!.extended!.length, 1);
  assertEquals(attrs!.extended![0].type, 'my-ext@example.com');
  assertEquals(
    new TextDecoder().decode(attrs!.extended![0].data),
    'some-value',
  );
});

Deno.test('PacketParser: readAttrs EXTENDED with 2 entries', () => {
  const p = makePacketParser();
  const count = writeU32(2);
  const ext1 = concat(sshString('ext-a'), sshString('val-a'));
  const ext2 = concat(sshString('ext-b'), sshString('val-b'));
  const extra = concat(count, ext1, ext2);
  p.init(buildAttrsBuffer(ATTR.EXTENDED, extra));
  const attrs = p.readAttrs();
  assertEquals(attrs!.extended!.length, 2);
  assertEquals(attrs!.extended![0].type, 'ext-a');
  assertEquals(attrs!.extended![1].type, 'ext-b');
});

Deno.test('PacketParser: readAttrs returns undefined when buffer too short', () => {
  const p = makePacketParser();
  p.init(new Uint8Array(2)); // need 4 for flags
  assertEquals(p.readAttrs(), undefined);
});

Deno.test('PacketParser: readAttrs returns undefined when SIZE data missing', () => {
  const p = makePacketParser();
  // flags with SIZE but only 4 extra bytes instead of 8
  const extra = new Uint8Array(4);
  p.init(buildAttrsBuffer(ATTR.SIZE, extra));
  assertEquals(p.readAttrs(), undefined);
});

// =============================================================================
// SFTP.push assembling a WRITE
// =============================================================================

/** A server's SFTP session that has taken INIT, and the bytes of a WRITE for it. */
function writeAssembly(dataLength: number) {
  const sftp = new SFTP(
    { protocol: { channelData() {}, channelClose() {} } },
    {
      type: 'session',
      incoming: { id: 0, window: 1 << 21, packetSize: 32768, state: 'open' },
      outgoing: { id: 0, window: 1 << 21, packetSize: 32768, state: 'open' },
    },
    { server: true },
  );
  sftp.push(new Uint8Array([0, 0, 0, 5, 1, 0, 0, 0, 3]));

  const handle = new Uint8Array([7, 7, 7, 7]);
  const data = new Uint8Array(dataLength);
  for (let i = 0; i < data.length; i++) data[i] = (i * 7) & 0xff;
  const body = 1 + 4 + 4 + handle.length + 8 + 4 + data.length;
  const packet = new Uint8Array(4 + body);
  const view = new DataView(packet.buffer);
  view.setUint32(0, body);
  packet[4] = 6; // WRITE
  view.setUint32(5, 42);
  view.setUint32(9, handle.length);
  packet.set(handle, 13);
  view.setBigUint64(13 + handle.length, 65536n);
  view.setUint32(21 + handle.length, data.length);
  packet.set(data, 25 + handle.length);

  const writes: { id: number; handle: Uint8Array; offset: number | bigint; data: Uint8Array }[] =
    [];
  sftp.on('WRITE', (id: number, h: Uint8Array, offset: number | bigint, d: Uint8Array) => {
    writes.push({ id, handle: h, offset, data: d });
  });
  return { sftp, packet, handle, data, writes };
}

Deno.test('SFTP.push: a WRITE spanning pushes has its data in a buffer it fills', () => {
  const { sftp, packet, handle, data, writes } = writeAssembly(32768);
  // Cut within the length and within the data, as channel packets may cut it.
  const parts = [packet.subarray(0, 2), packet.subarray(2, 20000), packet.subarray(20000)];
  for (const part of parts) sftp.push(part.slice());

  assertEquals(writes.length, 1);
  const [write] = writes;
  assertEquals(write.id, 42);
  assertEquals(write.handle, handle);
  assertEquals(write.offset, 65536);
  assertEquals(write.data, data);
  assertEquals(write.data.byteOffset, 0);
  assertEquals(write.data.byteLength, write.data.buffer.byteLength);
  // Taking the buffer leaves the handle, assembled apart, as it was.
  structuredClone(write.data, { transfer: [write.data.buffer as ArrayBuffer] });
  assertEquals(write.handle, handle);
});

Deno.test('SFTP.push: a WRITE whose fields before the data span pushes is assembled whole', () => {
  const { sftp, packet, data, writes } = writeAssembly(1000);
  sftp.push(packet.slice(0, 15));
  sftp.push(packet.slice(15));

  assertEquals(writes.length, 1);
  assertEquals(writes[0].data, data);
  assertEquals(writes[0].data.byteLength < writes[0].data.buffer.byteLength, true);
});

Deno.test('SFTP.push: a WRITE in one push is a view of it', () => {
  const { sftp, packet, data, writes } = writeAssembly(1000);
  sftp.push(packet);

  assertEquals(writes.length, 1);
  assertEquals(writes[0].data, data);
  assertEquals(writes[0].data.buffer, packet.buffer);
});
