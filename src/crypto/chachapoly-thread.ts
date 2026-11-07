/**
 * chacha20-poly1305@openssh.com sealing and opening on worker threads.
 *
 * Sealing or opening a 32 KiB packet takes the thread that does it about 40 µs,
 * most of it Poly1305 and ChaCha20. A connection's large packets go to a pool
 * of workers, shared by every connection in the process, in batches: a message
 * costs the main thread about 23 µs there and back, whatever its size, so a
 * batch carries as many packets as are waiting. Opened payloads are written
 * to a buffer the worker allocates, so that its pages are faulted in there.
 *
 * A batch goes to the ready worker with the fewest batches waiting; another
 * is started while every ready one has some, up to MAX_THREADS. Any worker can
 * take any batch: each carries the 64-byte SSH key and its first sequence
 * number, and the cipher and decipher put the results back in order.
 *
 * A worker is started from a Blob URL holding the source of
 * `chachaPolyWorker`, so it needs no module of its own to be fetched or cached.
 * They stop together once none has had a batch for IDLE_MS.
 */

import { CHACHAPOLY_WASM } from './chachapoly-wasm.ts';

/** Room for the packets of one batch, before their tags. */
const BATCH = 256 * 1024;

/**
 * How long the workers outlive the last batch. A worker started from a worker,
 * as a server on a thread of its own starts them, takes about a second to
 * answer, so requests some seconds apart should find them running.
 */
const IDLE_MS = 30_000;

/** The `seq` of the reply that says a worker is ready; batches count from 1. */
const READY = 0;

/** The most workers at once: half the CPUs, which leaves the others to the threads that feed them. */
const MAX_THREADS = Math.max(1, Math.min(4, Math.floor((navigator.hardwareConcurrency || 2) / 2)));

/** Batch buffers the worker gave back; a fresh one faults in every page as it is filled. */
const spare: ArrayBuffer[] = [];
const MAX_SPARE = 8;

/**
 * A request to the worker. Packets lie back to back in `buf`, `used` bytes of
 * it: to be sealed, packets as allocPacket() lays them out; to be opened, the
 * records as they arrived, each its encrypted length, packet and MAC. Records
 * to be opened can also lie in `shared`, from `from` to `to`, after those in
 * `buf`: the memory a transport read them into, opened where they are.
 */
interface BatchRequest {
  op: 'seal' | 'open';
  seq: number;
  key: Uint8Array;
  seqno: number;
  buf?: ArrayBuffer;
  used: number;
  shared?: SharedArrayBuffer;
  from?: number;
  to?: number;
}

interface InitRequest {
  op: 'init';
  wasm: WebAssembly.Module;
}

interface BatchReply {
  seq: number;
  /** The request's buffer, handed back to be filled again. */
  buf?: ArrayBuffer;
  /** The sealed records, or the opened payloads, back to back. */
  out: ArrayBuffer;
  /** Opened: each payload's length. */
  lens?: number[];
  /** Opened: why the packet after those in `lens` could not be. */
  error?: string;
}

/**
 * The worker, given node:crypto's createCipheriv. Everything it uses is inside
 * it, since its source is all the worker gets. Its memory layout is that of
 * chacha20.ts. Payloads from NATIVE_MIN bytes on use the native ChaCha20, which
 * is faster than the WebAssembly one once its per-call setup is paid off.
 */
function chachaPolyWorker(createCipheriv: typeof import('node:crypto').createCipheriv): void {
  const KEY_MAIN = 64;
  const KEY_LEN = 96;
  const NONCE = 128;
  const POLY_KEY = 144;
  const PACKET = 208;
  const NATIVE_MIN = 2048;
  const PAGE = 65536;

  interface Exports {
    memory: WebAssembly.Memory;
    chacha20(key: number, nonce: number, counter: number, data: number, len: number): void;
    poly1305(key: number, msg: number, len: number, out: number): void;
  }
  type Scope = {
    onmessage: ((event: MessageEvent<InitRequest | BatchRequest>) => void) | null;
    postMessage(message: BatchReply, transfer: Transferable[]): void;
  };

  let wasm: Exports;
  let mem: Uint8Array;
  const keyMain = new Uint8Array(32);
  // The native counter-and-nonce block: payloads start at block 1.
  const iv = new Uint8Array(16);
  iv[0] = 1;

  const readU32 = (b: Uint8Array, o: number) =>
    ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

  const reserve = (size: number) => {
    const need = PACKET + size - mem.length;
    if (need > 0) {
      wasm.memory.grow(Math.ceil(need / PAGE));
      mem = new Uint8Array(wasm.memory.buffer);
    }
  };

  const begin = (seqno: number) => {
    mem[NONCE + 4] = seqno >>> 24;
    mem[NONCE + 5] = seqno >>> 16;
    mem[NONCE + 6] = seqno >>> 8;
    mem[NONCE + 7] = seqno;
    mem.fill(0, POLY_KEY, POLY_KEY + 32);
    wasm.chacha20(KEY_MAIN, NONCE, 0, POLY_KEY, 32);
  };

  const native = (data: Uint8Array): Uint8Array => {
    iv.set(mem.subarray(NONCE, NONCE + 8), 8);
    const cipher = createCipheriv('chacha20', keyMain, iv);
    const out = cipher.update(data);
    // Deno keeps the native context until final().
    cipher.final();
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
  };

  const seal = (src: Uint8Array, seqno: number): Uint8Array<ArrayBuffer> => {
    let count = 0;
    for (let o = 0; o < src.length; o += readU32(src, o) + 4) count++;
    const out = new Uint8Array(new ArrayBuffer(src.length + 16 * count));
    let w = 0;
    for (let o = 0; o < src.length; seqno = (seqno + 1) >>> 0) {
      const pktLen = readU32(src, o) + 4;
      const len = pktLen - 4;
      reserve(pktLen + 16);
      mem.set(src.subarray(o, o + pktLen), PACKET);
      begin(seqno);
      wasm.chacha20(KEY_LEN, NONCE, 0, PACKET, 4);
      if (len < NATIVE_MIN) wasm.chacha20(KEY_MAIN, NONCE, 1, PACKET + 4, len);
      else mem.set(native(src.subarray(o + 4, o + pktLen)), PACKET + 4);
      wasm.poly1305(POLY_KEY, PACKET, pktLen, PACKET + pktLen);
      out.set(mem.subarray(PACKET, PACKET + pktLen + 16), w);
      w += pktLen + 16;
      o += pktLen;
    }
    return out;
  };

  const open = (srcs: Uint8Array[], seqno: number) => {
    let size = 0;
    for (const src of srcs) size += src.length;
    const out = new Uint8Array(new ArrayBuffer(size));
    const lens: number[] = [];
    let w = 0;
    for (const src of srcs) {
      for (let o = 0; o < src.length; seqno = (seqno + 1) >>> 0) {
        begin(seqno);
        mem.set(src.subarray(o, o + 4), PACKET);
        wasm.chacha20(KEY_LEN, NONCE, 0, PACKET, 4);
        const len = readU32(mem, PACKET);
        const pktLen = len + 4;
        reserve(pktLen + 16);
        mem.set(src.subarray(o, o + pktLen), PACKET);
        wasm.poly1305(POLY_KEY, PACKET, pktLen, PACKET + pktLen);
        let diff = 0;
        for (let i = 0; i < 16; i++) diff |= mem[PACKET + pktLen + i] ^ src[o + pktLen + i];
        if (diff !== 0) return { out, lens, error: 'Invalid MAC' };
        // Packets come here from THREAD_MIN (chacha20.ts) bytes on, all native-sized.
        const plain = native(src.subarray(o + 4, o + pktLen));
        const padLen = plain[0];
        if (padLen > len - 1) return { out, lens, error: 'Invalid padding length' };
        const payloadLen = len - 1 - padLen;
        out.set(plain.subarray(1, 1 + payloadLen), w);
        w += payloadLen;
        lens.push(payloadLen);
        o += pktLen + 16;
      }
    }
    return { out, lens };
  };

  const scope = self as unknown as Scope;
  scope.onmessage = ({ data }) => {
    if (data.op === 'init') {
      wasm = new WebAssembly.Instance(data.wasm).exports as unknown as Exports;
      mem = new Uint8Array(wasm.memory.buffer);
      // READY: this source runs on its own, without the module around it.
      scope.postMessage({ seq: 0, out: new ArrayBuffer(0) }, []);
      return;
    }
    mem.set(data.key.subarray(0, 64), KEY_MAIN);
    keyMain.set(data.key.subarray(0, 32));
    const buf = data.buf;
    if (data.op === 'seal') {
      const out = seal(new Uint8Array(buf!, 0, data.used), data.seqno);
      scope.postMessage({ seq: data.seq, buf, out: out.buffer }, [buf!, out.buffer]);
      return;
    }
    const srcs: Uint8Array[] = [];
    if (buf) srcs.push(new Uint8Array(buf, 0, data.used));
    if (data.shared) srcs.push(new Uint8Array(data.shared, data.from, data.to! - data.from!));
    const { out, lens, error } = open(srcs, data.seqno);
    scope.postMessage(
      { seq: data.seq, buf, out: out.buffer, lens, error },
      buf ? [buf, out.buffer] : [out.buffer],
    );
  };
}

type Thread = {
  worker: Worker;
  /** Whether it has said it is ready: started from a worker, a worker takes about a second to. */
  warm: boolean;
  replies: Map<number, { resolve: (reply: BatchReply) => void; reject: (error: Error) => void }>;
};

const threads: Thread[] = [];
let workerUrl: string | undefined;
/**
 * The WebAssembly, compiled once for every worker: they share its code, and the
 * optimized code V8 makes of it once it runs hot, which a worker compiling its
 * own would wait for at every start.
 */
let compiled: WebAssembly.Module | undefined;
let nextSeq = 1;
/** When the last reply came, from any worker; the pool stops IDLE_MS after it. */
let idleSince = 0;
let idleTimer: ReturnType<typeof setTimeout> | undefined;

const stopThread = (stopping: Thread, error: Error) => {
  const at = threads.indexOf(stopping);
  if (at >= 0) threads.splice(at, 1);
  stopping.worker.terminate();
  for (const reply of stopping.replies.values()) reply.reject(error);
  stopping.replies.clear();
};

/**
 * Stops every worker once none has had a batch for IDLE_MS. They stop
 * together: a worker the others leave idle during a transfer is kept, since
 * starting one again costs it its warm-up. The timer is set once and looks
 * again when it fires, rather than being set again after every batch. It does
 * not keep the process alive, but the workers do until it fires.
 */
const releaseThreads = () => {
  idleSince = performance.now();
  if (idleTimer !== undefined) return;
  const check = (delay: number) => {
    idleTimer = setTimeout(() => {
      idleTimer = undefined;
      if (threads.some((t) => t.replies.size > 0)) return;
      const idle = performance.now() - idleSince;
      if (idle < IDLE_MS) return check(IDLE_MS - idle);
      for (const t of [...threads]) {
        stopThread(t, new Error('the chacha20-poly1305 thread stopped'));
      }
    }, delay);
    Deno.unrefTimer(idleTimer);
  };
  check(IDLE_MS);
};

/** Starts a worker; it takes batches once it says it is ready. One that fails fails the batches it holds. */
const startThread = (): Thread => {
  workerUrl ??= URL.createObjectURL(
    new Blob([
      `import { createCipheriv } from 'node:crypto';\n(${chachaPolyWorker})(createCipheriv);\n`,
    ], { type: 'text/javascript' }),
  );
  const worker = new Worker(workerUrl, { type: 'module' });
  const started: Thread = { worker, warm: false, replies: new Map() };
  worker.onmessage = ({ data }: MessageEvent<BatchReply>) => {
    if (data.seq === READY) {
      started.warm = true;
      return;
    }
    if (data.buf && spare.length < MAX_SPARE) spare.push(data.buf);
    const reply = started.replies.get(data.seq);
    if (!reply) return;
    started.replies.delete(data.seq);
    reply.resolve(data);
    releaseThreads();
  };
  worker.onerror = (event) => {
    event.preventDefault();
    stopThread(started, new Error(`the chacha20-poly1305 thread failed: ${event.message}`));
  };
  compiled ??= new WebAssembly.Module(CHACHAPOLY_WASM as BufferSource);
  worker.postMessage({ op: 'init', wasm: compiled } satisfies InitRequest);
  threads.push(started);
  return started;
};

/**
 * The worker for the next batch: the least busy ready one. While every ready
 * one is busy, another is started, one at a time, up to MAX_THREADS; the
 * batch still goes to a ready one, since a connection's records are written in
 * order and one batch waiting for a start holds back all that follow it. Only
 * when none is ready does the batch wait for a start.
 */
const startedThread = (): Thread => {
  let least: Thread | undefined;
  for (const t of threads) if (t.warm && (!least || t.replies.size < least.replies.size)) least = t;
  const starting = threads.find((t) => !t.warm);
  if (!starting && threads.length < MAX_THREADS && (!least || least.replies.size > 0)) {
    const fresh = startThread();
    if (!least) return fresh;
  }
  return least ?? starting!;
};

const request = (
  op: BatchRequest['op'],
  key: Uint8Array,
  seqno: number,
  buf: ArrayBuffer | undefined,
  used: number,
  shared?: InPlace,
): Promise<BatchReply> => {
  const owner = startedThread();
  const seq = nextSeq++;
  const { promise, resolve, reject } = Promise.withResolvers<BatchReply>();
  owner.replies.set(seq, { resolve, reject });
  owner.worker.postMessage(
    {
      op,
      seq,
      key,
      seqno,
      buf,
      used,
      shared: shared?.buffer,
      from: shared?.from,
      to: shared?.to,
    } satisfies BatchRequest,
    buf ? [buf] : [],
  );
  return promise;
};

/** A buffer for a batch of at least `size` bytes, one given back if there is one. */
export function batchBuffer(size = BATCH): ArrayBuffer {
  for (let i = spare.length - 1; i >= 0; i--) {
    if (spare[i].byteLength >= size) return spare.splice(i, 1)[0];
  }
  return new ArrayBuffer(Math.max(size, BATCH));
}

/**
 * Seals the packets in the first `used` bytes of `buf`, which is handed over,
 * the first under `seqno`. Resolves to their records back to back.
 */
export async function sealOnThread(
  key: Uint8Array,
  seqno: number,
  buf: ArrayBuffer,
  used: number,
): Promise<Uint8Array> {
  const reply = await request('seal', key, seqno, buf, used);
  return new Uint8Array(reply.out);
}

/** Payloads opened on the worker, back to back in `out`. */
export interface Opened {
  out: ArrayBuffer;
  lens: number[];
  /** Why the packet after those opened failed, if one did. */
  error?: string;
}

/** Records back to back in shared memory, from `from` to `to`. */
export interface InPlace {
  buffer: SharedArrayBuffer;
  from: number;
  to: number;
}

/**
 * Opens the records in the first `used` bytes of `buf`, which is handed over,
 * then those `shared` holds, the first under `seqno`. The shared memory is read
 * until the promise settles, and must not change before. Payloads are opened
 * until one fails its MAC or padding check.
 */
export async function openOnThread(
  key: Uint8Array,
  seqno: number,
  buf: ArrayBuffer | undefined,
  used: number,
  shared?: InPlace,
): Promise<Opened> {
  const { out, lens, error } = await request('open', key, seqno, buf, used, shared);
  return { out, lens: lens!, error };
}
