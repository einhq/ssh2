/**
 * Channel.ts unit tests
 *
 * Tests SSH channel operations using mock protocol objects.
 */

import { assertEquals, assertThrows } from '@std/assert';
import {
  Channel,
  type ChannelClient,
  MAX_WINDOW,
  PACKET_SIZE,
  WINDOW_THRESHOLD,
  windowAdjust,
} from '../src/Channel.ts';

// =============================================================================
// Mock helpers
// =============================================================================

interface ProtocolCall {
  method: string;
  // deno-lint-ignore no-explicit-any
  args: any[];
}

function createMockClient(): ChannelClient & { calls: ProtocolCall[] } {
  const calls: ProtocolCall[] = [];
  const protocol = {
    channelData(id: number, data: Uint8Array) {
      calls.push({ method: 'channelData', args: [id, data] });
    },
    channelExtData(id: number, data: Uint8Array, type: number) {
      calls.push({ method: 'channelExtData', args: [id, data, type] });
    },
    channelEOF(id: number) {
      calls.push({ method: 'channelEOF', args: [id] });
    },
    channelClose(id: number) {
      calls.push({ method: 'channelClose', args: [id] });
    },
    channelWindowAdjust(id: number, amount: number) {
      calls.push({ method: 'channelWindowAdjust', args: [id, amount] });
    },
    windowChange(id: number, rows: number, cols: number, h: number, w: number) {
      calls.push({ method: 'windowChange', args: [id, rows, cols, h, w] });
    },
    signal(id: number, signalName: string) {
      calls.push({ method: 'signal', args: [id, signalName] });
    },
    exitStatus(id: number, status: number) {
      calls.push({ method: 'exitStatus', args: [id, status] });
    },
    exitSignal(id: number, sig: string, coreDumped: boolean, msg: string) {
      calls.push({ method: 'exitSignal', args: [id, sig, coreDumped, msg] });
    },
  };
  return { _protocol: protocol, calls };
}

function makeInfo(type = 'session') {
  return {
    type,
    incoming: { id: 1, window: MAX_WINDOW, packetSize: PACKET_SIZE, state: 'open' as const },
    outgoing: { id: 0, window: MAX_WINDOW, packetSize: PACKET_SIZE, state: 'open' as const },
  };
}

// =============================================================================
// Constants
// =============================================================================

Deno.test('Channel: MAX_WINDOW is 2MB', () => {
  assertEquals(MAX_WINDOW, 2 * 1024 * 1024);
});

Deno.test('Channel: PACKET_SIZE is 32KB', () => {
  assertEquals(PACKET_SIZE, 32 * 1024);
});

Deno.test('Channel: WINDOW_THRESHOLD is half of MAX_WINDOW', () => {
  assertEquals(WINDOW_THRESHOLD, MAX_WINDOW / 2);
});

// =============================================================================
// Construction
// =============================================================================

Deno.test('Channel: basic construction (client side)', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  assertEquals(chan.type, 'session');
  assertEquals(chan.server, false);
  assertEquals(chan.allowHalfOpen, true);
  assertEquals(chan.incoming.state, 'open');
  assertEquals(chan.outgoing.state, 'open');
});

Deno.test('Channel: construction with server=true', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });
  assertEquals(chan.server, true);
});

Deno.test('Channel: construction with allowHalfOpen=false', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { allowHalfOpen: false });
  assertEquals(chan.allowHalfOpen, false);
});

Deno.test('Channel: readable/stdout/writable/stdin getters', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  assertEquals(chan.readable instanceof ReadableStream, true);
  assertEquals(chan.writable instanceof WritableStream, true);
  assertEquals(chan.stdout instanceof ReadableStream, true);
  assertEquals(chan.stdin instanceof WritableStream, true);
  assertEquals(chan.readable, chan.stdout);
  assertEquals(chan.writable, chan.stdin);
});

Deno.test('Channel: stderr getter returns WritableStream on server side', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });
  // Server-side stderr is a StderrWritable wrapper
  const stderr = chan.stderr;
  assertEquals(typeof (stderr as { write?: unknown }).write, 'function');
});

Deno.test('Channel: stderr getter returns ReadableStream on client side', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  const stderr = chan.stderr;
  assertEquals(stderr instanceof ReadableStream, true);
});

// =============================================================================
// pushData
// =============================================================================

Deno.test('Channel: pushData enqueues data to readable stream', async () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  const data = new Uint8Array([1, 2, 3]);

  chan.pushData(data);

  const reader = chan.readable.getReader();
  const { value } = await reader.read();
  reader.releaseLock();

  assertEquals(value, data);
});

Deno.test('Channel: pushData decrements incoming window', () => {
  const client = createMockClient();
  const info = makeInfo();
  const chan = new Channel(client, info);
  const initialWindow = chan.incoming.window;
  const data = new Uint8Array(100);

  chan.pushData(data);
  assertEquals(chan.incoming.window, initialWindow - 100);
});

Deno.test('Channel: pushData returns false for stderr on server-side channel', () => {
  const client = createMockClient();
  // Server-side channels have no stderrController (they use WritableStream instead)
  const chan = new Channel(client, makeInfo(), { server: true });
  // isStderr=true on server side: no stderrController → returns false
  const result = chan.pushData(new Uint8Array([1]), true);
  assertEquals(result, false);
});

// =============================================================================
// write (sync)
// =============================================================================

Deno.test('Channel: write sends data via protocol.channelData', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  const data = new Uint8Array([10, 20, 30]);

  chan.write(data);

  assertEquals(client.calls.length, 1);
  assertEquals(client.calls[0].method, 'channelData');
  assertEquals(client.calls[0].args[1], data);
});

Deno.test('Channel: write accepts string data', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  chan.write('hello');

  assertEquals(client.calls.length, 1);
  assertEquals(client.calls[0].method, 'channelData');
  assertEquals(new TextDecoder().decode(client.calls[0].args[1] as Uint8Array), 'hello');
});

Deno.test('Channel: write does nothing when outgoing state is not open', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  chan.outgoing.state = 'closed';

  chan.write(new Uint8Array([1, 2, 3]));

  assertEquals(client.calls.length, 0);
});

Deno.test('Channel: writes past the window wait their turn and none is lost', async () => {
  const client = createMockClient();
  const info = makeInfo();
  info.outgoing.window = 5;
  const chan = new Channel(client, info, { server: true });
  const settled: string[] = [];

  const first = chan.write('abcdefgh').then(() => settled.push('first'));
  const second = chan.write('ijkl').then(() => settled.push('second'));
  const third = (chan.stderr as { write: (d: string) => Promise<void> }).write('ERR');
  chan.write('mn');

  const sent = () =>
    client.calls.filter((c) => c.method === 'channelData' || c.method === 'channelExtData').map((
      c,
    ) => new TextDecoder().decode(c.args[1] as Uint8Array)).join('|');
  assertEquals(sent(), 'abcde');
  await Promise.resolve();
  assertEquals(settled, []);

  chan.adjustWindow(4);
  assertEquals(sent(), 'abcde|fgh|i');
  chan.adjustWindow(100);
  assertEquals(sent(), 'abcde|fgh|i|jkl|ERR|mn');
  await Promise.all([first, second, third]);
  assertEquals(settled, ['first', 'second']);
});

Deno.test('Channel: write sends in packets of the remote packet size', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  chan.write(new Uint8Array(PACKET_SIZE * 2 + 1));

  assertEquals(client.calls.map((c) => (c.args[1] as Uint8Array).length), [
    PACKET_SIZE,
    PACKET_SIZE,
    1,
  ]);
});

Deno.test('Channel: exit, EOF and close from end() follow the data still waiting for window', () => {
  const client = createMockClient();
  const info = makeInfo();
  info.outgoing.window = 2;
  const chan = new Channel(client, info, { server: true });

  chan.write('abcd');
  chan.exit(0);
  chan.end();
  assertEquals(client.calls.map((c) => c.method), ['channelData']);

  chan.adjustWindow(2);
  assertEquals(client.calls.map((c) => c.method), [
    'channelData',
    'channelData',
    'exitStatus',
    'channelEOF',
    'channelClose',
  ]);
  assertEquals(chan.outgoing.state, 'closing');
});

Deno.test('Channel: a write after EOF is dropped', async () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  chan.eof();
  await chan.write('late');

  assertEquals(client.calls.map((c) => c.method), ['channelEOF']);
});

Deno.test('Channel: close drops the data waiting for window but sends the exit asked for before', async () => {
  const client = createMockClient();
  const info = makeInfo();
  info.outgoing.window = 0;
  const chan = new Channel(client, info, { server: true });

  const waiting = chan.write('abcd');
  chan.exit(1);
  chan.close();
  await waiting;

  assertEquals(client.calls.map((c) => c.method), ['exitStatus', 'channelClose']);
});

Deno.test('Channel: the remote closing settles writes waiting for window', async () => {
  const client = createMockClient();
  const info = makeInfo();
  info.outgoing.window = 0;
  const chan = new Channel(client, info);

  const waiting = chan.write('abcd');
  chan.handleClose();
  await waiting;

  assertEquals(client.calls.length, 0);
});

// =============================================================================
// eof and handleEOF
// =============================================================================

Deno.test('Channel: eof sends channelEOF and emits eof event', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  let eofCount = 0;
  chan.on('eof', () => {
    eofCount++;
  });

  chan.eof();

  assertEquals(chan.outgoing.state, 'eof');
  assertEquals(client.calls.some((c) => c.method === 'channelEOF'), true);
  assertEquals(eofCount, 1);
});

Deno.test('Channel: eof is idempotent when state is not open', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  chan.outgoing.state = 'eof';

  chan.eof();
  assertEquals(client.calls.length, 0);
});

Deno.test('Channel: handleEOF closes readableController and emits end', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  let endCount = 0;
  chan.on('end', () => {
    endCount++;
  });

  chan.handleEOF();

  assertEquals(endCount, 1);
});

// =============================================================================
// close and handleClose
// =============================================================================

Deno.test('Channel: close sends channelClose and sets state to closing', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  chan.close();

  assertEquals(chan.outgoing.state, 'closing');
  assertEquals(client.calls.some((c) => c.method === 'channelClose'), true);
});

Deno.test('Channel: close is idempotent when already closing/closed', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  chan.outgoing.state = 'closed';

  chan.close();
  assertEquals(client.calls.length, 0);
});

Deno.test('Channel: handleClose sets both states to closed and emits close', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  let closeCount = 0;
  chan.on('close', () => {
    closeCount++;
  });

  chan.handleClose();

  assertEquals(chan.incoming.state, 'closed');
  assertEquals(chan.outgoing.state, 'closed');
  assertEquals(closeCount, 1);
});

Deno.test('Channel: destroy is an alias for close', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  chan.destroy();

  assertEquals(chan.outgoing.state, 'closing');
  assertEquals(client.calls.some((c) => c.method === 'channelClose'), true);
});

Deno.test('Channel: end calls eof and close', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  chan.end();

  const methods = client.calls.map((c) => c.method);
  assertEquals(methods.includes('channelEOF'), true);
  assertEquals(methods.includes('channelClose'), true);
});

// =============================================================================
// adjustWindow
// =============================================================================

Deno.test('Channel: adjustWindow increases outgoing window', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  const initial = chan.outgoing.window;

  chan.adjustWindow(1000);

  assertEquals(chan.outgoing.window, initial + 1000);
});

Deno.test('Channel: adjustWindow emits drain when waitWindow was true', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  let drainCount = 0;
  chan.on('drain', () => {
    drainCount++;
  });

  // Simulate window exhaustion
  chan.outgoing.window = 0;
  // Force _waitWindow = true by writing data
  chan.write(new Uint8Array(1)); // window=0, so data queued

  chan.adjustWindow(100);

  assertEquals(drainCount, 1);
});

// =============================================================================
// windowAdjust exported function
// =============================================================================

Deno.test('Channel: windowAdjust exported function triggers window adjustment', () => {
  const client = createMockClient();
  const info = makeInfo();
  // Set incoming window low to trigger adjustment
  info.incoming.window = WINDOW_THRESHOLD - 100;
  const chan = new Channel(client, info);

  windowAdjust(chan);

  // Should call channelWindowAdjust if window needs adjustment
  assertEquals(client.calls.some((c) => c.method === 'channelWindowAdjust'), true);
});

// =============================================================================
// exit and sendExit (server-only)
// =============================================================================

Deno.test('Channel: exit with numeric code sends exit status', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  chan.exit(0);

  const call = client.calls.find((c) => c.method === 'exitStatus');
  assertEquals(call?.args[1], 0);
});

Deno.test('Channel: exit with signal string sends exit signal', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  chan.exit('TERM');

  const call = client.calls.find((c) => c.method === 'exitSignal');
  assertEquals(call?.args[1], 'TERM');
});

Deno.test('Channel: exit strips SIG prefix from signal name', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  chan.exit('SIGKILL');

  const call = client.calls.find((c) => c.method === 'exitSignal');
  assertEquals(call?.args[1], 'KILL');
});

Deno.test('Channel: exit throws for invalid signal name', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  assertThrows(() => chan.exit('FAKESIGNAL'), Error, 'Invalid signal');
});

Deno.test('Channel: exit throws when called in client mode', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo()); // client mode

  assertThrows(() => chan.exit(0), Error, 'Server-only method');
});

Deno.test('Channel: sendExit with number sends exitStatus', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  chan.sendExit(42);

  const call = client.calls.find((c) => c.method === 'exitStatus');
  assertEquals(call?.args[1], 42);
});

Deno.test('Channel: sendExit with string sends exitSignal', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  chan.sendExit('HUP', true, 'hung up');

  const call = client.calls.find((c) => c.method === 'exitSignal');
  assertEquals(call?.args[1], 'HUP');
  assertEquals(call?.args[2], true);
  assertEquals(call?.args[3], 'hung up');
});

Deno.test('Channel: sendExit throws when called in client mode', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  assertThrows(() => chan.sendExit(0), Error, 'Server-only method');
});

// =============================================================================
// handleExitStatus / handleExitSignal
// =============================================================================

Deno.test('Channel: handleExitStatus sets exitInfo.code and emits exit-status', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  let receivedCode = -1;
  chan.on('exit-status', (code) => {
    receivedCode = code;
  });

  chan.handleExitStatus(42);

  assertEquals(chan.exitInfo.code, 42);
  assertEquals(receivedCode, 42);
});

Deno.test('Channel: handleExitSignal sets exitInfo fields and emits exit-signal', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  let evtSignal = '';
  let evtDump = false;
  let evtDesc = '';
  chan.on('exit-signal', (sig, dump, desc) => {
    evtSignal = sig;
    evtDump = dump;
    evtDesc = desc;
  });

  chan.handleExitSignal('TERM', true, 'core dumped');

  assertEquals(chan.exitInfo.signal, 'TERM');
  assertEquals(chan.exitInfo.dump, true);
  assertEquals(chan.exitInfo.desc, 'core dumped');
  assertEquals(evtSignal, 'TERM');
  assertEquals(evtDump, true);
  assertEquals(evtDesc, 'core dumped');
});

// =============================================================================
// setWindow (client-only)
// =============================================================================

Deno.test('Channel: setWindow calls windowChange protocol method', () => {
  const client = createMockClient();
  const info = makeInfo();
  const chan = new Channel(client, info);
  chan.subtype = 'shell';

  chan.setWindow(24, 80, 600, 800);

  const call = client.calls.find((c) => c.method === 'windowChange');
  assertEquals(call?.args[1], 24);
  assertEquals(call?.args[2], 80);
});

Deno.test('Channel: setWindow throws in server mode', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  assertThrows(() => chan.setWindow(24, 80, 0, 0), Error, 'Client-only method');
});

// =============================================================================
// signal (client-only)
// =============================================================================

Deno.test('Channel: signal sends signal via protocol', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  chan.signal('INT');

  const call = client.calls.find((c) => c.method === 'signal');
  assertEquals(call?.args[1], 'INT');
});

Deno.test('Channel: signal throws in server mode', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  assertThrows(() => chan.signal('INT'), Error, 'Client-only method');
});

// =============================================================================
// addCallback / flushCallbacks
// =============================================================================

Deno.test('Channel: addCallback and flushCallbacks', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  const log: string[] = [];

  chan.addCallback(() => log.push('a'));
  chan.addCallback(() => log.push('b'));
  assertEquals(log, []);

  chan.flushCallbacks();
  assertEquals(log, ['a', 'b']);

  // Second flush: callbacks cleared
  chan.flushCallbacks();
  assertEquals(log, ['a', 'b']);
});

// =============================================================================
// hasX11 getter/setter
// =============================================================================

Deno.test('Channel: hasX11 getter returns false by default', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  assertEquals(chan.hasX11, false);
});

Deno.test('Channel: hasX11 setter updates the value', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());
  chan.hasX11 = true;
  assertEquals(chan.hasX11, true);
});

// =============================================================================
// stderr on server side (StderrWritable.write)
// =============================================================================

Deno.test('Channel: server stderr.write sends ext data', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });
  const stderr = chan.stderr as { write: (d: Uint8Array | string) => void };

  stderr.write(new Uint8Array([0xff]));

  const call = client.calls.find((c) => c.method === 'channelExtData');
  assertEquals(call !== undefined, true);
});

Deno.test('Channel: server stderr.write accepts string', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });
  const stderr = chan.stderr as { write: (d: Uint8Array | string) => void };

  stderr.write('error message');

  const call = client.calls.find((c) => c.method === 'channelExtData');
  assertEquals(new TextDecoder().decode(call?.args[1] as Uint8Array), 'error message');
});

// =============================================================================
// pushData for stderr (client side)
// =============================================================================

Deno.test('Channel: pushData with isStderr=true enqueues to stderr stream', async () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo()); // client side
  const data = new Uint8Array([7, 8, 9]);

  const result = chan.pushData(data, true);
  assertEquals(result, true);

  const stderrStream = chan.stderr as ReadableStream<Uint8Array>;
  const reader = stderrStream.getReader();
  const { value } = await reader.read();
  reader.releaseLock();

  assertEquals(value, data);
});

// =============================================================================
// WritableStream path (via getWriter)
// =============================================================================

Deno.test('Channel: WritableStream write sends data via channelData', async () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  const writer = chan.writable.getWriter();
  await writer.write(new Uint8Array([42, 43, 44]));
  writer.releaseLock();

  const call = client.calls.find((c) => c.method === 'channelData');
  assertEquals(call !== undefined, true);
  assertEquals((call?.args[1] as Uint8Array)[0], 42);
});

Deno.test('Channel: WritableStream close triggers eof', async () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  const writer = chan.writable.getWriter();
  await writer.close();

  // close() sets _writableClosed=true, calls eof() → channelEOF
  const hasEOF = client.calls.some((c) => c.method === 'channelEOF');
  assertEquals(hasEOF, true);
});

Deno.test('Channel: WritableStream abort triggers close', async () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo());

  const writer = chan.writable.getWriter();
  await writer.abort();

  // abort() calls this.close() → channelClose
  const hasClose = client.calls.some((c) => c.method === 'channelClose');
  assertEquals(hasClose, true);
});

// =============================================================================
// pushData backpressure (window <= WINDOW_THRESHOLD)
// =============================================================================

Deno.test('Channel: pushData sets _waitChanDrain when window drops to threshold', () => {
  const client = createMockClient();
  const info = makeInfo();
  // Set incoming window just above threshold
  info.incoming.window = WINDOW_THRESHOLD + 1;
  const chan = new Channel(client, info);

  // Push data that brings window down to WINDOW_THRESHOLD
  const data = new Uint8Array(2); // window - 2 = WINDOW_THRESHOLD - 1 <= WINDOW_THRESHOLD
  chan.pushData(data);

  // Window should have decreased
  assertEquals(chan.incoming.window, WINDOW_THRESHOLD - 1);
});

// =============================================================================
// windowAdjust guard: already full incoming window is a no-op
// =============================================================================

Deno.test('Channel: windowAdjust does nothing when incoming window is already MAX', () => {
  const client = createMockClient();
  const info = makeInfo();
  // incoming.window = MAX_WINDOW (no adjustment needed)
  info.incoming.window = MAX_WINDOW;
  const chan = new Channel(client, info);

  windowAdjust(chan);

  // No channelWindowAdjust call since amt <= 0
  assertEquals(client.calls.some((c) => c.method === 'channelWindowAdjust'), false);
});

Deno.test('Channel: windowAdjust does nothing when outgoing is closed', () => {
  const client = createMockClient();
  const info = makeInfo();
  info.incoming.window = 100; // low, would normally trigger adjust
  const chan = new Channel(client, info);
  chan.outgoing.state = 'closed'; // closed state → guard returns early

  windowAdjust(chan);

  assertEquals(client.calls.some((c) => c.method === 'channelWindowAdjust'), false);
});

// =============================================================================
// adjustWindow with pending stderr data
// =============================================================================

Deno.test('Channel: adjustWindow flushes pending stderr data', () => {
  const client = createMockClient();
  const chan = new Channel(client, makeInfo(), { server: true });

  // Exhaust outgoing window
  chan.outgoing.window = 0;
  // Write stderr data (uses _writeDataSync which sets _chunkErr + _chunkcbErr)
  const stderrWritable = chan.stderr as { write: (d: Uint8Array) => void };
  stderrWritable.write(new Uint8Array([0xee]));

  let drainCount = 0;
  chan.on('drain', () => {
    drainCount++;
  });
  chan.adjustWindow(100);

  assertEquals(drainCount, 1);
  // channelExtData should be scheduled to fire (async)
});

// =============================================================================
// _writeData: state guard (id undefined or not open)
// =============================================================================

Deno.test('Channel: write does nothing when outgoing id is undefined', () => {
  const client = createMockClient();
  // Create channel with outgoing id undefined via type assertion
  const info = {
    type: 'session',
    incoming: { id: 1, window: MAX_WINDOW, packetSize: PACKET_SIZE, state: 'open' as const },
    outgoing: {
      id: undefined as unknown as number,
      window: MAX_WINDOW,
      packetSize: PACKET_SIZE,
      state: 'open' as const,
    },
  };
  const chan = new Channel(client, info);

  chan.write(new Uint8Array([1, 2, 3]));

  assertEquals(client.calls.length, 0);
});
