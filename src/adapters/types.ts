/**
 * SSH Transport Abstraction
 *
 * Defines interfaces for network transport used by SSH protocol.
 * Designed to work with Web Streams API for compatibility with
 * Deno, browsers (via WebSocket), and other runtimes.
 */

/**
 * Transport interface for SSH connections
 *
 * Provides readable and writable streams for bidirectional communication.
 * Implementations can wrap TCP sockets, WebSockets, or other transports.
 */
export interface Transport {
  /** Readable stream for incoming data */
  readonly readable: ReadableStream<Uint8Array>;

  /** Writable stream for outgoing data */
  readonly writable: WritableStream<Uint8Array>;

  /**
   * Reads into buf, resolving to the number of bytes read, or null at the end.
   * A transport that has it is read through it rather than `readable`, into a
   * buffer reused for every read.
   */
  read?(buf: Uint8Array): Promise<number | null>;

  /** Remote address information (if available) */
  readonly remoteAddress?: string;

  /** Remote port (if available) */
  readonly remotePort?: number;

  /** Local address information (if available) */
  readonly localAddress?: string;

  /** Local port (if available) */
  readonly localPort?: number;

  /** Close the transport */
  close(): void;

  /** Whether the transport is closed */
  readonly closed: boolean;
}

/**
 * Transport options for creating connections
 */
export interface TransportOptions {
  /** Host to connect to */
  host: string;

  /** Port to connect to */
  port: number;

  /** Connection timeout in milliseconds */
  timeout?: number;

  /** Keep-alive settings */
  keepAlive?: boolean;

  /** Keep-alive delay in milliseconds */
  keepAliveDelay?: number;
}

/**
 * Server listener interface
 */
export interface TransportListener extends AsyncIterable<Transport> {
  /** Accept incoming connections */
  accept(): AsyncIterableIterator<Transport>;

  /** Close the listener */
  close(): void;

  /** Local address the listener is bound to */
  readonly address: string;

  /** Local port the listener is bound to */
  readonly port: number;

  /** Deno-style addr property */
  readonly addr: { hostname: string; port: number };
}

/**
 * Server listen options
 */
export interface ListenOptions {
  /** Host/address to bind to */
  host?: string;

  /** Hostname to bind to */
  hostname?: string;

  /** Port to listen on */
  port: number;

  /** Backlog size for pending connections */
  backlog?: number;
}

/**
 * Transport factory interface
 *
 * Implementations provide platform-specific transport creation.
 */
export interface TransportFactory {
  /** Create a client transport connection */
  connect(options: TransportOptions): Promise<Transport>;

  /** Create a server listener */
  listen(options: ListenOptions): Promise<TransportListener>;
}

/**
 * Duplex stream wrapper for compatibility
 *
 * Wraps a Transport to provide a unified read/write interface.
 */
export class DuplexTransport {
  private _transport: Transport;
  private _reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  private _writer: WritableStreamDefaultWriter<Uint8Array> | null = null;

  constructor(transport: Transport) {
    this._transport = transport;
  }

  /** Get the underlying transport */
  get transport(): Transport {
    return this._transport;
  }

  /** Get a reader for the transport */
  getReader(): ReadableStreamDefaultReader<Uint8Array> {
    if (this._reader) {
      return this._reader;
    }
    this._reader = this._transport.readable.getReader();
    return this._reader;
  }

  /** Get a writer for the transport */
  getWriter(): WritableStreamDefaultWriter<Uint8Array> {
    if (this._writer) {
      return this._writer;
    }
    this._writer = this._transport.writable.getWriter();
    return this._writer;
  }

  /** Read data from the transport */
  async read(): Promise<Uint8Array | null> {
    const reader = this.getReader();
    const result = await reader.read();
    if (result.done) {
      return null;
    }
    return result.value;
  }

  /** Write data to the transport */
  async write(data: Uint8Array): Promise<void> {
    const writer = this.getWriter();
    await writer.write(data);
  }

  /** Close the transport */
  async close(): Promise<void> {
    if (this._reader) {
      this._reader.releaseLock();
      this._reader = null;
    }
    if (this._writer) {
      await this._writer.close();
      this._writer = null;
    }
    this._transport.close();
  }

  /** Whether the transport is closed */
  get closed(): boolean {
    return this._transport.closed;
  }
}

/**
 * Transform stream for processing SSH packets
 *
 * Can be used to add protocol-level processing to a transport.
 */
export interface PacketTransform {
  /** Transform incoming data */
  readonly readable: ReadableStream<Uint8Array>;

  /** Accept outgoing data */
  readonly writable: WritableStream<Uint8Array>;
}

/**
 * Create a transform stream for packet processing
 */
export function createPacketTransform(
  transform: (chunk: Uint8Array) => Uint8Array | Promise<Uint8Array>,
): PacketTransform {
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      const transformed = await transform(chunk);
      controller.enqueue(transformed);
    },
  });

  return { readable, writable };
}

/**
 * Pipe data from one transport to another with optional transformation
 */
export async function pipeTransport(
  source: Transport,
  destination: Transport,
  options?: {
    transform?: (chunk: Uint8Array) => Uint8Array | Promise<Uint8Array>;
    signal?: AbortSignal;
  },
): Promise<void> {
  const reader = source.readable.getReader();
  const writer = destination.writable.getWriter();

  try {
    while (true) {
      if (options?.signal?.aborted) {
        break;
      }

      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      const data = options?.transform ? await options.transform(value) : value;
      await writer.write(data);
    }
  } finally {
    reader.releaseLock();
    writer.releaseLock();
  }
}
