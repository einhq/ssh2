/**
 * Deno Transport Implementation
 *
 * Provides Transport interface implementation using Deno's native
 * networking APIs (Deno.connect, Deno.listen).
 */

import type {
  ListenOptions,
  Transport,
  TransportFactory,
  TransportListener,
  TransportOptions,
} from './types.ts';

/**
 * Deno TCP Transport
 *
 * Wraps a Deno.Conn to implement the Transport interface.
 * Deno.Conn already provides Web Streams via readable/writable properties.
 */
export class DenoTransport implements Transport {
  private _conn: Deno.Conn;
  private _closed = false;

  constructor(conn: Deno.Conn) {
    this._conn = conn;
    // SSH sends many records in bursts. Disable Nagle so control packets and
    // the tail of a burst are not held behind delayed acknowledgements.
    const tcp = conn as Deno.Conn & { setNoDelay?: (noDelay?: boolean) => void };
    tcp.setNoDelay?.(true);
  }

  get readable(): ReadableStream<Uint8Array> {
    return this._conn.readable;
  }

  get writable(): WritableStream<Uint8Array> {
    return this._conn.writable;
  }

  read(buf: Uint8Array): Promise<number | null> {
    return this._conn.read(buf);
  }

  get remoteAddress(): string | undefined {
    const addr = this._conn.remoteAddr;
    if (addr.transport === 'tcp' || addr.transport === 'udp') {
      return addr.hostname;
    }
    return undefined;
  }

  get remotePort(): number | undefined {
    const addr = this._conn.remoteAddr;
    if (addr.transport === 'tcp' || addr.transport === 'udp') {
      return addr.port;
    }
    return undefined;
  }

  get localAddress(): string | undefined {
    const addr = this._conn.localAddr;
    if (addr.transport === 'tcp' || addr.transport === 'udp') {
      return addr.hostname;
    }
    return undefined;
  }

  get localPort(): number | undefined {
    const addr = this._conn.localAddr;
    if (addr.transport === 'tcp' || addr.transport === 'udp') {
      return addr.port;
    }
    return undefined;
  }

  close(): void {
    if (!this._closed) {
      this._closed = true;
      try {
        this._conn.close();
      } catch {
        // Connection may already be closed
      }
    }
  }

  get closed(): boolean {
    return this._closed;
  }

  /** Get the underlying Deno connection */
  get conn(): Deno.Conn {
    return this._conn;
  }
}

/**
 * Deno TCP Listener
 *
 * Wraps a Deno.Listener to implement the TransportListener interface.
 */
export class DenoListener implements TransportListener {
  private _listener: Deno.Listener;
  private _closed = false;

  constructor(listener: Deno.Listener) {
    this._listener = listener;
  }

  async *accept(): AsyncIterableIterator<Transport> {
    try {
      for await (const conn of this._listener) {
        yield new DenoTransport(conn);
      }
    } catch (err) {
      // Listener closed or error
      if (!this._closed) {
        throw err;
      }
    }
  }

  close(): void {
    if (!this._closed) {
      this._closed = true;
      try {
        this._listener.close();
      } catch {
        // Listener may already be closed
      }
    }
  }

  get address(): string {
    const addr = this._listener.addr;
    if (addr.transport === 'tcp' || addr.transport === 'udp') {
      return addr.hostname;
    }
    return '';
  }

  get port(): number {
    const addr = this._listener.addr;
    if (addr.transport === 'tcp' || addr.transport === 'udp') {
      return addr.port;
    }
    return 0;
  }

  get addr(): { hostname: string; port: number } {
    const addr = this._listener.addr;
    if (addr.transport === 'tcp' || addr.transport === 'udp') {
      return { hostname: addr.hostname, port: addr.port };
    }
    return { hostname: '', port: 0 };
  }

  /** Async iterator implementation */
  [Symbol.asyncIterator](): AsyncIterableIterator<Transport> {
    return this.accept();
  }

  /** Get the underlying Deno listener */
  get listener(): Deno.Listener {
    return this._listener;
  }
}

/**
 * Deno Transport Factory
 *
 * Creates TCP connections and listeners using Deno APIs.
 */
export class DenoTransportFactory implements TransportFactory {
  /**
   * Create a TCP connection to a remote host
   */
  async connect(options: TransportOptions): Promise<Transport> {
    const { host, port, timeout } = options;

    let conn: Deno.Conn;

    if (timeout && timeout > 0) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        conn = await Deno.connect({ hostname: host, port, signal: controller.signal });
      } catch (err) {
        if (controller.signal.aborted) {
          throw new Error(`Connection timeout after ${timeout}ms`);
        }
        throw err;
      } finally {
        clearTimeout(timeoutId);
      }
    } else {
      conn = await Deno.connect({ hostname: host, port });
    }

    // Note: Deno doesn't have direct keepAlive options on connect
    // TCP keepalive would need to be set via socket options if available

    return new DenoTransport(conn);
  }

  /**
   * Create a TCP listener on a local address
   */
  async listen(options: ListenOptions): Promise<TransportListener> {
    const { host, hostname, port } = options;

    const listener = Deno.listen({
      hostname: hostname || host || '0.0.0.0',
      port,
    });

    return new DenoListener(listener);
  }
}

/**
 * Default transport factory instance
 */
export const denoTransport: DenoTransportFactory = new DenoTransportFactory();

/**
 * Connect to a remote SSH server
 *
 * Convenience function for creating client connections.
 */
export async function connect(
  host: string,
  port = 22,
  timeout?: number,
): Promise<Transport> {
  return denoTransport.connect({ host, port, timeout });
}

/**
 * Listen for incoming SSH connections
 *
 * Convenience function for creating server listeners.
 */
export async function listen(
  port: number,
  host?: string,
): Promise<TransportListener> {
  return denoTransport.listen({ port, host });
}
