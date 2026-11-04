import type { Transport } from '../adapters/types.ts';

/**
 * The buffer a transport with `read` is read into, reused for every chunk. It
 * is shared memory, so that the decipher's worker can open the packets where
 * they were read (chacha20.ts).
 */
export const READ_BUFFER = 256 * 1024;

/**
 * A read of this many bytes or more is taken as part of a bulk transfer. If it
 * did not fill the buffer, the next read waits PACE_MS, so that it brings many
 * packets at once and the decipher opens them in one batch (chacha20.ts); a
 * connection's reads otherwise keep up with its sender and bring one or two
 * packets each.
 */
export const PACE_MIN = 32 * 1024;

/**
 * The wait before a bulk transfer's next read. The sender's window, 2 MiB on a
 * channel of this library's and as much with OpenSSH's sftp, covers it many
 * times over.
 */
export const PACE_MS = 1;

/**
 * The chunks a transport delivers, in order, until it ends. Through `read`
 * they are views of one buffer of shared memory, each valid until the next is
 * asked for; a read that fills the buffer is followed by the next at once, as
 * more waits.
 *
 * `bulk` is told true when a bulk transfer's chunk is handed on, and false
 * just before the next read starts: what the connection writes in between,
 * such as the replies to an upload's SFTP writes, can wait to go out together.
 * Nothing waits while a read does, so a peer waiting for replies gets them.
 */
export async function* transportChunks(
  transport: Transport,
  bulk?: (busy: boolean) => void,
): AsyncGenerator<Uint8Array> {
  if (!transport.read) {
    const reader = transport.readable.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) return;
        yield value;
      }
    } finally {
      reader.releaseLock();
    }
  }

  const buf = new Uint8Array(new SharedArrayBuffer(READ_BUFFER));
  try {
    while (true) {
      const n = await transport.read(buf);
      if (n === null) return;
      const busy = n >= PACE_MIN;
      if (busy) bulk?.(true);
      yield buf.subarray(0, n);
      if (busy && n < buf.length) await new Promise((resolve) => setTimeout(resolve, PACE_MS));
      if (busy) bulk?.(false);
    }
  } finally {
    bulk?.(false);
  }
}
