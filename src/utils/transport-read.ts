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
 * How many reads go without the wait after one that did not pay: a wait whose
 * next read brought less than half the buffer. On a path that hands data over
 * a segment at a time, such as a user-space network stack (slirp4netns), a
 * wait per read caps the transfer instead of batching it; after this many
 * reads the wait is tried again.
 */
export const PACE_RETRY = 256;

/**
 * The chunks a transport delivers, in order, until it ends. Through `read`
 * they are views of one buffer of shared memory, each valid until the next is
 * asked for; a read that fills the buffer is followed by the next at once, as
 * more waits, and so is a bulk read for PACE_RETRY reads after a wait that did
 * not pay.
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
  let unpaced = 0;
  let waited = false;
  try {
    while (true) {
      const n = await transport.read(buf);
      if (n === null) return;
      if (waited && n < buf.length / 2) unpaced = PACE_RETRY;
      waited = false;
      const busy = n >= PACE_MIN;
      if (busy) bulk?.(true);
      yield buf.subarray(0, n);
      if (busy && n < buf.length) {
        if (unpaced > 0) {
          unpaced--;
        } else {
          await new Promise((resolve) => setTimeout(resolve, PACE_MS));
          waited = true;
        }
      }
      if (busy) bulk?.(false);
    }
  } finally {
    bulk?.(false);
  }
}
