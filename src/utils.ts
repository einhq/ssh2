/**
 * SSH2 Utilities
 *
 * Channel management and algorithm configuration utilities.
 */

import type { Channel } from './Channel.ts';

/** Maximum channel ID (2^32 - 1) */
const MAX_CHANNEL = 2 ** 32 - 1;

/**
 * Channel open failure info
 */
export interface ChannelOpenFailureInfo {
  reason: number | string;
  description: string;
}

/**
 * Error with reason property for channel failures
 */
export interface ChannelError extends Error {
  reason: number | string;
}

/**
 * Handle channel open failure
 */
export function onChannelOpenFailure(
  chanMgr: ChannelManager,
  recipient: number,
  info: Error | ChannelOpenFailureInfo | null,
  cb?: (err: Error) => void,
): void {
  chanMgr.remove(recipient);

  if (typeof cb !== 'function') {
    return;
  }

  let err: ChannelError;
  if (info instanceof Error) {
    err = info as ChannelError;
  } else if (info && typeof info === 'object') {
    err = new Error(`(SSH) Channel open failure: ${info.description}`) as ChannelError;
    err.reason = info.reason;
  } else {
    err = new Error(
      '(SSH) Channel open failure: server closed channel unexpectedly',
    ) as ChannelError;
    err.reason = '';
  }

  cb(err);
}

/**
 * Channel or callback type for pending opens
 */
export type ChannelOrCallback = Channel | ((err?: Error) => void);

/**
 * Handle CHANNEL_CLOSE message
 */
export function onChannelClose(
  chanMgr: ChannelManager,
  recipient: number,
  channel: ChannelOrCallback,
  err?: Error,
  dead = false,
): void {
  if (typeof channel === 'function') {
    // We got CHANNEL_CLOSE instead of CHANNEL_OPEN_FAILURE when
    // requesting to open a channel
    onChannelOpenFailure(chanMgr, recipient, err || null, channel);
    return;
  }

  if (typeof channel !== 'object' || channel === null) {
    return;
  }

  // Handle Session objects (server-side) which store channel info in _chanInfo
  // and use emit() instead of handleClose()
  const sessionLike = channel as unknown as Record<string, unknown>;
  if (
    '_chanInfo' in sessionLike &&
    typeof sessionLike.emit === 'function'
  ) {
    const chanInfo = sessionLike._chanInfo as {
      incoming: { state: string };
      outgoing: { state: string };
    };
    if (chanInfo.incoming.state === 'closed') return;
    // The session's exec, shell or subsystem channel shares its state, so it is closed first,
    // while that state still says open: afterwards it would look closed already and never hear
    // of it, and whoever runs the command would never learn its client is gone.
    const subChannel = sessionLike._channel as ChannelOrCallback | undefined;
    if (subChannel) {
      onChannelClose(chanMgr, recipient, subChannel, err, dead);
    }
    chanMgr.remove(recipient);
    chanInfo.incoming.state = 'closed';
    chanInfo.outgoing.state = 'closed';
    if (!sessionLike._ending) {
      sessionLike._ending = true;
      (sessionLike.emit as (event: string) => void)('eof');
      (sessionLike.emit as (event: string) => void)('end');
    }
    (sessionLike.emit as (event: string) => void)('close');
    return;
  }

  if (channel.incoming && channel.incoming.state === 'closed') {
    return;
  }

  chanMgr.remove(recipient);

  if (channel.incoming) {
    channel.incoming.state = 'closed';
  }

  // Handle close through Channel's handleClose method
  if (
    channel.outgoing &&
    (channel.outgoing.state === 'open' || channel.outgoing.state === 'eof') &&
    !dead &&
    typeof channel.close === 'function'
  ) {
    channel.close();
  }

  if (channel.outgoing && channel.outgoing.state === 'closing') {
    channel.outgoing.state = 'closed';
  }

  // Take care of any outstanding channel requests
  if (typeof channel.flushCallbacks === 'function') {
    channel.flushCallbacks();
  }

  // Emit close event
  if (typeof channel.handleClose === 'function') {
    channel.handleClose();
  }
}

/**
 * Channel manager for tracking open channels
 *
 * Manages channel IDs and channel objects for SSH connections.
 */
export class ChannelManager {
  private _channels: Map<number, ChannelOrCallback> = new Map();
  private _cur = -1;
  private _count = 0;

  /**
   * Add a new channel and get its ID
   */
  add(val?: ChannelOrCallback): number {
    let id: number | undefined;

    // Optimized paths
    if (this._cur < MAX_CHANNEL) {
      id = ++this._cur;
    } else if (this._count === 0) {
      // Revert and reset back to fast path once we no longer have any channels open
      this._cur = 0;
      id = 0;
    } else {
      // Slower lookup path
      // This path is triggered we have opened at least MAX_CHANNEL channels
      // while having at least one channel open at any given time
      for (let i = 0; i < MAX_CHANNEL; ++i) {
        if (!this._channels.has(i)) {
          id = i;
          break;
        }
      }
    }

    if (id === undefined) {
      return -1;
    }

    this._channels.set(id, val || (true as unknown as ChannelOrCallback));
    ++this._count;

    return id;
  }

  /**
   * Update a channel entry
   */
  update(id: number, val: ChannelOrCallback): void {
    if (typeof id !== 'number' || id < 0 || id >= MAX_CHANNEL || !isFinite(id)) {
      throw new Error(`Invalid channel id: ${id}`);
    }

    if (val && this._channels.has(id)) {
      this._channels.set(id, val);
    }
  }

  /**
   * Get a channel by ID
   */
  get(id: number): ChannelOrCallback | undefined {
    if (typeof id !== 'number' || id < 0 || id >= MAX_CHANNEL || !isFinite(id)) {
      throw new Error(`Invalid channel id: ${id}`);
    }

    return this._channels.get(id);
  }

  /**
   * Remove a channel by ID
   */
  remove(id: number): void {
    if (typeof id !== 'number' || id < 0 || id >= MAX_CHANNEL || !isFinite(id)) {
      throw new Error(`Invalid channel id: ${id}`);
    }

    if (this._channels.has(id)) {
      this._channels.delete(id);
      if (this._count) {
        --this._count;
      }
    }
  }

  /**
   * Cleanup all channels (on disconnect)
   */
  cleanup(err?: Error): void {
    const channels = this._channels;
    this._channels = new Map();
    this._cur = -1;
    this._count = 0;

    for (const [id, channel] of channels) {
      if (typeof channel === 'function') {
        // Pending channel open callback - call with error
        onChannelOpenFailure(this, id, err || null, channel);
      } else if (typeof channel === 'object' && channel !== null) {
        onChannelClose(this, id, channel, err, true);
      }
    }
  }

  /**
   * Get the number of open channels
   */
  get count(): number {
    return this._count;
  }
}

/**
 * Check if value is a RegExp
 */
export function isRegExp(val: unknown): val is RegExp {
  return Object.prototype.toString.call(val) === '[object RegExp]';
}

/**
 * Algorithm list modification options
 */
export interface AlgorithmListOptions {
  append?: string | RegExp | Array<string | RegExp>;
  prepend?: string | RegExp | Array<string | RegExp>;
  remove?: string | RegExp | Array<string | RegExp>;
}

/**
 * Generate an algorithm list based on user configuration
 *
 * @param algoList - User-provided algorithm configuration
 * @param defaultList - Default algorithm list
 * @param supportedList - List of all supported algorithms
 * @returns The resulting algorithm list
 */
export function generateAlgorithmList(
  algoList: string[] | AlgorithmListOptions | undefined,
  defaultList: string[],
  supportedList: string[],
): string[] {
  if (Array.isArray(algoList) && algoList.length > 0) {
    // Exact list
    for (let i = 0; i < algoList.length; ++i) {
      if (supportedList.indexOf(algoList[i]) === -1) {
        throw new Error(`Unsupported algorithm: ${algoList[i]}`);
      }
    }
    return algoList;
  }

  if (typeof algoList === 'object' && algoList !== null && !Array.isArray(algoList)) {
    // Operations based on the default list
    const opts = algoList as AlgorithmListOptions;
    let list = defaultList;

    // Handle append
    if (opts.append !== undefined) {
      let val = opts.append;
      if (!Array.isArray(val)) {
        val = [val];
      }
      for (let j = 0; j < val.length; ++j) {
        const append = val[j];
        if (typeof append === 'string') {
          if (!append || list.indexOf(append) !== -1) continue;
          if (supportedList.indexOf(append) === -1) {
            throw new Error(`Unsupported algorithm: ${append}`);
          }
          if (list === defaultList) list = list.slice();
          list.push(append);
        } else if (isRegExp(append)) {
          for (let k = 0; k < supportedList.length; ++k) {
            const algo = supportedList[k];
            if (append.test(algo)) {
              if (list.indexOf(algo) !== -1) continue;
              if (list === defaultList) list = list.slice();
              list.push(algo);
            }
          }
        }
      }
    }

    // Handle prepend
    if (opts.prepend !== undefined) {
      let val = opts.prepend;
      if (!Array.isArray(val)) {
        val = [val];
      }
      for (let j = val.length - 1; j >= 0; --j) {
        const prepend = val[j];
        if (typeof prepend === 'string') {
          if (!prepend || list.indexOf(prepend) !== -1) continue;
          if (supportedList.indexOf(prepend) === -1) {
            throw new Error(`Unsupported algorithm: ${prepend}`);
          }
          if (list === defaultList) list = list.slice();
          list.unshift(prepend);
        } else if (isRegExp(prepend)) {
          for (let k = supportedList.length - 1; k >= 0; --k) {
            const algo = supportedList[k];
            if (prepend.test(algo)) {
              if (list.indexOf(algo) !== -1) continue;
              if (list === defaultList) list = list.slice();
              list.unshift(algo);
            }
          }
        }
      }
    }

    // Handle remove
    if (opts.remove !== undefined) {
      let val = opts.remove;
      if (!Array.isArray(val)) {
        val = [val];
      }
      for (let j = 0; j < val.length; ++j) {
        const search = val[j];
        if (typeof search === 'string') {
          if (!search) continue;
          const idx = list.indexOf(search);
          if (idx === -1) continue;
          if (list === defaultList) list = list.slice();
          list.splice(idx, 1);
        } else if (isRegExp(search)) {
          for (let k = 0; k < list.length; ++k) {
            if (search.test(list[k])) {
              if (list === defaultList) list = list.slice();
              list.splice(k, 1);
              --k;
            }
          }
        }
      }
    }

    return list;
  }

  return defaultList;
}
