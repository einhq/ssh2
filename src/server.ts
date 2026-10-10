/**
 * SSH2 Server Implementation
 *
 * Provides an SSH server that can handle client connections, authentication,
 * and channel operations.
 *
 * @module
 */

import { Channel, type ChannelInfo, MAX_WINDOW, PACKET_SIZE } from './Channel.ts';
import type { Transport, TransportListener } from './adapters/types.ts';
import { Protocol, type ProtocolConfig } from './protocol/Protocol.ts';
import {
  CHANNEL_OPEN_FAILURE,
  DEFAULT_CIPHER,
  DEFAULT_COMPRESSION,
  DEFAULT_KEX,
  DEFAULT_MAC,
  DEFAULT_SERVER_HOST_KEY,
  DISCONNECT_REASON,
  DISCONNECT_REASON_BY_VALUE,
  SUPPORTED_CIPHER,
  SUPPORTED_COMPRESSION,
  SUPPORTED_KEX,
  SUPPORTED_MAC,
  SUPPORTED_SERVER_HOST_KEY,
} from './protocol/constants.ts';
import { isParsedKey, type ParsedKey, parseKey } from './protocol/keyParser.ts';
import {
  ChannelManager,
  type ChannelOrCallback,
  generateAlgorithmList,
  onChannelClose,
} from './utils.ts';
import { allocBytes, writeUInt32BE } from './utils/binary.ts';
import { EventEmitter } from './utils/events.ts';
import { coalesceTransportWrite } from './utils/transport-write.ts';

const MAX_PENDING_AUTHS = 10;

// ============================================================================
// Authentication Context Classes
// ============================================================================

/**
 * Base authentication context (server-side)
 */
export class ServerAuthContext extends EventEmitter<{ abort: [] }> {
  readonly username: string;
  readonly user: string;
  readonly service: string;
  readonly method: string;

  protected _initialResponse = false;
  protected _finalResponse = false;
  protected _multistep = false;
  protected _protocol: Protocol;
  protected _cleanup?: () => void;

  private _cbfinal: (allowed: boolean, methodsLeft?: string[], isPartial?: boolean) => void;

  constructor(
    protocol: Protocol,
    username: string,
    service: string,
    method: string,
    cb: (
      ctx: ServerAuthContext,
      allowed: boolean,
      methodsLeft?: string[],
      isPartial?: boolean,
    ) => void,
  ) {
    super();

    this.username = this.user = username;
    this.service = service;
    this.method = method;
    this._protocol = protocol;

    this._cbfinal = (allowed, methodsLeft, isPartial) => {
      if (!this._finalResponse) {
        this._finalResponse = true;
        cb(this, allowed, methodsLeft, isPartial);
      }
    };
  }

  accept(): void {
    this._cleanup?.();
    this._initialResponse = true;
    this._cbfinal(true);
  }

  reject(methodsLeft?: string[], isPartial?: boolean): void {
    this._cleanup?.();
    this._initialResponse = true;
    this._cbfinal(false, methodsLeft, isPartial);
  }
}

/**
 * Keyboard-interactive authentication context
 */
export class KeyboardAuthContext extends ServerAuthContext {
  readonly submethods: string;

  private _cb?: (responses: string[]) => void;
  private _onInfoResponse: (responses: string[]) => void;

  constructor(
    protocol: Protocol,
    username: string,
    service: string,
    method: string,
    submethods: string,
    cb: (
      ctx: ServerAuthContext,
      allowed: boolean,
      methodsLeft?: string[],
      isPartial?: boolean,
    ) => void,
  ) {
    super(protocol, username, service, method, cb);

    this._multistep = true;
    this.submethods = submethods;

    this._onInfoResponse = (responses: string[]) => {
      const callback = this._cb;
      if (callback) {
        this._cb = undefined;
        callback(responses);
      }
    };

    this.on('abort', () => {
      this._cb = undefined; // Clear callback on abort
    });
  }

  prompt(
    prompts: string | Array<{ prompt: string; echo?: boolean }>,
    titleOrCb?: string | ((responses: string[]) => void),
    instructionsOrCb?: string | ((responses: string[]) => void),
    cb?: (responses: string[]) => void,
  ): void {
    let title: string | undefined;
    let instructions: string | undefined;

    let promptArr: Array<{ prompt: string; echo: boolean }>;
    if (!Array.isArray(prompts)) {
      promptArr = [{ prompt: prompts, echo: true }];
    } else {
      promptArr = prompts.map((p) =>
        typeof p === 'string'
          ? { prompt: p, echo: true }
          : { prompt: p.prompt, echo: p.echo ?? true }
      );
    }

    if (typeof titleOrCb === 'function') {
      cb = titleOrCb;
    } else if (typeof instructionsOrCb === 'function') {
      title = titleOrCb;
      cb = instructionsOrCb;
    } else {
      title = titleOrCb;
      instructions = instructionsOrCb;
    }

    this._cb = cb;
    this._initialResponse = true;

    this._protocol.authInfoReq(title ?? '', instructions ?? '', promptArr);
  }

  handleInfoResponse(responses: string[]): void {
    this._onInfoResponse(responses);
  }
}

/**
 * Public key info for authentication
 */
export interface PKInfo {
  keyAlgo: string;
  key: Uint8Array;
  hashAlgo?: string;
  signature?: Uint8Array;
  blob?: Uint8Array;
}

/**
 * Public key authentication context
 */
export class PKAuthContext extends ServerAuthContext {
  readonly key: { algo: string; data: Uint8Array };
  readonly hashAlgo?: string;
  readonly signature?: Uint8Array;
  readonly blob?: Uint8Array;

  constructor(
    protocol: Protocol,
    username: string,
    service: string,
    method: string,
    pkInfo: PKInfo,
    cb: (
      ctx: ServerAuthContext,
      allowed: boolean,
      methodsLeft?: string[],
      isPartial?: boolean,
    ) => void,
  ) {
    super(protocol, username, service, method, cb);

    this.key = { algo: pkInfo.keyAlgo, data: pkInfo.key };
    this.hashAlgo = pkInfo.hashAlgo;
    this.signature = pkInfo.signature;
    this.blob = pkInfo.blob;
  }

  override accept(): void {
    if (!this.signature) {
      this._initialResponse = true;
      // PK_OK repeats the algorithm the client asked with (RFC 4252 7), which
      // for RSA names the hash rather than the key type
      let requested = this.key.algo;
      if (requested === 'ssh-rsa' && this.hashAlgo === 'sha256') requested = 'rsa-sha2-256';
      if (requested === 'ssh-rsa' && this.hashAlgo === 'sha512') requested = 'rsa-sha2-512';
      this._protocol.authPKOK(requested, this.key.data);
    } else {
      super.accept();
    }
  }
}

/**
 * Hostbased authentication info
 */
export interface HostbasedInfo extends PKInfo {
  localHostname: string;
  localUsername: string;
}

/**
 * Hostbased authentication context
 */
export class HostbasedAuthContext extends ServerAuthContext {
  readonly key: { algo: string; data: Uint8Array };
  readonly hashAlgo?: string;
  readonly signature?: Uint8Array;
  readonly blob?: Uint8Array;
  readonly localHostname: string;
  readonly localUsername: string;

  constructor(
    protocol: Protocol,
    username: string,
    service: string,
    method: string,
    pkInfo: HostbasedInfo,
    cb: (
      ctx: ServerAuthContext,
      allowed: boolean,
      methodsLeft?: string[],
      isPartial?: boolean,
    ) => void,
  ) {
    super(protocol, username, service, method, cb);

    this.key = { algo: pkInfo.keyAlgo, data: pkInfo.key };
    this.hashAlgo = pkInfo.hashAlgo;
    this.signature = pkInfo.signature;
    this.blob = pkInfo.blob;
    this.localHostname = pkInfo.localHostname;
    this.localUsername = pkInfo.localUsername;
  }
}

/**
 * Password authentication context
 */
export class PwdAuthContext extends ServerAuthContext {
  readonly password: string;

  private _changeCb?: (newPassword: string) => void;

  constructor(
    protocol: Protocol,
    username: string,
    service: string,
    method: string,
    password: string,
    cb: (
      ctx: ServerAuthContext,
      allowed: boolean,
      methodsLeft?: string[],
      isPartial?: boolean,
    ) => void,
  ) {
    super(protocol, username, service, method, cb);

    this.password = password;
  }

  requestChange(prompt: string, cb: (newPassword: string) => void): void {
    if (this._changeCb) {
      throw new Error('Change request already in progress');
    }
    if (typeof prompt !== 'string') {
      throw new Error('prompt argument must be a string');
    }
    if (typeof cb !== 'function') {
      throw new Error('Callback argument must be a function');
    }
    this._changeCb = cb;
    this._protocol.authPasswdChg(prompt);
  }

  handleNewPassword(newPassword: string): void {
    const cb = this._changeCb;
    this._changeCb = undefined;
    cb?.(newPassword);
  }
}

// ============================================================================
// Session Class
// ============================================================================

/**
 * Session events
 */
export interface SessionEvents {
  eof: [];
  end: [];
  close: [];
  env: [
    accept: (() => void) | undefined,
    reject: (() => void) | undefined,
    info: { key: string; val: string },
  ];
  pty: [
    accept: (() => void) | undefined,
    reject: (() => void) | undefined,
    info: {
      term: string;
      cols: number;
      rows: number;
      width: number;
      height: number;
      modes: Uint8Array;
    },
  ];
  'window-change': [
    accept: (() => void) | undefined,
    reject: (() => void) | undefined,
    info: { cols: number; rows: number; width: number; height: number },
  ];
  x11: [
    accept: (() => void) | undefined,
    reject: (() => void) | undefined,
    info: { single: boolean; protocol: string; cookie: string; screen: number },
  ];
  signal: [
    accept: (() => void) | undefined,
    reject: (() => void) | undefined,
    info: { name: string },
  ];
  'auth-agent': [accept: (() => void) | undefined, reject: (() => void) | undefined];
  shell: [accept: () => Channel | undefined, reject: (() => void) | undefined];
  exec: [
    accept: () => Channel | undefined,
    reject: (() => void) | undefined,
    info: { command: string },
  ];
  sftp: [accept: () => Channel | undefined, reject: (() => void) | undefined];
  subsystem: [
    accept: () => Channel | undefined,
    reject: (() => void) | undefined,
    info: { name: string },
  ];
}

/**
 * Session channel for server
 */
export class Session extends EventEmitter<SessionEvents> {
  readonly type = 'session';
  subtype?: string;
  readonly server = true;

  _ending = false;
  _channel?: Channel;
  _chanInfo: ChannelInfo;

  constructor(
    _client: Connection,
    info: { sender: number; window: number; packetSize: number },
    localChan: number,
  ) {
    super();

    this._chanInfo = {
      type: 'session',
      incoming: {
        id: localChan,
        window: MAX_WINDOW,
        packetSize: PACKET_SIZE,
        state: 'open',
      },
      outgoing: {
        id: info.sender,
        window: info.window,
        packetSize: info.packetSize,
        state: 'open',
      },
    };
  }
}

// ============================================================================
// Connection Class (Server-side client connection)
// ============================================================================

/**
 * Connection events
 */
export interface ConnectionEvents {
  error: [Error];
  end: [];
  close: [];
  greeting: [string];
  handshake: [unknown];
  rekey: [];
  authentication: [ServerAuthContext];
  ready: [];
  session: [accept: () => Session | undefined, reject: () => void];
  tcpip: [
    accept: () => Channel | undefined,
    reject: () => void,
    info: { srcIP: string; srcPort: number; destIP: string; destPort: number },
  ];
  'openssh.streamlocal': [
    accept: () => Channel | undefined,
    reject: () => void,
    info: { socketPath: string },
  ];
  request: [
    accept: ((port?: number) => void) | undefined,
    reject: (() => void) | undefined,
    name: string,
    info: unknown,
  ];
}

/**
 * Represents a client connection on the server side
 */
export class Connection extends EventEmitter<ConnectionEvents> {
  private _transport: Transport;
  private _protocol: Protocol;
  private _chanMgr: ChannelManager;
  private _debug?: (msg: string) => void;

  noMoreSessions = false;
  authenticated = false;

  /** Public accessor for the SSH protocol, used for SFTP server-side construction. */
  get protocol(): Protocol {
    return this._protocol;
  }

  constructor(
    transport: Transport,
    hostKeys: Map<string, ParsedKey>,
    ident: string | undefined,
    algorithms: {
      kex: string[];
      serverHostKey: string[];
      cs: { cipher: string[]; mac: string[]; compress: string[]; lang: string[] };
      sc: { cipher: string[]; mac: string[]; compress: string[]; lang: string[] };
    },
    debug: ((msg: string) => void) | undefined,
    server: Server,
    config: ServerConfig,
  ) {
    super();

    this._transport = transport;
    this._chanMgr = new ChannelManager();
    this._debug = debug;

    let exchanges = 0;
    let acceptedAuthSvc = false;
    let bannerSent = false;
    const pendingAuths: ServerAuthContext[] = [];
    let authCtx: ServerAuthContext | undefined;
    const unsentGlobalRequestsReplies: Array<{ type: string | null; buf: Uint8Array | null }> = [];

    const onAuthDecide = (
      ctx: ServerAuthContext,
      allowed: boolean,
      methodsLeft?: string[],
      isPartial?: boolean,
    ) => {
      if (authCtx === ctx && !this.authenticated) {
        // Shift from authsQueue when we make a final decision on this auth
        // (For keyboard-interactive, this happens after all prompts are done)
        this._protocol._authsQueue.shift();

        if (allowed) {
          authCtx = undefined;
          this.authenticated = true;
          this._protocol.authSuccess();
          pendingAuths.length = 0;
          this.emit('ready');
        } else {
          this._protocol.authFailure(methodsLeft, isPartial);
          if (pendingAuths.length) {
            authCtx = pendingAuths.pop();
            if (this.listenerCount('authentication') > 0) {
              this.emit('authentication', authCtx!);
            } else {
              authCtx!.reject();
            }
          }
        }
      }
    };

    const sendReplies = () => {
      while (unsentGlobalRequestsReplies.length > 0 && unsentGlobalRequestsReplies[0].type) {
        const reply = unsentGlobalRequestsReplies.shift()!;
        if (reply.type === 'SUCCESS') {
          this._protocol.requestSuccess(reply.buf ?? undefined);
        } else if (reply.type === 'FAILURE') {
          this._protocol.requestFailure();
        }
      }
    };

    // Build handlers
    const handlers: ProtocolConfig['messageHandlers'] = {};

    handlers.DEBUG = debug
      ? (_p, _display, msg) => {
        debug(`Debug output from client: ${JSON.stringify(msg)}`);
      }
      : undefined;

    handlers.DISCONNECT = (_p, reason, desc) => {
      if (reason !== DISCONNECT_REASON.BY_APPLICATION) {
        let description = desc;
        if (!description) {
          description =
            DISCONNECT_REASON_BY_VALUE[reason as keyof typeof DISCONNECT_REASON_BY_VALUE];
          if (description === undefined) {
            description = `Unexpected disconnection reason: ${reason}`;
          }
        }
        const err = new Error(description) as Error & { code: number };
        err.code = reason;
        this.emit('error', err);
      }
      transport.close();
    };

    handlers.SERVICE_REQUEST = (_p, service) => {
      if (exchanges === 0 || acceptedAuthSvc || this.authenticated || service !== 'ssh-userauth') {
        this._protocol.disconnect(DISCONNECT_REASON.SERVICE_NOT_AVAILABLE);
        transport.close();
        return;
      }

      acceptedAuthSvc = true;
      this._protocol.serviceAccept(service);
    };

    handlers.USERAUTH_REQUEST = (_p, username, service, method, methodData) => {
      if (
        exchanges === 0 ||
        this.authenticated ||
        (authCtx && (authCtx.username !== username || authCtx.service !== service)) ||
        (method !== 'password' &&
          method !== 'publickey' &&
          method !== 'hostbased' &&
          method !== 'keyboard-interactive' &&
          method !== 'none') ||
        pendingAuths.length === MAX_PENDING_AUTHS
      ) {
        this._protocol.disconnect(DISCONNECT_REASON.PROTOCOL_ERROR);
        transport.close();
        return;
      } else if (service !== 'ssh-connection') {
        this._protocol.disconnect(DISCONNECT_REASON.SERVICE_NOT_AVAILABLE);
        transport.close();
        return;
      }

      // Send banner once at the start of authentication
      if (!bannerSent && config.banner) {
        bannerSent = true;
        this._protocol.authBanner(config.banner);
      }

      let ctx: ServerAuthContext;
      switch (method) {
        case 'keyboard-interactive':
          ctx = new KeyboardAuthContext(
            this._protocol,
            username,
            service,
            method,
            (methodData as { submethods?: string })?.submethods ?? '',
            onAuthDecide,
          );
          break;
        case 'publickey':
          ctx = new PKAuthContext(
            this._protocol,
            username,
            service,
            method,
            methodData as PKInfo,
            onAuthDecide,
          );
          break;
        case 'hostbased':
          ctx = new HostbasedAuthContext(
            this._protocol,
            username,
            service,
            method,
            methodData as HostbasedInfo,
            onAuthDecide,
          );
          break;
        case 'password':
          if (
            authCtx && authCtx instanceof PwdAuthContext && (authCtx as PwdAuthContext)['_changeCb']
          ) {
            (authCtx as PwdAuthContext).handleNewPassword(
              (methodData as { newPassword: string }).newPassword,
            );
            return;
          }
          ctx = new PwdAuthContext(
            this._protocol,
            username,
            service,
            method,
            (methodData as { password: string }).password ?? (methodData as string),
            onAuthDecide,
          );
          break;
        case 'none':
        default:
          ctx = new ServerAuthContext(this._protocol, username, service, method, onAuthDecide);
          break;
      }

      if (authCtx) {
        if (!authCtx['_initialResponse']) {
          pendingAuths.push(ctx);
          return;
        } else if (authCtx['_multistep'] && !authCtx['_finalResponse']) {
          authCtx['_cleanup']?.();
          authCtx.emit('abort');
        }
      }

      authCtx = ctx;

      if (this.listenerCount('authentication') > 0) {
        this.emit('authentication', authCtx);
      } else {
        authCtx.reject();
      }
    };

    handlers.USERAUTH_INFO_RESPONSE = (_p, responses) => {
      if (authCtx && authCtx instanceof KeyboardAuthContext) {
        authCtx.handleInfoResponse(responses as string[]);
      }
    };

    handlers.CHANNEL_OPEN = (_p, info) => {
      if ((info.type === 'session' && this.noMoreSessions) || !this.authenticated) {
        const reasonCode = CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED;
        this._protocol.channelOpenFail(info.sender, reasonCode, '', '');
        return;
      }

      let localChan = -1;
      let reason: number | undefined;
      let replied = false;

      const reject = () => {
        if (replied) return;
        replied = true;

        if (reason === undefined) {
          if (localChan === -1) {
            reason = CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE;
          } else {
            reason = CHANNEL_OPEN_FAILURE.CONNECT_FAILED;
          }
        }

        if (localChan !== -1) {
          this._chanMgr.remove(localChan);
        }
        this._protocol.channelOpenFail(info.sender, reason, '', '');
      };

      const reserveChannel = () => {
        localChan = this._chanMgr.add();

        if (localChan === -1) {
          reason = CHANNEL_OPEN_FAILURE.RESOURCE_SHORTAGE;
          debug?.('Automatic rejection of incoming channel open: no channels available');
        }

        return localChan !== -1;
      };

      switch (info.type) {
        case 'session':
          if (this.listenerCount('session') > 0 && reserveChannel()) {
            const accept = () => {
              if (replied) return;
              replied = true;

              const instance = new Session(this, info, localChan);
              this._chanMgr.update(localChan, instance as unknown as ChannelOrCallback);

              this._protocol.channelOpenConfirm(info.sender, localChan, MAX_WINDOW, PACKET_SIZE);

              return instance;
            };

            this.emit('session', accept, reject);
            return;
          }
          break;
        case 'direct-tcpip':
          if (this.listenerCount('tcpip') > 0 && reserveChannel()) {
            const accept = () => {
              if (replied) return;
              replied = true;

              const chanInfo: ChannelInfo = {
                type: 'direct-tcpip',
                incoming: {
                  id: localChan,
                  window: MAX_WINDOW,
                  packetSize: PACKET_SIZE,
                  state: 'open',
                },
                outgoing: {
                  id: info.sender,
                  window: info.window,
                  packetSize: info.packetSize,
                  state: 'open',
                },
              };

              const stream = new Channel({ _protocol: this._protocol }, chanInfo);
              this._chanMgr.update(localChan, stream as unknown as ChannelOrCallback);

              this._protocol.channelOpenConfirm(info.sender, localChan, MAX_WINDOW, PACKET_SIZE);

              return stream;
            };

            this.emit(
              'tcpip',
              accept,
              reject,
              info.data as {
                srcIP: string;
                srcPort: number;
                destIP: string;
                destPort: number;
              },
            );
            return;
          }
          break;
        case 'direct-streamlocal@openssh.com':
          if (this.listenerCount('openssh.streamlocal') > 0 && reserveChannel()) {
            const accept = () => {
              if (replied) return;
              replied = true;

              const chanInfo: ChannelInfo = {
                type: 'direct-streamlocal',
                incoming: {
                  id: localChan,
                  window: MAX_WINDOW,
                  packetSize: PACKET_SIZE,
                  state: 'open',
                },
                outgoing: {
                  id: info.sender,
                  window: info.window,
                  packetSize: info.packetSize,
                  state: 'open',
                },
              };

              const stream = new Channel({ _protocol: this._protocol }, chanInfo);
              this._chanMgr.update(localChan, stream as unknown as ChannelOrCallback);

              this._protocol.channelOpenConfirm(info.sender, localChan, MAX_WINDOW, PACKET_SIZE);

              return stream;
            };

            this.emit('openssh.streamlocal', accept, reject, info.data as { socketPath: string });
            return;
          }
          break;
        default:
          reason = CHANNEL_OPEN_FAILURE.UNKNOWN_CHANNEL_TYPE;
          debug?.(`Automatic rejection of unsupported incoming channel open type: ${info.type}`);
      }

      if (reason === undefined) {
        reason = CHANNEL_OPEN_FAILURE.ADMINISTRATIVELY_PROHIBITED;
        debug?.(`Automatic rejection of unexpected incoming channel open for: ${info.type}`);
      }

      reject();
    };

    handlers.CHANNEL_OPEN_CONFIRMATION = (_p, info) => {
      const channel = this._chanMgr.get(info.recipient);
      if (typeof channel !== 'function') return;

      const chanInfo: ChannelInfo = {
        type: (channel as unknown as { type?: string }).type ?? 'unknown',
        incoming: {
          id: info.recipient,
          window: MAX_WINDOW,
          packetSize: PACKET_SIZE,
          state: 'open',
        },
        outgoing: {
          id: info.sender,
          window: info.window,
          packetSize: info.packetSize,
          state: 'open',
        },
      };

      const instance = new Channel({ _protocol: this._protocol }, chanInfo);
      this._chanMgr.update(info.recipient, instance as unknown as ChannelOrCallback);
      (channel as (err: Error | undefined, chan: Channel) => void)(undefined, instance);
    };

    handlers.CHANNEL_OPEN_FAILURE = (_p, recipient, reason, description) => {
      const channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'function') return;

      this._chanMgr.remove(recipient);
      const err = new Error(description || `Channel open failed: ${reason}`) as Error & {
        reason: number;
      };
      err.reason = reason;
      (channel as (err: Error) => void)(err);
    };

    handlers.CHANNEL_DATA = (_p, recipient, data) => {
      let channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      if (channel instanceof Session) {
        channel = channel._channel as unknown as ChannelOrCallback;
        if (!channel) return;
      }

      const chan = channel as unknown as Channel;
      chan.pushData(data);
    };

    handlers.CHANNEL_EXTENDED_DATA = (_p, _recipient, _data, _type) => {
      // NOOP - should not be sent by client
    };

    handlers.CHANNEL_WINDOW_ADJUST = (_p, recipient, amount) => {
      let channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      if (channel instanceof Session) {
        channel = channel._channel as unknown as ChannelOrCallback;
        if (!channel) return;
      }

      (channel as unknown as Channel).adjustWindow(amount);
    };

    handlers.CHANNEL_SUCCESS = (_p, recipient) => {
      let channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      if (channel instanceof Session) {
        channel = channel._channel as unknown as ChannelOrCallback;
        if (!channel) return;
      }

      // Handle channel success callback
    };

    handlers.CHANNEL_FAILURE = (_p, recipient) => {
      let channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      if (channel instanceof Session) {
        channel = channel._channel as unknown as ChannelOrCallback;
        if (!channel) return;
      }

      // Handle channel failure callback
    };

    handlers.CHANNEL_REQUEST = (_p, recipient, type, wantReply, data) => {
      const session = this._chanMgr.get(recipient);
      if (typeof session !== 'object' || session === null) return;

      let replied = false;
      let accept: (() => Channel | undefined) | (() => void) | undefined;
      let reject: (() => void) | undefined;

      if (!(session instanceof Session)) {
        // normal Channel instance
        if (wantReply) {
          const outId = (session as unknown as Channel).outgoing.id;
          if (outId !== undefined) {
            this._protocol.channelFailure(outId);
          }
        }
        return;
      }

      if (wantReply) {
        if (type !== 'shell' && type !== 'exec' && type !== 'subsystem') {
          accept = () => {
            if (replied || session._ending || session._channel) return;
            replied = true;

            const outId = session._chanInfo.outgoing.id;
            if (outId !== undefined) {
              this._protocol.channelSuccess(outId);
            }
          };
        }

        reject = () => {
          if (replied || session._ending || session._channel) return;
          replied = true;

          const outId = session._chanInfo.outgoing.id;
          if (outId !== undefined) {
            this._protocol.channelFailure(outId);
          }
        };
      }

      if (session._ending) {
        reject?.();
        return;
      }

      const dataObj = data as Record<string, unknown>;

      switch (type) {
        case 'env':
          if (session.listenerCount('env') > 0) {
            session.emit('env', accept as (() => void) | undefined, reject, {
              key: dataObj.name as string,
              val: dataObj.value as string,
            });
            return;
          }
          break;
        case 'pty-req':
          if (session.listenerCount('pty') > 0) {
            session.emit(
              'pty',
              accept as (() => void) | undefined,
              reject,
              data as {
                term: string;
                cols: number;
                rows: number;
                width: number;
                height: number;
                modes: Uint8Array;
              },
            );
            return;
          }
          break;
        case 'window-change':
          if (session.listenerCount('window-change') > 0) {
            session.emit(
              'window-change',
              accept as (() => void) | undefined,
              reject,
              data as {
                cols: number;
                rows: number;
                width: number;
                height: number;
              },
            );
          } else {
            reject?.();
          }
          return;
        case 'x11-req':
          if (session.listenerCount('x11') > 0) {
            session.emit(
              'x11',
              accept as (() => void) | undefined,
              reject,
              data as {
                single: boolean;
                protocol: string;
                cookie: string;
                screen: number;
              },
            );
            return;
          }
          break;
        case 'signal':
          if (session.listenerCount('signal') > 0) {
            session.emit('signal', accept as (() => void) | undefined, reject, {
              name: data as string,
            });
            return;
          }
          break;
        case 'auth-agent-req@openssh.com':
          if (session.listenerCount('auth-agent') > 0) {
            session.emit('auth-agent', accept as (() => void) | undefined, reject);
            return;
          }
          break;
        case 'shell':
          if (session.listenerCount('shell') > 0) {
            const shellAccept = (): Channel | undefined => {
              if (replied || session._ending || session._channel) return;
              replied = true;

              if (wantReply) {
                const outId = session._chanInfo.outgoing.id;
                if (outId !== undefined) {
                  this._protocol.channelSuccess(outId);
                }
              }

              const channel = new Channel({ _protocol: this._protocol }, session._chanInfo, {
                server: true,
              });
              channel.subtype = session.subtype = type;
              session._channel = channel;

              return channel;
            };

            session.emit('shell', shellAccept, reject);
            return;
          }
          break;
        case 'exec':
          if (session.listenerCount('exec') > 0) {
            const execAccept = (): Channel | undefined => {
              if (replied || session._ending || session._channel) return;
              replied = true;

              if (wantReply) {
                const outId = session._chanInfo.outgoing.id;
                if (outId !== undefined) {
                  this._protocol.channelSuccess(outId);
                }
              }

              const channel = new Channel({ _protocol: this._protocol }, session._chanInfo, {
                server: true,
              });
              channel.subtype = session.subtype = type;
              session._channel = channel;

              return channel;
            };

            session.emit('exec', execAccept, reject, { command: data as string });
            return;
          }
          break;
        case 'subsystem':
          if (
            session.listenerCount('subsystem') > 0 ||
            (data === 'sftp' && session.listenerCount('sftp') > 0)
          ) {
            const subsysAccept = (): Channel | undefined => {
              if (replied || session._ending || session._channel) return;
              replied = true;

              if (wantReply) {
                const outId = session._chanInfo.outgoing.id;
                if (outId !== undefined) {
                  this._protocol.channelSuccess(outId);
                }
              }

              const channel = new Channel({ _protocol: this._protocol }, session._chanInfo, {
                server: true,
              });
              channel.subtype = session.subtype = `${type}:${data}`;
              session._channel = channel;

              return channel;
            };

            if (data === 'sftp' && session.listenerCount('sftp') > 0) {
              session.emit('sftp', subsysAccept, reject);
            } else {
              session.emit('subsystem', subsysAccept, reject, { name: data as string });
            }
            return;
          }
          break;
      }

      debug?.(`Automatic rejection of incoming channel request: ${type}`);
      reject?.();
    };

    handlers.CHANNEL_EOF = (_p, recipient) => {
      let channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      if (channel instanceof Session) {
        if (!channel._ending) {
          channel._ending = true;
          channel.emit('eof');
          channel.emit('end');
        }
        channel = channel._channel as unknown as ChannelOrCallback;
        if (!channel) return;
      }

      (channel as unknown as Channel).handleEOF();
    };

    handlers.CHANNEL_CLOSE = (_p, recipient) => {
      let channel = this._chanMgr.get(recipient);
      if (typeof channel !== 'object' || channel === null) return;

      if (channel instanceof Session) {
        if (!channel._channel) {
          // No exec/shell/subsystem was ever started (e.g. it was refused), so
          // nothing else will answer the close: do it here (RFC 4254 5.3)
          const outId = channel._chanInfo.outgoing.id;
          if (channel._chanInfo.outgoing.state !== 'closed' && outId !== undefined) {
            this._protocol.channelClose(outId);
          }
          onChannelClose(this._chanMgr, recipient, channel as unknown as ChannelOrCallback);
          return;
        }
        channel._ending = true;
        channel.emit('close');
        channel = channel._channel as unknown as ChannelOrCallback;
      }

      onChannelClose(this._chanMgr, recipient, channel);
    };

    handlers.GLOBAL_REQUEST = (_p, name, wantReply, data) => {
      const reply = { type: null as string | null, buf: null as Uint8Array | null };

      const setReply = (type: string, buf?: Uint8Array) => {
        reply.type = type;
        reply.buf = buf ?? null;
        sendReplies();
      };

      if (wantReply) {
        unsentGlobalRequestsReplies.push(reply);
      }

      if (
        (name === 'tcpip-forward' ||
          name === 'cancel-tcpip-forward' ||
          name === 'no-more-sessions@openssh.com' ||
          name === 'streamlocal-forward@openssh.com' ||
          name === 'cancel-streamlocal-forward@openssh.com') &&
        this.listenerCount('request') > 0 &&
        this.authenticated
      ) {
        let accept: ((port?: number) => void) | undefined;
        let reject: (() => void) | undefined;

        if (wantReply) {
          let replied = false;
          accept = (chosenPort?: number) => {
            if (replied) return;
            replied = true;
            let bufPort: Uint8Array | undefined;
            if (
              name === 'tcpip-forward' &&
              (data as { bindPort?: number })?.bindPort === 0 &&
              typeof chosenPort === 'number'
            ) {
              bufPort = allocBytes(4);
              writeUInt32BE(bufPort, chosenPort, 0);
            }
            setReply('SUCCESS', bufPort);
          };
          reject = () => {
            if (replied) return;
            replied = true;
            setReply('FAILURE');
          };
        }

        if (name === 'no-more-sessions@openssh.com') {
          this.noMoreSessions = true;
          accept?.();
          return;
        }

        this.emit('request', accept, reject, name, data);
      } else if (wantReply) {
        setReply('FAILURE');
      }
    };

    // Convert hostKeys Map to HostKeyInfo array
    const hostKeyInfos: Array<{ type: string; publicKey: Uint8Array; privateKey: Uint8Array }> = [];
    for (const [keyType, key] of hostKeys) {
      const pubSSH = key.getPublicSSH();
      const privPEM = key.getPrivatePEM();
      if (pubSSH && privPEM) {
        hostKeyInfos.push({
          type: keyType,
          publicKey: pubSSH,
          privateKey: typeof privPEM === 'string' ? new TextEncoder().encode(privPEM) : privPEM,
        });
      }
    }

    // Create protocol
    const protocolConfig: ProtocolConfig = {
      server: true,
      hostKeys: hostKeyInfos,
      ident,
      offer: algorithms,
      greeting: config.greeting,
      banner: config.banner,
      onWrite: (data) => {
        this._writeToTransport(data);
      },
      onError: (err) => {
        this.emit('error', err);
        transport.close();
      },
      onHeader: (header) => {
        const info: ConnectionInfo = {
          ip: transport.remoteAddress,
          port: transport.remotePort,
          header,
        };
        if (!server.emit('connection', this, info)) {
          this._protocol.disconnect(DISCONNECT_REASON.BY_APPLICATION);
          transport.close();
          return;
        }

        if (header.greeting) {
          this.emit('greeting', header.greeting);
        }
      },
      onHandshakeComplete: (algorithms) => {
        if (++exchanges > 1) {
          this.emit('rekey');
        }
        this.emit('handshake', algorithms ? { serverHostKey: algorithms.serverHostKey } : {});
      },
      debug,
      messageHandlers: handlers,
    };

    this._protocol = new Protocol(protocolConfig);

    // Start reading from transport
    this._startReading();

    // Start protocol
    this._protocol.start?.();
  }

  /** Write queue for sequential writes */
  private _writeQueue: Uint8Array[] = [];
  private _writeInProgress = false;

  /**
   * Write data to transport (queued for sequential writes)
   */
  private _writeToTransport(data: Uint8Array): void {
    this._writeQueue.push(data);
    this._processWriteQueue();
  }

  /**
   * Process the write queue
   */
  private async _processWriteQueue(): Promise<void> {
    if (this._writeInProgress) {
      return;
    }

    this._writeInProgress = true;
    let writer: WritableStreamDefaultWriter<Uint8Array> | undefined;

    try {
      writer = this._transport.writable.getWriter();

      for (let i = 0; i < this._writeQueue.length;) {
        const { data, nextIndex } = coalesceTransportWrite(this._writeQueue, i);
        await writer.write(data);
        i = nextIndex;
      }
      this._writeQueue.length = 0;
    } catch (err) {
      // Clear the queue to prevent infinite recursion when transport is closed
      this._writeQueue.length = 0;
      this.emit('error', err as Error);
    } finally {
      // Always release the writer lock, even on error
      writer?.releaseLock();
      this._writeInProgress = false;
      // Check if more data arrived while we were processing
      if (this._writeQueue.length > 0) {
        this._processWriteQueue();
      } else if (this._closing) {
        this._transport.close();
      }
    }
  }

  /**
   * Start reading from transport
   */
  private async _startReading(): Promise<void> {
    try {
      const reader = this._transport.readable.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          this._debug?.('Transport closed');
          this.emit('end');
          break;
        }
        if (value) {
          try {
            await this._protocol.parse(value, 0, value.length);
          } catch (err) {
            this.emit('error', err as Error);
            break;
          }
        }
      }
      reader.releaseLock();
    } catch (err) {
      const error = err as Error & { level?: string };
      error.level = 'socket';
      this.emit('error', error);
    } finally {
      this._protocol.cleanup();
      this.emit('close');
      this._chanMgr.cleanup(new Error('Connection closed'));
    }
  }

  /**
   * End the connection
   */
  end(): this {
    this._protocol.disconnect(DISCONNECT_REASON.BY_APPLICATION);
    this._closing = true;
    // If no write is in progress, close immediately; otherwise _processWriteQueue will close
    if (!this._writeInProgress) {
      this._transport.close();
    }
    return this;
  }

  private _closing = false;

  /**
   * Open X11 channel
   */
  x11(originAddr: string, originPort: number, cb: (err?: Error, channel?: Channel) => void): this {
    this._openChannel('x11', { originAddr, originPort }, cb);
    return this;
  }

  /**
   * Forward outgoing connection
   */
  forwardOut(
    boundAddr: string,
    boundPort: number,
    remoteAddr: string,
    remotePort: number,
    cb: (err?: Error, channel?: Channel) => void,
  ): this {
    this._openChannel('forwarded-tcpip', { boundAddr, boundPort, remoteAddr, remotePort }, cb);
    return this;
  }

  /**
   * OpenSSH forward out stream local
   */
  openssh_forwardOutStreamLocal(
    socketPath: string,
    cb: (err?: Error, channel?: Channel) => void,
  ): this {
    this._openChannel('forwarded-streamlocal@openssh.com', { socketPath }, cb);
    return this;
  }

  /**
   * Rekey the connection
   */
  rekey(cb?: (err?: Error) => void): void {
    try {
      this._protocol.rekey();
      if (cb) {
        this.once('rekey', () => cb());
      }
    } catch (err) {
      if (cb) {
        queueMicrotask(() => cb(err as Error));
      }
    }
  }

  /**
   * Open a channel
   */
  private _openChannel(
    type: string,
    opts: Record<string, unknown>,
    cb: (err?: Error, channel?: Channel) => void,
  ): void {
    const wrapper = (err: Error | undefined, stream: Channel | undefined) => {
      cb(err, stream);
    };
    (wrapper as unknown as { type: string }).type = type;

    const localChan = this._chanMgr.add(wrapper as unknown as ChannelOrCallback);

    if (localChan === -1) {
      cb(new Error('No free channels available'));
      return;
    }

    switch (type) {
      case 'forwarded-tcpip':
        this._protocol.forwardedTcpip(
          localChan,
          MAX_WINDOW,
          PACKET_SIZE,
          opts as { boundAddr: string; boundPort: number; remoteAddr: string; remotePort: number },
        );
        break;
      case 'x11':
        this._protocol.x11(
          localChan,
          MAX_WINDOW,
          PACKET_SIZE,
          opts as { originAddr: string; originPort: number },
        );
        break;
      case 'forwarded-streamlocal@openssh.com':
        this._protocol.openssh_forwardedStreamLocal(
          localChan,
          MAX_WINDOW,
          PACKET_SIZE,
          opts as { socketPath: string },
        );
        break;
      default:
        throw new Error(`Unsupported channel type: ${type}`);
    }
  }
}

// ============================================================================
// Server Class
// ============================================================================

/**
 * Host key configuration
 */
export interface HostKeyConfig {
  key: string | Uint8Array;
  passphrase?: string;
}

/** Accepted forms of a server host key: a path/PEM string, raw bytes, a config object, or a pre-parsed key. */
export type HostKeyInput = string | Uint8Array | HostKeyConfig | ParsedKey;

/**
 * Server configuration
 */
export interface ServerConfig {
  /** Host keys for the server (can be ParsedKey objects for testing) */
  hostKeys: HostKeyInput[];
  /** Algorithm preferences */
  algorithms?: {
    kex?: string[];
    serverHostKey?: string[];
    cipher?: string[];
    hmac?: string[];
    compress?: string[];
  };
  /** Server identification string */
  ident?: string;
  /** Greeting message */
  greeting?: string;
  /** Banner message */
  banner?: string;
  /** Debug function */
  debug?: (msg: string) => void;
  /** Keepalive interval in milliseconds */
  keepaliveInterval?: number;
  /** Max keepalive failures */
  keepaliveCountMax?: number;
}

/**
 * What a server knows about a client when it connects
 */
export interface ConnectionInfo {
  /** Client address, when the transport has one */
  ip?: string;
  /** Client port, when the transport has one */
  port?: number;
  /** The client's identification header */
  header: unknown;
}

/**
 * Server events
 */
export interface ServerEvents {
  connection: [client: Connection, info: ConnectionInfo];
  error: [Error];
  listening: [];
  close: [];
}

/**
 * SSH Server
 */
export class Server extends EventEmitter<ServerEvents> {
  private _listener?: TransportListener;
  private _hostKeys: Map<string, ParsedKey>;
  private _hostKeyAlgoOrder: string[];
  private _algorithms!: {
    kex: string[];
    serverHostKey: string[];
    cs: { cipher: string[]; mac: string[]; compress: string[]; lang: string[] };
    sc: { cipher: string[]; mac: string[]; compress: string[]; lang: string[] };
  };
  private _config: ServerConfig;
  private _hostKeysInitialized = false;
  private _connections = 0;

  maxConnections = Infinity;

  static KEEPALIVE_CLIENT_INTERVAL = 15000;
  static KEEPALIVE_CLIENT_COUNT_MAX = 3;

  constructor(
    config: ServerConfig,
    listener?: (client: Connection, info: { header: unknown }) => void,
  ) {
    super();

    if (typeof config !== 'object' || config === null) {
      throw new Error('Missing configuration object');
    }

    this._config = config;
    this._hostKeys = new Map();
    this._hostKeyAlgoOrder = [];
    this._hostKeysInitialized = false;

    const hostKeys = config.hostKeys;
    if (!Array.isArray(hostKeys)) {
      throw new Error('hostKeys must be an array');
    }

    if (listener) {
      this.on('connection', listener);
    }
  }

  /**
   * Initialize host keys (async to support encrypted keys with passphrases)
   */
  private async _initHostKeys(): Promise<void> {
    if (this._hostKeysInitialized) return;
    this._hostKeysInitialized = true;

    const config = this._config;
    const hostKeys = config.hostKeys;
    const cfgAlgos = config.algorithms ?? {};

    const hostKeyAlgos = generateAlgorithmList(
      cfgAlgos.serverHostKey,
      DEFAULT_SERVER_HOST_KEY,
      SUPPORTED_SERVER_HOST_KEY,
    );

    for (const hostKeyConfig of hostKeys) {
      let privateKey: ParsedKey;

      if (isParsedKey(hostKeyConfig)) {
        privateKey = hostKeyConfig;
      } else if (hostKeyConfig instanceof Uint8Array || typeof hostKeyConfig === 'string') {
        const keyResult = parseKey(hostKeyConfig);
        if (keyResult instanceof Error) {
          throw new Error(`Cannot parse privateKey: ${keyResult.message}`);
        }
        privateKey = Array.isArray(keyResult) ? keyResult[0] : keyResult;
      } else {
        let keyResult: ParsedKey | Error;
        if (hostKeyConfig.passphrase) {
          keyResult = await parseKey(hostKeyConfig.key, hostKeyConfig.passphrase);
        } else {
          keyResult = parseKey(hostKeyConfig.key);
        }
        if (keyResult instanceof Error) {
          throw new Error(`Cannot parse privateKey: ${keyResult.message}`);
        }
        privateKey = Array.isArray(keyResult) ? keyResult[0] : keyResult;
      }

      if (privateKey.getPrivatePEM() === null) {
        throw new Error('privateKey value contains an invalid private key');
      }

      if (this._hostKeyAlgoOrder.includes(privateKey.type)) {
        continue;
      }

      if (privateKey.type === 'ssh-rsa') {
        let sha1Pos = hostKeyAlgos.indexOf('ssh-rsa');
        const sha256Pos = hostKeyAlgos.indexOf('rsa-sha2-256');
        const sha512Pos = hostKeyAlgos.indexOf('rsa-sha2-512');
        if (sha1Pos === -1) {
          sha1Pos = Infinity;
        }
        [sha1Pos, sha256Pos, sha512Pos]
          .sort((a, b) => a - b)
          .forEach((pos) => {
            if (pos === -1) return;

            let type: string;
            switch (pos) {
              case sha1Pos:
                type = 'ssh-rsa';
                break;
              case sha256Pos:
                type = 'rsa-sha2-256';
                break;
              case sha512Pos:
                type = 'rsa-sha2-512';
                break;
              default:
                return;
            }

            this._hostKeys.set(type, privateKey);
            this._hostKeyAlgoOrder.push(type);
          });
      } else {
        this._hostKeys.set(privateKey.type, privateKey);
        this._hostKeyAlgoOrder.push(privateKey.type);
      }
    }

    const cs = {
      cipher: generateAlgorithmList(cfgAlgos.cipher, DEFAULT_CIPHER, SUPPORTED_CIPHER),
      mac: generateAlgorithmList(cfgAlgos.hmac, DEFAULT_MAC, SUPPORTED_MAC),
      compress: generateAlgorithmList(
        cfgAlgos.compress,
        DEFAULT_COMPRESSION,
        SUPPORTED_COMPRESSION,
      ),
      lang: [] as string[],
    };

    this._algorithms = {
      kex: generateAlgorithmList(cfgAlgos.kex, DEFAULT_KEX, SUPPORTED_KEX).concat([
        'kex-strict-s-v00@openssh.com',
      ]),
      serverHostKey: this._hostKeyAlgoOrder,
      cs,
      sc: cs,
    };
  }

  /**
   * Start listening for connections
   */
  async listen(port: number, hostname?: string): Promise<void> {
    await this._initHostKeys();

    const { DenoTransportFactory } = await import('./adapters/deno.ts');
    const factory = new DenoTransportFactory();

    this._listener = await factory.listen({ port, hostname });
    this.emit('listening');

    // Accept connections
    this._acceptConnections();
  }

  /**
   * Accept incoming connections
   */
  private async _acceptConnections(): Promise<void> {
    if (!this._listener) return;

    try {
      for await (const transport of this._listener) {
        if (this._connections >= this.maxConnections) {
          transport.close();
          continue;
        }

        this._connections++;

        let debug = this._config.debug;
        if (debug) {
          const debugPrefix = `[${Date.now()}] `;
          const origDebug = debug;
          debug = (msg: string) => origDebug(`${debugPrefix}${msg}`);
        }

        const connection = new Connection(
          transport,
          this._hostKeys,
          this._config.ident,
          this._algorithms,
          debug,
          this,
          this._config,
        );

        connection.on('close', () => {
          this._connections--;
        });
      }
    } catch (err) {
      this.emit('error', err as Error);
    }
  }

  /**
   * Get server address
   */
  address(): { hostname: string; port: number } | undefined {
    return this._listener?.addr;
  }

  /**
   * Close the server
   */
  close(): this {
    this._listener?.close();
    this.emit('close');
    return this;
  }

  /**
   * Inject a socket/transport
   */
  injectTransport(transport: Transport): void {
    if (this._connections >= this.maxConnections) {
      transport.close();
      return;
    }

    this._connections++;

    let debug = this._config.debug;
    if (debug) {
      const debugPrefix = `[${Date.now()}] `;
      const origDebug = debug;
      debug = (msg: string) => origDebug(`${debugPrefix}${msg}`);
    }

    const connection = new Connection(
      transport,
      this._hostKeys,
      this._config.ident,
      this._algorithms,
      debug,
      this,
      this._config,
    );

    connection.on('close', () => {
      this._connections--;
    });
  }
}
