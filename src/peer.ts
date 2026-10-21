import { Socket } from "node:net";
import {
  Cache,
  Cause,
  Clock,
  Deferred,
  Effect,
  Exit,
  Metric,
  Queue,
  Schema,
  Scope,
  Stream,
} from "effect";
import {
  bytes32,
  edgeHash,
  freshEdgeNonce,
  PeerIdentity,
  publicKeyBorsh,
  verifyEd25519,
  FrameDecoder,
  decodeMessage,
  decodeRouted,
  decodeRoutedV3,
  encodeReceiptRequest,
  encodeMessage,
  encodePong,
  frameMessage,
  signRouted,
  type RoutedEnvelope,
  type RoutedTarget,
} from "./protocol.ts";
import type { HandshakePayload, WireMessage } from "./schemas.ts";

export const peerMetrics = {
  bytesIn: Metric.counter("p2p_received_bytes"),
  bytesOut: Metric.counter("p2p_sent_bytes", {
    description: "bytes queued for socket writes, including uncertain failures",
  }),
  frames: Metric.counter("p2p_received_frames"),
  handshakeMs: Metric.timer("p2p_handshake_ms"),
};
export interface ClockStamp {
  readonly unixMs: number;
  readonly monotonicNs: bigint;
}
export class PeerError extends Schema.TaggedError<PeerError>()("PeerError", {
  operation: Schema.String,
  message: Schema.String,
}) {}
const peerError = (operation: string, cause: unknown) =>
  new PeerError({ operation, message: cause instanceof Error ? cause.message : String(cause) });
export interface PeerOptions {
  readonly host: string;
  readonly port: number;
  readonly peerId: string | Uint8Array;
  readonly genesisHash: string | Uint8Array;
  readonly protocolVersion: number;
  readonly height?: number | bigint;
  readonly handshakeTimeoutMs?: number;
}
export type PeerEvent =
  | { readonly type: "message"; readonly message: WireMessage; readonly receivedAt: ClockStamp }
  | {
      readonly type: "routed";
      readonly message: RoutedEnvelope & { readonly forUs: boolean };
      readonly receivedAt: ClockStamp;
    };
export interface Peer {
  /** One consumer owns this bounded stream. Overflow fails the connection. */
  readonly events: Stream.Stream<PeerEvent, PeerError>;
  readonly requestBlock: (hash: string | Uint8Array) => Effect.Effect<void, PeerError>;
  readonly requestChunk: (
    hash: string | Uint8Array,
    shardId: number | bigint,
  ) => Effect.Effect<void, PeerError>;
  readonly close: () => Effect.Effect<void>;
}

function validateHandshake(
  handshake: HandshakePayload,
  identity: PeerIdentity,
  remote: Buffer,
  genesisHash: Buffer,
  nonce: bigint,
  version: number,
): void {
  if (!publicKeyBorsh(remote).equals(handshake.sender_peer_id.borsh))
    throw new Error("handshake sender mismatch");
  if (!publicKeyBorsh(identity.publicKey).equals(handshake.target_peer_id.borsh))
    throw new Error("handshake targets another peer");
  const genesis = handshake.sender_chain_info.genesis_id;
  if (
    genesis?.chain_id !== "testnet" ||
    !genesis.hash?.hash ||
    !genesisHash.equals(genesis.hash.hash)
  )
    throw new Error("handshake genesis mismatch");
  if (handshake.protocol_version < version - 2 || handshake.oldest_supported_version > version)
    throw new Error("handshake protocol versions do not overlap");
  const edge = Buffer.from(handshake.partial_edge_info.borsh);
  if (edge.length !== 73 || edge[8] !== 0 || edge.readBigUInt64LE() !== nonce)
    throw new Error("invalid handshake edge encoding or nonce");
  if (!verifyEd25519(remote, edgeHash(identity.publicKey, remote, nonce), edge.subarray(9)))
    throw new Error("invalid handshake edge signature");
}

/** Scoped testnet Tier2 connection. Only block/proof requests and keepalive replies can be sent. */
export const openPeer: (options: PeerOptions) => Effect.Effect<Peer, PeerError, Scope.Scope> =
  Effect.fn("Peer.open")(function* (options: PeerOptions) {
    const clock = yield* Clock.Clock;
    const metricContext = yield* Effect.context<never>();
    const { remote, genesisHash, identity, decoder } = yield* Effect.try({
      try: () => {
        for (const [label, value, min, max] of [
          ["port", options.port, 1, 65535],
          ["protocol", options.protocolVersion, 2, 0xffffffff],
          ["handshake timeout", options.handshakeTimeoutMs ?? 10_000, 1, 0x7fffffff],
        ] as const)
          if (!Number.isSafeInteger(value) || value < min || value > max)
            throw new Error(`invalid ${label}`);
        const height = options.height ?? 0;
        if (
          (typeof height === "number" && !Number.isSafeInteger(height)) ||
          BigInt(height) < 0n ||
          BigInt(height) > 0xffffffffffffffffn
        )
          throw new Error("invalid height");
        return {
          remote: bytes32(options.peerId),
          genesisHash: bytes32(options.genesisHash),
          identity: new PeerIdentity(),
          decoder: new FrameDecoder(),
        };
      },
      catch: (cause) => peerError("configuration", cause),
    });
    const incoming = yield* Queue.make<
      { message: WireMessage; bytes: number; receivedAt: ClockStamp },
      PeerError | Cause.Done
    >({ capacity: 128, strategy: "dropping" });
    const handshake = yield* Deferred.make<HandshakePayload, PeerError>();
    const routes = yield* Cache.make({
      capacity: 4096,
      timeToLive: "1 minute",
      lookup: (_key: string) => Effect.succeed(true),
    });
    let ready = false;
    let released = false;
    let queuedBytes = 0;
    let failure: PeerError | undefined;
    let nonce = 0n;
    let frameTimer: ReturnType<typeof setTimeout> | undefined;
    const socket = yield* Effect.acquireRelease(
      Effect.sync(() => new Socket()),
      (owned) =>
        Effect.sync(() => {
          released = true;
          ready = false;
          if (frameTimer) clearTimeout(frameTimer);
          owned.destroy();
          Queue.endUnsafe(incoming);
          Queue.shutdownUnsafe(incoming);
        }),
    );
    const fail = (error: PeerError) => {
      if (failure || released) return;
      failure = error;
      ready = false;
      Deferred.doneUnsafe(handshake, Effect.fail(error));
      Queue.failCauseUnsafe(incoming, Cause.fail(error));
      Queue.shutdownUnsafe(incoming);
      if (frameTimer) clearTimeout(frameTimer);
      socket.destroy();
    };
    const write = Effect.fn("Peer.write")(function* (type: string, payload: object) {
      const frame = yield* Effect.try({
        try: () => {
          if (socket.destroyed || released) throw failure ?? new Error("peer is closed");
          const value = frameMessage(encodeMessage(type, payload), decoder.maxBytes);
          if (socket.writableLength + value.length > decoder.maxBytes * 2)
            throw new Error("peer send queue is full");
          return value;
        },
        catch: (cause) => peerError("encode", cause),
      });
      yield* Effect.callback<void, PeerError>((resume) => {
        peerMetrics.bytesOut.updateUnsafe(frame.length, metricContext);
        socket.write(frame, (error) =>
          resume(error ? Effect.fail(peerError("write", error)) : Effect.void),
        );
      }).pipe(
        Effect.timeoutOrElse({
          duration: "10 seconds",
          orElse: () => Effect.fail(peerError("write", "peer write timed out")),
        }),
        Effect.tapError((error) => Effect.sync(() => fail(error))),
      );
    });
    yield* Effect.sync(() => {
      socket.setNoDelay(true);
      socket.setTimeout(30_000);
      socket.on("timeout", () => fail(peerError("receive", "peer idle timeout")));
      socket.on("error", (error) => fail(peerError("socket", error)));
      socket.on("close", () => {
        ready = false;
        if (!released) fail(peerError("receive", "peer closed the connection"));
      });
      socket.on("end", () => {
        if (decoder.hasPartialFrame)
          fail(peerError("receive", "peer closed with an incomplete frame"));
      });
      socket.on("data", (bytes) => {
        try {
          const receivedAt = {
            unixMs: clock.currentTimeMillisUnsafe(),
            monotonicNs: clock.monotonicTimeNanosUnsafe(),
          };
          peerMetrics.bytesIn.updateUnsafe(bytes.length, metricContext);
          const frames = decoder.push(bytes);
          if (frameTimer && frames.length > 0) {
            clearTimeout(frameTimer);
            frameTimer = undefined;
          }
          if (decoder.hasPartialFrame && !frameTimer)
            frameTimer = setTimeout(
              () => fail(peerError("receive", "peer frame assembly timeout")),
              10_000,
            );
          else if (!decoder.hasPartialFrame && frameTimer) {
            clearTimeout(frameTimer);
            frameTimer = undefined;
          }
          for (const frame of frames) {
            peerMetrics.frames.updateUnsafe(1, metricContext);
            const message = decodeMessage(frame);
            if (!ready) {
              if (message.type !== "tier2_handshake")
                throw new Error(`unexpected ${message.type} before handshake`);
              validateHandshake(
                message.payload,
                identity,
                remote,
                genesisHash,
                nonce,
                options.protocolVersion,
              );
              ready = true;
              Deferred.doneUnsafe(handshake, Effect.succeed(message.payload));
            }
            if (queuedBytes + frame.length > 32 * 1024 * 1024)
              throw new Error("peer receive byte queue overflow");
            queuedBytes += frame.length;
            if (!Queue.offerUnsafe(incoming, { message, bytes: frame.length, receivedAt }))
              throw new Error("peer receive message queue overflow");
          }
        } catch (cause) {
          fail(peerError("receive", cause));
        }
      });
    });
    yield* Effect.gen(function* () {
      yield* Effect.callback<void, PeerError>((resume) => {
        const onError = (cause: Error) => resume(Effect.fail(peerError("connect", cause)));
        socket.once("error", onError);
        socket.connect(options.port, options.host, () => {
          socket.off("error", onError);
          resume(Effect.void);
        });
        return Effect.sync(() => {
          socket.off("error", onError);
        });
      });
      nonce = freshEdgeNonce();
      // Match nearcore's raw connection: advertise the ephemeral local port, with no listener.
      yield* write("tier2_handshake", {
        protocol_version: options.protocolVersion,
        oldest_supported_version: options.protocolVersion - 2,
        sender_peer_id: { borsh: publicKeyBorsh(identity.publicKey) },
        target_peer_id: { borsh: publicKeyBorsh(remote) },
        sender_listen_port: socket.localPort,
        sender_chain_info: {
          genesis_id: { chain_id: "testnet", hash: { hash: genesisHash } },
          height: String(options.height ?? 0),
          tracked_shards: [],
          archival: false,
        },
        partial_edge_info: { borsh: identity.partialEdge(remote, nonce) },
      });
      yield* Deferred.await(handshake);
    }).pipe(
      Effect.timeoutOrElse({
        duration: options.handshakeTimeoutMs ?? 10_000,
        orElse: () => Effect.fail(peerError("handshake", "peer handshake timed out")),
      }),
      Effect.trackDuration(peerMetrics.handshakeMs),
      Effect.onExit((exit) =>
        Exit.isFailure(exit) ? Effect.sync(() => socket.destroy()) : Effect.void,
      ),
    );
    const requireReady = Effect.fn("Peer.requireReady")(function* () {
      if (!ready || socket.destroyed)
        return yield* Effect.fail(failure ?? peerError("send", "peer is closed"));
    });
    const sendRouted = Effect.fn("Peer.sendRouted")(function* (
      body: Uint8Array,
      target: RoutedTarget,
    ) {
      yield* requireReady();
      const signed = yield* Effect.try({
        try: () => signRouted(identity, target, body),
        catch: (cause) => peerError("routed", cause),
      });
      yield* Cache.set(routes, signed.hash.toString("hex"), true);
      yield* write("routed", {
        borsh: signed.borsh,
        created_at: {
          seconds: String(Math.floor(clock.currentTimeMillisUnsafe() / 1000)),
          nanos: 0,
        },
        num_hops: 0,
      });
    });
    const decodeEvent = Effect.fn("Peer.decodeEvent")(function* (entry: {
      message: WireMessage;
      bytes: number;
      receivedAt: ClockStamp;
    }): Effect.fn.Return<PeerEvent, PeerError> {
      queuedBytes -= entry.bytes;
      const message = entry.message;
      if (message.type !== "routed" && message.type !== "routed_v3")
        return { type: "message", message, receivedAt: entry.receivedAt };
      const routed = yield* Effect.try({
        try: () =>
          message.type === "routed"
            ? decodeRouted(message.payload.borsh)
            : decodeRoutedV3(message.payload),
        catch: (cause) => peerError("routed", cause),
      });
      if (!routed) return { type: "message", message, receivedAt: entry.receivedAt };
      if (!routed.signatureValid)
        return yield* Effect.fail(peerError("routed", "invalid routed message signature"));
      const forUs =
        routed.target.type === "peer_id"
          ? identity.publicKey.equals(routed.target.bytes)
          : yield* Cache.has(routes, Buffer.from(routed.target.bytes).toString("hex"));
      if (forUs && routed.bodyType === 14 && routed.bodyBytes.length === 41)
        yield* sendRouted(
          encodePong(Buffer.from(routed.bodyBytes).readBigUInt64LE(), identity.publicKey),
          { type: "hash", bytes: routed.hash },
        );
      return { type: "routed", receivedAt: entry.receivedAt, message: { ...routed, forUs } };
    });
    return {
      events: Stream.fromQueue(incoming).pipe(
        Stream.mapEffect(decodeEvent),
        Stream.tapError((error) => Effect.sync(() => fail(error))),
      ),
      requestBlock: Effect.fn("Peer.requestBlock")(function* (hash: string | Uint8Array) {
        yield* requireReady();
        const hashBytes = yield* Effect.try({
          try: () => bytes32(hash),
          catch: (cause) => peerError("block request", cause),
        });
        yield* write("block_request", { block_hash: { hash: hashBytes } });
      }),
      requestChunk: Effect.fn("Peer.requestChunk")(function* (
        hash: string | Uint8Array,
        shardId: number | bigint,
      ) {
        const body = yield* Effect.try({
          try: () => encodeReceiptRequest(hash, shardId),
          catch: (cause) => peerError("receipt request", cause),
        });
        yield* sendRouted(body, { type: "peer_id", bytes: remote });
      }),
      close: Effect.fn("Peer.close")(function* () {
        released = true;
        ready = false;
        if (frameTimer) clearTimeout(frameTimer);
        socket.destroy();
        yield* Queue.end(incoming);
      }),
    } satisfies Peer;
  });
