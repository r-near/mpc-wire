import { isIP } from "node:net";
import bs58 from "bs58";
import { Near } from "near-kit";
import {
  Cache,
  Cause,
  Clock,
  Deferred,
  Duration,
  Effect,
  Exit,
  Fiber,
  Metric,
  Option,
  Queue,
  Schedule,
  Schema,
  Stream,
} from "effect";
import {
  decodeBlock,
  decodeChunkResponse,
  verifyReceiptProof,
  type ChunkHeader,
} from "./protocol.ts";
import { openPeer, type Peer, type PeerError, type PeerEvent, type ClockStamp } from "./peer.ts";
import {
  TESTNET_GENESIS as GENESIS,
  TestnetStatus,
  RpcBlock,
  RpcProtocol,
  RpcNetwork,
  Uint,
  type Receipt,
} from "./schemas.ts";

export class NetworkError extends Schema.TaggedError<NetworkError>()("NetworkError", {
  message: Schema.String,
}) {}
const error = (cause: unknown) =>
  cause instanceof NetworkError ? cause : new NetworkError({ message: String(cause) });
const checked = <A>(run: () => A) => Effect.try({ try: run, catch: error });
const timer = (name: string) =>
  Metric.timer(name, { boundaries: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500] });
export const metrics = {
  blocks: Metric.counter("blocks"),
  requests: Metric.counter("receipt_requests"),
  proofs: Metric.counter("receipt_proofs"),
  missing: Metric.counter("missing_proofs"),
  failures: Metric.counter("peer_failures"),
  active: Metric.gauge("fresh_peers"),
  decode: timer("block_decode_ms"),
  verify: timer("receipt_verify_ms"),
  fetch: timer("receipt_fetch_ms"),
  processing: timer("response_processing_ms"),
};

export interface ReceiptObservation {
  readonly receipt: Receipt;
  readonly blockHeight: string;
  readonly peer: string;
  readonly observedAt: string;
  readonly blockToReceiptMs: number;
}

const Options = Schema.Struct({
  accountId: Schema.String.check(
    Schema.isMinLength(2),
    Schema.isMaxLength(64),
    Schema.isPattern(/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/),
  ),
  rpcUrl: Schema.String,
  peers: Uint.check(Schema.isBetween({ minimum: 1, maximum: 12 })),
});
export interface Options extends Schema.Schema.Type<typeof Options> {}

export function parseSeed(id: string, address: string) {
  const [host, portText, extra] = address.split(":");
  const [a, b, c] = host.split(".").map(Number);
  const port = Number(portText);
  if (
    isIP(host) !== 4 ||
    extra !== undefined ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535 ||
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  )
    throw new Error("not a public IPv4 peer");
  if (!id.startsWith("ed25519:") || id.length > 52 || bs58.decode(id.slice(8)).length !== 32)
    throw new Error("invalid peer key");
  return { host, port, peerId: id };
}
const bootstrap = Effect.fn("Network.bootstrap")(function* (rpcUrl: string, accountId: string) {
  const url = yield* checked(() => new URL(rpcUrl));
  if (url.protocol !== "https:" || url.username || url.password)
    return yield* Effect.fail(error("RPC requires credential-free HTTPS"));
  const near = new Near({
    network: { networkId: "testnet", rpcUrl },
    retryConfig: { maxRetries: 0 },
  });
  const read = (method: string, params: unknown) =>
    Effect.tryPromise({ try: () => near.rpc.call<unknown>(method, params), catch: error }).pipe(
      Effect.timeout("15 seconds"),
    );
  yield* read("status", {}).pipe(Effect.flatMap(Schema.decodeUnknownEffect(TestnetStatus)));
  const { header } = yield* read("block", { finality: "final" }).pipe(
    Effect.flatMap(Schema.decodeUnknownEffect(RpcBlock)),
  );
  const [protocol, network] = yield* Effect.all(
    [
      read("EXPERIMENTAL_protocol_config", { block_id: header.hash }).pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(RpcProtocol)),
      ),
      read("network_info", {}).pipe(Effect.flatMap(Schema.decodeUnknownEffect(RpcNetwork))),
    ],
    { concurrency: 2 },
  );
  const { boundary_accounts: boundaries, shard_ids: shards } = protocol.shard_layout.V3;
  if (
    shards.length !== boundaries.length + 1 ||
    shards.length > 128 ||
    new Set(shards).size !== shards.length ||
    boundaries.some((value, i) => i > 0 && value <= boundaries[i - 1])
  )
    return yield* Effect.fail(error("unsupported shard layout"));
  const shard = shards[boundaries.filter((boundary) => accountId >= boundary).length];
  const seeds = network.active_peers
    .slice(0, 256)
    .flatMap(({ id, addr }) => {
      try {
        return [parseSeed(id, addr)];
      } catch {
        return [];
      }
    })
    .filter(
      (peer, i, peers) =>
        peers.findIndex(
          (other) =>
            other.peerId === peer.peerId || (other.host === peer.host && other.port === peer.port),
        ) === i,
    )
    .slice(0, 48);
  return {
    height: header.height,
    blockHash: header.hash,
    epochId: header.epoch_id,
    protocolVersion: protocol.protocol_version,
    shard,
    seeds,
  };
});
interface ReceiptContext {
  header: ChunkHeader;
  height: bigint;
  blockAt: ClockStamp;
  requestedAt: bigint;
  done: boolean;
}

/** Verify receipt membership against blocks received from this peer. */
export const observePeer = (
  peer: Peer,
  context: { accountId: string; shard: number; epochId: string },
  onBlock: (height: bigint, at: bigint) => Effect.Effect<void>,
  host: string,
) =>
  Stream.unwrap(
    Effect.gen(function* () {
      const clock = yield* Clock.Clock;
      const pending = yield* Cache.make({
        capacity: 1024,
        timeToLive: "1 minute",
        lookup: (_hash: string): Effect.Effect<ReceiptContext, NetworkError> =>
          Effect.fail(error("missing chunk")),
      });
      const handle = Effect.fn("Network.message")(function* (
        event: PeerEvent,
      ): Effect.fn.Return<ReceiptObservation[], NetworkError | PeerError> {
        if (event.type === "message") {
          if (event.message.type !== "block_response") return [];
          const bytes = event.message.payload.block.borsh;
          const block = yield* checked(() => decodeBlock(bytes)).pipe(
            Effect.trackDuration(metrics.decode),
          );
          if (bs58.encode(block.innerLite.epochId) !== context.epochId)
            return yield* Effect.fail(error("epoch changed; restart to refresh the shard layout"));
          yield* Metric.update(metrics.blocks, 1);
          yield* onBlock(block.height, event.receivedAt.monotonicNs);
          for (const header of block.chunks) {
            if (header.heightIncluded !== block.height) continue;
            const hash = bs58.encode(header.chunkHash);
            if (yield* Cache.has(pending, hash)) continue;
            yield* Cache.set(pending, hash, {
              header,
              height: block.height,
              blockAt: event.receivedAt,
              requestedAt: yield* clock.monotonicTimeNanos,
              done: false,
            });
            yield* peer.requestChunk(header.chunkHash, context.shard);
            yield* Metric.update(metrics.requests, 1);
          }
          return [];
        }
        if (!event.message.forUs || event.message.bodyType !== 12) return [];
        const response = yield* checked(() => {
          if (!event.message.signatureValid) throw new Error("invalid receipt response signature");
          return decodeChunkResponse(event.message.bodyBytes);
        });
        const entry = yield* Cache.getOption(pending, bs58.encode(response.chunkHash));
        if (Option.isNone(entry) || entry.value.done) return [];
        const saved = entry.value;
        const proofs = response.receipts.filter(
          (proof) => proof.toShardId === BigInt(context.shard),
        );
        if (proofs.length === 0) {
          yield* Metric.update(metrics.missing, 1);
          return [];
        }
        const proof = yield* checked(() => {
          if (
            proofs.length !== 1 ||
            !verifyReceiptProof(
              proofs[0],
              saved.header.receiptRoot,
              saved.header.shardId,
              BigInt(context.shard),
            )
          )
            throw new Error("receipt proof does not match the block");
          return proofs[0];
        }).pipe(Effect.trackDuration(metrics.verify));
        saved.done = true;
        const now = yield* clock.monotonicTimeNanos;
        yield* Metric.update(metrics.proofs, 1);
        yield* Metric.update(
          metrics.fetch,
          Duration.nanos(event.receivedAt.monotonicNs - saved.requestedAt),
        );
        yield* Metric.update(
          metrics.processing,
          Duration.nanos(now - event.receivedAt.monotonicNs),
        );
        const observedAt = new Date(yield* clock.currentTimeMillis).toISOString();
        return proof.receipts
          .filter((receipt) => receipt.receiverId === context.accountId)
          .map((receipt) => ({
            receipt,
            blockHeight: saved.height.toString(),
            peer: host,
            observedAt,
            blockToReceiptMs: Number(now - saved.blockAt.monotonicNs) / 1e6,
          }));
      });
      return peer.events.pipe(
        Stream.mapEffect(handle),
        Stream.flatMap(Stream.fromIterable),
        Stream.mapError(error),
      );
    }),
  );

/** One read-only subscription. Different peers may report the same receipt. */
export const observe = (options: Options): Stream.Stream<ReceiptObservation, NetworkError> =>
  Stream.callback<ReceiptObservation, NetworkError>(
    (queue) =>
      Effect.gen(function* () {
        const config = yield* Schema.decodeUnknownEffect(Options)(options).pipe(
          Effect.mapError(error),
        );
        const context = yield* bootstrap(config.rpcUrl, config.accountId).pipe(
          Effect.mapError(error),
        );
        const clock = yield* Clock.Clock;
        const states: { height: bigint; at: bigint; running: boolean }[] = [];
        let connecting = true;
        const health = Effect.gen(function* () {
          const now = yield* clock.monotonicTimeNanos;
          const fresh = states.filter(
            (state) => state.running && now - state.at < 20_000_000_000n,
          ).length;
          yield* Metric.update(metrics.active, fresh);
          if (fresh === 0 && !connecting)
            return yield* Effect.fail(error("no fresh peers; restart to discover new peers"));
        });
        let next = 0;
        const connect = Effect.fn("Network.connect")(function* () {
          while (next < context.seeds.length) {
            const endpoint = context.seeds[next++];
            const ready = yield* Deferred.make<void, NetworkError>();
            const state = { height: BigInt(context.height), at: 0n, running: false };
            states.push(state);
            const connection = Effect.gen(function* () {
              const peer = yield* openPeer({
                ...endpoint,
                genesisHash: GENESIS,
                protocolVersion: context.protocolVersion,
                height: context.height,
              });
              const consuming = yield* observePeer(
                peer,
                { ...context, accountId: config.accountId },
                (height, at) =>
                  Effect.gen(function* () {
                    if (height <= state.height) return;
                    state.height = height;
                    state.at = at;
                    state.running = true;
                    yield* Deferred.succeed(ready, undefined);
                  }),
                endpoint.host,
              ).pipe(
                Stream.runForEach((receipt) => Queue.offer(queue, receipt)),
                Effect.forkScoped,
              );
              yield* peer.requestBlock(context.blockHash);
              yield* Fiber.join(consuming);
              return yield* Effect.fail(error("peer stream ended"));
            }).pipe(
              Effect.scoped,
              Effect.onExit((exit) =>
                Effect.gen(function* () {
                  state.running = false;
                  yield* Deferred.fail(ready, error("peer stopped before a fresh block"));
                  if (
                    Exit.isFailure(exit) &&
                    (Cause.hasFails(exit.cause) || Cause.hasDies(exit.cause))
                  ) {
                    yield* Metric.update(metrics.failures, 1);
                    yield* Effect.logWarning(
                      `${endpoint.host}: ${Cause.pretty(exit.cause).split("\n")[0]}`,
                    );
                  }
                }),
              ),
            );
            const fiber = yield* connection.pipe(Effect.forkScoped);
            const result = yield* Deferred.await(ready).pipe(
              Effect.timeout("12 seconds"),
              Effect.result,
            );
            if (result._tag === "Success") return;
            yield* Fiber.interrupt(fiber);
          }
        });
        // The callback scope owns every connection; consumers drain while startup is still running.
        yield* Effect.all(
          [
            Effect.forEach(Array.from({ length: config.peers }), connect, {
              concurrency: config.peers,
            }).pipe(
              Effect.andThen(
                Effect.sync(() => {
                  connecting = false;
                }),
              ),
              Effect.andThen(health),
            ),
            health.pipe(Effect.repeat(Schedule.spaced("10 seconds"))),
          ],
          { concurrency: 2 },
        );
      }),
    { bufferSize: 1, strategy: "suspend" },
  );
