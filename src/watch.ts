import { isIP } from "node:net";
import bs58 from "bs58";
import { Near } from "near-kit";
import {
  Cache,
  Cause,
  Clock,
  Config,
  Console,
  Deferred,
  Duration,
  Effect,
  Exit,
  Fiber,
  Logger,
  Metric,
  Option,
  Ref,
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
import { openPeer, type Peer, type PeerEvent, type ClockStamp } from "./peer.ts";

export const CONTRACT = "v1.signer-prod.testnet";
const GENESIS = "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b";
class WatchError extends Schema.TaggedError<WatchError>()("WatchError", {
  message: Schema.String,
}) {}
const error = (cause: unknown) => new WatchError({ message: String(cause) });
const checked = <A>(run: () => A) => Effect.try({ try: run, catch: error });
const counter = (name: string) => Metric.counter(name);
const timer = (name: string) =>
  Metric.timer(name, { boundaries: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500] });
export const metrics = {
  blocks: counter("blocks"),
  requests: counter("receipt_requests"),
  proofs: counter("receipt_proofs"),
  missing: counter("missing_proofs"),
  calls: counter("sign_requests"),
  failures: counter("peer_failures"),
  active: Metric.gauge("fresh_peers"),
  decode: timer("block_decode_ms"),
  verify: timer("receipt_verify_ms"),
  fetch: timer("receipt_fetch_ms"),
  processing: timer("response_processing_ms"),
  delivery: timer("block_to_request_ms"),
};
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
const Uint = Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }));
const Block = Schema.Struct({
  header: Schema.Struct({ hash: Schema.String, height: Uint, epoch_id: Schema.String }),
});
const Protocol = Schema.Struct({
  protocol_version: Uint,
  shard_layout: Schema.Struct({
    V3: Schema.Struct({
      boundary_accounts: Schema.Array(Schema.String),
      shard_ids: Schema.Array(Uint),
    }),
  }),
});
const Network = Schema.Struct({
  active_peers: Schema.Array(Schema.Struct({ id: Schema.String, addr: Schema.String })),
});
const SignArgsBytes = Schema.Uint8Array.check(
  Schema.isMaxLength(16 * 1024, { expected: "sign arguments at most 16 KiB" }),
);
const decodeArgsJson = Schema.decodeEffect(Schema.fromJsonString(Schema.Unknown));
const utf8 = new TextDecoder("utf-8", { fatal: true });
const bootstrap = Effect.fn("Watch.bootstrap")(function* (rpcUrl: string) {
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
  yield* read("status", {}).pipe(
    Effect.flatMap(
      Schema.decodeUnknownEffect(
        Schema.Struct({
          chain_id: Schema.Literal("testnet"),
          genesis_hash: Schema.Literal(GENESIS),
        }),
      ),
    ),
  );
  const { header } = yield* read("block", { finality: "final" }).pipe(
    Effect.flatMap(Schema.decodeUnknownEffect(Block)),
  );
  const [protocol, network] = yield* Effect.all(
    [
      read("EXPERIMENTAL_protocol_config", { block_id: header.hash }).pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(Protocol)),
      ),
      read("network_info", {}).pipe(Effect.flatMap(Schema.decodeUnknownEffect(Network))),
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
  const shard = shards[boundaries.filter((boundary) => CONTRACT >= boundary).length];
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
export interface ReceiptContext {
  header: ChunkHeader;
  height: bigint;
  blockAt: ClockStamp;
  requestedAt: bigint;
  done: boolean;
}
export interface Request {
  receiptId: string;
  actionIndex: number;
  caller: string;
  args: unknown;
  blockHeight: string;
  peer: string;
  observedAt: string;
  blockToRequestMs: number;
}

/** One consumer per peer; proof checks precede printing and metrics use monotonic time. */
export const consume = Effect.fn("Watch.consume")(function* (
  peer: Peer,
  context: { shard: number; epochId: string },
  onBlock: (height: bigint, at: bigint) => Effect.Effect<void>,
  onRequest: (request: Request) => Effect.Effect<void>,
  host: string,
) {
  const clock = yield* Clock.Clock;
  const pending = yield* Cache.make({
    capacity: 1024,
    timeToLive: "1 minute",
    lookup: (_hash: string): Effect.Effect<ReceiptContext, WatchError> =>
      Effect.fail(error("missing chunk")),
  });
  const handle = Effect.fn("Watch.message")(function* (event: PeerEvent) {
    if (event.type === "message") {
      if (event.message.type !== "block_response") return;
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
      return;
    }
    if (!event.message.forUs || event.message.bodyType !== 12) return;
    const response = yield* checked(() => {
      if (!event.message.signatureValid) throw new Error("invalid receipt response signature");
      return decodeChunkResponse(event.message.bodyBytes);
    });
    const entry = yield* Cache.getOption(pending, bs58.encode(response.chunkHash));
    if (Option.isNone(entry) || entry.value.done) return;
    const saved = entry.value;
    const proofs = response.receipts.filter((proof) => proof.toShardId === BigInt(context.shard));
    if (proofs.length === 0) {
      yield* Metric.update(metrics.missing, 1);
      return;
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
    yield* Metric.update(metrics.processing, Duration.nanos(now - event.receivedAt.monotonicNs));
    for (const receipt of proof.receipts) {
      if (receipt.receiverId !== CONTRACT) continue;
      const body = receipt.receipt;
      const actions =
        "Action" in body ? body.Action.actions : "ActionV2" in body ? body.ActionV2.actions : [];
      for (const [actionIndex, action] of actions.entries()) {
        if (!("FunctionCall" in action) || action.FunctionCall.methodName !== "sign") continue;
        const args = yield* Schema.decodeEffect(SignArgsBytes)(action.FunctionCall.args).pipe(
          Effect.flatMap((bytes) => checked(() => utf8.decode(bytes))),
          Effect.flatMap(decodeArgsJson),
        );
        yield* onRequest({
          receiptId: bs58.encode(receipt.receiptId),
          actionIndex,
          caller: receipt.predecessorId,
          args,
          blockHeight: saved.height.toString(),
          peer: host,
          observedAt: new Date(yield* clock.currentTimeMillis).toISOString(),
          blockToRequestMs: Number(now - saved.blockAt.monotonicNs) / 1e6,
        });
      }
    }
  });
  yield* peer.events.pipe(Stream.runForEach(handle));
});

const main = Effect.gen(function* () {
  const count = yield* Config.schema(
    Uint.check(Schema.isBetween({ minimum: 1, maximum: 12 })),
    "PEERS",
  ).pipe(Config.withDefault(12));
  const seconds = yield* Config.schema(
    Uint.check(Schema.isBetween({ minimum: 1, maximum: 3600 })),
    "DURATION_SECONDS",
  ).pipe(Config.withDefault(60));
  const rpcUrl = yield* Config.String("RPC_URL").pipe(
    Config.withDefault("https://test.rpc.fastnear.com"),
  );
  const context = yield* bootstrap(rpcUrl);
  const clock = yield* Clock.Clock;
  const seen = yield* Cache.make({
    capacity: 4096,
    timeToLive: "10 minutes",
    lookup: (_id: string) => Ref.make(false),
  });
  const states: { height: bigint; at: bigint; running: boolean }[] = [];
  const report = Effect.gen(function* () {
    const now = yield* clock.monotonicTimeNanos;
    const fresh = states.filter(
      (state) => state.running && now - state.at < 20_000_000_000n,
    ).length;
    yield* Metric.update(metrics.active, fresh);
    const snapshot = yield* Metric.snapshot;
    yield* Console.error(
      JSON.stringify({
        event: "metrics",
        at: new Date().toISOString(),
        metrics: snapshot.map(({ id, type, state }) => ({ name: id, type, ...state })),
      }),
    );
    return fresh;
  });
  yield* Effect.addFinalizer(() => report);
  let next = 0;
  const connect = Effect.fn("Watch.connect")(function* () {
    while (next < context.seeds.length) {
      const endpoint = context.seeds[next++];
      const ready = yield* Deferred.make<void, WatchError>();
      const state = { height: BigInt(context.height), at: 0n, running: false };
      states.push(state);
      const connection = Effect.gen(function* () {
        const peer = yield* openPeer({
          ...endpoint,
          genesisHash: GENESIS,
          protocolVersion: context.protocolVersion,
          height: context.height,
        });
        const consuming = yield* consume(
          peer,
          context,
          (height, at) =>
            Effect.gen(function* () {
              if (height <= state.height) return;
              state.height = height;
              state.at = at;
              state.running = true;
              yield* Deferred.succeed(ready, undefined);
            }),
          (request) =>
            Effect.gen(function* () {
              if (
                yield* Ref.getAndSet(
                  yield* Cache.get(seen, `${request.receiptId}:${request.actionIndex}`),
                  true,
                )
              )
                return;
              yield* Metric.update(metrics.calls, 1);
              yield* Metric.update(metrics.delivery, Duration.millis(request.blockToRequestMs));
              yield* Console.log(JSON.stringify({ event: "sign-request", ...request }));
            }),
          endpoint.host,
        ).pipe(Effect.forkScoped);
        yield* peer.requestBlock(context.blockHash);
        yield* Fiber.join(consuming);
        return yield* Effect.fail(error("peer stream ended"));
      }).pipe(
        Effect.scoped,
        Effect.onExit((exit) =>
          Effect.gen(function* () {
            state.running = false;
            yield* Deferred.fail(ready, error("peer stopped before a fresh block"));
            if (Exit.isFailure(exit) && (Cause.hasFails(exit.cause) || Cause.hasDies(exit.cause))) {
              yield* Metric.update(metrics.failures, 1);
              yield* Console.error(`${endpoint.host}: ${Cause.pretty(exit.cause).split("\n")[0]}`);
            }
          }),
        ),
      );
      const fiber = yield* connection.pipe(Effect.forkScoped);
      const result = yield* Deferred.await(ready).pipe(Effect.timeout("12 seconds"), Effect.result);
      if (result._tag === "Success") return;
      yield* Fiber.interrupt(fiber);
    }
  });
  yield* Console.error(`connecting to up to ${count} testnet peers; watching ${CONTRACT}`);
  yield* Effect.forEach(Array.from({ length: count }), connect, { concurrency: count });
  if ((yield* report) === 0) return yield* Effect.fail(error("no fresh peers"));
  yield* report.pipe(
    Effect.flatMap((fresh) =>
      fresh === 0 ? Effect.fail(error("all peers stopped or went stale")) : Effect.void,
    ),
    Effect.repeat(Schedule.spaced("10 seconds")),
    Effect.timeoutOption(`${seconds} seconds`),
  );
}).pipe(Effect.scoped, Effect.provideService(Logger.LogToStderr, true));

if (import.meta.main)
  await Effect.runPromise(main).catch((cause) => {
    console.error(String(cause));
    process.exitCode = 1;
  });
