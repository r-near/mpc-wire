import { Clock, Config, Console, Effect, Logger, Metric, Schedule, Schema, Stream } from "effect";
import { observe } from "./network.ts";
import { CONTRACT, signRequests } from "./mpc.ts";
import { Uint } from "./schemas.ts";

const main = Effect.gen(function* () {
  const peers = yield* Config.schema(
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
  const report = Effect.gen(function* () {
    const snapshot = yield* Metric.snapshot;
    yield* Console.error(
      JSON.stringify({
        event: "metrics",
        at: new Date(yield* Clock.currentTimeMillis).toISOString(),
        metrics: snapshot.map(({ id, type, state }) => ({ name: id, type, ...state })),
      }),
    );
  });
  yield* Effect.addFinalizer(() => report);
  yield* report.pipe(Effect.repeat(Schedule.spaced("10 seconds")), Effect.forkScoped);
  yield* Console.error(`connecting to up to ${peers} testnet peers; watching ${CONTRACT}`);
  yield* observe({ accountId: CONTRACT, rpcUrl, peers }).pipe(
    signRequests,
    Stream.runForEach((request) =>
      Console.log(JSON.stringify({ event: "sign-request", ...request })),
    ),
    Effect.timeoutOption(`${seconds} seconds`),
  );
}).pipe(Effect.scoped, Effect.provideService(Logger.LogToStderr, true));

if (import.meta.main)
  await Effect.runPromise(main).catch((cause) => {
    console.error(String(cause));
    process.exitCode = 1;
  });
