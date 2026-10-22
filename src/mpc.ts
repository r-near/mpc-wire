import bs58 from "bs58";
import { Cache, Duration, Effect, Metric, Option, Schema, Stream } from "effect";
import type { ReceiptObservation } from "./network.ts";

export const CONTRACT = "v1.signer-prod.testnet";
export const metrics = {
  calls: Metric.counter("sign_requests"),
  invalid: Metric.counter("invalid_sign_requests"),
  delivery: Metric.timer("block_to_request_ms", {
    boundaries: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500],
  }),
};
const SignArgsBytes = Schema.Uint8Array.check(
  Schema.isMaxLength(16 * 1024, { expected: "sign arguments at most 16 KiB" }),
);
const decodeJson = Schema.decodeEffect(Schema.fromJsonString(Schema.Unknown));
const utf8 = new TextDecoder("utf-8", { fatal: true });
export class SignArgsError extends Schema.TaggedError<SignArgsError>()("SignArgsError", {
  message: Schema.String,
}) {}
export const decodeArgs = Effect.fn("Mpc.decodeArgs")(function* (bytes: Uint8Array) {
  const bounded = yield* Schema.decodeEffect(SignArgsBytes)(bytes);
  const text = yield* Effect.try({
    try: () => utf8.decode(bounded),
    catch: (cause) => new SignArgsError({ message: String(cause) }),
  });
  return yield* decodeJson(text);
});

export interface SignRequest {
  receiptId: string;
  actionIndex: number;
  caller: string;
  args: unknown;
  blockHeight: string;
  peer: string;
  observedAt: string;
  blockToRequestMs: number;
}

/** Deduplicate sign actions across peers for this subscription, with bounded retention. */
export const signRequests = <E, R>(
  receipts: Stream.Stream<ReceiptObservation, E, R>,
  contractId = CONTRACT,
) =>
  Stream.unwrap(
    Effect.gen(function* () {
      const seen = yield* Cache.make({
        capacity: 4096,
        timeToLive: "10 minutes",
        lookup: (_id: string) => Effect.succeed(true),
      });
      const extract = Effect.fn("Mpc.signRequests")(function* ({
        receipt,
        ...observation
      }: ReceiptObservation) {
        if (receipt.receiverId !== contractId) return [];
        const body = receipt.receipt;
        const actions = body._tag === "Action" || body._tag === "ActionV2" ? body.actions : [];
        const requests: SignRequest[] = [];
        for (const [actionIndex, action] of actions.entries()) {
          if (action._tag !== "FunctionCall" || action.methodName !== "sign") continue;
          const receiptId = bs58.encode(receipt.receiptId);
          const key = `${receiptId}:${actionIndex}`;
          if (yield* Cache.has(seen, key)) continue;
          yield* Cache.set(seen, key, true);
          const decoded = yield* decodeArgs(action.args).pipe(
            Effect.map(Option.some),
            Effect.catch((cause) =>
              Effect.gen(function* () {
                yield* Metric.update(metrics.invalid, 1);
                yield* Effect.logWarning("invalid sign arguments", cause).pipe(
                  Effect.annotateLogs({ receiptId, actionIndex }),
                );
                return Option.none();
              }),
            ),
          );
          if (Option.isNone(decoded)) continue;
          const request = {
            receiptId,
            actionIndex,
            caller: receipt.predecessorId,
            args: decoded.value,
            blockHeight: observation.blockHeight,
            peer: observation.peer,
            observedAt: observation.observedAt,
            blockToRequestMs: observation.blockToReceiptMs,
          };
          requests.push(request);
          yield* Metric.update(metrics.calls, 1);
          yield* Metric.update(metrics.delivery, Duration.millis(request.blockToRequestMs));
        }
        return requests;
      });
      return receipts.pipe(Stream.mapEffect(extract), Stream.flatMap(Stream.fromIterable));
    }),
  );
