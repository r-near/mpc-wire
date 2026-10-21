# mpc-wire

A read-only watcher for `sign` calls to NEAR's `v1.signer-prod.testnet` MPC contract. Connects to up to 12 peers and prints the request arguments without running a NEAR node.

## Run

Install [Vite+](https://viteplus.dev/guide), then:

```sh
vp install
vp run watch
```

No account, key, or testnet funds needed. By default it runs for 60 seconds, including setup.

```sh
PEERS=4 DURATION_SECONDS=300 vp run watch
```

Request lines are JSON, including receipt ID, action index, caller, arguments, block height, peer, and observation time. Effect metrics go to stderr every 10 seconds and at shutdown: fresh peers, traffic, verified and missing proofs, failures, request count, and timing histograms.

`receipt_fetch_ms` measures request-to-response time. `response_processing_ms` includes local queuing, decoding, and proof verification. `block_to_request_ms` runs from block arrival through receipt verification, before the consumer processes the arguments. `observedAt` is the local wall-clock time when verification finishes. These are local monotonic durations; they do not measure submission latency or compare clocks with another node.

## Sample run

Captured on October 21, 2026 UTC with `PEERS=12 DURATION_SECONDS=45 vp run watch`. All 12 peers became active. The run observed four distinct sign requests and checked 2,886 receipt proofs; six candidate connections failed. This excerpt shows the first request and the final metrics, expanded for readability with selected metrics; histogram buckets and counter flags are omitted.

```text
connecting to up to 12 testnet peers; watching v1.signer-prod.testnet
{
  "event": "sign-request",
  "receiptId": "5BnhosB1oiPxaybKToDtm3yaa3B6i3ur2r4vKssrAij1",
  "actionIndex": 0,
  "caller": "tx-bench.testnet",
  "args": {
    "request": {
      "domain_id": 0,
      "path": "",
      "payload_v2": {
        "Ecdsa": "a49bdd2ff1b9309859f4bf5a614e70a6ae2670fad6061f3632851ac59a3b1415"
      }
    }
  },
  "blockHeight": "274136991",
  "peer": "142.132.203.80",
  "observedAt": "2026-10-21T19:02:27.594Z",
  "blockToRequestMs": 181.5625
}
{
  "event": "metrics",
  "at": "2026-10-21T19:03:09.078Z",
  "metrics": [
    {"name": "fresh_peers","type": "Gauge","value": 12},
    {"name": "peer_failures","type": "Counter","count": 6},
    {"name": "missing_proofs","type": "Counter","count": 4874},
    {"name": "receipt_proofs","type": "Counter","count": 2886},
    {"name": "receipt_fetch_ms","type": "Histogram","count": 2886,"min": 40.162416,"max": 228.539459,"sum": 517539.60204300063},
    {"name": "response_processing_ms","type": "Histogram","count": 2886,"min": 0.076959,"max": 1.661083,"sum": 731.7642309999992},
    {"name": "sign_requests","type": "Counter","count": 4},
    {"name": "block_to_request_ms","type": "Histogram","count": 4,"min": 177.535584,"max": 182.70325,"sum": 722.672501}
  ]
}
```

## What it sees

Read-only RPC supplies the initial testnet identity, shard layout, and peer addresses. Set `RPC_URL` to change the bootstrap endpoint. After setup, incoming P2P blocks trigger receipt-proof requests; there is no RPC polling.

Receipt membership is checked against the received block's commitments. This client does not validate consensus or execute the contract. A request can still fail execution. It does not obtain continuation IDs or completed signatures.

This is a bounded experiment: no backfill, reconnect loop, or completeness guarantee. Missing proofs and dropped peers remain visible in the metrics. An epoch change stops that peer's observer; restart to refresh the shard layout. Twelve connections can include peers operated by the same provider. Slow consumers apply backpressure; a peer disconnects if its bounded incoming queue fills. Invalid sign arguments are skipped with a warning and an `invalid_sign_requests` counter, without disconnecting the peer.

## Develop

```sh
vp check
vp test run
vp fmt
```

The code has six modules in `src/`:

- `schemas.ts`: Zorsh layouts, inferred types and Effect schemas for RPC and peer messages.
- `protocol.ts`: bounded codecs, framing, signatures and receipt commitment checks.
- `peer.ts`: one authenticated TCP peer and its scoped socket lifetime.
- `network.ts`: bootstrap, peer connections and an Effect stream of receipts for an account.
- `mpc.ts`: `sign` arguments, per-action deduplication and MPC metrics.
- `watch.ts`: CLI configuration and output.

To watch another account, consume the network stream directly:

```ts
import { Console, Effect, Stream } from "effect";
import { observe } from "./src/network.ts";

await Effect.runPromise(
  observe({
    accountId: "example.testnet",
    rpcUrl: "https://test.rpc.fastnear.com",
    peers: 4,
  }).pipe(
    Stream.runForEach(({ receipt }) => Console.log(receipt)),
    Effect.timeoutOption("60 seconds"),
  ),
);
```

Each observation includes the raw decoded receipt, block height, source peer and local timing. Peers may report the same receipt. The MPC consumer deduplicates by receipt ID and action index for up to ten minutes, retaining at most 4,096 entries per subscription. The network layer does not interpret function arguments.

Synthetic fixtures are typed values serialized with the same Zorsh schemas used by the decoder. Their builders compute the dependent receipt, chunk and block hashes. The two captured files in `fixtures/` stay fixed: their hashes and exact round trips catch compatibility mistakes that a generated fixture could share with the decoder. Add captures when supporting new wire versions; do not regenerate the historical ones.

Uses Effect 4, published Zorsh 0.5.2 and near-kit for bootstrap. The pinned [nearcore](https://github.com/near/nearcore/tree/44f7ae6cd7ef08bab604e20a473bf77e35d4c993) protobuf schema is in `vendor/` with its MIT license. Zorsh handles Borsh; the cursor adds resource limits, records original byte spans for proof hashes and rejects trailing bytes. Use the bounded protocol decoders for network input. Zorsh's native [`@zorsh/effect`](https://github.com/r-near/zorsh/tree/main/packages/effect) integration is still unpublished as of October 21, 2026.

[`protobuf-effect`](https://github.com/erikshestopal/effect-protobuf) 1.1.0 supports Effect 4 and generates schemas from `.proto` files using protobuf-es. A local spike matched five NEAR message encodings byte for byte, including full-width integers and unknown fields. We keep `protobufjs` here because migration would add roughly 1,700 generated lines and a generation step. It remains an option for a browser client, where avoiding runtime schema parsing and filesystem access is useful.
