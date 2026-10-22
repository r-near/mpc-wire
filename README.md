# mpc-wire

A read-only watcher for `sign` calls to NEAR's `v1.signer-prod.testnet` MPC contract. Connects to up to 12 peers and prints the request arguments without running a NEAR node.

This branch uses the unreleased `@zorsh/effect` package from [Zorsh main at `541e03f`](https://github.com/r-near/zorsh/tree/541e03f91bc51d9de59606e1fa60ecd8ebdf40e8/packages/effect). Its built npm tarball is pinned in `vendor/`, so `vp install` works without a separate Zorsh checkout. The package still reports version `0.0.0`; this is not the published 0.1.0 release.

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

Captured on October 22, 2026 UTC with `PEERS=12 DURATION_SECONDS=45 vp run watch` and Zorsh main at `541e03f`. All 12 peers became active. The run observed two distinct sign requests and checked 2,105 receipt proofs; four candidates failed connection or handshake checks. This excerpt shows the first request and final selected metrics. Histogram buckets and counter flags are omitted.

```text
connecting to up to 12 testnet peers; watching v1.signer-prod.testnet
{
  "event": "sign-request",
  "receiptId": "2L6Vx4UrcyWJSBJ9B2d1SNW76xdwwNgp2nh7XjX9RRkV",
  "actionIndex": 0,
  "caller": "tx-bench.testnet",
  "args": {
    "request": {
      "domain_id": 1,
      "path": "",
      "payload_v2": {
        "Eddsa": "ccf1efa2f508e0fb443e05376ee1ca21006ab3557975142a9da02506dd50644c"
      }
    }
  },
  "blockHeight": "274269922",
  "peer": "34.34.24.155",
  "observedAt": "2026-10-22T16:03:27.487Z",
  "blockToRequestMs": 172.266875
}
{
  "event": "metrics",
  "at": "2026-10-22T16:03:54.108Z",
  "metrics": [
    {"name": "fresh_peers","type": "Gauge","value": 12},
    {"name": "peer_failures","type": "Counter","count": 4},
    {"name": "receipt_proofs","type": "Counter","count": 2105},
    {"name": "receipt_fetch_ms","type": "Histogram","count": 2105,"min": 19.909042,"max": 557.037542,"sum": 374829.44544499967},
    {"name": "response_processing_ms","type": "Histogram","count": 2105,"min": 0.080458,"max": 3.445458,"sum": 611.6430219999988},
    {"name": "missing_proofs","type": "Counter","count": 5355},
    {"name": "sign_requests","type": "Counter","count": 2},
    {"name": "block_to_request_ms","type": "Histogram","count": 2,"min": 172.266875,"max": 179.49725,"sum": 351.76412500000004}
  ]
}
```

## What it sees

Read-only RPC supplies the initial testnet identity, shard layout, and peer addresses. Set `RPC_URL` to change the bootstrap endpoint. After setup, incoming P2P blocks trigger receipt-proof requests; there is no RPC polling.

Receipt membership is checked against the received block's commitments. This client does not validate consensus or execute the contract. A request can still fail execution. It does not obtain continuation IDs or completed signatures.

This is a bounded experiment: no backfill, reconnect loop, or completeness guarantee. Missing proofs and dropped peers remain visible in the metrics. An epoch change stops that peer's observer; restart to refresh the shard layout. Twelve connections can include peers operated by the same provider. Slow consumers apply backpressure; a peer disconnects if its bounded incoming queue fills. Invalid sign arguments are skipped with a warning and an `invalid_sign_requests` counter, without disconnecting the peer.

Each Borsh message is limited to 16 MiB and 16,384 collection items in total, including nested collections. Strings are limited to 1 MiB of UTF-8 bytes. These are watcher limits, not NEAR protocol limits. Receipt-only requests reject responses containing unsolicited chunk parts.

## Develop

```sh
vp check
vp test run
vp fmt
```

The code has six modules in `src/`:

- `schemas.ts`: native Effect schemas, with Zorsh annotations for Borsh widths and layouts.
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

Synthetic fixtures use the same native Effect schemas as the decoder. Seeded `Arbitrary.schema` tests generate sign actions, hashes and fixed-length signature arrays, then round-trip their wire encoding. The fixture builders compute the dependent receipt, chunk and block hashes. The two captured files in `fixtures/` stay fixed: their hashes and exact round trips catch compatibility mistakes that a generated fixture could share with the decoder. Add captures when supporting new wire versions; do not regenerate the historical ones.

Uses Effect 4 and near-kit for bootstrap. `protobufjs` reads the pinned [nearcore](https://github.com/near/nearcore/tree/44f7ae6cd7ef08bab604e20a473bf77e35d4c993) schema in `vendor/`. Zorsh decodes the Borsh schemas with `maxBytes` and `maxItems`; native length checks reject unwanted data before allocation. `withBytes` retains the received receipt, header and body bytes for proof hashes, while prefix decoding separates routing headers from their bodies. There is no custom Borsh cursor or schema walker.

The trial tarball was built from unmodified commit `541e03f91bc51d9de59606e1fa60ecd8ebdf40e8` with `vp -C packages/effect pack` and `vp -C packages/effect pm pack`, using the existing frozen-lockfile install. It includes the upstream MIT license. Its SHA-256 is `006c399217e874807f5dec7667611935edea86dd6e8c6bd5eab9a5d605282e8e`.

`WireString` is an Effect transformation from bounded bytes to strict UTF-8. This keeps the byte limit ahead of string decoding, preserves leading BOMs and rejects lone UTF-16 surrogates on encode. The layouts are fixed and nonrecursive; the shared item budget replaces the old parser's structural-work counter. Tests build captured fields from typed values and their schema encoding, so `withBytes` also checks that those values and bytes agree.
