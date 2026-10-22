# mpc-wire

A read-only watcher for `sign` calls to NEAR's `v1.signer-prod.testnet` MPC contract. Connects to up to 12 peers and prints the request arguments without running a NEAR node.

This branch uses the unreleased `@zorsh/effect` package from [Zorsh main at `d2c6494`](https://github.com/r-near/zorsh/tree/d2c649405d79a6a0c9e3fe73ca8b68afb0d0bef0/packages/effect). Its built npm tarball is pinned in `vendor/`, so `vp install` works without a separate Zorsh checkout. The package still reports version `0.0.0`; this is not the published 0.1.0 release.

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

Captured on October 22, 2026 UTC with `PEERS=12 DURATION_SECONDS=45 vp run watch` and Zorsh main at `d2c6494`. All 12 peers became active. The run observed three distinct sign requests and checked 2,309 receipt proofs; five candidates failed connection or handshake checks. This excerpt shows the first request and final selected metrics. Histogram buckets and counter flags are omitted.

```text
connecting to up to 12 testnet peers; watching v1.signer-prod.testnet
{
  "event": "sign-request",
  "receiptId": "9yFdVoGK4pVwYiD9LSFkxECdzqA7GMR8pG8ayZpUgeMp",
  "actionIndex": 0,
  "caller": "tx-bench.testnet",
  "args": {
    "request": {
      "domain_id": 1,
      "path": "",
      "payload_v2": {
        "Eddsa": "92088bdfcafe7c41071a1e99616dcc22a77c3b2c23f4d9be1f8b3635b36f7115"
      }
    }
  },
  "blockHeight": "274284240",
  "peer": "34.34.24.155",
  "observedAt": "2026-10-22T18:19:26.934Z",
  "blockToRequestMs": 178.877584
}
{
  "event": "metrics",
  "at": "2026-10-22T18:20:02.889Z",
  "metrics": [
    {"name":"fresh_peers","type":"Gauge","value":12},
    {"name":"peer_failures","type":"Counter","count":5},
    {"name":"receipt_proofs","type":"Counter","count":2309},
    {"name":"receipt_fetch_ms","type":"Histogram","count":2309,"min":19.3625,"max":914.695125,"sum":426903.13083199994},
    {"name":"response_processing_ms","type":"Histogram","count":2309,"min":0.098084,"max":7.081625,"sum":2518.8185869999984},
    {"name":"missing_proofs","type":"Counter","count":5151},
    {"name":"sign_requests","type":"Counter","count":3},
    {"name":"block_to_request_ms","type":"Histogram","count":3,"min":172.767542,"max":196.86,"sum":548.505126}
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

Uses Effect 4 and near-kit for bootstrap. `protobufjs` reads the pinned [nearcore](https://github.com/near/nearcore/tree/44f7ae6cd7ef08bab604e20a473bf77e35d4c993) schema in `vendor/`. Zorsh decodes the Borsh schemas with `maxBytes` and `maxItems`; explicit `Borsh.maxLength` checks reject oversized strings and unwanted vectors at their length prefixes. Ordinary Effect length checks run after decoding. `withBytes` retains the received receipt, header and body bytes for proof hashes, while prefix decoding separates routing headers from their bodies. There is no custom Borsh cursor or schema walker.

The trial tarball was built from unmodified commit `d2c649405d79a6a0c9e3fe73ca8b68afb0d0bef0` with `vp -C packages/effect pack` and `vp -C packages/effect pm pack`, using the existing frozen-lockfile install. It includes the upstream MIT license. Its SHA-256 is `53f662b012b1a4100cf1a5cb791df3a1338691e851547290d6156f4c2478de61`.

`WireString` is `Schema.String.check(Borsh.maxLength(1_048_576))`. Zorsh checks its byte limit before UTF-8 decoding, preserves leading BOMs and rejects lone UTF-16 surrogates on encode. The layouts are fixed and nonrecursive. Tests build captured fields from typed values and their schema encoding, so `withBytes` also checks that those values and bytes agree.
