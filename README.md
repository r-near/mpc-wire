# mpc-wire

A read-only watcher for `sign` calls to NEAR's `v1.signer-prod.testnet` MPC contract. Connects to up to 12 peers and prints the request arguments without running a NEAR node.

This branch uses the unreleased `@zorsh/effect` package from [Zorsh main at `c8be68c`](https://github.com/r-near/zorsh/tree/c8be68c8f0fb2b3ef24a19029705bd0cb66e47ac/packages/effect). Its built npm tarball is pinned in `vendor/`, so `vp install` works without a separate Zorsh checkout. The package still reports version `0.0.0`; this is not the published 0.1.0 release.

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

Captured on October 22, 2026 UTC with `PEERS=12 DURATION_SECONDS=45 vp run watch` and Zorsh main at `c8be68c`. All 12 peers became active. The run observed four distinct sign requests and checked 3,266 receipt proofs. Seven candidates failed connection or handshake checks, and one was rejected for an epoch mismatch. This excerpt shows the first request and final selected metrics. Histogram buckets and counter flags are omitted.

```text
connecting to up to 12 testnet peers; watching v1.signer-prod.testnet
{
  "event": "sign-request",
  "receiptId": "GKLTBxnWr6utToTriDxqVGcYfDNLTsTRunwCfC8LJAFF",
  "actionIndex": 0,
  "caller": "tx-bench.testnet",
  "args": {
    "request": {
      "domain_id": 0,
      "path": "",
      "payload_v2": {
        "Ecdsa": "1f626618b7d5b8e732959c553d3eebc0ff5176fb55ed26498a37bf72dda1299f"
      }
    }
  },
  "blockHeight": "274294853",
  "peer": "142.132.203.80",
  "observedAt": "2026-10-22T20:00:05.280Z",
  "blockToRequestMs": 184.361958
}
{
  "event": "metrics",
  "at": "2026-10-22T20:00:41.238Z",
  "metrics": [
    {"name":"fresh_peers","type":"Gauge","value":12},
    {"name":"peer_failures","type":"Counter","count":8},
    {"name":"receipt_proofs","type":"Counter","count":3266},
    {"name":"receipt_fetch_ms","type":"Histogram","count":3266,"min":44.011584,"max":2559.101917,"sum":739315.9621669969},
    {"name":"response_processing_ms","type":"Histogram","count":3266,"min":0.092208,"max":8.535333,"sum":3897.6738010000026},
    {"name":"missing_proofs","type":"Counter","count":5235},
    {"name":"sign_requests","type":"Counter","count":4},
    {"name":"block_to_request_ms","type":"Histogram","count":4,"min":182.83375,"max":186.128,"sum":736.5379579999999}
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

The trial tarball was built from unmodified commit `c8be68c8f0fb2b3ef24a19029705bd0cb66e47ac` with `vp -C packages/effect pack` and `vp -C packages/effect pm pack`, using the existing frozen-lockfile install. It includes the upstream MIT license. Its SHA-256 is `74b0388eab2ce1149aa9fbec815c92670f316cd14f620800976b3d904afffd9e`.

`WireString` is `Schema.String.check(Borsh.maxLength(1_048_576))`. Zorsh checks its byte limit before UTF-8 decoding, preserves leading BOMs and rejects lone UTF-16 surrogates on encode. The layouts are fixed and nonrecursive. Tests build captured fields from typed values and their schema encoding, so `withBytes` also checks that those values and bytes agree.
