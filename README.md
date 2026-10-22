# mpc-wire

A read-only watcher for `sign` calls to NEAR's `v1.signer-prod.testnet` MPC contract. Connects to up to 12 peers and prints the request arguments without running a NEAR node.

This branch trials the unreleased `@zorsh/effect` package from [Zorsh main at `ec3938f`](https://github.com/r-near/zorsh/tree/ec3938feb4eaa16f009026d4a8b1cf6626ee56f0/packages/effect). Its built npm tarball is pinned in `vendor/`, so `vp install` works without a separate Zorsh checkout. The package still reports version `0.0.0`; this is not the published 0.1.0 release.

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

Captured on October 22, 2026 UTC with `PEERS=12 DURATION_SECONDS=45 vp run watch` and the Zorsh Effect trial build. All 12 peers became active. The run observed two distinct sign requests and checked 3,093 receipt proofs; eleven candidates failed connection, handshake or epoch checks. This excerpt shows the first request and final selected metrics. Histogram buckets and counter flags are omitted.

```text
connecting to up to 12 testnet peers; watching v1.signer-prod.testnet
{
  "event": "sign-request",
  "receiptId": "7oQHnDgV12rDTLHB6Yejz8TZoUoWP2as761tfV4YKuSa",
  "actionIndex": 0,
  "caller": "tx-bench.testnet",
  "args": {
    "request": {
      "domain_id": 0,
      "path": "",
      "payload_v2": {
        "Ecdsa": "6803262d7828f32d50c5ea737fd64baed20c2e0dc094b65a01e2f83f12cabd98"
      }
    }
  },
  "blockHeight": "274199451",
  "peer": "185.44.207.120",
  "observedAt": "2026-10-22T04:55:57.877Z",
  "blockToRequestMs": 177.193292
}
{
  "event": "metrics",
  "at": "2026-10-22T04:56:25.693Z",
  "metrics": [
    {"name": "fresh_peers","type": "Gauge","value": 12},
    {"name": "peer_failures","type": "Counter","count": 11},
    {"name": "receipt_proofs","type": "Counter","count": 3093},
    {"name": "receipt_fetch_ms","type": "Histogram","count": 3093,"min": 38.108291,"max": 753.670583,"sum": 584329.9487999995},
    {"name": "response_processing_ms","type": "Histogram","count": 3093,"min": 0.08625,"max": 4.39625,"sum": 1168.8955550000019},
    {"name": "missing_proofs","type": "Counter","count": 4237},
    {"name": "sign_requests","type": "Counter","count": 2},
    {"name": "block_to_request_ms","type": "Histogram","count": 2,"min": 177.193292,"max": 184.527292,"sum": 361.72058400000003}
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

Synthetic fixtures use the same native Effect schemas as the decoder. A seeded `Arbitrary.schema` test also generates sign actions and round-trips their wire encoding. Their builders compute the dependent receipt, chunk and block hashes. The two captured files in `fixtures/` stay fixed: their hashes and exact round trips catch compatibility mistakes that a generated fixture could share with the decoder. Add captures when supporting new wire versions; do not regenerate the historical ones.

Uses Effect 4 and near-kit for bootstrap. `protobufjs` reads the pinned [nearcore](https://github.com/near/nearcore/tree/44f7ae6cd7ef08bab604e20a473bf77e35d4c993) schema in `vendor/`. Zorsh's Effect codecs validate Borsh tags, UTF-8 and exact input consumption. The cursor still limits item counts, string bytes and structural complexity before allocation, and locates the original byte spans needed by proof checks. It reads layout annotations from the pinned package; use the bounded protocol decoders for network input.

The trial tarball was built from unmodified commit `ec3938feb4eaa16f009026d4a8b1cf6626ee56f0` with `vp install --frozen-lockfile`, `vp -C packages/effect pack` and `vp -C packages/effect pm pack`. It includes the upstream MIT license. Its SHA-256 is `e7c4eb9a49f11c3883e4b8c7dd997d2b3d5fa255a1386494e9271345f2eba271`.

A few limits matter when generating fixtures: `fixedBytes(32)` needs native minimum/maximum length checks for reliable arbitrary generation, and `fixedArray(3)` alone does not constrain generated array lengths. Native strings can include lone UTF-16 surrogates that Borsh correctly rejects; the sign-action generator narrows the method to `"sign"`. These findings have been sent to the Zorsh package owner.
