# mpc-wire

Watch live `sign` calls to NEAR's `v1.signer-prod.testnet` MPC contract. Connect to up to 12 peers and print the request arguments, without running a NEAR node or submitting transactions.

**This is a read-only experiment, not a source of signing authorization.** It checks receipt proofs against blocks supplied by peers, but does not validate NEAR consensus or receipt execution. A malicious peer can supply a self-consistent fake block and request that pass those checks.

## Run

Use Node.js 24.11+ on the 24.x line, or 26+, and install [Vite+](https://viteplus.dev/guide). From this directory:

```sh
vp install --frozen-lockfile
vp run watch
```

No NEAR account, wallet key, or testnet funds are needed. The watcher uses outbound TCP connections and stops after 60 seconds by default.

```sh
PEERS=4 DURATION_SECONDS=300 vp run watch
```

| Variable           | Default                         | Meaning                                                    |
| ------------------ | ------------------------------- | ---------------------------------------------------------- |
| `PEERS`            | `12`                            | Target connections, from 1 to 12                           |
| `DURATION_SECONDS` | `60`                            | Total runtime including setup, from 1 to 3,600 seconds     |
| `RPC_URL`          | `https://test.rpc.fastnear.com` | Testnet bootstrap endpoint; credential-free HTTPS required |

RPC supplies the initial testnet identity, shard layout, block and peer addresses. After setup, incoming P2P blocks trigger receipt-proof requests; there is no RPC polling. The watcher authenticates its peer connections with a temporary in-memory identity.

## Output

Sign requests go to stdout as JSON. Each includes the receipt ID, action index, caller, arguments, block height, source peer and observation time. The caller is the receipt's predecessor account; it is not necessarily the transaction signer. Arguments are parsed as JSON without assuming a particular version of the MPC contract's request format.

Effect metrics go to stderr every 10 seconds and at shutdown. They include fresh peers, traffic, checked and missing proofs, failures, request count and timing histograms:

| Metric                   | Measures                                                                    |
| ------------------------ | --------------------------------------------------------------------------- |
| `receipt_fetch_ms`       | Receipt-proof request to response arrival                                   |
| `response_processing_ms` | Local queuing, decoding and proof checking                                  |
| `block_to_request_ms`    | Block arrival to receipt verification, before the consumer parses arguments |

These durations use the local monotonic clock. They do not measure transaction submission latency. `observedAt` is the local wall-clock time when receipt verification finishes. Proof counts include repeated observations across peers; sign requests are deduplicated by receipt ID and action index for up to ten minutes, with a 4,096-entry limit per subscription.

## Sample run

Captured on October 23, 2026 UTC with the published `@zorsh/effect` 0.1.0 and `PEERS=12 DURATION_SECONDS=45 vp run watch`. All 12 peers became active. The watcher observed four distinct sign requests, checked 4,452 receipt proofs, counted 4,683 responses without a requested proof, and recorded one peer failure.

This excerpt contains the first request and selected final metrics. Identifiers, the derivation path and payload are redacted; timestamps, timings and counts are unchanged. Histogram buckets and counter flags are omitted.

```text
connecting to up to 12 testnet peers; watching v1.signer-prod.testnet
{
  "event": "sign-request",
  "receiptId": "<redacted>",
  "actionIndex": 0,
  "caller": "<redacted>",
  "args": {
    "request": {
      "path": "<redacted>",
      "payload_v2": {
        "Eddsa": "<redacted>"
      },
      "domain_id": 1
    }
  },
  "blockHeight": "274325556",
  "peer": "<redacted>",
  "observedAt": "2026-10-23T00:50:20.403Z",
  "blockToRequestMs": 186.530042
}
{
  "event": "metrics",
  "at": "2026-10-23T00:51:01.038Z",
  "metrics": [
    {"name":"fresh_peers","type":"Gauge","value":12},
    {"name":"peer_failures","type":"Counter","count":1},
    {"name":"receipt_proofs","type":"Counter","count":4452},
    {"name":"receipt_fetch_ms","type":"Histogram","count":4452,"min":28.292875,"max":2834.040958,"sum":1177030.314410002},
    {"name":"response_processing_ms","type":"Histogram","count":4452,"min":0.082167,"max":3.531459,"sum":1725.1901970000006},
    {"name":"missing_proofs","type":"Counter","count":4683},
    {"name":"sign_requests","type":"Counter","count":4},
    {"name":"block_to_request_ms","type":"Histogram","count":4,"min":73.2915,"max":186.530042,"sum":527.9110830000001}
  ]
}
```

## Limits

- Receipt membership is checked against the received block's commitments, using the original wire bytes. Neither the block's canonical status nor the claimed caller is independently established. More peers do not turn these checks into consensus verification.
- A call may fail execution. The watcher does not obtain execution outcomes, continuation IDs or completed MPC signatures, and cannot replace the MPC node's validating indexer.
- There is no backfill, reconnect loop or completeness guarantee. An epoch change stops that peer's observer; restart to refresh the shard layout. Twelve connections can include peers run by the same operator.
- Slow consumers apply backpressure. A peer disconnects if its bounded incoming queue fills. Invalid or oversized sign arguments are skipped with a warning and an `invalid_sign_requests` counter.
- Frames and Borsh messages are capped at 16 MiB. Each Borsh message permits at most 16,384 collection items, including nested collections; strings allow up to 1 MiB of UTF-8 bytes. Sign arguments allow 16 KiB. Receipt-only responses must not include chunk parts. These are watcher limits, not NEAR protocol limits.

## Develop

```sh
vp fmt
vp check
vp test run
```

CI runs the same formatting, lint, type and test checks. Tests use a local TCP peer and fixed captures; they do not need a testnet connection.

The six modules in `src/` separate the wire format, networking and MPC interpretation:

- `schemas.ts`: Effect schemas with Zorsh's explicit Borsh layouts and bounds.
- `protocol.ts`: codecs, framing, signatures and receipt commitment checks.
- `peer.ts`: one authenticated TCP peer and its scoped socket lifetime.
- `network.ts`: bootstrap, peer connections and an Effect receipt stream for an account.
- `mpc.ts`: sign arguments, per-action deduplication and MPC metrics.
- `watch.ts`: CLI configuration and output.

To observe receipts for another testnet account, use the network stream directly:

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

The network stream includes the decoded receipt, block height, source peer and local timing. It does not interpret function arguments or deduplicate observations across peers.

Synthetic test data is generated from the shared schemas. The two binary files in `fixtures/` are frozen testnet captures with hash and exact-byte round-trip assertions. They provide an independent compatibility check; do not regenerate them from the schemas.

Uses published `@zorsh/effect` 0.1.0, Effect 4, near-kit for RPC bootstrap, and protobufjs for NEAR's network envelope. Zorsh handles Borsh bounds, prefix decoding and original byte spans; there is no custom Borsh parser.

## License

[MIT](LICENSE). The vendored protobuf schema comes from [nearcore at `44f7ae6`](https://github.com/near/nearcore/tree/44f7ae6cd7ef08bab604e20a473bf77e35d4c993) and retains its [MIT license](vendor/LICENSE-MIT).
