# mpc-wire

A read-only watcher for `sign` calls to NEAR's `v1.signer-prod.testnet` MPC contract. Connects to up to 12 peers and prints the request arguments without running a NEAR node.

## Run

Install [Vite+](https://viteplus.dev/guide), then:

```sh
vp install
vp run watch
```

No account, key, or testnet funds needed. By default it watches for 60 seconds after connecting.

```sh
PEERS=4 DURATION_SECONDS=300 vp run watch
```

Request lines are JSON, including receipt ID, action index, caller, arguments, block height, peer, and observation time. Effect metrics go to stderr every 10 seconds and at shutdown: fresh peers, traffic, verified and missing proofs, failures, request count, and timing histograms.

`receipt_fetch_ms` measures request-to-response time. `response_processing_ms` includes local queuing, decoding, and proof verification. `block_to_request_ms` runs from block arrival to the checked request. These are local monotonic durations; they do not measure submission latency or compare clocks with another node.

## Sample run

Captured on October 21, 2026 UTC with `PEERS=4 DURATION_SECONDS=5 vp run watch`. This excerpt combines stdout and stderr. JSON is expanded for readability; only selected metrics are shown, with histogram buckets omitted.

```text
connecting to up to 4 testnet peers; watching v1.signer-prod.testnet
198.244.253.254: PeerError: connect ECONNREFUSED 198.244.253.254:24567
91.134.22.129: PeerError: connect ECONNREFUSED 91.134.22.129:24567
{
  "event": "sign-request",
  "receiptId": "HFGCP2E729mT1wDaYXddQNN28d2SBr3exhga3mmA76XV",
  "actionIndex": 0,
  "caller": "tx-bench.testnet",
  "args": {
    "request": {
      "domain_id": 0,
      "path": "",
      "payload_v2": {
        "Ecdsa": "9ebdaf15d13fdff078cacbf39f1a74c1db7088fa4692ef204067ec7063f0c6ef"
      }
    }
  },
  "blockHeight": "274029264",
  "peer": "185.44.207.120",
  "observedAt": "2026-10-21T01:57:42.205Z",
  "blockToRequestMs": 181.420375
}
{
  "event": "metrics",
  "at": "2026-10-21T01:57:42.403Z",
  "metrics": [
    {"name": "receipt_proofs","type": "Counter","count": 85},
    {"name": "receipt_fetch_ms","type": "Histogram","count": 85,"min": 82.626334,"max": 182.858666,"sum": 12299.432785999998},
    {"name": "response_processing_ms","type": "Histogram","count": 85,"min": 0.10075,"max": 1.49575,"sum": 40.985837000000004},
    {"name": "missing_proofs","type": "Counter","count": 65},
    {"name": "sign_requests","type": "Counter","count": 1},
    {"name": "block_to_request_ms","type": "Histogram","count": 1,"min": 181.420375,"max": 181.420375,"sum": 181.420375},
    {"name": "fresh_peers","type": "Gauge","value": 4}
  ]
}
```

## What it sees

Read-only RPC supplies the initial testnet identity, shard layout, and peer addresses. Set `RPC_URL` to change the bootstrap endpoint. After setup, incoming P2P blocks trigger receipt-proof requests; there is no RPC polling.

Receipt membership is checked against the received block's commitments. This client does not validate consensus or execute the contract. A request can still fail execution. It does not obtain continuation IDs or completed signatures.

This is a bounded experiment: no backfill, reconnect loop, or completeness guarantee. Missing proofs and dropped peers remain visible in the metrics. An epoch change stops that peer's observer; restart to refresh the shard layout. Twelve connections can include peers operated by the same provider.

## Develop

```sh
vp check
vp test run
vp fmt
```

Three implementation files in `src/`, one test file, and `vite.config.ts`. Uses Effect 4, published Zorsh 0.5.2, and near-kit for bootstrap. The pinned [nearcore](https://github.com/near/nearcore/tree/44f7ae6cd7ef08bab604e20a473bf77e35d4c993) protobuf schema is in `vendor/` with its MIT license; captured testnet fixtures are in `fixtures/`.
