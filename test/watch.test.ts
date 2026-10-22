import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import bs58 from "bs58";
import { Borsh } from "@zorsh/effect";
import { Arbitrary, Clock, Deferred, Effect, Metric, Option, Schema, Stream } from "effect";
import { test } from "vite-plus/test";
import {
  observe,
  observePeer,
  parseSeed,
  metrics,
  type ReceiptObservation,
} from "../src/network.ts";
import { decodeArgs, signRequests, metrics as mpcMetrics, type SignRequest } from "../src/mpc.ts";
import {
  encode,
  decode,
  encodeMessage,
  decodeMessage,
  publicKeyBorsh,
  decodeBlock,
  decodeChunkResponse,
  verifyReceiptProof,
  FrameDecoder,
  frameMessage,
  PeerIdentity,
  signRouted,
  decodeRouted,
} from "../src/protocol.ts";
import { openPeer, peerMetrics, type Peer, type PeerEvent } from "../src/peer.ts";

import {
  ActionSchema,
  BlockBodySchema,
  BlockSchema,
  ChunkInnerSchema,
  ChunkInnerV4,
  ChunkResponseSchema,
  ReceiptsSchema,
  type Action,
  type Receipt,
} from "../src/schemas.ts";

const cat = (...parts: Uint8Array[]) => Buffer.concat(parts);
const u8 = (n: number) => Buffer.from([n]);
const u32 = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};
const u64 = (n: bigint) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
};
const bytes = (b: Uint8Array) => cat(u32(b.length), b);
const hash = (b: Uint8Array) => createHash("sha256").update(b).digest();
const zero = Buffer.alloc(32);
const contractId = "v1.signer-prod.testnet";
const targetShardId = 4;
const sourceShardId = 7n;
const epochId = bs58.encode(zero);
const signCall = (args: Uint8Array): Action => ({
  _tag: "FunctionCall" as const,
  methodName: "sign",
  args,
  gas: 30n,
  deposit: 1n,
});
const signAction = signCall(Buffer.from('{"request":{"payload":[1]}}'));
const receipt = (receiverId: string, actions: Action[] = [signAction]): Receipt => ({
  predecessorId: "caller.testnet",
  receiverId,
  receiptId: Buffer.alloc(32, receiverId === contractId ? 1 : 2),
  receipt: {
    _tag: "ActionV2" as const,
    signerId: "caller.testnet",
    refundTo: Option.none(),
    signerPublicKey: { _tag: "Ed25519" as const, value: zero },
    gasPrice: 1n,
    outputDataReceivers: [],
    inputDataIds: [],
    actions,
  },
});

// Values use the production layouts; hashes are derived independently below.
// Frozen testnet captures separately guard against a shared encoder/decoder bug.
function fixture(receipts = [receipt(contractId), receipt("other.testnet")]) {
  const list = encode(ReceiptsSchema, receipts);
  const root = hash(hash(cat(u64(BigInt(targetShardId)), list)));
  const inner: typeof ChunkInnerV4.Type = {
    prevBlockHash: zero,
    prevStateRoot: zero,
    prevOutcomeRoot: zero,
    encodedMerkleRoot: zero,
    encodedLength: 8n,
    heightCreated: 42n,
    shardId: sourceShardId,
    prevGasUsed: 0n,
    gasLimit: 1_000_000n,
    prevBalanceBurnt: 0n,
    receiptRoot: root,
    txRoot: zero,
    prevValidatorProposals: [],
    congestionInfo: {
      _tag: "V1" as const,
      delayedReceiptsGas: 0n,
      bufferedReceiptsGas: 0n,
      receiptBytes: 0n,
      allowedShard: 0,
    },
    bandwidthRequests: { _tag: "V1" as const, requests: [] },
  };
  const chunkHash = hash(
    cat(hash(encode(ChunkInnerSchema, { _tag: "V4" as const, ...inner })), zero),
  );
  const signature = { _tag: "Ed25519" as const, value: Buffer.alloc(64) };
  const body: typeof BlockBodySchema.Type = {
    _tag: "V2" as const,
    chunks: [
      {
        _tag: "V3" as const,
        inner: { _tag: "V4" as const, ...inner },
        heightIncluded: 42n,
        signature,
      },
    ],
    challenges: [],
    vrfValue: zero,
    vrfProof: Buffer.alloc(64),
    chunkEndorsements: [[]],
  };
  const blockBytes = encode(BlockSchema, {
    _tag: "V4" as const,
    header: {
      _tag: "V5" as const,
      prevHash: zero,
      innerLite: {
        height: 42n,
        epochId: zero,
        nextEpochId: zero,
        prevStateRoot: zero,
        prevOutcomeRoot: zero,
        timestamp: 1000n,
        nextBpHash: zero,
        blockMerkleRoot: zero,
      },
      innerRest: {
        blockBodyHash: hash(encode(BlockBodySchema, body)),
        prevChunkOutgoingReceiptsRoot: zero,
        chunkHeadersRoot: zero,
        chunkTxRoot: zero,
        challengesRoot: zero,
        randomValue: zero,
        prevValidatorProposals: [],
        chunkMask: [true],
        nextGasPrice: 1n,
        totalSupply: 2n,
        challengesResult: [],
        lastFinalBlock: zero,
        lastDsFinalBlock: zero,
        blockOrdinal: 42n,
        prevHeight: 41n,
        epochSyncDataHash: Option.none(),
        approvals: [],
        latestProtocolVersion: 87,
        chunkEndorsements: [Buffer.alloc(0)],
      },
      signature,
    },
    body,
  });
  const responseBytes = encode(ChunkResponseSchema, {
    chunkHash,
    parts: [],
    receipts: [
      { receipts, fromShardId: sourceShardId, toShardId: BigInt(targetShardId), proof: [] },
    ],
  });
  const emptyResponse = encode(ChunkResponseSchema, { chunkHash, parts: [], receipts: [] });
  const block: PeerEvent = {
    receivedAt: { unixMs: 1000, monotonicNs: 0n },
    type: "message",
    message: { type: "block_response", payload: { block: { borsh: blockBytes } } },
  };
  return { block, responseBytes, emptyResponse, chunkHash };
}
function response(bodyBytes: Uint8Array, signatureValid = true): PeerEvent {
  return {
    type: "routed",
    receivedAt: { unixMs: 1030, monotonicNs: 30_000_000n },
    message: {
      forUs: true,
      target: { type: "hash", bytes: zero },
      author: zero,
      signature: Buffer.alloc(64),
      ttl: 100,
      bodyType: 12,
      bodyBytes,
      hash: zero,
      signatureValid,
    },
  };
}
const collect = (events: PeerEvent[], expectedEpoch = epochId) =>
  Effect.gen(function* () {
    const calls: SignRequest[] = [];
    const requested: (number | bigint)[] = [];
    let now = { unixMs: 1000, monotonicNs: 20_000_000n };
    const clock: Clock.Clock = {
      currentTimeMillis: Effect.sync(() => now.unixMs),
      monotonicTimeNanos: Effect.sync(() => now.monotonicNs),
      currentTimeNanos: Effect.sync(() => BigInt(now.unixMs) * 1_000_000n),
      currentTimeMillisUnsafe: () => now.unixMs,
      monotonicTimeNanosUnsafe: () => now.monotonicNs,
      currentTimeNanosUnsafe: () => BigInt(now.unixMs) * 1_000_000n,
      sleep: () => Effect.never,
    };
    const peer: Peer = {
      events: Stream.fromIterable(events),
      requestBlock: () => Effect.void,
      requestChunk: (_hash, shard) =>
        Effect.sync(() => {
          requested.push(shard);
          now = { unixMs: 500, monotonicNs: 50_000_000n };
        }),
      close: () => Effect.void,
    };
    yield* observePeer(
      peer,
      { accountId: contractId, shard: targetShardId, epochId: expectedEpoch },
      () => Effect.void,
      "fixture",
    ).pipe(
      signRequests,
      Stream.runForEach((request) =>
        Effect.sync(() => {
          calls.push(request);
        }),
      ),
      Effect.provideService(Clock.Clock, clock),
    );
    return {
      calls,
      invalid: yield* Metric.value(mpcMetrics.invalid),
      requested,
      fetched: yield* Metric.value(metrics.fetch),
      processed: yield* Metric.value(metrics.processing),
      proofs: yield* Metric.value(metrics.proofs),
      missing: yield* Metric.value(metrics.missing),
    };
  }).pipe(Effect.provideService(Metric.MetricRegistry, new Map()));

test("proofs preserve multiple sign actions, suppress repeated responses, and record monotonic metrics", async () => {
  const f = fixture([
    receipt(contractId, [signAction, { _tag: "Transfer" as const, deposit: 1n }, signAction]),
    receipt("other.testnet"),
  ]);
  const result = await Effect.runPromise(
    collect([f.block, f.block, response(f.responseBytes), response(f.responseBytes)]),
  );
  assert.deepEqual(result.requested, [4]);
  assert.deepEqual(
    result.calls.map((call) => call.actionIndex),
    [0, 2],
  );
  assert.equal(result.calls[0]?.caller, "caller.testnet");
  assert.deepEqual(result.calls[0]?.args, { request: { payload: [1] } });
  assert.equal(result.proofs.count, 1);
  assert.equal(result.fetched.sum, 10);
  assert.equal(result.processed.sum, 20);
  assert.equal(result.calls[0]?.blockToRequestMs, 50);
});

test("missing proofs remain visible and never produce a call; epoch and signature changes fail", async () => {
  const f = fixture();
  const result = await Effect.runPromise(collect([f.block, response(f.emptyResponse)]));
  assert.equal(result.calls.length, 0);
  assert.equal(result.missing.count, 1);
  await assert.rejects(Effect.runPromise(collect([f.block], "wrong-epoch")), /epoch changed/);
  await assert.rejects(
    Effect.runPromise(collect([f.block, response(f.responseBytes, false)])),
    /signature/,
  );
  const corrupt = Buffer.from(f.responseBytes);
  corrupt[40] ^= 1;
  await assert.rejects(Effect.runPromise(collect([f.block, response(corrupt)])));
});

test("Effect decodes sign JSON without imposing a contract version, with strict UTF-8 and byte limits", async () => {
  for (const value of [
    null,
    { request: { path: "鍵🔑", futureField: [true, 7] } },
    "x".repeat(16 * 1024 - 2),
  ]) {
    const f = fixture([receipt(contractId, [signCall(Buffer.from(JSON.stringify(value)))])]);
    const result = await Effect.runPromise(collect([f.block, response(f.responseBytes)]));
    assert.deepEqual(result.calls[0]?.args, value);
  }
  for (const [args, expected] of [
    [Buffer.from('{"request":'), /JSON/],
    [Buffer.from([0x22, 0xff, 0x22]), /encoded data/],
    [Buffer.from(JSON.stringify("x".repeat(16 * 1024 - 1))), /16 KiB/],
    [Buffer.from(JSON.stringify("鍵".repeat(6000))), /16 KiB/],
  ] as const) {
    const f = fixture([receipt(contractId, [signCall(args), signAction])]);
    const result = await Effect.runPromise(collect([f.block, response(f.responseBytes)]));
    assert.deepEqual(
      result.calls.map((call) => call.actionIndex),
      [1],
    );
    assert.equal(result.invalid.count, 1);
    await assert.rejects(Effect.runPromise(decodeArgs(args)), expected);
  }
});

test("network observations work for other accounts and leave action interpretation to the consumer", async () => {
  const raw = receipt("other.testnet", [signCall(Buffer.from("not JSON"))]);
  const f = fixture([receipt(contractId), raw]);
  const peer: Peer = {
    events: Stream.fromIterable([f.block, response(f.responseBytes)]),
    requestBlock: () => Effect.void,
    requestChunk: () => Effect.void,
    close: () => Effect.void,
  };
  const observations = await Effect.runPromise(
    observePeer(
      peer,
      {
        accountId: "other.testnet",
        shard: targetShardId,
        epochId,
      },
      () => Effect.void,
      "fixture",
    ).pipe(Stream.runCollect),
  );
  assert.equal(observations.length, 1);
  assert.deepEqual(
    encode(
      ReceiptsSchema,
      observations.map((item) => item.receipt),
    ),
    encode(ReceiptsSchema, [raw]),
  );
  assert.equal(observations[0]?.blockHeight, "42");
  assert.deepEqual(
    await Effect.runPromise(
      signRequests(Stream.fromIterable(observations)).pipe(Stream.runCollect),
    ),
    [],
  );
});

test("MPC deduplicates individual actions across peers, with fresh state per subscription", async () => {
  const item: ReceiptObservation = {
    receipt: receipt(contractId, [
      signAction,
      { _tag: "Transfer" as const, deposit: 1n },
      signAction,
    ]),
    blockHeight: "42",
    peer: "first",
    observedAt: "2026-10-21T00:00:00.000Z",
    blockToReceiptMs: 12,
  };
  const stream = signRequests(Stream.make(item, { ...item, peer: "second" }));
  for (let i = 0; i < 2; i++) {
    const calls = await Effect.runPromise(stream.pipe(Stream.runCollect));
    assert.deepEqual(
      calls.map(({ actionIndex, peer }) => [actionIndex, peer]),
      [
        [0, "first"],
        [2, "first"],
      ],
    );
  }
});

test("network options fail before RPC for invalid accounts, peer counts and insecure endpoints", async () => {
  const valid = { accountId: contractId, peers: 4, rpcUrl: "https://test.rpc.fastnear.com" };
  for (const options of [
    { ...valid, peers: 0 },
    { ...valid, peers: 13 },
    { ...valid, accountId: "BAD..testnet" },
    { ...valid, rpcUrl: "http://localhost:3030" },
  ]) {
    await assert.rejects(Effect.runPromise(observe(options).pipe(Stream.runDrain)), /NetworkError/);
  }
});

test("native Effect schemas generate typed function-call fixtures with the NEAR action discriminant", async () => {
  const actions = await Effect.runPromise(
    Arbitrary.sampleEffect(
      Arbitrary.schema(
        ActionSchema.cases.FunctionCall.mapFields((fields) => ({
          ...fields,
          methodName: Schema.Literal("sign"),
        })),
      ),
      {
        count: 25,
        seed: 42,
      },
    ),
  );
  for (const action of actions) {
    const bytes = encode(ActionSchema, action);
    assert.equal(bytes[0], 2);
    assert.ok(Schema.toEquivalence(ActionSchema)(decode(ActionSchema, bytes), action));
  }
});

test("Effect Borsh validates tags, UTF-8 and EOF; preflight retains application resource limits", () => {
  assert.throws(() => decode(Schema.Boolean, u8(2)), /Boolean|bool/i);
  assert.throws(() => decode(Schema.Option(Borsh.U8), u8(2)), /Option/);
  assert.throws(() => decode(Schema.String, bytes(u8(0xff))), /UTF-8/);
  assert.throws(() => decode(Borsh.U8, cat(u8(7), u8(99))), /Trailing/);
  assert.throws(() => decode(Schema.Array(Borsh.Unit), u32(16_385)), /zero-sized/);
  assert.throws(() => decodeChunkResponse(Buffer.alloc(16 * 1024 * 1024 + 1)), /16 MiB/);
  assert.throws(() => decodeChunkResponse(cat(zero, u32(16_385))), /count/);
  assert.throws(() => decodeChunkResponse(cat(zero, u32(0), u32(16_385))), /count/);
  assert.throws(
    () => decodeChunkResponse(cat(zero, u32(0), u32(1), u32(1), u32(1_048_577))),
    /1 MiB/,
  );
  // Skipped chunk parts still have bounded vectors and valid Merkle direction tags.
  const part = cat(zero, u32(1), u64(0n), bytes(Buffer.alloc(0)));
  assert.throws(() => decodeChunkResponse(cat(part, u32(16_385))), /count/);
  assert.throws(() => decodeChunkResponse(cat(part, u32(1), zero, u8(2))), /variant/);
  assert.throws(() => decodeChunkResponse(cat(zero, u32(0), u32(0), u8(0))), /trailing/);
  const f = fixture();
  assert.ok(f.block.type === "message" && f.block.message.type === "block_response");
  const blockBytes = f.block.message.payload.block.borsh;
  assert.throws(() => decodeBlock(cat(blockBytes, u8(0))), /trailing/);
});

test("captured testnet data retains its MPC request, verifies its commitment, and rejects corrupt/trailing payloads", () => {
  const blockBytes = readFileSync(new URL("../fixtures/block.borsh", import.meta.url));
  const proofBytes = readFileSync(new URL("../fixtures/receipts.borsh", import.meta.url));
  assert.equal(
    hash(blockBytes).toString("hex"),
    "f755a002c7972bd9049bd145f6e1ac0825d058f1b3e9045b55ea7b8597c759bf",
  );
  assert.equal(
    hash(proofBytes).toString("hex"),
    "389665c2073f9ea83e04f5b4a06f6149fe7cbd71cbf6fecb4b24cad472c177d9",
  );
  assert.deepEqual(Buffer.from(encode(BlockSchema, decode(BlockSchema, blockBytes))), blockBytes);
  assert.deepEqual(
    Buffer.from(encode(ChunkResponseSchema, decode(ChunkResponseSchema, proofBytes))),
    proofBytes,
  );
  const block = decodeBlock(blockBytes),
    response = decodeChunkResponse(proofBytes);
  const header = block.chunks.find((chunk) =>
    Buffer.from(chunk.chunkHash).equals(response.chunkHash),
  );
  assert.ok(header);
  const proof = response.receipts[0];
  assert.ok(proof);
  assert.equal(verifyReceiptProof(proof, header.receiptRoot, header.shardId, 5n), true);
  assert.equal(proof.receipts[0]?.receiverId, contractId);
  assert.equal(
    bs58.encode(proof.receipts[0].receiptId),
    "66cjSFYwtGetDjaTQ7ebMXX8HfL9HjBqbFZ24EknTqRh",
  );
  assert.equal(verifyReceiptProof(proof, zero, header.shardId, 5n), false);
  const corruptBlock = Buffer.from(blockBytes);
  corruptBlock[corruptBlock.length - 1] ^= 1;
  assert.throws(() => decodeBlock(corruptBlock), /body hash/);
  for (const bytes of [
    proofBytes.subarray(0, -1),
    cat(proofBytes, u8(0)),
    cat(zero, u32(0xffffffff)),
  ])
    assert.throws(() => decodeChunkResponse(bytes));
});

test("routed signatures bind the body and frame limits hold across fragmented input", () => {
  const identity = new PeerIdentity();
  const signed = signRouted(identity, { type: "hash", bytes: zero }, Buffer.from([12, 1, 2]));
  assert.equal(decodeRouted(signed.borsh).signatureValid, true);
  const changed = Buffer.from(signed.borsh);
  changed[changed.length - 1] ^= 1;
  assert.equal(decodeRouted(changed).signatureValid, false);
  const decoder = new FrameDecoder(1000),
    framed = frameMessage(signed.borsh);
  const output = [...framed].flatMap((byte) => decoder.push(Buffer.from([byte])));
  assert.deepEqual(output, [signed.borsh]);
  assert.throws(() => new FrameDecoder(2).push(u32(3)), /frame size/);
});

test("bootstrap skips private, malformed, and repeated address tricks", () => {
  const id = `ed25519:${bs58.encode(zero)}`;
  assert.equal(parseSeed(id, "8.8.8.8:24567").port, 24567);
  for (const host of [
    "127.0.0.1:80",
    "10.0.0.1:80",
    "192.168.1.1:80",
    "100.64.0.1:80",
    "192.0.2.1:80",
    "peer.example:80",
    "[::1]:80",
    "8.8.8.8:0",
    "8.8.8.8:80:90",
  ])
    assert.throws(() => parseSeed(id, host));
  assert.throws(() => parseSeed("ed25519:bad", "8.8.8.8:80"));
});

test("scoped peer authenticates its handshake, sends only reads, and records transport metrics", async (t) => {
  const identity = new PeerIdentity();
  const received = Deferred.makeUnsafe<void, Error>();
  const closed = Deferred.makeUnsafe<void>();
  const sockets = new Set<Socket>();
  const kinds: string[] = [];
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.on("close", () => {
      sockets.delete(socket);
      Deferred.doneUnsafe(closed, Effect.void);
    });
    const decoder = new FrameDecoder();
    socket.on("data", (bytes) => {
      try {
        for (const frame of decoder.push(bytes)) {
          const message = decodeMessage(frame);
          kinds.push(message.type === "unsupported" ? message.name : message.type);
          if (message.type === "tier2_handshake") {
            const request = message.payload;
            socket.write(
              frameMessage(
                encodeMessage("tier2_handshake", {
                  ...request,
                  sender_peer_id: { borsh: publicKeyBorsh(identity.publicKey) },
                  target_peer_id: request.sender_peer_id,
                  partial_edge_info: {
                    borsh: identity.partialEdge(
                      request.sender_peer_id.borsh.subarray(1),
                      Buffer.from(request.partial_edge_info.borsh).readBigUInt64LE(),
                    ),
                  },
                }),
              ),
            );
          }
          if (message.type === "routed") {
            const request = decodeRouted(message.payload.borsh);
            assert.equal(request.signatureValid, true);
            assert.equal(request.bodyType, 11);
            assert.deepEqual(Buffer.from(request.bodyBytes), cat(zero, u32(0), u32(1), u64(5n)));
            Deferred.doneUnsafe(received, Effect.void);
          }
        }
      } catch (cause) {
        Deferred.doneUnsafe(
          received,
          Effect.fail(cause instanceof Error ? cause : new Error(String(cause))),
        );
      }
    });
  });
  t.onTestFinished(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const peer = yield* openPeer({
          host: "127.0.0.1",
          port: address.port,
          peerId: identity.peerId,
          genesisHash: zero,
          protocolVersion: 87,
        });
        assert.deepEqual(Object.keys(peer).sort(), [
          "close",
          "events",
          "requestBlock",
          "requestChunk",
        ]);
        yield* peer.requestBlock(zero);
        yield* peer.requestChunk(zero, 5);
        yield* Deferred.await(received);
        assert.equal((yield* Metric.value(peerMetrics.frames)).count, 1);
        assert.ok((yield* Metric.value(peerMetrics.bytesIn)).count > 0);
        assert.ok((yield* Metric.value(peerMetrics.bytesOut)).count > 0);
        assert.equal((yield* Metric.value(peerMetrics.handshakeMs)).count, 1);
      }),
    ).pipe(Effect.provideService(Metric.MetricRegistry, new Map())),
    { signal: t.signal },
  );
  await Effect.runPromise(Deferred.await(closed), { signal: t.signal });
  assert.deepEqual(kinds, ["tier2_handshake", "block_request", "routed"]);
});
