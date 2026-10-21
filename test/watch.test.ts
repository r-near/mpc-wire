import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import bs58 from "bs58";
import { Clock, Deferred, Effect, Metric, Stream } from "effect";
import { test } from "vite-plus/test";
import { consume, parseSeed, metrics, type Request } from "../src/watch.ts";
import {
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
const u128 = (n: bigint) => cat(u64(n), u64(0n));
const bytes = (b: Uint8Array) => cat(u32(b.length), b);
const str = (s: string) => bytes(Buffer.from(s));
const hash = (b: Uint8Array) => createHash("sha256").update(b).digest();
const zero = Buffer.alloc(32);
const signature = cat(u8(0), Buffer.alloc(64));
const contractId = "v1.signer-prod.testnet";
const targetShardId = 4;
const sourceShardId = 7n;
const epochId = bs58.encode(zero);
const signAction = cat(
  u8(2),
  str("sign"),
  bytes(Buffer.from('{"request":{"payload":[1]}}')),
  u64(30n),
  u128(1n),
);
const receipt = (receiver: string, actions: Uint8Array[] = [signAction]) =>
  cat(
    str("caller.testnet"),
    str(receiver),
    Buffer.alloc(32, receiver === contractId ? 1 : 2),
    u8(5),
    str("caller.testnet"),
    u8(0),
    u8(0),
    zero,
    u128(1n),
    u32(0),
    u32(0),
    u32(actions.length),
    ...actions,
  );

function fixture(receipts = [receipt(contractId), receipt("other.testnet")]) {
  const list = cat(u32(receipts.length), ...receipts);
  const root = hash(hash(cat(u64(BigInt(targetShardId)), list)));
  const chunkInner = cat(
    u8(3),
    zero,
    zero,
    zero,
    zero,
    u64(8n),
    u64(42n),
    u64(sourceShardId),
    u64(0n),
    u64(1000000n),
    u128(0n),
    root,
    zero,
    u32(0),
    u8(0),
    u128(0n),
    u128(0n),
    u64(0n),
    Buffer.alloc(2),
    u8(0),
    u32(0),
  );
  const chunkHash = hash(cat(hash(chunkInner), zero));
  const chunk = cat(u8(2), chunkInner, u64(42n), signature);
  const body = cat(
    u8(1),
    u32(1),
    chunk,
    u32(0),
    Buffer.alloc(32),
    Buffer.alloc(64),
    u32(1),
    u32(0),
  );
  const lite = cat(u64(42n), zero, zero, zero, zero, u64(1000n), zero, zero);
  const rest = cat(
    hash(body),
    zero,
    zero,
    zero,
    zero,
    zero,
    u32(0),
    u32(1),
    u8(1),
    u128(1n),
    u128(2n),
    u32(0),
    zero,
    zero,
    u64(42n),
    u64(41n),
    u8(0),
    u32(0),
    u32(87),
    u32(1),
    bytes(Buffer.alloc(0)),
  );
  const blockBytes = cat(u8(3), u8(4), zero, lite, rest, signature, body);
  const responseBytes = cat(
    chunkHash,
    u32(0),
    u32(1),
    list,
    u64(sourceShardId),
    u64(BigInt(targetShardId)),
    u32(0),
  );
  const emptyResponse = cat(chunkHash, u32(0), u32(0));
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
    const calls: Request[] = [];
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
    yield* consume(
      peer,
      { shard: targetShardId, epochId: expectedEpoch },
      () => Effect.void,
      (request) =>
        Effect.sync(() => {
          calls.push(request);
        }),
      "fixture",
    ).pipe(Effect.provideService(Clock.Clock, clock));
    return {
      calls,
      requested,
      fetched: yield* Metric.value(metrics.fetch),
      processed: yield* Metric.value(metrics.processing),
      proofs: yield* Metric.value(metrics.proofs),
      missing: yield* Metric.value(metrics.missing),
    };
  }).pipe(Effect.provideService(Metric.MetricRegistry, new Map()));

test("proofs preserve multiple sign actions, suppress repeated responses, and record monotonic metrics", async () => {
  const f = fixture([
    receipt(contractId, [signAction, cat(u8(3), u128(1n)), signAction]),
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
