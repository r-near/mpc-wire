/** NEAR Tier2 framing and receipt codecs. Hash checks establish header consistency, not consensus. */
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import bs58 from "bs58";
import protobuf from "protobufjs";
import { Borsh } from "@zorsh/effect";
import { Schema } from "effect";
import {
  edgeSchema,
  KnownWireMessage,
  chunkRequest,
  BlockSchema,
  ChunkResponseSchema,
  RoutedHeaderSchema,
  wireLimits,
  type MerklePath,
  type RoutedV3Payload,
  type WireMessage,
} from "./schemas.ts";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function sha256(bytes: Uint8Array): Buffer {
  return createHash("sha256").update(bytes).digest();
}

export function bytes32(value: Uint8Array | string, label = "hash"): Buffer {
  const bytes =
    typeof value === "string"
      ? Buffer.from(bs58.decode(value.replace(/^ed25519:/, "")))
      : Buffer.from(value);
  if (bytes.length !== 32) throw new Error(`${label} must contain 32 bytes`);
  return bytes;
}

export function publicKeyBorsh(publicKey: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from([0]), bytes32(publicKey, "public key")]);
}

export function edgeHash(ours: Uint8Array, theirs: Uint8Array, nonce: bigint): Buffer {
  const left = publicKeyBorsh(ours);
  const right = publicKeyBorsh(theirs);
  return sha256(
    encode(
      edgeSchema,
      Buffer.compare(left, right) < 0
        ? { first: left, second: right, nonce }
        : { first: right, second: left, nonce },
    ),
  );
}

export function freshEdgeNonce(): bigint {
  return BigInt(Math.floor(Date.now() / 1000)) | 1n;
}

export function verifyEd25519(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
  return verify(null, message, key, signature);
}

export class PeerIdentity {
  readonly publicKey: Buffer;
  readonly peerId: string;
  private readonly secretKey: KeyObject;

  constructor() {
    const pair = generateKeyPairSync("ed25519");
    this.secretKey = pair.privateKey;
    this.publicKey = Buffer.from(
      pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32),
    );
    this.peerId = bs58.encode(this.publicKey);
  }

  sign(message: Uint8Array): Buffer {
    return sign(null, message, this.secretKey);
  }

  signBorsh(message: Uint8Array): Buffer {
    return Buffer.concat([Buffer.from([0]), this.sign(message)]);
  }

  partialEdge(theirs: Uint8Array, nonce: bigint): Buffer {
    return Buffer.concat([
      encode(Borsh.U64, nonce),
      this.signBorsh(edgeHash(this.publicKey, theirs, nonce)),
    ]);
  }
}

export const NEARCORE_REVISION = "44f7ae6cd7ef08bab604e20a473bf77e35d4c993";
export const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024;

const root = protobuf.parse(
  readFileSync(new URL("../vendor/network.proto", import.meta.url), "utf8"),
  { keepCase: true },
).root;
// The pinned schema imports only this standard protobuf type.
root
  .define("google.protobuf")
  .add(
    new protobuf.Type("Timestamp")
      .add(new protobuf.Field("seconds", 1, "int64"))
      .add(new protobuf.Field("nanos", 2, "int32")),
  );
root.resolveAll();
const peerMessage = root.lookupType("network.PeerMessage");
const messageOneof = peerMessage.oneofs.message_type;
if (!messageOneof) throw new Error("pinned protobuf schema has no message_type");
const peerMessageFields = messageOneof.oneof;

const supported = new Set<string>([
  "tier2_handshake",
  "handshake_failure",
  "block_response",
  "routed",
  "routed_v3",
]);

export function encodeMessage(type: string, payload: object): Buffer {
  if (!["tier2_handshake", "block_request", "routed"].includes(type))
    throw new Error(`unsupported read-only message: ${type}`);
  const message = peerMessage.fromObject({ [type]: payload });
  const error = peerMessage.verify(message);
  if (error) throw new Error(`invalid peer message: ${error}`);
  return Buffer.from(peerMessage.encode(message).finish());
}

export function decodeMessage(bytes: Uint8Array): WireMessage {
  const decoded = peerMessage.toObject(peerMessage.decode(bytes), {
    longs: String,
    defaults: false,
    oneofs: true,
  });
  // Protobuf oneofs use the last member present on the wire.
  const name = peerMessageFields.find((field) => decoded[field] != null);
  // Protobuf preserves forward compatibility by skipping unknown fields.
  if (!name) return { type: "unsupported", name: "unknown", payload: {} };
  if (!supported.has(name))
    return {
      type: "unsupported",
      name,
      payload: Schema.decodeUnknownSync(Schema.Record(Schema.String, Schema.Unknown))(
        decoded[name],
      ),
    };
  return Schema.decodeUnknownSync(KnownWireMessage)({ type: name, payload: decoded[name] });
}

export function frameMessage(bytes: Uint8Array, maxBytes = DEFAULT_MAX_FRAME_BYTES): Buffer {
  if (bytes.length === 0 || bytes.length > maxBytes)
    throw new Error(`invalid frame size: ${bytes.length}`);
  const frame = Buffer.allocUnsafe(bytes.length + 4);
  frame.writeUInt32LE(bytes.length, 0);
  frame.set(bytes, 4);
  return frame;
}

/** A bounded incremental decoder. Fragmentation never repeatedly copies a growing frame. */
export class FrameDecoder {
  readonly maxBytes: number;
  private readonly header = Buffer.alloc(4);
  private headerOffset = 0;
  private frame: Buffer | undefined;
  private frameOffset = 0;

  constructor(maxBytes = DEFAULT_MAX_FRAME_BYTES) {
    this.maxBytes = maxBytes;
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 0xffffffff)
      throw new Error("invalid frame bound");
  }

  get hasPartialFrame(): boolean {
    return this.headerOffset > 0 || this.frame !== undefined;
  }

  push(bytes: Uint8Array): Buffer[] {
    const frames: Buffer[] = [];
    let offset = 0;
    while (offset < bytes.length) {
      if (!this.frame) {
        const count = Math.min(4 - this.headerOffset, bytes.length - offset);
        this.header.set(bytes.subarray(offset, offset + count), this.headerOffset);
        offset += count;
        this.headerOffset += count;
        if (this.headerOffset < 4) continue;
        const length = this.header.readUInt32LE();
        this.headerOffset = 0;
        if (length === 0 || length > this.maxBytes)
          throw new Error(`invalid peer frame size: ${length} (limit ${this.maxBytes})`);
        this.frame = Buffer.allocUnsafe(length);
        this.frameOffset = 0;
      }
      const count = Math.min(this.frame.length - this.frameOffset, bytes.length - offset);
      this.frame.set(bytes.subarray(offset, offset + count), this.frameOffset);
      offset += count;
      this.frameOffset += count;
      if (this.frameOffset === this.frame.length) {
        frames.push(this.frame);
        this.frame = undefined;
        this.frameOffset = 0;
      }
    }
    return frames;
  }
}

export type RoutedTarget = { type: "peer_id" | "hash"; bytes: Uint8Array };
export interface RoutedEnvelope {
  target: RoutedTarget;
  author: Uint8Array;
  signature: Uint8Array;
  ttl: number;
  bodyType: number;
  bodyBytes: Uint8Array;
  hash: Uint8Array;
  signatureValid: boolean;
}

export function encodeTarget(target: RoutedTarget): Buffer {
  return target.type === "peer_id"
    ? Buffer.concat([Buffer.from([0]), publicKeyBorsh(target.bytes)])
    : Buffer.concat([Buffer.from([1]), bytes32(target.bytes)]);
}

export function routedHash(target: RoutedTarget, author: Uint8Array, body: Uint8Array): Buffer {
  return sha256(Buffer.concat([encodeTarget(target), publicKeyBorsh(author), body]));
}

export function signRouted(
  identity: PeerIdentity,
  target: RoutedTarget,
  body: Uint8Array,
  ttl = 100,
): { borsh: Buffer; hash: Buffer } {
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 255) throw new Error("invalid routed message ttl");
  if (body.length === 0) throw new Error("empty routed body");
  const hash = routedHash(target, identity.publicKey, body);
  return {
    borsh: Buffer.concat([
      encodeTarget(target),
      publicKeyBorsh(identity.publicKey),
      identity.signBorsh(hash),
      Buffer.from([ttl]),
      body,
    ]),
    hash,
  };
}

/** Parse only the fixed routing envelope; the body remains untrusted Borsh bytes. */
export function decodeRouted(bytes: Uint8Array): RoutedEnvelope {
  if (bytes.byteLength > wireLimits.maxBytes) {
    throw new Error("routed payload exceeds 16 MiB");
  }
  const { value, offset } = decodeRoutedHeader(bytes);
  const target: RoutedTarget =
    value.target._tag === "PeerId"
      ? { type: "peer_id", bytes: value.target.key.value }
      : { type: "hash", bytes: value.target.hash };
  const author = value.author.value;
  const signature = value.signature.value;
  const bodyBytes = bytes.subarray(offset);
  const hash = routedHash(target, author, bytes.subarray(offset - 1));
  return {
    target,
    author,
    signature,
    ttl: value.ttl,
    bodyType: value.bodyType,
    bodyBytes,
    hash,
    signatureValid: verifyEd25519(author, hash, signature),
  };
}

// The outer routed_v3 body has TieredMessageBody::T2 = 1, then T2MessageBody.
const t2ToLegacy = [1, 2, 3, 11, 12, 14, 15, 21, 27, 31, 32, 34];
export function decodeRoutedV3(
  payload: Schema.Schema.Type<typeof RoutedV3Payload>,
): RoutedEnvelope | undefined {
  const body = payload.borsh_body;
  if (!body || body.length < 2 || body[0] !== 1) return undefined;
  const bodyType = t2ToLegacy[body[1]!];
  if (bodyType === undefined) return undefined;
  const author = payload.author?.borsh;
  const signature = payload.signature?.borsh;
  if (
    !author ||
    author.length !== 33 ||
    author[0] !== 0 ||
    !signature ||
    signature.length !== 65 ||
    signature[0] !== 0
  )
    throw new Error("invalid routed_v3 identity");
  let target: RoutedTarget;
  if (payload.target?.peer_id) {
    const key = payload.target.peer_id.borsh;
    if (key.length !== 33 || key[0] !== 0) throw new Error("invalid routed_v3 target key");
    target = { type: "peer_id", bytes: key.subarray(1) };
  } else if (payload.target?.hash)
    target = { type: "hash", bytes: bytes32(payload.target.hash.hash) };
  else throw new Error("missing routed_v3 target");
  const bodyBytes = body.subarray(2);
  const hash = routedHash(
    target,
    author.subarray(1),
    Buffer.concat([Buffer.from([bodyType]), bodyBytes]),
  );
  return {
    target,
    author: author.subarray(1),
    signature: signature.subarray(1),
    ttl: payload.ttl ?? 0,
    bodyType,
    bodyBytes,
    hash,
    signatureValid: verifyEd25519(author.subarray(1), hash, signature.subarray(1)),
  };
}

function uint64(value: bigint | number): bigint {
  if (typeof value === "number" && !Number.isSafeInteger(value))
    throw new Error("unsafe u64 number");
  const integer = BigInt(value);
  if (integer < 0n || integer > 0xffffffffffffffffn) throw new Error("u64 out of range");
  return integer;
}
export function encodeReceiptRequest(hash: Uint8Array | string, shardId: number | bigint): Buffer {
  return Buffer.concat([
    Buffer.from([11]),
    encode(chunkRequest, {
      chunk_hash: bytes32(hash),
      part_ords: [],
      tracking_shards: new Set([uint64(shardId)]),
    }),
  ]);
}

export function encodePong(nonce: bigint, source: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from([15]),
    encode(Borsh.U64, uint64(nonce)),
    publicKeyBorsh(source),
  ]);
}

// The schemas own Borsh layouts, limits and captured bytes; no parallel parser.
export const encode = <A, I>(schema: Schema.Codec<A, I>, value: NoInfer<A>) =>
  Schema.encodeSync(Borsh.toCodec(schema, wireLimits))(value);
export const decode = <A, I>(schema: Schema.Codec<A, I>, bytes: Uint8Array) =>
  Schema.decodeSync(Borsh.toCodec(schema, wireLimits))(bytes);
const decodeRoutedHeader = Borsh.decodePrefixSync(RoutedHeaderSchema, wireLimits);

function combine(a: Uint8Array, c: Uint8Array): Uint8Array {
  return sha256(Buffer.concat([a, c]));
}
function equal(a: Uint8Array, c: Uint8Array): boolean {
  return a.length === c.length && timingSafeEqual(a, c);
}

export function decodeChunkResponse(bytes: Uint8Array) {
  const response = decode(ChunkResponseSchema, bytes);
  return {
    chunkHash: response.chunkHash,
    receipts: response.receipts.map(({ receipts, ...proof }) => ({
      ...proof,
      receipts: receipts.value,
      receiptBytes: receipts.bytes,
    })),
  };
}
export type DecodedReceiptProof = ReturnType<typeof decodeChunkResponse>["receipts"][number];

/**
 * Match ReceiptProof::verify_against_receipt_root: hash Borsh(toShardId,
 * Vec<Receipt>) using the original byte span, then hash that 32-byte digest
 * again: Rust verify_path hashes its CryptoHash item before traversing the path.
 * fromShardId is not committed by that hash and MUST be checked separately.
 * This proves membership against a supplied header, not its finality, execution,
 * or that every receipt addressed to the contract has been delivered.
 */
export function verifyReceiptProof(
  receipt: DecodedReceiptProof,
  root: Uint8Array,
  headerShardId: bigint,
  targetShardId: bigint,
): boolean {
  if (
    receipt.fromShardId !== headerShardId ||
    receipt.toShardId !== targetShardId ||
    root.length !== 32
  )
    return false;
  const hash = createHash("sha256")
    .update(encode(Borsh.U64, receipt.toShardId))
    .update(receipt.receiptBytes)
    .digest();
  return verifyMerklePath(sha256(hash), receipt.proof, root);
}
export function verifyMerklePath(
  leafHash: Uint8Array,
  proof: MerklePath,
  root: Uint8Array,
): boolean {
  let hash = leafHash;
  for (const item of proof)
    hash = item.direction._tag === "Left" ? combine(item.hash, hash) : combine(hash, item.hash);
  return equal(hash, root);
}
export function decodeBlock(bytes: Uint8Array) {
  const { header, body } = decode(BlockSchema, bytes);
  const lite = header.innerLite.value;
  const rest = header.innerRest.value;
  const bodyHash = sha256(body.bytes);
  if (!equal(bodyHash, rest.blockBodyHash)) {
    throw new Error("block body hash mismatch");
  }
  const chunks = body.value.chunks.map(({ inner, heightIncluded, signature }) => ({
    ...inner.value,
    version: 3,
    innerVersion: inner.value._tag === "V4" ? 4 : 5,
    heightIncluded,
    signature,
    chunkHash: combine(sha256(inner.bytes), inner.value.encodedMerkleRoot),
  }));
  return {
    hash: combine(
      combine(sha256(header.innerLite.bytes), sha256(header.innerRest.bytes)),
      header.prevHash,
    ),
    height: lite.height,
    prevHash: header.prevHash,
    lastFinalBlock: rest.lastFinalBlock,
    timestamp: lite.timestamp,
    headerVersion: header._tag === "V5" ? 5 : 6,
    protocolVersion: rest.latestProtocolVersion,
    chunks,
    signature: header.signature,
    innerLite: lite,
    innerRest: rest,
    bodyHash,
    vrfValue: body.value.vrfValue,
    vrfProof: body.value.vrfProof,
    chunkEndorsements: body.value.chunkEndorsements,
  };
}
export type ChunkHeader = ReturnType<typeof decodeBlock>["chunks"][number];
