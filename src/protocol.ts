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
import { b, type Schema as BorshSchema } from "@zorsh/zorsh";
import { Schema } from "effect";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const edgeSchema = b.struct({ first: b.bytes(33), second: b.bytes(33), nonce: b.u64() });

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
    edgeSchema.serialize(
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
      b.u64().serialize(nonce),
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

const BorshPayload = Schema.Struct({ borsh: Schema.Uint8Array });
const HashPayload = Schema.Struct({ hash: Schema.Uint8Array });
const GenesisId = Schema.Struct({ chain_id: Schema.String, hash: HashPayload });
export const HandshakePayload = Schema.Struct({
  protocol_version: Schema.Number,
  oldest_supported_version: Schema.Number,
  sender_peer_id: BorshPayload,
  target_peer_id: BorshPayload,
  sender_listen_port: Schema.optionalKey(Schema.Number),
  sender_chain_info: Schema.Struct({
    genesis_id: GenesisId,
    height: Schema.optionalKey(Schema.String),
    tracked_shards: Schema.optionalKey(Schema.Array(Schema.String)),
    archival: Schema.optionalKey(Schema.Boolean),
  }),
  partial_edge_info: BorshPayload,
});
export interface HandshakePayload extends Schema.Schema.Type<typeof HandshakePayload> {}
const RoutedV3Payload = Schema.Struct({
  target: Schema.Struct({
    peer_id: Schema.optionalKey(BorshPayload),
    hash: Schema.optionalKey(HashPayload),
  }),
  author: BorshPayload,
  ttl: Schema.optionalKey(Schema.Number),
  borsh_body: Schema.Uint8Array,
  signature: Schema.optionalKey(BorshPayload),
});
const KnownWireMessage = Schema.Union([
  Schema.Struct({ type: Schema.tag("tier2_handshake"), payload: HandshakePayload }),
  Schema.Struct({
    type: Schema.tag("handshake_failure"),
    payload: Schema.Struct({
      reason: Schema.Number,
      version: Schema.optionalKey(Schema.Number),
      oldest_supported_version: Schema.optionalKey(Schema.Number),
      genesis_id: Schema.optionalKey(GenesisId),
    }),
  }),
  Schema.Struct({
    type: Schema.tag("block_response"),
    payload: Schema.Struct({ block: BorshPayload }),
  }),
  Schema.Struct({
    type: Schema.tag("routed"),
    payload: BorshPayload,
  }),
  Schema.Struct({ type: Schema.tag("routed_v3"), payload: RoutedV3Payload }),
]);
export type WireMessage =
  | Schema.Schema.Type<typeof KnownWireMessage>
  | { type: "unsupported"; name: string; payload: Record<string, unknown> };

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
  const populated = peerMessageFields.filter((field) => decoded[field] != null);
  if (populated.length > 1) throw new Error("peer envelope has multiple message variants");
  const name = populated[0];
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
  const cursor = new Cursor(bytes);
  const targetType = cursor.byte();
  let target: RoutedTarget;
  if (targetType === 0) {
    if (cursor.byte() !== 0) throw new Error("unsupported routed target key type");
    target = { type: "peer_id", bytes: cursor.take(32) };
  } else if (targetType === 1) {
    target = { type: "hash", bytes: cursor.take(32) };
  } else throw new Error("invalid routed target tag");
  if (cursor.byte() !== 0) throw new Error("unsupported routed author key type");
  const author = cursor.take(32);
  if (cursor.byte() !== 0) throw new Error("unsupported routed signature type");
  const signature = cursor.take(64);
  const ttl = cursor.byte();
  const bodyType = cursor.byte();
  const bodyBytes = bytes.subarray(cursor.offset);
  const hash = routedHash(target, author, bytes.subarray(cursor.offset - 1));
  return {
    target,
    author,
    signature,
    ttl,
    bodyType,
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

const chunkRequest = b.struct({
  chunk_hash: b.bytes(32),
  part_ords: b.vec(b.u64()),
  tracking_shards: b.hashSet(b.u64()),
});
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
    chunkRequest.serialize({
      chunk_hash: bytes32(hash),
      part_ords: [],
      tracking_shards: new Set([uint64(shardId)]),
    }),
  ]);
}

export function encodePong(nonce: bigint, source: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from([15]),
    b.u64().serialize(uint64(nonce)),
    publicKeyBorsh(source),
  ]);
}

const MAX_PAYLOAD = 16 * 1024 * 1024;
const MAX_ITEMS = 16_384;
const MAX_NODES = 200_000;
const Hash = b.bytes(32);
const PublicKey = b.enum({ Ed25519: b.bytes(32), Secp256k1: b.bytes(64), MlDsa65: b.bytes(1952) });
const Signature = b.enum({ Ed25519: b.bytes(64), Secp256k1: b.bytes(65), MlDsa65: b.bytes(3309) });
const ValidatorStake = b.enum({
  V1: b.struct({ accountId: b.string(), publicKey: PublicKey, stake: b.u128() }),
});
const SlashedValidator = b.struct({ accountId: b.string(), isDoubleSign: b.bool() });

// Zorsh 0.5.2 validates Borsh tags and UTF-8. This preflight adds our resource
// limits and locates field boundaries; end() rejects trailing message bytes.
type Shape = { type: string; options: unknown };
class Cursor {
  readonly bytes: Uint8Array;
  offset = 0;
  private nodes = 0;
  constructor(bytes: Uint8Array) {
    this.bytes = bytes;
    if (bytes.byteLength > MAX_PAYLOAD) throw new Error("borsh payload exceeds 16 MiB");
  }
  take(size: number): Uint8Array {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.bytes.length - this.offset) {
      throw new Error(`truncated borsh payload at offset ${this.offset}`);
    }
    const result = this.bytes.subarray(this.offset, this.offset + size);
    this.offset += size;
    return result;
  }
  byte(): number {
    return this.take(1)[0]!;
  }
  count(label: string): number {
    const value = b.u32().deserialize(this.take(4));
    if (value > MAX_ITEMS) throw new Error(`${label} count ${value} exceeds ${MAX_ITEMS}`);
    return value;
  }
  scan(shape: Shape, depth = 0): void {
    if (++this.nodes > MAX_NODES || depth > 64) throw new Error("borsh structure limit exceeded");
    // Metadata is library-owned and the shapes are fixed locally, never supplied by a peer.
    const o = shape.options as Record<string, any> | null;
    const nested = (type: string, options: unknown) => this.scan({ type, options }, depth + 1);
    const sizes: Record<string, number> = { u8: 1, u16: 2, u32: 4, u64: 8, u128: 16 };
    if (shape.type in sizes) {
      this.take(sizes[shape.type]!);
      return;
    }
    switch (shape.type) {
      case "unit":
        return;
      case "bool":
        this.take(1);
        return;
      case "bytes": {
        const length = o?.length ?? b.u32().deserialize(this.take(4));
        this.take(length);
        return;
      }
      case "string": {
        const length = b.u32().deserialize(this.take(4));
        if (length > 1_048_576) throw new Error("borsh string exceeds 1 MiB");
        this.take(length);
        return;
      }
      case "struct":
        for (const field of Object.values(o!)) nested(field.type, field.options);
        return;
      case "vec": {
        const length = this.count("vector");
        for (let i = 0; i < length; i++) nested(o!.elementType, o!.elementOptions);
        return;
      }
      case "option": {
        if (this.byte() === 1) nested(o!.valueType, o!.valueOptions);
        return;
      }
      case "enum": {
        const tag = this.byte();
        const variant = o!.variants.find((v: { index: number }) => v.index === tag);
        if (!variant || variant.name.startsWith("Unsupported")) {
          throw new Error(
            `unsupported borsh enum variant ${tag}${variant ? ` (${variant.name})` : ""}`,
          );
        }
        nested(variant.type, variant.options);
        return;
      }
      default:
        throw new Error(`unsupported schema kind ${shape.type}`);
    }
  }
  read<T>(schema: BorshSchema<T>): T {
    const start = this.offset;
    this.scan(schema);
    return schema.deserialize(this.bytes.subarray(start, this.offset));
  }
  end(): void {
    if (this.offset !== this.bytes.length)
      throw new Error(`trailing borsh bytes: ${this.bytes.length - this.offset}`);
  }
}

function combine(a: Uint8Array, c: Uint8Array): Uint8Array {
  return sha256(Buffer.concat([a, c]));
}
function equal(a: Uint8Array, c: Uint8Array): boolean {
  return a.length === c.length && timingSafeEqual(a, c);
}

const FunctionCallPermission = b.struct({
  allowance: b.option(b.u128()),
  receiverId: b.string(),
  methodNames: b.vec(b.string()),
});
const GasKeyInfo = b.struct({ balance: b.u128(), numNonces: b.u16() });
const AccessKeyPermission = b.enum({
  FunctionCall: FunctionCallPermission,
  FullAccess: b.unit(),
  GasKeyFunctionCall: b.struct({ gasKey: GasKeyInfo, permission: FunctionCallPermission }),
  GasKeyFullAccess: GasKeyInfo,
});
const GlobalContractIdentifier = b.enum({ CodeHash: Hash, AccountId: b.string() });
const TransactionNonce = b.enum({
  Nonce: b.struct({ nonce: b.u64() }),
  GasKeyNonce: b.struct({ nonce: b.u64(), nonceIndex: b.u16() }),
});
const basicActions = {
  CreateAccount: b.unit(),
  DeployContract: b.struct({ code: b.bytes() }),
  FunctionCall: b.struct({
    methodName: b.string(),
    args: b.bytes(),
    gas: b.u64(),
    deposit: b.u128(),
  }),
  Transfer: b.struct({ deposit: b.u128() }),
  Stake: b.struct({ stake: b.u128(), publicKey: PublicKey }),
  AddKey: b.struct({
    publicKey: PublicKey,
    accessKey: b.struct({ nonce: b.u64(), permission: AccessKeyPermission }),
  }),
  DeleteKey: b.struct({ publicKey: PublicKey }),
  DeleteAccount: b.struct({ beneficiaryId: b.string() }),
};
const extendedActions = {
  DeployGlobalContract: b.struct({
    code: b.bytes(),
    deployMode: b.enum({ CodeHash: b.unit(), AccountId: b.unit() }),
  }),
  UseGlobalContract: b.struct({ contractIdentifier: GlobalContractIdentifier }),
  DeterministicStateInit: b.struct({
    stateInit: b.enum({
      V1: b.struct({
        code: GlobalContractIdentifier,
        data: b.vec(b.struct({ key: b.bytes(), value: b.bytes() })),
      }),
    }),
    deposit: b.u128(),
  }),
  TransferToGasKey: b.struct({ publicKey: PublicKey, deposit: b.u128() }),
  WithdrawFromGasKey: b.struct({ publicKey: PublicKey, amount: b.u128() }),
};
const UniversalStateInit = b.struct({ stateInit: b.bytes(), deposit: b.u128() });
// NonDelegateAction has the same tags as Action, but rejects tags 8 and 14.
// Placeholder variants preserve the wire indices and Cursor rejects them.
const NonDelegateAction = b.enum({
  ...basicActions,
  UnsupportedNestedDelegate: b.unit(),
  ...extendedActions,
  UnsupportedNestedDelegateV2: b.unit(),
  UniversalStateInit,
});
const delegatePrefix = {
  senderId: b.string(),
  receiverId: b.string(),
  actions: b.vec(NonDelegateAction),
};
const delegateTail = { maxBlockHeight: b.u64(), publicKey: PublicKey };
const ActionSchema = b.enum({
  ...basicActions,
  Delegate: b.struct({
    delegateAction: b.struct({ ...delegatePrefix, nonce: b.u64(), ...delegateTail }),
    signature: Signature,
  }),
  ...extendedActions,
  DelegateV2: b.struct({
    delegateAction: b.enum({
      V2: b.struct({ ...delegatePrefix, nonce: TransactionNonce, ...delegateTail }),
    }),
    signature: Signature,
  }),
  UniversalStateInit,
});
const DataReceiver = b.struct({ dataId: Hash, receiverId: b.string() });
const ActionReceiptTail = {
  signerPublicKey: PublicKey,
  gasPrice: b.u128(),
  outputDataReceivers: b.vec(DataReceiver),
  inputDataIds: b.vec(Hash),
  actions: b.vec(ActionSchema),
};
const ActionReceipt = b.struct({ signerId: b.string(), ...ActionReceiptTail });
const ActionReceiptV2 = b.struct({
  signerId: b.string(),
  refundTo: b.option(b.string()),
  ...ActionReceiptTail,
});
const DataReceipt = b.struct({ dataId: Hash, data: b.option(b.bytes()) });
const GlobalDistributionFields = {
  id: GlobalContractIdentifier,
  targetShard: b.u64(),
  alreadyDeliveredShards: b.vec(b.u64()),
  code: b.bytes(),
};
const ReceiptSchema = b.struct({
  predecessorId: b.string(),
  receiverId: b.string(),
  receiptId: Hash,
  receipt: b.enum({
    Action: ActionReceipt,
    Data: DataReceipt,
    PromiseYield: ActionReceipt,
    PromiseResume: DataReceipt,
    GlobalContractDistribution: b.enum({
      V1: b.struct(GlobalDistributionFields),
      V2: b.struct({ ...GlobalDistributionFields, nonce: b.u64() }),
    }),
    ActionV2: ActionReceiptV2,
    PromiseYieldV2: ActionReceiptV2,
  }),
});
function readReceipts(cursor: Cursor) {
  const count = cursor.count("receipts");
  return Array.from({ length: count }, () => cursor.read(ReceiptSchema));
}
const MerklePathSchema = b.vec(
  b.struct({ hash: Hash, direction: b.enum({ Left: b.unit(), Right: b.unit() }) }),
);
type MerklePath = b.infer<typeof MerklePathSchema>;
const ChunkPartSchema = b.struct({
  partOrd: b.u64(),
  part: b.bytes(),
  merkleProof: MerklePathSchema,
});
export function decodeChunkResponse(bytes: Uint8Array) {
  const cursor = new Cursor(bytes);
  const chunkHash = cursor.read(Hash);
  // We request receipts only. Skip any parts without allocating decoded objects.
  cursor.scan(b.vec(ChunkPartSchema));
  const count = cursor.count("receipt proofs");
  const receipts = Array.from({ length: count }, () => {
    const start = cursor.offset;
    const receipts = readReceipts(cursor);
    const receiptBytes = cursor.bytes.subarray(start, cursor.offset);
    return {
      receipts,
      receiptBytes,
      fromShardId: cursor.read(b.u64()),
      toShardId: cursor.read(b.u64()),
      proof: cursor.read(MerklePathSchema),
    };
  });
  cursor.end();
  return { chunkHash, receipts };
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
    .update(b.u64().serialize(receipt.toShardId))
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
    hash = "Left" in item.direction ? combine(item.hash, hash) : combine(hash, item.hash);
  return equal(hash, root);
}
const InnerLite = b.struct({
  height: b.u64(),
  epochId: Hash,
  nextEpochId: Hash,
  prevStateRoot: Hash,
  prevOutcomeRoot: Hash,
  timestamp: b.u64(),
  nextBpHash: Hash,
  blockMerkleRoot: Hash,
});
const RestPrefix = {
  blockBodyHash: Hash,
  prevChunkOutgoingReceiptsRoot: Hash,
  chunkHeadersRoot: Hash,
  chunkTxRoot: Hash,
};
const RestMiddle = {
  randomValue: Hash,
  prevValidatorProposals: b.vec(ValidatorStake),
  chunkMask: b.vec(b.bool()),
  nextGasPrice: b.u128(),
  totalSupply: b.u128(),
};
const RestTail = {
  lastFinalBlock: Hash,
  lastDsFinalBlock: Hash,
  blockOrdinal: b.u64(),
  prevHeight: b.u64(),
  epochSyncDataHash: b.option(Hash),
  approvals: b.vec(b.option(Signature)),
  latestProtocolVersion: b.u32(),
  chunkEndorsements: b.vec(b.bytes()),
};
const InnerRestV5 = b.struct({
  ...RestPrefix,
  challengesRoot: Hash,
  ...RestMiddle,
  challengesResult: b.vec(SlashedValidator),
  ...RestTail,
});
const InnerRestV6 = b.struct({
  ...RestPrefix,
  ...RestMiddle,
  ...RestTail,
  shardSplit: b.option(b.struct({ shardId: b.u64(), accountId: b.string() })),
});
const ChunkInnerPrefix = {
  prevBlockHash: Hash,
  prevStateRoot: Hash,
  prevOutcomeRoot: Hash,
  encodedMerkleRoot: Hash,
  encodedLength: b.u64(),
  heightCreated: b.u64(),
  shardId: b.u64(),
  prevGasUsed: b.u64(),
  gasLimit: b.u64(),
  prevBalanceBurnt: b.u128(),
  receiptRoot: Hash,
  txRoot: Hash,
  prevValidatorProposals: b.vec(ValidatorStake),
  congestionInfo: b.enum({
    V1: b.struct({
      delayedReceiptsGas: b.u128(),
      bufferedReceiptsGas: b.u128(),
      receiptBytes: b.u64(),
      allowedShard: b.u16(),
    }),
  }),
  bandwidthRequests: b.enum({
    V1: b.struct({
      requests: b.vec(b.struct({ toShard: b.u16(), requestedValuesBitmap: b.bytes(5) })),
    }),
  }),
};
const ChunkInnerV4 = b.struct(ChunkInnerPrefix);
const ChunkInnerV5 = b.struct({
  ...ChunkInnerPrefix,
  proposedSplit: b.option(
    b.struct({ boundaryAccount: b.string(), leftMemory: b.u64(), rightMemory: b.u64() }),
  ),
});
function readChunkHeader(cursor: Cursor) {
  const version = cursor.byte();
  if (version !== 2)
    throw new Error(`unsupported chunk header version ${version}; expected V3 tag 2`);
  const start = cursor.offset;
  const innerVersion = cursor.byte();
  if (innerVersion !== 3 && innerVersion !== 4)
    throw new Error(`unsupported chunk inner version ${innerVersion}; expected V4/V5`);
  const inner = innerVersion === 3 ? cursor.read(ChunkInnerV4) : cursor.read(ChunkInnerV5);
  const innerHash = sha256(cursor.bytes.subarray(start, cursor.offset));
  const heightIncluded = cursor.read(b.u64());
  const signature = cursor.read(Signature);
  return {
    ...inner,
    version: version + 1,
    innerVersion: innerVersion + 1,
    heightIncluded,
    signature,
    chunkHash: combine(innerHash, inner.encodedMerkleRoot),
  };
}
export type ChunkHeader = ReturnType<typeof readChunkHeader>;
export function decodeBlock(bytes: Uint8Array) {
  const cursor = new Cursor(bytes);
  const version = cursor.byte();
  if (version !== 3)
    throw new Error(`unsupported block version ${version}; expected BlockV4 tag 3`);
  const headerVersion = cursor.byte();
  if (headerVersion !== 4 && headerVersion !== 5)
    throw new Error(`unsupported block header version ${headerVersion}; expected V5/V6`);
  const prevHash = cursor.read(Hash);
  const liteStart = cursor.offset;
  const lite = cursor.read(InnerLite);
  const liteHash = sha256(cursor.bytes.subarray(liteStart, cursor.offset));
  const restStart = cursor.offset;
  const rest = headerVersion === 4 ? cursor.read(InnerRestV5) : cursor.read(InnerRestV6);
  const restHash = sha256(cursor.bytes.subarray(restStart, cursor.offset));
  const signature = cursor.read(Signature);
  const bodyStart = cursor.offset;
  const bodyVersion = cursor.byte();
  if (bodyVersion !== 1)
    throw new Error(`unsupported block body version ${bodyVersion}; expected V2 tag 1`);
  const count = cursor.count("chunk headers");
  const chunks = Array.from({ length: count }, () => readChunkHeader(cursor));
  if (cursor.count("challenges") !== 0)
    throw new Error("nonempty deprecated challenges are unsupported");
  const vrfValue = cursor.read(b.bytes(32));
  const vrfProof = cursor.read(b.bytes(64));
  const chunkEndorsements = cursor.read(b.vec(b.vec(b.option(Signature))));
  cursor.end();
  const bodyHash = sha256(bytes.subarray(bodyStart));
  if (!equal(bodyHash, rest.blockBodyHash)) throw new Error("block body hash mismatch");
  return {
    hash: combine(combine(liteHash, restHash), prevHash),
    height: lite.height,
    prevHash,
    lastFinalBlock: rest.lastFinalBlock,
    timestamp: lite.timestamp,
    headerVersion: headerVersion + 1,
    protocolVersion: rest.latestProtocolVersion,
    chunks,
    signature,
    innerLite: lite,
    innerRest: rest,
    bodyHash,
    vrfValue,
    vrfProof,
    chunkEndorsements,
  };
}
