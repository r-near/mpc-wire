/** NEAR wire and RPC schemas. No transport, cryptography or MPC dependencies. */
import { Borsh } from "@zorsh/effect";
import { Effect, Schema, SchemaIssue, SchemaTransformation } from "effect";

export const wireLimits = { maxBytes: 16 * 1024 * 1024, maxItems: 16_384 };
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
// A Borsh string is a byte vector. Bound its encoded bytes before UTF-8 decoding.
export const WireString = Borsh.Bytes.check(
  Schema.isMaxLength(1_048_576, { expected: "string at most 1 MiB" }),
).pipe(
  Schema.decodeTo(
    Schema.String.check(
      Schema.makeFilter((value) => value.isWellFormed(), {
        expected: "well-formed Unicode",
      }),
    ),
    SchemaTransformation.transformEffect({
      decode: (bytes) =>
        Effect.try({
          try: () => utf8.decode(bytes),
          catch: () => new SchemaIssue.InvalidValue({ message: "invalid UTF-8" }),
        }),
      encode: (value) => Effect.succeed(encoder.encode(value)),
    }),
  ),
);

export const TESTNET_GENESIS = "FWJ9kR6KFWoyMoNjpLXXGHeuiy7tEY6GmoFeCA5yuc6b";
export const Uint = Schema.Int.check(
  Schema.isBetween({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
);
export const TestnetStatus = Schema.Struct({
  chain_id: Schema.Literal("testnet"),
  genesis_hash: Schema.Literal(TESTNET_GENESIS),
});
export const RpcBlock = Schema.Struct({
  header: Schema.Struct({ hash: Schema.String, height: Uint, epoch_id: Schema.String }),
});
export const RpcProtocol = Schema.Struct({
  protocol_version: Uint,
  shard_layout: Schema.Struct({
    V3: Schema.Struct({
      boundary_accounts: Schema.Array(Schema.String),
      shard_ids: Schema.Array(Uint),
    }),
  }),
});
export const RpcNetwork = Schema.Struct({
  active_peers: Schema.Array(Schema.Struct({ id: Schema.String, addr: Schema.String })),
});

export const edgeSchema = Schema.Struct({
  first: Borsh.fixedBytes(33),
  second: Borsh.fixedBytes(33),
  nonce: Borsh.U64,
});
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
export const RoutedV3Payload = Schema.Struct({
  target: Schema.Struct({
    peer_id: Schema.optionalKey(BorshPayload),
    hash: Schema.optionalKey(HashPayload),
  }),
  author: BorshPayload,
  ttl: Schema.optionalKey(Schema.Number),
  borsh_body: Schema.Uint8Array,
  signature: Schema.optionalKey(BorshPayload),
});
export const KnownWireMessage = Schema.Union([
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
export const chunkRequest = Schema.Struct({
  chunk_hash: Borsh.fixedBytes(32),
  part_ords: Schema.Array(Borsh.U64),
  tracking_shards: Schema.ReadonlySet(Borsh.U64),
});
export const Hash = Borsh.fixedBytes(32);
const Ed25519Key = Schema.TaggedUnion({ Ed25519: { value: Hash } });
const Ed25519Signature = Schema.TaggedUnion({ Ed25519: { value: Borsh.fixedBytes(64) } });
export const RoutedHeaderSchema = Schema.Struct({
  target: Schema.TaggedUnion({ PeerId: { key: Ed25519Key }, Hash: { hash: Hash } }),
  author: Ed25519Key,
  signature: Ed25519Signature,
  ttl: Borsh.U8,
  bodyType: Borsh.U8,
});
const PublicKey = Schema.TaggedUnion({
  Ed25519: { value: Borsh.fixedBytes(32) },
  Secp256k1: { value: Borsh.fixedBytes(64) },
  MlDsa65: { value: Borsh.fixedBytes(1952) },
});
export const Signature = Schema.TaggedUnion({
  Ed25519: { value: Borsh.fixedBytes(64) },
  Secp256k1: { value: Borsh.fixedBytes(65) },
  MlDsa65: { value: Borsh.fixedBytes(3309) },
});
const ValidatorStake = Schema.TaggedUnion({
  V1: { accountId: WireString, publicKey: PublicKey, stake: Borsh.U128 },
});
const SlashedValidator = Schema.Struct({ accountId: WireString, isDoubleSign: Schema.Boolean });
const FunctionCallPermission = Schema.Struct({
  allowance: Schema.Option(Borsh.U128),
  receiverId: WireString,
  methodNames: Schema.Array(WireString),
});
const GasKeyInfo = Schema.Struct({ balance: Borsh.U128, numNonces: Borsh.U16 });
const AccessKeyPermission = Schema.TaggedUnion({
  FunctionCall: { ...FunctionCallPermission.fields },
  FullAccess: {},
  GasKeyFunctionCall: { gasKey: GasKeyInfo, permission: FunctionCallPermission },
  GasKeyFullAccess: { ...GasKeyInfo.fields },
});
const GlobalContractIdentifier = Schema.TaggedUnion({
  CodeHash: { value: Hash },
  AccountId: { value: WireString },
});
const TransactionNonce = Schema.TaggedUnion({
  Nonce: { nonce: Borsh.U64 },
  GasKeyNonce: { nonce: Borsh.U64, nonceIndex: Borsh.U16 },
});
const basicActions = {
  CreateAccount: {},
  DeployContract: { code: Borsh.Bytes },
  FunctionCall: {
    methodName: WireString,
    args: Borsh.Bytes,
    gas: Borsh.U64,
    deposit: Borsh.U128,
  },
  Transfer: { deposit: Borsh.U128 },
  Stake: { stake: Borsh.U128, publicKey: PublicKey },
  AddKey: {
    publicKey: PublicKey,
    accessKey: Schema.Struct({ nonce: Borsh.U64, permission: AccessKeyPermission }),
  },
  DeleteKey: { publicKey: PublicKey },
  DeleteAccount: { beneficiaryId: WireString },
};
const extendedActions = {
  DeployGlobalContract: {
    code: Borsh.Bytes,
    deployMode: Schema.TaggedUnion({ CodeHash: {}, AccountId: {} }),
  },
  UseGlobalContract: { contractIdentifier: GlobalContractIdentifier },
  DeterministicStateInit: {
    stateInit: Schema.TaggedUnion({
      V1: {
        code: GlobalContractIdentifier,
        data: Schema.Array(Schema.Struct({ key: Borsh.Bytes, value: Borsh.Bytes })),
      },
    }),
    deposit: Borsh.U128,
  },
  TransferToGasKey: { publicKey: PublicKey, deposit: Borsh.U128 },
  WithdrawFromGasKey: { publicKey: PublicKey, amount: Borsh.U128 },
};
const UniversalStateInit = Schema.Struct({ stateInit: Borsh.Bytes, deposit: Borsh.U128 });
// NonDelegateAction uses Action's tags, with delegation (8 and 14) omitted.
const NonDelegateAction = Schema.TaggedUnion({
  ...basicActions,
  ...extendedActions,
  UniversalStateInit: { ...UniversalStateInit.fields },
}).pipe(
  Borsh.discriminants({
    CreateAccount: 0,
    DeployContract: 1,
    FunctionCall: 2,
    Transfer: 3,
    Stake: 4,
    AddKey: 5,
    DeleteKey: 6,
    DeleteAccount: 7,
    DeployGlobalContract: 9,
    UseGlobalContract: 10,
    DeterministicStateInit: 11,
    TransferToGasKey: 12,
    WithdrawFromGasKey: 13,
    UniversalStateInit: 15,
  }),
);
const delegatePrefix = {
  senderId: WireString,
  receiverId: WireString,
  actions: Schema.Array(NonDelegateAction),
};
const delegateTail = { maxBlockHeight: Borsh.U64, publicKey: PublicKey };
export const ActionSchema = Schema.TaggedUnion({
  ...basicActions,
  Delegate: {
    delegateAction: Schema.Struct({ ...delegatePrefix, nonce: Borsh.U64, ...delegateTail }),
    signature: Signature,
  },
  ...extendedActions,
  DelegateV2: {
    delegateAction: Schema.TaggedUnion({
      V2: { ...delegatePrefix, nonce: TransactionNonce, ...delegateTail },
    }),
    signature: Signature,
  },
  UniversalStateInit: { ...UniversalStateInit.fields },
});
const DataReceiver = Schema.Struct({ dataId: Hash, receiverId: WireString });
const ActionReceiptTail = {
  signerPublicKey: PublicKey,
  gasPrice: Borsh.U128,
  outputDataReceivers: Schema.Array(DataReceiver),
  inputDataIds: Schema.Array(Hash),
  actions: Schema.Array(ActionSchema),
};
const ActionReceipt = Schema.Struct({ signerId: WireString, ...ActionReceiptTail });
const ActionReceiptV2 = Schema.Struct({
  signerId: WireString,
  refundTo: Schema.Option(WireString),
  ...ActionReceiptTail,
});
const DataReceipt = Schema.Struct({ dataId: Hash, data: Schema.Option(Borsh.Bytes) });
const GlobalDistributionFields = {
  id: GlobalContractIdentifier,
  targetShard: Borsh.U64,
  alreadyDeliveredShards: Schema.Array(Borsh.U64),
  code: Borsh.Bytes,
};
export const ReceiptSchema = Schema.Struct({
  predecessorId: WireString,
  receiverId: WireString,
  receiptId: Hash,
  receipt: Schema.TaggedUnion({
    Action: { ...ActionReceipt.fields },
    Data: { ...DataReceipt.fields },
    PromiseYield: { ...ActionReceipt.fields },
    PromiseResume: { ...DataReceipt.fields },
    GlobalContractDistribution: {
      value: Schema.TaggedUnion({
        V1: GlobalDistributionFields,
        V2: { ...GlobalDistributionFields, nonce: Borsh.U64 },
      }),
    },
    ActionV2: { ...ActionReceiptV2.fields },
    PromiseYieldV2: { ...ActionReceiptV2.fields },
  }),
});
export const MerklePathSchema = Schema.Array(
  Schema.Struct({ hash: Hash, direction: Schema.TaggedUnion({ Left: {}, Right: {} }) }),
);
export type MerklePath = typeof MerklePathSchema.Type;
export const ChunkPartSchema = Schema.Struct({
  partOrd: Borsh.U64,
  part: Borsh.Bytes,
  merkleProof: MerklePathSchema,
});
export const InnerLite = Schema.Struct({
  height: Borsh.U64,
  epochId: Hash,
  nextEpochId: Hash,
  prevStateRoot: Hash,
  prevOutcomeRoot: Hash,
  timestamp: Borsh.U64,
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
  prevValidatorProposals: Schema.Array(ValidatorStake),
  chunkMask: Schema.Array(Schema.Boolean),
  nextGasPrice: Borsh.U128,
  totalSupply: Borsh.U128,
};
const RestTail = {
  lastFinalBlock: Hash,
  lastDsFinalBlock: Hash,
  blockOrdinal: Borsh.U64,
  prevHeight: Borsh.U64,
  epochSyncDataHash: Schema.Option(Hash),
  approvals: Schema.Array(Schema.Option(Signature)),
  latestProtocolVersion: Borsh.U32,
  chunkEndorsements: Schema.Array(Borsh.Bytes),
};
export const InnerRestV5 = Schema.Struct({
  ...RestPrefix,
  challengesRoot: Hash,
  ...RestMiddle,
  challengesResult: Schema.Array(SlashedValidator),
  ...RestTail,
});
export const InnerRestV6 = Schema.Struct({
  ...RestPrefix,
  ...RestMiddle,
  ...RestTail,
  shardSplit: Schema.Option(Schema.Struct({ shardId: Borsh.U64, accountId: WireString })),
});
const ChunkInnerPrefix = {
  prevBlockHash: Hash,
  prevStateRoot: Hash,
  prevOutcomeRoot: Hash,
  encodedMerkleRoot: Hash,
  encodedLength: Borsh.U64,
  heightCreated: Borsh.U64,
  shardId: Borsh.U64,
  prevGasUsed: Borsh.U64,
  gasLimit: Borsh.U64,
  prevBalanceBurnt: Borsh.U128,
  receiptRoot: Hash,
  txRoot: Hash,
  prevValidatorProposals: Schema.Array(ValidatorStake),
  congestionInfo: Schema.TaggedUnion({
    V1: {
      delayedReceiptsGas: Borsh.U128,
      bufferedReceiptsGas: Borsh.U128,
      receiptBytes: Borsh.U64,
      allowedShard: Borsh.U16,
    },
  }),
  bandwidthRequests: Schema.TaggedUnion({
    V1: {
      requests: Schema.Array(
        Schema.Struct({ toShard: Borsh.U16, requestedValuesBitmap: Borsh.fixedBytes(5) }),
      ),
    },
  }),
};
export const ChunkInnerV4 = Schema.Struct(ChunkInnerPrefix);
export const ChunkInnerV5 = Schema.Struct({
  ...ChunkInnerPrefix,
  proposedSplit: Schema.Option(
    Schema.Struct({
      boundaryAccount: WireString,
      leftMemory: Borsh.U64,
      rightMemory: Borsh.U64,
    }),
  ),
});

export type Action = typeof ActionSchema.Type;
export type Receipt = typeof ReceiptSchema.Type;
export const ReceiptsSchema = Schema.Array(ReceiptSchema);
export const ReceiptProofSchema = Schema.Struct({
  receipts: Borsh.withBytes(ReceiptsSchema),
  fromShardId: Borsh.U64,
  toShardId: Borsh.U64,
  proof: MerklePathSchema,
});
export const ChunkResponseSchema = Schema.Struct({
  chunkHash: Hash,
  // Our requests contain no part ordinals; reject unsolicited parts before decoding.
  parts: Schema.Array(ChunkPartSchema).check(Schema.isMaxLength(0)),
  receipts: Schema.Array(ReceiptProofSchema),
});

// Only supported NEAR versions have schemas; their wire tags stay explicit.
export const ChunkInnerSchema = Schema.TaggedUnion({
  V4: { ...ChunkInnerV4.fields },
  V5: { ...ChunkInnerV5.fields },
}).pipe(Borsh.discriminants({ V4: 3, V5: 4 }));
export const ChunkHeaderSchema = Schema.TaggedUnion({
  V3: { inner: Borsh.withBytes(ChunkInnerSchema), heightIncluded: Borsh.U64, signature: Signature },
}).pipe(Borsh.discriminants({ V3: 2 }));
const headerFields = { prevHash: Hash, innerLite: Borsh.withBytes(InnerLite) };
export const BlockHeaderSchema = Schema.TaggedUnion({
  V5: { ...headerFields, innerRest: Borsh.withBytes(InnerRestV5), signature: Signature },
  V6: { ...headerFields, innerRest: Borsh.withBytes(InnerRestV6), signature: Signature },
}).pipe(Borsh.discriminants({ V5: 4, V6: 5 }));
export const BlockBodySchema = Schema.TaggedUnion({
  V2: {
    chunks: Schema.Array(ChunkHeaderSchema),
    // Deprecated challenges must be empty.
    challenges: Schema.Array(Borsh.U8).check(Schema.isMaxLength(0)),
    vrfValue: Borsh.fixedBytes(32),
    vrfProof: Borsh.fixedBytes(64),
    chunkEndorsements: Schema.Array(Schema.Array(Schema.Option(Signature))),
  },
}).pipe(Borsh.discriminants({ V2: 1 }));
export const BlockSchema = Schema.TaggedUnion({
  V4: { header: BlockHeaderSchema, body: Borsh.withBytes(BlockBodySchema) },
}).pipe(Borsh.discriminants({ V4: 3 }));
