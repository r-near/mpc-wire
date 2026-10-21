/** NEAR wire and RPC schemas. No transport, cryptography or MPC dependencies. */
import { b } from "@zorsh/zorsh";
import { Schema } from "effect";

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

export const edgeSchema = b.struct({ first: b.bytes(33), second: b.bytes(33), nonce: b.u64() });
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
export const chunkRequest = b.struct({
  chunk_hash: b.bytes(32),
  part_ords: b.vec(b.u64()),
  tracking_shards: b.hashSet(b.u64()),
});
export const Hash = b.bytes(32);
const PublicKey = b.enum({ Ed25519: b.bytes(32), Secp256k1: b.bytes(64), MlDsa65: b.bytes(1952) });
export const Signature = b.enum({
  Ed25519: b.bytes(64),
  Secp256k1: b.bytes(65),
  MlDsa65: b.bytes(3309),
});
const ValidatorStake = b.enum({
  V1: b.struct({ accountId: b.string(), publicKey: PublicKey, stake: b.u128() }),
});
const SlashedValidator = b.struct({ accountId: b.string(), isDoubleSign: b.bool() });
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
export const ActionSchema = b.enum({
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
export const ReceiptSchema = b.struct({
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
export const MerklePathSchema = b.vec(
  b.struct({ hash: Hash, direction: b.enum({ Left: b.unit(), Right: b.unit() }) }),
);
export type MerklePath = b.infer<typeof MerklePathSchema>;
export const ChunkPartSchema = b.struct({
  partOrd: b.u64(),
  part: b.bytes(),
  merkleProof: MerklePathSchema,
});
export const InnerLite = b.struct({
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
export const InnerRestV5 = b.struct({
  ...RestPrefix,
  challengesRoot: Hash,
  ...RestMiddle,
  challengesResult: b.vec(SlashedValidator),
  ...RestTail,
});
export const InnerRestV6 = b.struct({
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
export const ChunkInnerV4 = b.struct(ChunkInnerPrefix);
export const ChunkInnerV5 = b.struct({
  ...ChunkInnerPrefix,
  proposedSplit: b.option(
    b.struct({ boundaryAccount: b.string(), leftMemory: b.u64(), rightMemory: b.u64() }),
  ),
});

export type Action = b.infer<typeof ActionSchema>;
export type Receipt = b.infer<typeof ReceiptSchema>;
export const ReceiptsSchema = b.vec(ReceiptSchema);
export const ReceiptProofSchema = b.struct({
  receipts: ReceiptsSchema,
  fromShardId: b.u64(),
  toShardId: b.u64(),
  proof: MerklePathSchema,
});
export const ChunkResponseSchema = b.struct({
  chunkHash: Hash,
  parts: b.vec(ChunkPartSchema),
  receipts: b.vec(ReceiptProofSchema),
});

// Unsupported placeholders retain nearcore's enum indices. The bounded decoder
// rejects them; adding a version means defining its actual layout here.
export const ChunkInnerSchema = b.enum({
  UnsupportedV1: b.unit(),
  UnsupportedV2: b.unit(),
  UnsupportedV3: b.unit(),
  V4: ChunkInnerV4,
  V5: ChunkInnerV5,
});
export const ChunkHeaderSchema = b.enum({
  UnsupportedV1: b.unit(),
  UnsupportedV2: b.unit(),
  V3: b.struct({ inner: ChunkInnerSchema, heightIncluded: b.u64(), signature: Signature }),
});
const headerFields = { prevHash: Hash, innerLite: InnerLite };
export const BlockHeaderSchema = b.enum({
  UnsupportedV1: b.unit(),
  UnsupportedV2: b.unit(),
  UnsupportedV3: b.unit(),
  UnsupportedV4: b.unit(),
  V5: b.struct({ ...headerFields, innerRest: InnerRestV5, signature: Signature }),
  V6: b.struct({ ...headerFields, innerRest: InnerRestV6, signature: Signature }),
});
export const BlockBodySchema = b.enum({
  UnsupportedV1: b.unit(),
  V2: b.struct({
    chunks: b.vec(ChunkHeaderSchema),
    // The reader supports only an empty deprecated challenges vector.
    challenges: b.vec(b.unit()),
    vrfValue: b.bytes(32),
    vrfProof: b.bytes(64),
    chunkEndorsements: b.vec(b.vec(b.option(Signature))),
  }),
});
export const BlockSchema = b.enum({
  UnsupportedV1: b.unit(),
  UnsupportedV2: b.unit(),
  UnsupportedV3: b.unit(),
  V4: b.struct({ header: BlockHeaderSchema, body: BlockBodySchema }),
});
