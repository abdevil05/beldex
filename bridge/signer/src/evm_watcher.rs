//! EVM watcher (**Phase E.2**, the `l2_tracker` port): reads the wBDX **burn**
//! (`RedeemToNative`) logs from **this member's own** Ethereum JSON-RPC endpoint,
//! waits `E` confirmations, and emits reorg-safe normalized [`ReleaseEvent`]s that
//! feed the session's independent-agreement stage (E.4 → S4).
//!
//! No shared oracle: each committee member runs its own watcher against its own RPC,
//! so a single compromised endpoint cannot fool the committee — honest members on
//! honest RPCs derive identical [`ReleaseEvent::canonical_id`]s; a tampered endpoint
//! diverges and is out-voted (a NACK, never a silent accept).
//!
//! Split for testability, mirroring the rest of the crate: the **decode + reorg
//! gating** (the security-critical logic) is generic over a [`JsonRpcClient`] and
//! exercised with a mock + canned JSON; the real blocking HTTP client
//! ([`HttpJsonRpc`]) is a thin, separately-gated (`evm-watcher-http`) backend.
//!
//! Reorg safety (S9): a burn is [`Final`](crate::watch::Finality::Final) only once
//! it is `confirmations` deep **and** the block that included it still carries the
//! same hash (checked via `eth_getBlockByNumber`); a log whose block reorgs away
//! before finality is **dropped** and never triggers a release signing.
//!
//! The `RedeemToNative(address,uint256,bytes)` event is the canonical burn the wBDX
//! contract (Phase H) will emit; its `topic0` and ABI layout are fixed here so the
//! contract mirrors them.

use crate::chain_registry::{ChainId, ChainRegistry, ChainRow};
use crate::watch::{Observation, ReleaseEvent, Tracker, TrackerUpdate};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, BTreeSet};

/// Bound `eth_getLogs` queries so provider range limits cannot turn a long outage
/// into a permanent watcher stall. Catch-up continues one chunk per service tick.
pub const MAX_LOG_BLOCK_RANGE: u64 = 2_000;

/// The wBDX burn event signature; `topic0` is its keccak256.
pub const REDEEM_EVENT_SIG: &[u8] = b"RedeemToNative(address,uint256,bytes)";

/// `topic0` = keccak256(event signature) — the first log topic to filter on.
pub fn redeem_topic0() -> [u8; 32] {
    Keccak256::digest(REDEEM_EVENT_SIG).into()
}

/// The wBDX signer-rotation event signature (H.6). Emitted by both `activateRotation`
/// and the admin break-glass, so a single decoder covers every gate-relevant key move
/// (H.6.3). `topic0` is its keccak256.
pub const ROTATED_EVENT_SIG: &[u8] = b"Rotated(address,uint64)";

/// `topic0` = keccak256(`ROTATED_EVENT_SIG`).
pub fn rotated_topic0() -> [u8; 32] {
    Keccak256::digest(ROTATED_EVENT_SIG).into()
}

/// JSON-RPC transport / protocol failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// Network / client error (stringified to stay dep-free in the interface).
    Transport(String),
    /// A JSON-RPC `error` object from the node.
    Rpc { code: i64, message: String },
    /// A malformed or unexpected response shape.
    BadResponse(String),
}

/// A single burn log failed to decode (skipped, never fatal to the scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    MissingField(&'static str),
    BadHex,
    /// Amount exceeds `u128` (a `uint256` with non-zero high 128 bits).
    AmountOverflow,
    /// EVM log index does not fit the native/contract uint32 identity field.
    IndexOverflow,
    /// `topics[0]` is not the `RedeemToNative` topic.
    WrongTopic,
    /// The log is from a contract other than this chain's wBDX.
    ForeignContract,
}

/// A minimal Ethereum JSON-RPC client. `call` returns the JSON-RPC **result** value
/// (the impl unwraps the envelope / surfaces `error`). Generic so the watcher's
/// decode + reorg logic is testable against a mock.
pub trait JsonRpcClient {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError>;
}

// ---- hex helpers (std-only) ------------------------------------------------

fn strip0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = strip0x(s);
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_to_u64(s: &str) -> Option<u64> {
    let s = strip0x(s);
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn hex_to_fixed32(s: &str) -> Option<[u8; 32]> {
    let b = hex_to_bytes(s)?;
    (b.len() == 32).then(|| {
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    })
}

fn to_hex_quantity(n: u64) -> String {
    format!("0x{n:x}")
}

fn to_hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

// ---- log decoding ----------------------------------------------------------

/// Decode one `eth_getLogs` entry into a burn observation, verifying it is the
/// `RedeemToNative` event from this chain's wBDX contract.
///
/// `data` is `abi.encode(uint256 amount, bytes beldexRecipient)`:
/// `[amount(32)][offset=0x40(32)][len(32)][recipient right-padded]`.
pub fn decode_redeem_log(
    log: &Value,
    chain: ChainId,
    contract: [u8; 20],
) -> Result<Observation<ReleaseEvent>, DecodeError> {
    let field = |k: &'static str| {
        log.get(k)
            .and_then(Value::as_str)
            .ok_or(DecodeError::MissingField(k))
    };

    let addr = hex_to_bytes(field("address")?).ok_or(DecodeError::BadHex)?;
    if addr != contract {
        return Err(DecodeError::ForeignContract);
    }
    let topics = log
        .get("topics")
        .and_then(Value::as_array)
        .ok_or(DecodeError::MissingField("topics"))?;
    let t0 = topics
        .first()
        .and_then(Value::as_str)
        .ok_or(DecodeError::MissingField("topics[0]"))?;
    if hex_to_fixed32(t0).ok_or(DecodeError::BadHex)? != redeem_topic0() {
        return Err(DecodeError::WrongTopic);
    }

    let inclusion_height = hex_to_u64(field("blockNumber")?).ok_or(DecodeError::BadHex)?;
    let block_hash = hex_to_fixed32(field("blockHash")?).ok_or(DecodeError::BadHex)?;
    let evm_txid = hex_to_fixed32(field("transactionHash")?).ok_or(DecodeError::BadHex)?;
    // H-1: which burn *within* the transaction. One tx may emit several RedeemToNative
    // logs (a batching wallet or aggregator), and they differ only here. Without it,
    // every burn after the first is indistinguishable from a duplicate and is dropped.
    let log_index = u32::try_from(hex_to_u64(field("logIndex")?).ok_or(DecodeError::BadHex)?)
        .map_err(|_| DecodeError::IndexOverflow)?;

    let data = hex_to_bytes(field("data")?).ok_or(DecodeError::BadHex)?;
    if data.len() < 96 {
        return Err(DecodeError::MissingField("data"));
    }
    // amount: reject a uint256 that doesn't fit u128 (high 16 bytes must be zero).
    if data[0..16].iter().any(|&b| b != 0) {
        return Err(DecodeError::AmountOverflow);
    }
    let amount = u128::from_be_bytes(data[16..32].try_into().unwrap());
    // recipient length (low 8 bytes of the 3rd word) then the bytes.
    let len = u64::from_be_bytes(data[88..96].try_into().unwrap()) as usize;
    let recipient = data
        .get(96..96 + len)
        .ok_or(DecodeError::MissingField("recipient"))?
        .to_vec();

    Ok(Observation {
        event: ReleaseEvent {
            evm_txid,
            log_index,
            chain,
            amount,
            beldex_recipient: recipient,
        },
        inclusion_height,
        block_hash,
    })
}

/// Decode an `eth_getLogs` result array, skipping any entry that does not decode as
/// one of this contract's burn events (robust: a stray log never aborts a scan).
pub fn decode_get_logs(
    result: &Value,
    chain: ChainId,
    contract: [u8; 20],
) -> Vec<Observation<ReleaseEvent>> {
    result
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|l| decode_redeem_log(l, chain, contract).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// A normalized `Rotated(address indexed newSigner, uint64 newKeyEpoch)` observation
/// (H.6.3): the wBDX `currentSigner` on `chain` moved to `new_signer` at key generation
/// `key_epoch`. This is the fact the rotation-ack attests to L1 so an outgoing seat's
/// bond can be released once every chain has rotated past its unbond-time baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationEvent {
    /// The EVM tx that emitted the event (for the watcher's reorg/finality tracking).
    pub evm_txid: [u8; 32],
    pub chain: ChainId,
    pub contract: [u8; 20],
    pub log_index: u32,
    /// The contract's new monotonic key epoch after this rotation.
    pub key_epoch: u64,
    /// The incoming `Pevm` address the contract now trusts as mint authority.
    pub new_signer: [u8; 20],
}

/// Decode one `eth_getLogs` entry into a rotation observation, verifying it is the
/// `Rotated` event from this chain's wBDX contract.
///
/// `newSigner` is **indexed** → `topics[1]` (a 20-byte address right-aligned in the
/// 32-byte topic word). `newKeyEpoch` is non-indexed → the single `data` word, a
/// `uint64` in its low 8 bytes.
pub fn decode_rotated_log(
    log: &Value,
    chain: ChainId,
    contract: [u8; 20],
) -> Result<Observation<RotationEvent>, DecodeError> {
    let field = |k: &'static str| {
        log.get(k)
            .and_then(Value::as_str)
            .ok_or(DecodeError::MissingField(k))
    };

    let addr = hex_to_bytes(field("address")?).ok_or(DecodeError::BadHex)?;
    if addr != contract {
        return Err(DecodeError::ForeignContract);
    }
    let topics = log
        .get("topics")
        .and_then(Value::as_array)
        .ok_or(DecodeError::MissingField("topics"))?;
    let t0 = topics
        .first()
        .and_then(Value::as_str)
        .ok_or(DecodeError::MissingField("topics[0]"))?;
    if hex_to_fixed32(t0).ok_or(DecodeError::BadHex)? != rotated_topic0() {
        return Err(DecodeError::WrongTopic);
    }

    // topics[1] = indexed newSigner (address in the low 20 bytes; high 12 must be zero).
    let t1 = topics
        .get(1)
        .and_then(Value::as_str)
        .ok_or(DecodeError::MissingField("topics[1]"))?;
    let t1b = hex_to_fixed32(t1).ok_or(DecodeError::BadHex)?;
    if t1b[0..12].iter().any(|&b| b != 0) {
        return Err(DecodeError::BadHex);
    }
    let mut new_signer = [0u8; 20];
    new_signer.copy_from_slice(&t1b[12..32]);

    let inclusion_height = hex_to_u64(field("blockNumber")?).ok_or(DecodeError::BadHex)?;
    let block_hash = hex_to_fixed32(field("blockHash")?).ok_or(DecodeError::BadHex)?;
    let evm_txid = hex_to_fixed32(field("transactionHash")?).ok_or(DecodeError::BadHex)?;
    let log_index_u64 = hex_to_u64(field("logIndex")?).ok_or(DecodeError::BadHex)?;
    let log_index = u32::try_from(log_index_u64).map_err(|_| DecodeError::AmountOverflow)?;

    // data = abi.encode(uint64 newKeyEpoch): one 32-byte word, value in the low 8 bytes.
    let data = hex_to_bytes(field("data")?).ok_or(DecodeError::BadHex)?;
    if data.len() < 32 {
        return Err(DecodeError::MissingField("data"));
    }
    if data[0..24].iter().any(|&b| b != 0) {
        return Err(DecodeError::AmountOverflow); // key epoch does not fit u64
    }
    let key_epoch = u64::from_be_bytes(data[24..32].try_into().unwrap());

    Ok(Observation {
        event: RotationEvent {
            evm_txid,
            chain,
            contract,
            log_index,
            key_epoch,
            new_signer,
        },
        inclusion_height,
        block_hash,
    })
}

/// Decode an `eth_getLogs` result array of `Rotated` logs, skipping non-matching entries.
pub fn decode_rotated_logs(
    result: &Value,
    chain: ChainId,
    contract: [u8; 20],
) -> Vec<Observation<RotationEvent>> {
    result
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|l| decode_rotated_log(l, chain, contract).ok())
                .collect()
        })
        .unwrap_or_default()
}

// ---- the watcher -----------------------------------------------------------

/// One member's EVM watcher for one chain.
pub struct EvmWatcher<C: JsonRpcClient> {
    client: C,
    chain: ChainId,
    contract: [u8; 20],
    tracker: Tracker<ReleaseEvent>,
    /// Next block to scan (inclusive).
    next_scan: u64,
    finality: EvmFinality,
    /// Last consensus-finalized anchor accepted by this watcher. In strong
    /// finality modes every later poll proves this anchor is still canonical;
    /// a regression or conflicting finalized ancestry halts releases.
    last_actionable_anchor: Option<(u64, [u8; 32])>,
}

/// Which EVM consensus boundary is allowed to authorize an irreversible native
/// release. `Confirmations` is retained for explicit development use; production
/// deployments should consume the RPC's consensus-aware `safe` or `finalized` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmFinality {
    Confirmations,
    Safe,
    Finalized,
}

impl EvmFinality {
    pub fn is_consensus_aware(self) -> bool {
        matches!(self, Self::Safe | Self::Finalized)
    }

    fn rpc_tag(self) -> Option<&'static str> {
        match self {
            Self::Confirmations => None,
            Self::Safe => Some("safe"),
            Self::Finalized => Some("finalized"),
        }
    }

    pub fn settlement_tag(self) -> &'static str {
        self.rpc_tag().unwrap_or("latest")
    }
}

impl<C: JsonRpcClient> EvmWatcher<C> {
    pub fn new(
        client: C,
        chain: ChainId,
        contract: [u8; 20],
        confirmations: u64,
        start_block: u64,
    ) -> Self {
        EvmWatcher {
            client,
            chain,
            contract,
            tracker: Tracker::new(confirmations),
            next_scan: start_block,
            finality: EvmFinality::Confirmations,
            last_actionable_anchor: None,
        }
    }

    pub fn with_finality(mut self, finality: EvmFinality) -> Self {
        self.finality = finality;
        if finality.is_consensus_aware() {
            self.tracker = Tracker::new(0);
        }
        self
    }

    /// Restore the last fsynced safe/finalized anchor after a restart.
    pub fn with_finalized_anchor(mut self, height: u64, hash: [u8; 32]) -> Self {
        self.last_actionable_anchor = Some((height, hash));
        self
    }

    /// Current chain head (`eth_blockNumber`).
    pub fn tip(&self) -> Result<u64, RpcError> {
        let v = self.client.call("eth_blockNumber", json!([]))?;
        v.as_str()
            .and_then(hex_to_u64)
            .ok_or_else(|| RpcError::BadResponse("eth_blockNumber".into()))
    }

    /// Highest block the configured consensus finality policy permits us to act
    /// upon. Safe/finalized tags are resolved by the node itself; unsupported tags
    /// fail closed instead of silently degrading to confirmation depth.
    pub fn actionable_tip(&self) -> Result<u64, RpcError> {
        self.actionable_anchor().map(|(height, _)| height)
    }

    fn actionable_anchor(&self) -> Result<(u64, Option<[u8; 32]>), RpcError> {
        let Some(tag) = self.finality.rpc_tag() else {
            return self.tip().map(|height| (height, None));
        };
        let v = self
            .client
            .call("eth_getBlockByNumber", json!([tag, false]))?;
        if v.is_null() {
            return Err(RpcError::BadResponse(format!(
                "eth_getBlockByNumber({tag}) unsupported or unavailable"
            )));
        }
        let height = v
            .get("number")
            .and_then(Value::as_str)
            .and_then(hex_to_u64)
            .ok_or_else(|| RpcError::BadResponse(format!("{tag} block.number")))?;
        let hash = v
            .get("hash")
            .and_then(Value::as_str)
            .and_then(hex_to_fixed32)
            .ok_or_else(|| RpcError::BadResponse(format!("{tag} block.hash")))?;
        Ok((height, Some(hash)))
    }

    fn get_logs(&self, from: u64, to: u64) -> Result<Vec<Observation<ReleaseEvent>>, RpcError> {
        let params = json!([{
            "address": to_hex_bytes(&self.contract),
            "topics": [to_hex_bytes(&redeem_topic0())],
            "fromBlock": to_hex_quantity(from),
            "toBlock": to_hex_quantity(to),
        }]);
        let v = self.client.call("eth_getLogs", params)?;
        Ok(decode_get_logs(&v, self.chain, self.contract))
    }

    /// The current canonical block hash at `height`, or `None` if that height is not
    /// (yet / any longer) on chain.
    fn block_hash_at(&self, height: u64) -> Result<Option<[u8; 32]>, RpcError> {
        let v = self.client.call(
            "eth_getBlockByNumber",
            json!([to_hex_quantity(height), false]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let h = v
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::BadResponse("block.hash".into()))?;
        Ok(hex_to_fixed32(h))
    }

    /// Scan any new blocks up to the tip, then finalize/drop pending burns against
    /// the current chain (reorg-aware). Returns what became final (actionable
    /// [`ReleaseEvent`]s) and what dropped this step.
    pub fn advance(&mut self) -> Result<TrackerUpdate<ReleaseEvent>, RpcError> {
        let chain_tip = self.tip()?;
        let actionable_tip = self.validate_finality()?;

        self.advance_at(chain_tip, actionable_tip)
    }

    /// Recheck accepted ancestry before signing or retrying any native payment,
    /// including duties that were observed during a previous process lifetime.
    pub fn validate_finality(&mut self) -> Result<u64, RpcError> {
        let (actionable_tip, actionable_hash) = self.actionable_anchor()?;

        if self.finality.is_consensus_aware() {
            let actionable_hash = actionable_hash.expect("strong finality returns a hash");
            if let Some((previous_height, previous_hash)) = self.last_actionable_anchor {
                if actionable_tip < previous_height {
                    return Err(RpcError::BadResponse(format!(
                        "{} head regressed from {previous_height} to {actionable_tip}",
                        self.finality.rpc_tag().expect("strong finality tag")
                    )));
                }
                let still_canonical = self.block_hash_at(previous_height)?;
                if still_canonical != Some(previous_hash) {
                    return Err(RpcError::BadResponse(format!(
                        "{} ancestry changed at previously accepted height {previous_height}",
                        self.finality.rpc_tag().expect("strong finality tag")
                    )));
                }
            }
            self.last_actionable_anchor = Some((actionable_tip, actionable_hash));
        }
        Ok(actionable_tip)
    }

    fn advance_at(
        &mut self,
        chain_tip: u64,
        actionable_tip: u64,
    ) -> Result<TrackerUpdate<ReleaseEvent>, RpcError> {
        // With depth finality, rescan the entire still-reorgable window on every
        // poll. This catches replacement blocks that add a burn at a height already
        // scanned (including heights where the old block contained no burn). Strong
        // safe/finalized modes only scan newly-finalized blocks: by definition a
        // finalized prefix cannot be replaced without violating the chain's safety.
        let scan_from = if self.finality == EvmFinality::Confirmations {
            self.next_scan
                .min(chain_tip.saturating_sub(self.tracker.required_confirmations()))
        } else {
            self.next_scan
        };
        let scan_tip = if self.finality == EvmFinality::Confirmations {
            chain_tip
        } else {
            actionable_tip
        };

        if scan_tip >= scan_from {
            let scan_to = scan_tip.min(scan_from.saturating_add(MAX_LOG_BLOCK_RANGE - 1));
            for obs in self.get_logs(scan_from, scan_to)? {
                self.tracker.observe(obs);
            }
            self.next_scan = self.next_scan.max(scan_to.saturating_add(1));
        }

        // Pre-fetch the current hash at each pending inclusion height (so `poll`'s
        // canonical check reads a map, not `self` — no borrow tangle).
        let heights: BTreeSet<u64> = self
            .tracker
            .pending()
            .iter()
            .map(|o| o.inclusion_height)
            .collect();
        let mut current: BTreeMap<u64, Option<[u8; 32]>> = BTreeMap::new();
        for h in heights {
            current.insert(h, self.block_hash_at(h)?);
        }

        Ok(self.tracker.poll(actionable_tip, |h, hash| {
            current.get(&h).copied().flatten() == Some(*hash)
        }))
    }

    pub fn chain(&self) -> ChainId {
        self.chain
    }

    pub fn pending_len(&self) -> usize {
        self.tracker.pending_len()
    }

    /// Earliest block that must be rescanned after a crash. Pending observations are
    /// intentionally replayed because their in-memory canonicality anchors are not yet
    /// durable; finalized work is reconciled against chain replay guards by the caller.
    pub fn durable_resume_block(&self) -> u64 {
        self.tracker
            .pending()
            .iter()
            .map(|o| o.inclusion_height)
            .min()
            .unwrap_or(self.next_scan)
    }

    pub fn durable_finality_anchor(&self) -> Option<(u64, [u8; 32])> {
        self.finality
            .is_consensus_aware()
            .then_some(self.last_actionable_anchor)
            .flatten()
    }
}

/// A real blocking HTTP JSON-RPC backend (opt-in: `--features evm-watcher-http`).
#[cfg(feature = "evm-watcher-http")]
pub struct HttpJsonRpc {
    url: String,
    id: std::cell::Cell<u64>,
}

#[cfg(feature = "evm-watcher-http")]
impl HttpJsonRpc {
    pub fn new(url: impl Into<String>) -> HttpJsonRpc {
        HttpJsonRpc {
            url: url.into(),
            id: std::cell::Cell::new(1),
        }
    }
}

#[cfg(feature = "evm-watcher-http")]
impl JsonRpcClient for HttpJsonRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.id.get();
        self.id.set(id.wrapping_add(1));
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let resp = crate::http_deadline::post(&self.url)
            .send_json(req)
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let v: Value = resp
            .into_json()
            .map_err(|e| RpcError::BadResponse(e.to_string()))?;
        if let Some(err) = v.get("error") {
            return Err(RpcError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RpcError::BadResponse("missing result".into()))
    }
}

// ---- multi-chain config (E.3) ---------------------------------------------

/// One EVM chain's watcher configuration, parsed from `BRIDGE_SIGNER_EVM_CHAINS`.
/// Each committee member supplies its **own** `rpc_url` (no shared oracle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmChainConfig {
    pub chain_id: u64,
    pub contract: [u8; 20],
    pub key_epoch: u64,
    pub confirmations: u64,
    pub finality: EvmFinality,
    pub rpc_url: String,
    pub per_tx_max: u128,
    pub per_epoch_cap: u128,
    /// First block to scan (e.g. the wBDX deployment block); defaults to 0.
    pub start_block: u64,
}

impl EvmChainConfig {
    /// The registry row (E.3) for this chain.
    pub fn to_chain_row(&self) -> ChainRow {
        ChainRow {
            chain_id: ChainId(self.chain_id),
            contract: self.contract,
            key_epoch: self.key_epoch,
            confirmations: self.confirmations,
            per_epoch_cap: self.per_epoch_cap,
            per_tx_max: self.per_tx_max,
            rpc_endpoint: Some(self.rpc_url.clone()),
        }
    }
}

/// A `u128` from a JSON string (preferred — avoids f64 precision loss) or number.
fn value_to_u128(v: Option<&Value>) -> Option<u128> {
    match v {
        Some(Value::String(s)) => s.parse::<u128>().ok(),
        Some(Value::Number(n)) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// Parse the `BRIDGE_SIGNER_EVM_CHAINS` JSON array into per-chain configs. Shape:
/// `[{"chain_id":1,"contract":"0x…20 bytes","key_epoch":1,"confirmations":12,"rpc":"https://…",
///   "per_tx_max":"…","per_epoch_cap":"…","start_block":18000000}, …]`
/// (`per_tx_max`/`per_epoch_cap` may be strings or numbers; `start_block` optional).
pub fn parse_evm_chains(json: &str) -> Result<Vec<EvmChainConfig>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("EVM chains JSON: {e}"))?;
    let arr = v
        .as_array()
        .ok_or("EVM chains config must be a JSON array")?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, row) in arr.iter().enumerate() {
        let miss = |f: &str| format!("chain[{i}]: missing/invalid `{f}`");
        let object = row.as_object().ok_or_else(|| miss("object"))?;
        for key in object.keys() {
            if ![
                "chain_id",
                "contract",
                "key_epoch",
                "confirmations",
                "finality",
                "rpc",
                "per_tx_max",
                "per_epoch_cap",
                "start_block",
            ]
            .contains(&key.as_str())
            {
                return Err(format!("chain[{i}]: unknown field `{key}`"));
            }
        }

        let chain_id = row
            .get("chain_id")
            .and_then(Value::as_u64)
            .ok_or_else(|| miss("chain_id"))?;
        let contract_hex = row
            .get("contract")
            .and_then(Value::as_str)
            .ok_or_else(|| miss("contract"))?;
        let contract_bytes = hex_to_bytes(contract_hex).ok_or_else(|| miss("contract (hex)"))?;
        if contract_bytes.len() != 20 {
            return Err(format!("chain[{i}]: `contract` must be 20 bytes"));
        }
        let mut contract = [0u8; 20];
        contract.copy_from_slice(&contract_bytes);
        let key_epoch = row
            .get("key_epoch")
            .and_then(Value::as_u64)
            .filter(|e| *e != 0)
            .ok_or_else(|| miss("key_epoch (non-zero)"))?;
        let confirmations = row
            .get("confirmations")
            .and_then(Value::as_u64)
            .ok_or_else(|| miss("confirmations"))?;
        let finality = match row.get("finality") {
            None => "confirmations",
            Some(value) => value.as_str().ok_or_else(|| miss("finality"))?,
        };
        let finality = match finality {
            "confirmations" => EvmFinality::Confirmations,
            "safe" => EvmFinality::Safe,
            "finalized" => EvmFinality::Finalized,
            _ => {
                return Err(format!(
                    "chain[{i}]: `finality` must be confirmations, safe, or finalized"
                ))
            }
        };
        let rpc_url = row
            .get("rpc")
            .and_then(Value::as_str)
            .ok_or_else(|| miss("rpc"))?
            .to_string();
        let per_tx_max = value_to_u128(row.get("per_tx_max")).ok_or_else(|| miss("per_tx_max"))?;
        let per_epoch_cap =
            value_to_u128(row.get("per_epoch_cap")).ok_or_else(|| miss("per_epoch_cap"))?;
        let start_block = match row.get("start_block") {
            None => 0,
            Some(value) => value.as_u64().ok_or_else(|| miss("start_block"))?,
        };
        if chain_id == 0
            || confirmations == 0
            || rpc_url.trim().is_empty()
            || per_tx_max == 0
            || per_epoch_cap == 0
            || per_tx_max > per_epoch_cap
            || per_tx_max > u128::from(u64::MAX)
            || per_epoch_cap > u128::from(u64::MAX)
        {
            return Err(format!(
                "chain[{i}]: require non-zero chain_id/confirmations/caps, non-empty rpc, per_tx_max <= per_epoch_cap, and native-u64-sized caps"
            ));
        }

        out.push(EvmChainConfig {
            chain_id,
            contract,
            key_epoch,
            confirmations,
            finality,
            rpc_url,
            per_tx_max,
            per_epoch_cap,
            start_block,
        });
    }
    Ok(out)
}

/// Build the E.3 [`ChainRegistry`] from parsed configs (rejects duplicate chain ids).
pub fn build_registry(configs: &[EvmChainConfig]) -> Result<ChainRegistry, String> {
    let mut reg = ChainRegistry::new();
    for c in configs {
        reg.add(c.to_chain_row())
            .map_err(|e| format!("chain {}: {e:?}", c.chain_id))?;
    }
    Ok(reg)
}

#[cfg(feature = "evm-watcher-http")]
impl EvmChainConfig {
    /// Identify the RPC implementation before enabling value-moving release duties. Local
    /// test nodes such as Anvil expose arbitrary snapshot/revert controls, so callers can
    /// fail closed unless an operator explicitly acknowledges that trust model.
    pub fn rpc_client_version(&self) -> Result<String, String> {
        let rpc = HttpJsonRpc::new(self.rpc_url.clone());
        rpc.call("web3_clientVersion", json!([]))
            .map_err(|e| format!("chain {} web3_clientVersion: {e:?}", self.chain_id))?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| {
                format!(
                    "chain {} returned invalid web3_clientVersion",
                    self.chain_id
                )
            })
    }

    pub fn total_supply(&self) -> Result<u128, String> {
        let rpc = HttpJsonRpc::new(self.rpc_url.clone());
        let result = rpc
            .call(
                "eth_call",
                json!([{"to": to_hex_bytes(&self.contract), "data": "0x18160ddd"}, "latest"]),
            )
            .map_err(|e| format!("chain {} eth_call totalSupply: {e:?}", self.chain_id))?;
        let bytes = result
            .as_str()
            .and_then(hex_to_bytes)
            .ok_or_else(|| format!("chain {} invalid totalSupply result", self.chain_id))?;
        if bytes.len() != 32 || bytes[..16].iter().any(|b| *b != 0) {
            return Err(format!("chain {} totalSupply exceeds u128", self.chain_id));
        }
        Ok(u128::from_be_bytes(
            bytes[16..].try_into().expect("length checked"),
        ))
    }

    /// Fail-closed startup parity check against the deployed `WrappedBDX`.
    pub fn validate_contract(&self) -> Result<(), String> {
        let rpc = HttpJsonRpc::new(self.rpc_url.clone());
        let remote_chain = rpc
            .call("eth_chainId", json!([]))
            .map_err(|e| format!("chain {} eth_chainId: {e:?}", self.chain_id))?
            .as_str()
            .and_then(hex_to_u64)
            .ok_or_else(|| format!("chain {} returned invalid eth_chainId", self.chain_id))?;
        if remote_chain != self.chain_id {
            return Err(format!(
                "chain id mismatch: config {} but RPC reports {}",
                self.chain_id, remote_chain
            ));
        }
        let address = to_hex_bytes(&self.contract);
        let code = rpc
            .call("eth_getCode", json!([address, "latest"]))
            .map_err(|e| format!("chain {} eth_getCode: {e:?}", self.chain_id))?;
        if code.as_str().is_none_or(|s| strip0x(s).is_empty()) {
            return Err(format!("chain {} wBDX address has no code", self.chain_id));
        }

        let read_u128 = |selector: &str| -> Result<u128, String> {
            let result = rpc
                .call(
                    "eth_call",
                    json!([{"to": to_hex_bytes(&self.contract), "data": selector}, "latest"]),
                )
                .map_err(|e| format!("chain {} eth_call {selector}: {e:?}", self.chain_id))?;
            let bytes = result
                .as_str()
                .and_then(hex_to_bytes)
                .ok_or_else(|| format!("chain {} invalid eth_call result", self.chain_id))?;
            if bytes.len() != 32 || bytes[..16].iter().any(|b| *b != 0) {
                return Err(format!(
                    "chain {} uint256 result exceeds u128",
                    self.chain_id
                ));
            }
            Ok(u128::from_be_bytes(
                bytes[16..].try_into().expect("length checked"),
            ))
        };
        let tag = rpc
            .call(
                "eth_call",
                json!([{"to": to_hex_bytes(&self.contract), "data": "0x6749ccae"}, "latest"]),
            )
            .map_err(|e| format!("chain {} eth_call MINT_TAG: {e:?}", self.chain_id))?
            .as_str()
            .and_then(hex_to_fixed32)
            .ok_or_else(|| format!("chain {} returned invalid MINT_TAG", self.chain_id))?;
        if tag != crate::watch::MINT_TAG {
            return Err(format!(
                "chain {} contract does not expose BELDEX_BRIDGE_MINT_V2",
                self.chain_id
            ));
        }
        let epoch = read_u128("0x6fdf657e")?;
        let per_tx = read_u128("0x89fbcc98")?;
        let window_cap = read_u128("0x466351f2")?;
        let bond_limit = read_u128("0x8e801d1b")?;
        if epoch != u128::from(self.key_epoch) {
            return Err(format!(
                "chain {} key_epoch config {} != contract {}",
                self.chain_id, self.key_epoch, epoch
            ));
        }
        if per_tx != self.per_tx_max || window_cap != self.per_epoch_cap {
            return Err(format!(
                "chain {} cap mismatch: config per_tx/window {}/{}; contract {}/{}",
                self.chain_id, self.per_tx_max, self.per_epoch_cap, per_tx, window_cap
            ));
        }
        if window_cap
            .checked_mul(2)
            .is_none_or(|needed| bond_limit < needed)
        {
            return Err(format!(
                "chain {} contract bond limit {} does not cover 2x window cap {}",
                self.chain_id, bond_limit, window_cap
            ));
        }
        Ok(())
    }

    /// Build a live watcher for this chain over its own HTTP JSON-RPC endpoint.
    pub fn build_watcher(&self) -> EvmWatcher<HttpJsonRpc> {
        EvmWatcher::new(
            HttpJsonRpc::new(self.rpc_url.clone()),
            ChainId(self.chain_id),
            self.contract,
            self.confirmations,
            self.start_block,
        )
        .with_finality(self.finality)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// abi.encode(uint256 amount, bytes recipient) as a 0x-hex string.
    fn redeem_data(amount: u128, recipient: &[u8]) -> String {
        let mut d = Vec::new();
        let mut amt = [0u8; 32];
        amt[16..].copy_from_slice(&amount.to_be_bytes());
        d.extend_from_slice(&amt);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        d.extend_from_slice(&off);
        let mut len = [0u8; 32];
        len[24..].copy_from_slice(&(recipient.len() as u64).to_be_bytes());
        d.extend_from_slice(&len);
        d.extend_from_slice(recipient);
        let pad = (32 - recipient.len() % 32) % 32;
        d.extend(std::iter::repeat(0).take(pad));
        to_hex_bytes(&d)
    }

    fn burn_log(
        block: u64,
        block_hash: [u8; 32],
        txid: [u8; 32],
        amount: u128,
        recipient: &[u8],
    ) -> Value {
        burn_log_at(block, block_hash, txid, 0, amount, recipient)
    }

    /// A burn log at a specific `logIndex` — several burns can share one transaction.
    fn burn_log_at(
        block: u64,
        block_hash: [u8; 32],
        txid: [u8; 32],
        log_index: u64,
        amount: u128,
        recipient: &[u8],
    ) -> Value {
        json!({
            "address": to_hex_bytes(&[0x22u8; 20]),
            "topics": [to_hex_bytes(&redeem_topic0()), to_hex_bytes(&[0u8; 32])],
            "data": redeem_data(amount, recipient),
            "blockNumber": to_hex_quantity(block),
            "blockHash": to_hex_bytes(&block_hash),
            "transactionHash": to_hex_bytes(&txid),
            "logIndex": to_hex_quantity(log_index),
        })
    }

    /// H-1: two burns in ONE transaction must decode as two distinct events. Before the
    /// fix `logIndex` was never read and the second was indistinguishable from the first.
    #[test]
    fn two_burns_in_one_tx_decode_distinctly() {
        let txid = [0xAA; 32];
        let a = decode_redeem_log(
            &burn_log_at(10, [0xBB; 32], txid, 0, 500, b"bxALICE"),
            ChainId(1),
            [0x22; 20],
        )
        .expect("first burn");
        let b = decode_redeem_log(
            &burn_log_at(10, [0xBB; 32], txid, 1, 800, b"bxBOB"),
            ChainId(1),
            [0x22; 20],
        )
        .expect("second burn");

        assert_eq!(a.event.evm_txid, b.event.evm_txid, "same transaction");
        assert_eq!(a.event.log_index, 0);
        assert_eq!(b.event.log_index, 1);
        assert_ne!(a.event, b.event, "distinct burns");
        // The bytes the committee agrees on must differ, or one signature would
        // authorize the other withdrawal.
        assert_ne!(
            a.event.canonical_id([7u8; 32]),
            b.event.canonical_id([7u8; 32])
        );
    }

    /// A log with no `logIndex` is refused rather than assumed to be index 0 — guessing
    /// would silently collide with a real burn at index 0.
    #[test]
    fn burn_log_without_log_index_is_rejected() {
        let mut l = burn_log_at(10, [0xBB; 32], [0xAA; 32], 0, 500, b"bx");
        l.as_object_mut().unwrap().remove("logIndex");
        assert_eq!(
            decode_redeem_log(&l, ChainId(1), [0x22; 20]),
            Err(DecodeError::MissingField("logIndex"))
        );
    }

    /// A canned JSON-RPC node: a settable tip, a fixed log set (filtered by the
    /// requested block range), and a height→hash map for the canonical check.
    struct MockNode {
        tip: Cell<u64>,
        logs: RefCell<Vec<Value>>,
        hashes: RefCell<BTreeMap<u64, [u8; 32]>>,
    }
    impl JsonRpcClient for MockNode {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            match method {
                "eth_blockNumber" => Ok(json!(to_hex_quantity(self.tip.get()))),
                "eth_getLogs" => {
                    let from = hex_to_u64(params[0]["fromBlock"].as_str().unwrap()).unwrap();
                    let to = hex_to_u64(params[0]["toBlock"].as_str().unwrap()).unwrap();
                    let hits: Vec<Value> = self
                        .logs
                        .borrow()
                        .iter()
                        .filter(|l| {
                            let b = hex_to_u64(l["blockNumber"].as_str().unwrap()).unwrap();
                            b >= from && b <= to
                        })
                        .cloned()
                        .collect();
                    Ok(json!(hits))
                }
                "eth_getBlockByNumber" => {
                    let requested = params[0].as_str().unwrap();
                    if requested == "safe" || requested == "finalized" {
                        return Ok(json!({
                            "number": to_hex_quantity(self.tip.get()),
                            "hash": to_hex_bytes(
                                &self.hashes.borrow().get(&self.tip.get()).copied().unwrap_or([0; 32])
                            )
                        }));
                    }
                    let h = hex_to_u64(requested).unwrap();
                    Ok(match self.hashes.borrow().get(&h) {
                        Some(hash) => json!({ "hash": to_hex_bytes(hash) }),
                        None => Value::Null,
                    })
                }
                other => Err(RpcError::Transport(format!("unmocked {other}"))),
            }
        }
    }

    #[test]
    fn decode_extracts_the_release_intent() {
        let log = burn_log(100, [0xAA; 32], [0x01u8; 32], 500, b"bxRecipient");
        let obs = decode_redeem_log(&log, ChainId(1), [0x22; 20]).expect("decode");
        assert_eq!(obs.inclusion_height, 100);
        assert_eq!(obs.block_hash, [0xAA; 32]);
        assert_eq!(obs.event.amount, 500);
        assert_eq!(obs.event.beldex_recipient, b"bxRecipient");
        assert_eq!(obs.event.chain, ChainId(1));
    }

    #[test]
    fn decode_rejects_foreign_contract_and_wrong_topic() {
        let log = burn_log(100, [0xAA; 32], [1; 32], 1, b"x");
        assert_eq!(
            decode_redeem_log(&log, ChainId(1), [0x99; 20]),
            Err(DecodeError::ForeignContract)
        );

        let mut bad_topic = log.clone();
        bad_topic["topics"][0] = json!(to_hex_bytes(&[0xde; 32]));
        assert_eq!(
            decode_redeem_log(&bad_topic, ChainId(1), [0x22; 20]),
            Err(DecodeError::WrongTopic)
        );
    }

    /// A `Rotated(address indexed newSigner, uint64 newKeyEpoch)` log (H.6.3): newSigner
    /// in topic1 (right-aligned), newKeyEpoch as the single data word.
    fn rotated_log(
        block: u64,
        block_hash: [u8; 32],
        txid: [u8; 32],
        new_signer: [u8; 20],
        key_epoch: u64,
    ) -> Value {
        let mut signer_topic = [0u8; 32];
        signer_topic[12..].copy_from_slice(&new_signer);
        let mut data = [0u8; 32];
        data[24..].copy_from_slice(&key_epoch.to_be_bytes());
        json!({
            "address": to_hex_bytes(&[0x22u8; 20]),
            "topics": [to_hex_bytes(&rotated_topic0()), to_hex_bytes(&signer_topic)],
            "data": to_hex_bytes(&data),
            "blockNumber": to_hex_quantity(block),
            "blockHash": to_hex_bytes(&block_hash),
            "transactionHash": to_hex_bytes(&txid),
            "logIndex": "0x0",
        })
    }

    #[test]
    fn decode_extracts_the_rotation() {
        let signer = [0xCDu8; 20];
        let log = rotated_log(200, [0xBB; 32], [0x02u8; 32], signer, 7);
        let obs = decode_rotated_log(&log, ChainId(42), [0x22; 20]).expect("decode");
        assert_eq!(obs.inclusion_height, 200);
        assert_eq!(obs.block_hash, [0xBB; 32]);
        assert_eq!(obs.event.chain, ChainId(42));
        assert_eq!(obs.event.contract, [0x22; 20]);
        assert_eq!(obs.event.log_index, 0);
        assert_eq!(obs.event.key_epoch, 7);
        assert_eq!(obs.event.new_signer, signer);
        assert_eq!(obs.event.evm_txid, [0x02u8; 32]);
    }

    #[test]
    fn decode_rotation_rejects_foreign_contract_and_wrong_topic() {
        let log = rotated_log(200, [0xBB; 32], [2; 32], [0xCD; 20], 7);
        assert_eq!(
            decode_rotated_log(&log, ChainId(1), [0x99; 20]),
            Err(DecodeError::ForeignContract)
        );

        // A burn log must not decode as a rotation (topic0 differs).
        let burn = burn_log(100, [0xAA; 32], [1; 32], 1, b"x");
        assert_eq!(
            decode_rotated_log(&burn, ChainId(1), [0x22; 20]),
            Err(DecodeError::WrongTopic)
        );
        // ...and vice-versa.
        assert_eq!(
            decode_redeem_log(&log, ChainId(1), [0x22; 20]),
            Err(DecodeError::WrongTopic)
        );
    }

    #[test]
    fn watcher_finalizes_after_confirmations() {
        let node = MockNode {
            tip: Cell::new(105),
            logs: RefCell::new(vec![burn_log(
                100,
                [0xAA; 32],
                [0x01; 32],
                500,
                b"bxRecipient",
            )]),
            hashes: RefCell::new([(100u64, [0xAA; 32])].into_iter().collect()),
        };
        let mut w = EvmWatcher::new(node, ChainId(1), [0x22; 20], 12, 100);

        // Only 5 deep → still pending.
        let u = w.advance().unwrap();
        assert!(u.finalized.is_empty() && u.dropped.is_empty());
        assert_eq!(w.pending_len(), 1);

        // Advance the tip to 120 (12+ deep) with the block still canonical → final.
        w.client.tip.set(120);
        let u = w.advance().unwrap();
        assert_eq!(u.finalized.len(), 1);
        let ev = &u.finalized[0];
        assert_eq!(ev.amount, 500);
        assert_eq!(ev.beldex_recipient, b"bxRecipient");
        // Deterministic canonical id (what members agree on).
        assert_eq!(ev.canonical_id([7; 32]), ev.clone().canonical_id([7; 32]));
        assert_eq!(w.pending_len(), 0);
    }

    #[test]
    fn parses_multi_chain_config() {
        let json = r#"[
            {"chain_id":1,"contract":"0x2222222222222222222222222222222222222222",
             "key_epoch":1,"confirmations":12,"rpc":"https://eth.example/key","per_tx_max":"1000000000",
             "per_epoch_cap":"100000000000","start_block":18000000},
            {"chain_id":137,"contract":"0x3333333333333333333333333333333333333333",
             "key_epoch":7,"confirmations":128,"rpc":"https://polygon.example","per_tx_max":500,"per_epoch_cap":9000}
        ]"#;
        let cfgs = parse_evm_chains(json).expect("parse");
        assert_eq!(cfgs.len(), 2);
        assert_eq!(cfgs[0].chain_id, 1);
        assert_eq!(cfgs[0].contract, [0x22; 20]);
        assert_eq!(cfgs[0].key_epoch, 1);
        assert_eq!(cfgs[0].confirmations, 12);
        assert_eq!(cfgs[0].finality, EvmFinality::Confirmations);
        assert_eq!(cfgs[0].per_tx_max, 1_000_000_000u128);
        assert_eq!(cfgs[0].start_block, 18_000_000);
        assert_eq!(cfgs[1].chain_id, 137);
        assert_eq!(cfgs[1].per_tx_max, 500, "numeric amounts accepted too");
        assert_eq!(cfgs[1].start_block, 0, "start_block defaults to 0");

        // The registry (E.3) is built from the same configs.
        let reg = build_registry(&cfgs).unwrap();
        assert!(reg.is_known(ChainId(1)) && reg.is_known(ChainId(137)));
    }

    #[test]
    fn config_errors_are_specific() {
        assert!(parse_evm_chains("not json").is_err());
        assert!(parse_evm_chains(r#"{"chain_id":1}"#)
            .unwrap_err()
            .contains("array"));
        let bad_addr = r#"[{"chain_id":1,"contract":"0x1234","confirmations":1,"rpc":"x","per_tx_max":"1","per_epoch_cap":"1"}]"#;
        assert!(parse_evm_chains(bad_addr).unwrap_err().contains("20 bytes"));
        let missing = r#"[{"chain_id":1,"contract":"0x2222222222222222222222222222222222222222","key_epoch":1,"rpc":"x","per_tx_max":"1","per_epoch_cap":"1"}]"#;
        assert!(parse_evm_chains(missing)
            .unwrap_err()
            .contains("confirmations"));
        // A duplicate chain id is rejected at registry build.
        let dup = r#"[
            {"chain_id":1,"contract":"0x2222222222222222222222222222222222222222","key_epoch":1,"confirmations":1,"rpc":"a","per_tx_max":"1","per_epoch_cap":"1"},
            {"chain_id":1,"contract":"0x3333333333333333333333333333333333333333","key_epoch":1,"confirmations":1,"rpc":"b","per_tx_max":"1","per_epoch_cap":"1"}
        ]"#;
        let cfgs = parse_evm_chains(dup).unwrap();
        assert!(build_registry(&cfgs).is_err());
    }

    #[test]
    fn config_rejects_typos_and_invalid_optional_values() {
        let base = serde_json::json!([{"chain_id":1,"contract":"22".repeat(20),
            "key_epoch":1,"confirmations":12,"rpc":"http://localhost",
            "per_tx_max":1,"per_epoch_cap":10}]);
        assert!(parse_evm_chains(&base.to_string()).is_ok());
        for (field, value) in [
            ("finalty", serde_json::json!("finalized")),
            ("finality", Value::Null),
            ("finality", serde_json::json!(12)),
            ("start_block", serde_json::json!(-1)),
            ("start_block", serde_json::json!("100")),
        ] {
            let mut bad = base.clone();
            bad[0][field] = value;
            assert!(parse_evm_chains(&bad.to_string())
                .unwrap_err()
                .contains(field));
        }
        assert!(parse_evm_chains("[null]").is_err());
    }

    #[test]
    fn watcher_drops_reorged_burn() {
        let node = MockNode {
            tip: Cell::new(105),
            logs: RefCell::new(vec![burn_log(100, [0xAA; 32], [0x01; 32], 500, b"bx")]),
            hashes: RefCell::new([(100u64, [0xAA; 32])].into_iter().collect()),
        };
        let mut w = EvmWatcher::new(node, ChainId(1), [0x22; 20], 12, 100);
        assert!(w.advance().unwrap().finalized.is_empty()); // pending

        // Reorg: height 100 now carries a different block hash.
        w.client.hashes.borrow_mut().insert(100, [0xBB; 32]);
        w.client.tip.set(120);
        let u = w.advance().unwrap();
        assert!(u.finalized.is_empty(), "reorged burn is never finalized");
        assert_eq!(u.dropped.len(), 1);
        assert_eq!(w.pending_len(), 0);
    }

    /// Regression for H-03: a previously scanned block can be replaced by one
    /// containing a new burn. The overlap scan must discover that replacement log.
    #[test]
    fn watcher_rescans_reorg_window_for_new_replacement_logs() {
        let node = MockNode {
            tip: Cell::new(105),
            logs: RefCell::new(Vec::new()),
            hashes: RefCell::new([(100u64, [0xAA; 32])].into_iter().collect()),
        };
        let mut w = EvmWatcher::new(node, ChainId(1), [0x22; 20], 12, 100);
        assert!(w.advance().unwrap().finalized.is_empty());

        // Height 100 was already scanned without a burn. A reorg replaces it with
        // a block that does contain one; at depth 12 it must be rediscovered.
        w.client.hashes.borrow_mut().insert(100, [0xBB; 32]);
        w.client.logs.borrow_mut().push(burn_log(
            100,
            [0xBB; 32],
            [0x02; 32],
            700,
            b"bxReplacement",
        ));
        w.client.tip.set(112);
        let update = w.advance().unwrap();
        assert_eq!(update.finalized.len(), 1);
        assert_eq!(update.finalized[0].evm_txid, [0x02; 32]);
    }

    #[test]
    fn finalized_policy_uses_consensus_tag_without_depth_fallback() {
        let node = MockNode {
            tip: Cell::new(100),
            logs: RefCell::new(vec![burn_log(100, [0xAA; 32], [0x03; 32], 900, b"bxFinal")]),
            hashes: RefCell::new([(100u64, [0xAA; 32])].into_iter().collect()),
        };
        let mut watcher = EvmWatcher::new(node, ChainId(1), [0x22; 20], 12, 100)
            .with_finality(EvmFinality::Finalized);
        let update = watcher.advance().unwrap();
        assert_eq!(update.finalized.len(), 1);
        assert_eq!(update.finalized[0].evm_txid, [0x03; 32]);
    }

    #[test]
    fn finalized_policy_halts_on_regression_or_conflicting_ancestry() {
        let node = MockNode {
            tip: Cell::new(100),
            logs: RefCell::new(vec![]),
            hashes: RefCell::new([(100u64, [0xAA; 32])].into_iter().collect()),
        };
        let mut watcher = EvmWatcher::new(node, ChainId(1), [0x22; 20], 12, 100)
            .with_finality(EvmFinality::Finalized);
        watcher.advance().unwrap();
        assert_eq!(watcher.durable_finality_anchor(), Some((100, [0xAA; 32])));

        watcher.client.tip.set(99);
        watcher.client.hashes.borrow_mut().insert(99, [0x99; 32]);
        assert!(matches!(
            watcher.advance(),
            Err(RpcError::BadResponse(message)) if message.contains("regressed")
        ));

        // A restart restores the fsynced anchor. Even if the finalized head moves
        // forward, changing its already-finalized ancestor is a safety violation.
        let node = MockNode {
            tip: Cell::new(101),
            logs: RefCell::new(vec![]),
            hashes: RefCell::new(
                [(100u64, [0xBB; 32]), (101u64, [0xCC; 32])]
                    .into_iter()
                    .collect(),
            ),
        };
        let mut restored = EvmWatcher::new(node, ChainId(1), [0x22; 20], 12, 101)
            .with_finality(EvmFinality::Finalized)
            .with_finalized_anchor(100, [0xAA; 32]);
        assert!(matches!(
            restored.advance(),
            Err(RpcError::BadResponse(message)) if message.contains("ancestry changed")
        ));
    }
}
