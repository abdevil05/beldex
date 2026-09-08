//! Durable, single-flight gas-wallet recovery. Each chain/wallet has one pending nonce.
//! All processes using a gas wallet must share this directory; do not use that wallet
//! elsewhere. Disk state is committed before broadcasting, including fee replacements.

use crate::{Eip1559Tx, HttpSubmitter, PreparedCall, SubmitError};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::os::unix::{
    fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};
use std::{fs, io::Write, path::Path};

fn error(e: impl std::fmt::Display) -> SubmitError {
    SubmitError::Transport(e.to_string())
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, SubmitError> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| error(format!("state: missing {key}")))
}
fn number(v: &Value, key: &str) -> Result<u64, SubmitError> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| error(format!("state: missing {key}")))
}
fn uint128(v: &Value, key: &str) -> Result<u128, SubmitError> {
    text(v, key)?.parse().map_err(error)
}
fn hash(raw: &[u8]) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(raw)))
}

/// Injectable chain interface: tests exercise the same recovery state machine as HTTP.
trait Backend {
    fn rpc(&self, method: &str, params: Value) -> Result<Value, SubmitError>;
    fn prepare(
        &self,
        call: &PreparedCall,
        previous: Option<(u64, u128, u128)>,
    ) -> Result<(Vec<u8>, Eip1559Tx), SubmitError>;
    fn broadcast(&self, raw: &[u8]) -> Result<String, SubmitError>;
}
struct HttpBackend<'a> {
    submitter: &'a HttpSubmitter,
    chain: u64,
}
impl Backend for HttpBackend<'_> {
    fn rpc(&self, method: &str, params: Value) -> Result<Value, SubmitError> {
        self.submitter.rpc(
            &self.submitter.endpoint(self.chain)?.rpc_url,
            method,
            params,
        )
    }
    fn prepare(
        &self,
        call: &PreparedCall,
        previous: Option<(u64, u128, u128)>,
    ) -> Result<(Vec<u8>, Eip1559Tx), SubmitError> {
        self.submitter.prepare(call, previous)
    }
    fn broadcast(&self, raw: &[u8]) -> Result<String, SubmitError> {
        self.submitter.broadcast(self.chain, raw)
    }
}

fn atomic_save(path: &Path, state: &Value) -> Result<(), SubmitError> {
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    // The chain/wallet lock serializes writers. A crash-left temporary file is never
    // read as committed state; truncating it under the lock cannot lose a broadcast.
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temp)
        .map_err(error)?;
    file.write_all(&serde_json::to_vec(state).map_err(error)?)
        .map_err(error)?;
    file.sync_all().map_err(error)?;
    fs::rename(&temp, path).map_err(error)?;
    fs::File::open(path.parent().ok_or_else(|| error("missing state parent"))?)
        .map_err(error)?
        .sync_all()
        .map_err(error)
}

// Kernel advisory locking is released even if a process is killed. A create_new
// lockfile alone would leave an unrecoverable stale lock after a crash.
fn wallet_lock(path: &Path) -> Result<fs::File, SubmitError> {
    unsafe extern "C" {
        fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(error)?;
    // SAFETY: file owns a valid fd for the duration of this call and lock lifetime.
    if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 {
        return Err(error(
            "gas wallet busy; retry using the same state directory",
        ));
    }
    Ok(file)
}

fn block_height(v: &Value) -> Result<u64, SubmitError> {
    u64::try_from(HttpSubmitter::hex_quantity(&v["number"], "block number")?).map_err(error)
}
fn block_hash(v: &Value) -> Result<&str, SubmitError> {
    let h = text(v, "hash")?;
    if h.len() != 66 || !h.starts_with("0x") || hex::decode(&h[2..]).is_err() {
        return Err(error("invalid block hash"));
    }
    Ok(h)
}

fn step<B: Backend>(
    backend: &B,
    path: &Path,
    state: &mut Value,
    call: &PreparedCall,
    now: u64,
) -> Result<String, SubmitError> {
    if HttpSubmitter::hex_quantity(&backend.rpc("eth_chainId", json!([]))?, "chain ID")?
        != call.chain_id as u128
    {
        return Err(error("RPC chain ID does not match destination"));
    }
    let finalized = backend.rpc("eth_getBlockByNumber", json!(["finalized", false]))?;
    let frontier = block_height(&finalized)?;
    let frontier_hash = block_hash(&finalized)?.to_string();
    if !state["anchor"].is_null() {
        let old = number(&state["anchor"], "height")?;
        if frontier < old {
            return Err(error(
                "finalized head regressed; operator investigation required",
            ));
        }
        let canonical =
            backend.rpc("eth_getBlockByNumber", json!([format!("0x{old:x}"), false]))?;
        if block_height(&canonical)? != old
            || block_hash(&canonical)? != text(&state["anchor"], "hash")?
        {
            return Err(error(
                "finalized ancestry changed; operator investigation required",
            ));
        }
    }
    state["anchor"] = json!({"height":frontier,"hash":frontier_hash});
    atomic_save(path, state)?;

    if !state["pending"].is_null() {
        let pending = state["pending"].clone();
        let same = text(&pending, "to")? == hex::encode(call.to)
            && text(&pending, "data")? == hex::encode(&call.data);
        let hashes = pending["hashes"]
            .as_array()
            .ok_or_else(|| error("invalid transaction history"))?;
        for h in hashes {
            let receipt = backend.rpc("eth_getTransactionReceipt", json!([h]))?;
            if receipt.is_null() {
                continue;
            }
            if receipt.get("transactionHash") != Some(h) {
                return Err(error("receipt hash mismatch"));
            }
            let height = u64::try_from(HttpSubmitter::hex_quantity(
                &receipt["blockNumber"],
                "receipt height",
            )?)
            .map_err(error)?;
            let canonical = backend.rpc(
                "eth_getBlockByNumber",
                json!([format!("0x{height:x}"), false]),
            )?;
            if block_height(&canonical)? != height
                || receipt["blockHash"].as_str() != Some(block_hash(&canonical)?)
            {
                continue; // orphaned receipt: retain and rebroadcast the saved nonce
            }
            if height > frontier {
                return if same {
                    Ok(h.as_str().ok_or_else(|| error("invalid hash"))?.into())
                } else {
                    Err(error(
                        "previous gas transaction is included but not finalized",
                    ))
                };
            }
            let status = HttpSubmitter::hex_quantity(&receipt["status"], "receipt status")?;
            if status > 1 {
                return Err(error("invalid receipt status"));
            }
            state["last_receipt"] = receipt;
            state["pending"] = Value::Null;
            atomic_save(path, state)?;
            if same {
                return if status == 1 {
                    Ok(h.as_str().ok_or_else(|| error("invalid hash"))?.into())
                } else {
                    Err(SubmitError::Rejected(
                        "transaction finalized with a revert".into(),
                    ))
                };
            }
            break;
        }
        if !state["pending"].is_null() {
            let nonce = number(&pending, "nonce")?;
            let mined_nonce = HttpSubmitter::hex_quantity(
                &backend.rpc("eth_getTransactionCount", json!([state["from"], "latest"]))?,
                "mined nonce",
            )?;
            if mined_nonce > nonce as u128 {
                return Err(error("nonce consumed without a canonical known receipt; retain state and investigate"));
            }
            let saved_call = PreparedCall {
                chain_id: call.chain_id,
                to: hex::decode(text(&pending, "to")?)
                    .map_err(error)?
                    .try_into()
                    .map_err(|_| error("invalid saved address"))?,
                data: hex::decode(text(&pending, "data")?).map_err(error)?,
            };
            if now.saturating_sub(number(&pending, "updated")?) >= 60 {
                match backend.prepare(
                    &saved_call,
                    Some((
                        nonce,
                        uint128(&pending, "max_fee")?,
                        uint128(&pending, "tip")?,
                    )),
                ) {
                    Ok((raw, tx)) => {
                        let mut history = hashes.clone();
                        history.push(json!(hash(&raw)));
                        state["pending"] = record(&saved_call, &raw, &tx, now, history);
                        atomic_save(path, state)?;
                    }
                    Err(SubmitError::Rejected(_)) => {} // fee ceiling/revert: retain original envelope
                    Err(e) => return Err(e),
                }
            }
            let raw = hex::decode(text(&state["pending"], "raw")?).map_err(error)?;
            let sent = backend.broadcast(&raw)?;
            return if same {
                Ok(sent)
            } else {
                Err(error(
                    "previous gas nonce pending; rebroadcast before accepting another call",
                ))
            };
        }
    }
    let (raw, tx) = backend.prepare(call, None)?;
    state["pending"] = record(call, &raw, &tx, now, vec![json!(hash(&raw))]);
    atomic_save(path, state)?; // load-bearing: never send first and persist later
    backend.broadcast(&raw)
}

fn record(call: &PreparedCall, raw: &[u8], tx: &Eip1559Tx, now: u64, hashes: Vec<Value>) -> Value {
    json!({"to":hex::encode(call.to),"data":hex::encode(&call.data),"nonce":tx.nonce,
        "max_fee":tx.max_fee_per_gas.to_string(),"tip":tx.max_priority_fee_per_gas.to_string(),
        "raw":hex::encode(raw),"hashes":hashes,"updated":now})
}

impl HttpSubmitter {
    /// Progress one wallet/chain transaction. Call repeatedly until destination
    /// reconciliation confirms settlement. A returned hash can still be pending.
    pub fn submit_durable(
        &self,
        call: &PreparedCall,
        directory: &Path,
    ) -> Result<String, SubmitError> {
        self.endpoint(call.chain_id)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .map_err(error)?;
        if fs::metadata(directory).map_err(error)?.permissions().mode() & 0o077 != 0 {
            return Err(error("relayer state directory must be private (mode 0700)"));
        }
        if let Some(parent) = directory.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::File::open(parent)
                .map_err(error)?
                .sync_all()
                .map_err(error)?;
        }
        let id = format!("{}-{}", call.chain_id, hex::encode(self.address));
        let _lock = wallet_lock(&directory.join(format!("{id}.lock")))?;
        let path = directory.join(format!("{id}.json"));
        let from = format!("0x{}", hex::encode(self.address));
        let mut state: Value = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).map_err(error)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                json!({"version":1,"chain_id":call.chain_id,"from":from,"anchor":null,"pending":null})
            }
            Err(e) => return Err(error(e)),
        };
        if state["version"] != 1 || state["chain_id"] != call.chain_id || state["from"] != from {
            return Err(error("relayer state identity/version mismatch"));
        }
        if state.get("pending").is_none() || state.get("anchor").is_none() {
            return Err(error(
                "incomplete relayer state; refusing to allocate a new nonce",
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(error)?
            .as_secs();
        step(
            &HttpBackend {
                submitter: self,
                chain: call.chain_id,
            },
            &path,
            &mut state,
            call,
            now,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        path: PathBuf,
        frontier: Cell<u64>,
        fork: Cell<bool>,
        nonce: Cell<u64>,
        fail_send: Cell<bool>,
        reject_replacement: Cell<bool>,
        prepared: Cell<u64>,
        sends: RefCell<Vec<Vec<u8>>>,
        receipts: RefCell<BTreeMap<String, Value>>,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "bridge-durable-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            Self {
                path: dir.join("state.json"),
                frontier: Cell::new(10),
                fork: Cell::new(false),
                nonce: Cell::new(7),
                fail_send: Cell::new(false),
                reject_replacement: Cell::new(false),
                prepared: Cell::new(0),
                sends: RefCell::new(Vec::new()),
                receipts: RefCell::new(BTreeMap::new()),
            }
        }
        fn reload(&self) -> Value {
            serde_json::from_slice(&fs::read(&self.path).unwrap()).unwrap()
        }
        fn block(&self, height: u64) -> Value {
            json!({"number":format!("0x{height:x}"),"hash":format!("0x{:064x}", height + if self.fork.get() {1000} else {0})})
        }
        fn receipt(&self, tx: &str, height: u64, status: u64) {
            self.receipts.borrow_mut().insert(tx.into(), json!({"transactionHash":tx,
                "blockNumber":format!("0x{height:x}"), "blockHash":self.block(height)["hash"], "status":format!("0x{status:x}")}));
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(self.path.parent().unwrap()).unwrap();
        }
    }
    impl Backend for Fixture {
        fn rpc(&self, method: &str, params: Value) -> Result<Value, SubmitError> {
            Ok(match method {
                "eth_chainId" => json!("0x1"),
                "eth_getBlockByNumber" => {
                    let tag = params[0].as_str().unwrap();
                    self.block(if tag == "finalized" {
                        self.frontier.get()
                    } else {
                        u64::from_str_radix(&tag[2..], 16).unwrap()
                    })
                }
                "eth_getTransactionReceipt" => self
                    .receipts
                    .borrow()
                    .get(params[0].as_str().unwrap())
                    .cloned()
                    .unwrap_or(Value::Null),
                "eth_getTransactionCount" => json!(format!("0x{:x}", self.nonce.get())),
                _ => panic!("unexpected RPC {method}"),
            })
        }
        fn prepare(
            &self,
            call: &PreparedCall,
            prior: Option<(u64, u128, u128)>,
        ) -> Result<(Vec<u8>, Eip1559Tx), SubmitError> {
            if prior.is_some() && self.reject_replacement.get() {
                return Err(SubmitError::Rejected("fee cap".into()));
            }
            self.prepared.set(self.prepared.get() + 1);
            let (nonce, fee, tip) = match prior {
                Some((n, f, t)) => (
                    n,
                    crate::http_submit::replacement_fee(f)?,
                    crate::http_submit::replacement_fee(t)?,
                ),
                None => (7, 100, 8),
            };
            let tx = Eip1559Tx::from_call(call, nonce, tip, fee, 21000);
            Ok((
                format!("{}-{nonce}-{fee}-{tip}", hex::encode(&call.data)).into_bytes(),
                tx,
            ))
        }
        fn broadcast(&self, raw: &[u8]) -> Result<String, SubmitError> {
            // This assertion checks the actual disk commit, not the in-memory state.
            assert_eq!(
                text(&self.reload()["pending"], "raw").unwrap(),
                hex::encode(raw)
            );
            if self.fail_send.get() {
                return Err(error("connection lost during broadcast"));
            }
            self.sends.borrow_mut().push(raw.to_vec());
            Ok(hash(raw))
        }
    }
    fn call() -> PreparedCall {
        PreparedCall {
            chain_id: 1,
            to: [0x22; 20],
            data: vec![1, 2, 3],
        }
    }
    fn initial() -> Value {
        json!({"version":1,"chain_id":1,"from":"0x1111111111111111111111111111111111111111","pending":null,"anchor":null})
    }

    #[test]
    fn restart_after_ambiguous_broadcast_reuses_saved_envelope() {
        let f = Fixture::new();
        f.fail_send.set(true);
        assert!(step(&f, &f.path, &mut initial(), &call(), 100).is_err());
        let raw = f.reload()["pending"]["raw"].clone();
        f.fail_send.set(false);
        step(&f, &f.path, &mut f.reload(), &call(), 101).unwrap();
        assert_eq!(f.prepared.get(), 1);
        assert_eq!(f.reload()["pending"]["raw"], raw);
        assert!(
            !f.reload()["pending"].is_null(),
            "broadcast is not settlement"
        );
    }
    #[test]
    fn fee_replacement_keeps_nonce_and_tracks_old_receipts() {
        let f = Fixture::new();
        let first = step(&f, &f.path, &mut initial(), &call(), 100).unwrap();
        let second = step(&f, &f.path, &mut f.reload(), &call(), 161).unwrap();
        assert_ne!(first, second);
        assert_eq!(f.reload()["pending"]["nonce"], 7);
        assert_eq!(f.reload()["pending"]["hashes"].as_array().unwrap().len(), 2);
        f.receipt(&first, 9, 1); // original transaction won the race against replacement
        assert_eq!(
            step(&f, &f.path, &mut f.reload(), &call(), 162).unwrap(),
            first
        );
        assert!(f.reload()["pending"].is_null());
    }
    #[test]
    fn included_is_not_finalized_and_wallet_does_not_allocate_another_nonce() {
        let f = Fixture::new();
        let first = step(&f, &f.path, &mut initial(), &call(), 100).unwrap();
        f.receipt(&first, 11, 1);
        step(&f, &f.path, &mut f.reload(), &call(), 101).unwrap();
        let mut next = call();
        next.data.push(4);
        assert!(step(&f, &f.path, &mut f.reload(), &next, 102).is_err());
        assert_eq!(f.prepared.get(), 1);
        assert!(!f.reload()["pending"].is_null());
        f.frontier.set(11);
        step(&f, &f.path, &mut f.reload(), &call(), 103).unwrap();
        assert!(f.reload()["pending"].is_null());
    }
    #[test]
    fn finality_regression_or_conflicting_ancestry_halts_rebroadcast() {
        let f = Fixture::new();
        step(&f, &f.path, &mut initial(), &call(), 100).unwrap();
        f.frontier.set(9);
        assert!(step(&f, &f.path, &mut f.reload(), &call(), 101).is_err());
        f.frontier.set(11);
        f.fork.set(true);
        assert!(step(&f, &f.path, &mut f.reload(), &call(), 102).is_err());
        assert_eq!(f.sends.borrow().len(), 1);
    }
    #[test]
    fn nonce_consumed_without_receipt_does_not_create_duplicate_payment() {
        let f = Fixture::new();
        step(&f, &f.path, &mut initial(), &call(), 100).unwrap();
        f.nonce.set(8);
        assert!(step(&f, &f.path, &mut f.reload(), &call(), 200).is_err());
        assert_eq!(f.prepared.get(), 1);
    }
    #[test]
    fn rejected_replacement_preserves_original_and_finalized_revert_is_not_success() {
        let f = Fixture::new();
        let tx = step(&f, &f.path, &mut initial(), &call(), 100).unwrap();
        f.reject_replacement.set(true);
        assert_eq!(
            step(&f, &f.path, &mut f.reload(), &call(), 161).unwrap(),
            tx
        );
        assert_eq!(f.prepared.get(), 1);
        f.receipt(&tx, 9, 0);
        assert!(matches!(
            step(&f, &f.path, &mut f.reload(), &call(), 162),
            Err(SubmitError::Rejected(_))
        ));
        assert!(f.reload()["pending"].is_null());
    }
    #[test]
    fn wallet_lock_excludes_other_process_handles_and_releases_on_close() {
        let f = Fixture::new();
        let path = f.path.with_extension("lock");
        let lock = wallet_lock(&path).unwrap();
        assert!(wallet_lock(&path).is_err());
        drop(lock);
        assert!(wallet_lock(&path).is_ok());
    }
    #[test]
    fn replacement_fee_rounds_up_and_checks_overflow() {
        assert_eq!(crate::http_submit::replacement_fee(9).unwrap(), 11);
        assert!(crate::http_submit::replacement_fee(u128::MAX).is_err());
    }
}
