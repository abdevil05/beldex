//! Cryptographically strong routing tag for one live DKG ceremony.
//!
//! Epoch and key generation are predictable and can be reused after a failed run. Live
//! launchers therefore provide a fresh 32-byte ceremony id shared by all participants.
//! The tag additionally binds the native genesis, exact ordered committee, and protocol
//! phase so neither cross-network replay nor delayed frames from a different membership
//! can enter the cryptographic transcript.

use crate::committee::CommitteeView;
use sha3::{Digest, Keccak256};

/// Reserve an execution identity durably before sending any protocol messages.
/// The reservation survives crashes; a failed run must use a fresh attempt or
/// ceremony id. Never remove these records while the associated shares exist.
pub fn reserve_execution_at(
    directory: &std::path::Path,
    id: &[u8; 32],
    self_index: u16,
) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .map_err(|e| format!("create execution ledger: {e}"))?;
    // Persist the directory entry as well as the record before MPC can start.
    if let Some(parent) = directory.parent() {
        std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("fsync execution ledger parent: {e}"))?;
    }
    let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(directory.join(format!("{self_index}-{name}")))
        .map_err(|e| format!("execution already used or ledger unavailable ({e}); use a fresh attempt/ceremony id"))?;
    file.sync_all()
        .map_err(|e| format!("fsync execution reservation: {e}"))?;
    std::fs::File::open(directory)
        .and_then(|d| d.sync_all())
        .map_err(|e| format!("fsync execution ledger: {e}"))
}

pub fn reserve_execution(id: &[u8; 32], self_index: u16) -> Result<(), String> {
    #[cfg(test)]
    {
        let _ = (id, self_index);
        Ok(())
    }
    #[cfg(not(test))]
    {
        let shares = std::env::var("BRIDGE_SIGNER_SHARE_DIR").map_err(|_| {
            "BRIDGE_SIGNER_SHARE_DIR is required for durable execution reservations".to_string()
        })?;
        reserve_execution_at(
            &std::path::Path::new(&shares).join("executions"),
            id,
            self_index,
        )
    }
}

pub fn network_genesis() -> Result<[u8; 32], String> {
    #[cfg(test)]
    if std::env::var("BRIDGE_SIGNER_GENESIS_HASH").is_err() {
        return Ok([0x5A; 32]);
    }

    let raw = std::env::var("BRIDGE_SIGNER_GENESIS_HASH")
        .map_err(|_| "set BRIDGE_SIGNER_GENESIS_HASH to the native genesis hash".to_string())?;
    crate::config::parse_hex32(raw.strip_prefix("0x").unwrap_or(&raw))
        .filter(|v| *v != [0u8; 32])
        .ok_or_else(|| "BRIDGE_SIGNER_GENESIS_HASH must be non-zero 32-byte hex".to_string())
}

pub fn validate_live_ceremony_id() -> Result<[u8; 32], String> {
    let raw = std::env::var("BRIDGE_SIGNER_DKG_CEREMONY_ID").map_err(|_| {
        "set BRIDGE_SIGNER_DKG_CEREMONY_ID to a fresh shared 32-byte hex value".to_string()
    })?;
    let raw = raw.strip_prefix("0x").unwrap_or(&raw);
    if raw.len() != 64 {
        return Err("BRIDGE_SIGNER_DKG_CEREMONY_ID must be exactly 32 bytes of hex".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|_| "BRIDGE_SIGNER_DKG_CEREMONY_ID contains non-hex characters")?;
    }
    if out == [0u8; 32] {
        return Err("BRIDGE_SIGNER_DKG_CEREMONY_ID must not be zero".into());
    }
    Ok(out)
}

pub fn ceremony_tag_with_context(
    domain: &[u8],
    committee: &CommitteeView,
    key_generation: u32,
    id: [u8; 32],
    genesis: [u8; 32],
) -> [u8; 32] {
    assert_ne!(id, [0u8; 32], "DKG ceremony id must not be zero");
    assert_ne!(genesis, [0u8; 32], "native genesis must not be zero");
    let mut h = Keccak256::new();
    h.update(b"BELDEX_BRIDGE_DKG_CEREMONY_V2");
    h.update(domain);
    h.update(id);
    h.update(genesis);
    h.update(committee.epoch.to_le_bytes());
    h.update(committee.height.to_le_bytes());
    h.update((committee.threshold as u64).to_le_bytes());
    h.update((committee.members.len() as u64).to_le_bytes());
    for member in &committee.members {
        h.update(member);
    }
    h.update((committee.signer_keys.len() as u64).to_le_bytes());
    for signer_key in &committee.signer_keys {
        h.update(signer_key);
    }
    h.update(key_generation.to_le_bytes());
    h.finalize().into()
}

pub fn ceremony_tag(
    domain: &[u8],
    committee: &CommitteeView,
    key_generation: u32,
) -> Result<[u8; 32], String> {
    #[cfg(test)]
    let id = validate_live_ceremony_id().unwrap_or([0xA5; 32]);
    #[cfg(not(test))]
    let id = validate_live_ceremony_id()?;
    Ok(ceremony_tag_with_context(
        domain,
        committee,
        key_generation,
        id,
        network_genesis()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_execution_reservation_has_exactly_one_winner() {
        let directory =
            std::env::temp_dir().join(format!("bridge-execution-race-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let directory = directory.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    reserve_execution_at(&directory.join("executions"), &[9; 32], 0).is_ok()
                })
            })
            .collect();
        let successes = threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>();
        assert_eq!(successes, 1);
        assert!(reserve_execution_at(&directory.join("executions"), &[9; 32], 0).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn execution_reservation_survives_reopen_and_rejects_reuse() {
        let directory =
            std::env::temp_dir().join(format!("bridge-execution-ledger-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let ledger = directory.join("executions");
        reserve_execution_at(&ledger, &[1; 32], 0).unwrap();
        assert!(reserve_execution_at(&ledger, &[1; 32], 0).is_err());
        reserve_execution_at(&ledger, &[2; 32], 0).unwrap();
        reserve_execution_at(&ledger, &[1; 32], 1).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn protocol_domains_do_not_cross_route() {
        let id = [7u8; 32];
        let genesis = [8u8; 32];
        let committee = CommitteeView {
            epoch: 7,
            height: 840,
            members: vec![[1u8; 32], [2u8; 32]],
            signer_keys: vec![[3u8; 32], [4u8; 32]],
            member_ips: vec![],
            member_x25519: vec![],
            daemon_self_index: None,
            threshold: 2,
        };
        assert_ne!(
            ceremony_tag_with_context(b"pgw", &committee, 2, id, genesis),
            ceremony_tag_with_context(b"pevm", &committee, 2, id, genesis)
        );
        assert_ne!(
            ceremony_tag_with_context(b"pevm", &committee, 2, id, genesis),
            ceremony_tag_with_context(b"pevm-aux", &committee, 2, id, genesis)
        );
        assert_ne!(
            ceremony_tag_with_context(b"pgw", &committee, 2, id, genesis),
            ceremony_tag_with_context(b"pgw", &committee, 3, id, genesis)
        );

        let mut changed = committee.clone();
        changed.members.swap(0, 1);
        assert_ne!(
            ceremony_tag_with_context(b"pgw", &committee, 2, id, genesis),
            ceremony_tag_with_context(b"pgw", &changed, 2, id, genesis)
        );
        assert_ne!(
            ceremony_tag_with_context(b"pgw", &committee, 2, id, genesis),
            ceremony_tag_with_context(b"pgw", &committee, 2, id, [9u8; 32])
        );
    }
}
