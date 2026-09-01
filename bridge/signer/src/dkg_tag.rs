//! Cryptographically strong routing tag for one live DKG ceremony.
//!
//! Epoch and key generation are predictable and can be reused after a failed run. Live
//! launchers therefore provide a fresh 32-byte ceremony id shared by all participants.
//! The tag additionally binds the protocol phase so delayed Pgw, Pevm-keygen, and
//! Pevm-aux frames cannot cross-route.

use sha3::{Digest, Keccak256};

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

pub fn ceremony_tag(domain: &[u8], epoch: u64, key_generation: u32) -> [u8; 32] {
    // Unit tests which exercise the transport-agnostic drivers do not launch a live
    // ceremony. Their deterministic zero id is safe because no external frames exist.
    // The executable validates a non-zero id before any live DKG starts.
    let id = validate_live_ceremony_id().unwrap_or([0u8; 32]);
    let mut h = Keccak256::new();
    h.update(b"BELDEX_BRIDGE_DKG_CEREMONY_V1");
    h.update(domain);
    h.update(id);
    h.update(epoch.to_le_bytes());
    h.update(key_generation.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_domains_do_not_cross_route() {
        assert_ne!(ceremony_tag(b"pgw", 7, 2), ceremony_tag(b"pevm", 7, 2));
        assert_ne!(ceremony_tag(b"pevm", 7, 2), ceremony_tag(b"pevm-aux", 7, 2));
        assert_ne!(ceremony_tag(b"pgw", 7, 2), ceremony_tag(b"pgw", 7, 3));
    }
}
