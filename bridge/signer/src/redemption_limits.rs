//! Contract-authoritative, immutable per-deployment withdrawal fees.
use crate::evm_watcher::JsonRpcClient;
pub use crate::release_policy::NATIVE_RELEASE_MAX;
use serde_json::json;
use sha3::{Digest, Keccak256};

pub fn read_fee<C: JsonRpcClient>(rpc: &C, contract: &[u8; 20]) -> Result<u64, String> {
    let hex = |bytes: &[u8]| {
        format!(
            "0x{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    };
    let head = rpc
        .call("eth_getBlockByNumber", json!(["finalized", false]))
        .map_err(|e| format!("redemption block: {e:?}"))?;
    let hash = head["hash"]
        .as_str()
        .and_then(crate::config::parse_hex32)
        .ok_or("invalid redemption block hash")?;
    let block = json!({"blockHash":hex(&hash),"requireCanonical":true});
    let read = |signature: &str| -> Result<u64, String> {
        let selector = Keccak256::digest(signature.as_bytes());
        let value = rpc
            .call(
                "eth_call",
                json!([{"to":hex(contract),"data":hex(&selector[..4])},block]),
            )
            .map_err(|e| format!("{signature}: {e:?}"))?;
        let word = value
            .as_str()
            .and_then(crate::config::parse_hex32)
            .ok_or("invalid ABI fee result")?;
        if word[..24] != [0; 24] {
            return Err("ABI value exceeds u64".into());
        }
        Ok(u64::from_be_bytes(word[24..].try_into().unwrap()))
    };
    if read("redemptionFeeInitialized()")? != 1 {
        return Err("contract redemption fee is not initialized".into());
    }
    let fee = read("redemptionFee()")?;
    if u128::from(fee) >= NATIVE_RELEASE_MAX {
        return Err("fee exceeds native payout limit".into());
    }
    Ok(fee)
}

/// Legacy local settings are assertions, never an independent payout fee source.
pub fn validate_local(
    fee: u64,
    configured: Option<u64>,
    maximum: Option<u64>,
    cap: Option<u64>,
) -> Result<(), String> {
    if configured.is_some_and(|v| v != fee) {
        return Err("local release fee differs from contract redemptionFee".into());
    }
    if maximum.is_some_and(|v| v < fee) {
        return Err("local maximum fee is below contract redemptionFee".into());
    }
    if cap.is_some_and(|v| u128::from(v) < NATIVE_RELEASE_MAX) {
        return Err("local release cap must cover the native maximum".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_watcher::RpcError;
    use serde_json::Value;
    struct Rpc {
        ready: u64,
        fee: u64,
        malformed: bool,
    }
    impl JsonRpcClient for Rpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            if method == "eth_getBlockByNumber" {
                assert_eq!(params[0], "finalized");
                return Ok(json!({"hash":format!("0x{}","11".repeat(32))}));
            }
            assert_eq!(params[1]["requireCanonical"], true);
            if self.malformed {
                return Ok(json!("0x01"));
            }
            let selector = Keccak256::digest(b"redemptionFeeInitialized()");
            let ready = format!(
                "0x{}",
                selector[..4]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            Ok(json!(format!(
                "0x{:064x}",
                if params[0]["data"] == ready {
                    self.ready
                } else {
                    self.fee
                }
            )))
        }
    }
    #[test]
    fn fee_reads_are_canonical_and_fail_closed() {
        assert_eq!(
            read_fee(
                &Rpc {
                    ready: 1,
                    fee: 100,
                    malformed: false
                },
                &[2; 20]
            ),
            Ok(100)
        );
        for rpc in [
            Rpc {
                ready: 0,
                fee: 100,
                malformed: false,
            },
            Rpc {
                ready: 2,
                fee: 100,
                malformed: false,
            },
            Rpc {
                ready: 1,
                fee: NATIVE_RELEASE_MAX as u64,
                malformed: false,
            },
            Rpc {
                ready: 1,
                fee: 100,
                malformed: true,
            },
        ] {
            assert!(read_fee(&rpc, &[2; 20]).is_err());
        }
    }
    #[test]
    fn local_settings_cannot_strand_contract_accepted_burns() {
        assert!(validate_local(100, None, None, None).is_ok());
        assert!(validate_local(100, Some(100), Some(100), Some(NATIVE_RELEASE_MAX as u64)).is_ok());
        assert!(validate_local(100, Some(101), None, None).is_err());
        assert!(validate_local(100, None, Some(99), None).is_err());
        assert!(validate_local(100, None, None, Some(1)).is_err());
    }
}
