//! Approved proxy/implementation bytecode pins. Never learn approval from the RPC
//! being checked: the operator supplies hashes from a reviewed build/release.
use crate::evm_watcher::JsonRpcClient;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
const IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
fn bytes<const N: usize>(value: &Value) -> Result<[u8; N], String> {
    let s = value.as_str().ok_or("pin must be hex text")?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.is_ascii() || s.len() != N * 2 {
        return Err(format!("expected {N}-byte hex pin"));
    }
    let mut out = [0; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| "invalid pin hex")?;
    }
    Ok(out)
}
fn hex(b: &[u8]) -> String {
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}
fn code_hash(code: Value) -> Result<[u8; 32], String> {
    let s = code
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or("invalid runtime bytecode")?;
    if !s.is_ascii() || s.is_empty() || s.len() % 2 != 0 {
        return Err("missing/invalid runtime bytecode".into());
    }
    let data = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid runtime hex"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Keccak256::digest(data).into())
}
pub fn verify<C: JsonRpcClient>(
    rpc: &C,
    chain: u64,
    proxy: [u8; 20],
    manifest: &Value,
) -> Result<(), String> {
    let entries = manifest
        .as_array()
        .ok_or("implementation manifest must be an array")?;
    let matches = entries
        .iter()
        .filter(|e| {
            e["chain_id"].as_u64() == Some(chain) && bytes::<20>(&e["proxy"]).ok() == Some(proxy)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "chain {chain}: require exactly one approved proxy implementation entry"
        ));
    }
    let entry = matches[0];
    let implementation = bytes::<20>(&entry["implementation"])?;
    if implementation == [0; 20] {
        return Err("zero approved implementation".into());
    }
    let expected_proxy = bytes::<32>(&entry["proxy_code_hash"])?;
    let expected_impl = bytes::<32>(&entry["implementation_code_hash"])?;
    let ask = |method, params| {
        rpc.call(method, params)
            .map_err(|e| format!("implementation attestation {method}: {e:?}"))
    };
    let remote = ask("eth_chainId", json!([]))?;
    let remote = remote
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .and_then(|s| u64::from_str_radix(s, 16).ok());
    if remote != Some(chain) {
        return Err("implementation attestation chain mismatch".into());
    }
    let head = ask("eth_getBlockByNumber", json!(["latest", false]))?;
    let hash = bytes::<32>(&head["hash"])?;
    let block = json!({"blockHash":hex(&hash),"requireCanonical":true});
    let slot = bytes::<32>(&ask(
        "eth_getStorageAt",
        json!([hex(&proxy), IMPLEMENTATION_SLOT, block]),
    )?)?;
    if slot[..12] != [0; 12] || slot[12..] != implementation {
        return Err("unapproved ERC-1967 implementation address".into());
    }
    if code_hash(ask("eth_getCode", json!([hex(&proxy), block]))?)? != expected_proxy {
        return Err("unapproved proxy runtime bytecode".into());
    }
    if code_hash(ask("eth_getCode", json!([hex(&implementation), block]))?)? != expected_impl {
        return Err("unapproved implementation runtime bytecode".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_watcher::RpcError;
    struct Rpc {
        changed: bool,
    }
    impl JsonRpcClient for Rpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            Ok(match method {
                "eth_chainId" => json!("0x1"),
                "eth_getBlockByNumber" => json!({"hash":hex(&[1;32])}),
                "eth_getStorageAt" => {
                    assert_eq!(params[2]["requireCanonical"], true);
                    let mut slot = [0; 32];
                    slot[12..].copy_from_slice(&[2; 20]);
                    json!(hex(&slot))
                }
                "eth_getCode" => {
                    assert_eq!(params[1]["blockHash"], hex(&[1; 32]));
                    json!(if self.changed && params[0] == hex(&[2; 20]) {
                        "0x6001"
                    } else {
                        "0x6000"
                    })
                }
                _ => panic!("unexpected call"),
            })
        }
    }
    #[test]
    fn approved_code_passes_and_changed_semantics_or_missing_approval_fail() {
        let entry = json!({"chain_id":1,"proxy":hex(&[3;20]),"implementation":hex(&[2;20]),
            "proxy_code_hash":hex(&code_hash(json!("0x6000")).unwrap()),
            "implementation_code_hash":hex(&code_hash(json!("0x6000")).unwrap())});
        assert!(verify(&Rpc { changed: false }, 1, [3; 20], &json!([entry])).is_ok());
        assert!(verify(&Rpc { changed: true }, 1, [3; 20], &json!([entry])).is_err());
        assert!(verify(&Rpc { changed: false }, 1, [3; 20], &json!([])).is_err());
        assert!(verify(&Rpc { changed: false }, 1, [3; 20], &json!([entry, entry])).is_err());
    }
}
