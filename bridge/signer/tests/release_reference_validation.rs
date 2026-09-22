//! Exercise the real HTTP decoder and signing policy together. RPC replies stand
//! for our own daemon's independent reading of the blob, not leader metadata.
#![cfg(feature = "autonomy")]

use beldex_bridge_signer::{
    chain_registry::ChainId,
    coordinator::{BuildError, ProposalPolicy, ProposalVerdict},
    live_backend::HttpGatewayRpc,
    orchestrator::Duty,
    release_policy::{ReleasePolicy, ReleaseProposal},
    session::NackReason,
    watch::ReleaseEvent,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::Duration,
};

fn decoded() -> Value {
    json!({
        "source_gateway_id": "aa", "source_gateway_address": "gw",
        "dest_all_outputs_match": true, "dest_amount": 975, "fee": 25,
        "hash_to_sign": "11".repeat(32), "release_ref_count": 1,
        "release_ref": {"version": 0, "chain_id": 1,
            "evm_txid": "22".repeat(32), "log_index": 0}
    })
}

fn verify_reply(reply: Value) -> ProposalVerdict {
    let listener = TcpListener::bind("127.0.0.1:0").expect("local RPC test listener");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "incomplete request");
            request.extend_from_slice(&buf[..n]);
            if let Some(end) = request.windows(4).position(|b| b == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                if request.len() >= end + 4 + length {
                    let req: Value =
                        serde_json::from_slice(&request[end + 4..end + 4 + length]).unwrap();
                    assert_eq!(req["method"], "gateway_decode_withdrawal");
                    assert_eq!(req["params"]["tx_blob"], "01");
                    let body =
                        json!({"jsonrpc":"2.0", "id": req["id"], "result":reply}).to_string();
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                    break;
                }
            }
        }
    });
    let ev = ReleaseEvent {
        chain: ChainId(1),
        evm_txid: [0x22; 32],
        log_index: 0,
        amount: 1000,
        beldex_recipient: b"recipient".to_vec(),
    };
    let p = ReleaseProposal {
        version: 1,
        chain_id: 1,
        evm_txid: ev.evm_txid,
        log_index: 0,
        fee: 25,
        hash_to_sign: [0x11; 32],
        tx_key: [3; 32],
        unsigned_tx_blob: vec![1],
    };
    let mut rpc = HttpGatewayRpc::new(endpoint);
    let mut policy = ReleasePolicy {
        build_tx: |_ev: &ReleaseEvent| Err(BuildError::Transient("unused".into())),
        inspect: move |p: &ReleaseProposal, recipient: &[u8]| {
            rpc.decode_withdrawal(p, std::str::from_utf8(recipient).unwrap(), "aa")
        },
        release_gateway: "aa".into(),
        max_fee: 25,
        per_tx_cap: 1000,
    };
    let verdict = policy.verify(&Duty::Release(ev), &p.encode());
    server.join().unwrap();
    verdict
}

#[test]
fn matching_decoded_reference_is_accepted() {
    assert_eq!(verify_reply(decoded()), ProposalVerdict::Accept);
}

#[test]
fn substituted_decoded_reference_is_rejected_despite_honest_envelope() {
    for (field, value) in [
        ("chain_id", json!(999)),
        ("evm_txid", json!("99".repeat(32))),
        ("log_index", json!(7)),
    ] {
        let mut reply = decoded();
        reply["release_ref"][field] = value;
        assert_eq!(
            verify_reply(reply),
            ProposalVerdict::Reject(NackReason::PayloadMismatch),
            "{field}"
        );
    }
}

#[test]
fn missing_duplicate_or_unknown_version_reference_fails_closed() {
    let mut cases = Vec::new();
    let mut reply = decoded();
    reply.as_object_mut().unwrap().remove("release_ref_count"); // old daemon
    cases.push(reply);
    let mut reply = decoded();
    reply.as_object_mut().unwrap().remove("release_ref");
    cases.push(reply);
    for count in [json!(0), json!(2), json!("1"), Value::Null] {
        let mut reply = decoded();
        reply["release_ref_count"] = count;
        cases.push(reply);
    }
    let mut reply = decoded();
    reply["release_ref"]
        .as_object_mut()
        .unwrap()
        .remove("version");
    cases.push(reply);
    for version in [json!(1), json!(256), json!("0"), Value::Null] {
        let mut reply = decoded();
        reply["release_ref"]["version"] = version;
        cases.push(reply);
    }
    for reply in cases {
        assert_eq!(verify_reply(reply), ProposalVerdict::Abstain);
    }
}

#[test]
fn malformed_or_truncated_reference_fields_fail_closed() {
    for field in ["chain_id", "evm_txid", "log_index"] {
        let mut reply = decoded();
        reply["release_ref"].as_object_mut().unwrap().remove(field);
        assert_eq!(
            verify_reply(reply),
            ProposalVerdict::Abstain,
            "missing {field}"
        );
    }
    for (field, value) in [
        ("chain_id", json!(-1)),
        ("chain_id", json!("1")),
        ("evm_txid", json!("22".repeat(31))),
        ("evm_txid", json!("zz".repeat(32))),
        ("evm_txid", json!("é".repeat(32))),
        ("evm_txid", json!(7)),
        ("log_index", json!(4294967296u64)),
        ("log_index", json!(-1)),
        ("log_index", json!(0.5)),
    ] {
        let mut reply = decoded();
        reply["release_ref"][field] = value;
        assert_eq!(verify_reply(reply), ProposalVerdict::Abstain, "{field}");
    }
}
