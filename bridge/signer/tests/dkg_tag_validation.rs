#![cfg(feature = "tss-integration")]

// This test links the normal library, not its cfg(test) fallback.
#[test]
fn library_caller_cannot_fall_back_to_a_test_ceremony() {
    use beldex_bridge_signer::{committee::CommitteeView, dkg_tag::ceremony_tag};
    let committee = CommitteeView {
        epoch: 7,
        height: 840,
        members: vec![[1; 32], [2; 32]],
        signer_keys: vec![[3; 32], [4; 32]],
        member_ips: vec![],
        member_x25519: vec![],
        daemon_self_index: None,
        threshold: 2,
    };
    std::env::set_var("BRIDGE_SIGNER_GENESIS_HASH", "08".repeat(32));
    std::env::remove_var("BRIDGE_SIGNER_DKG_CEREMONY_ID");
    assert!(ceremony_tag(b"pgw", &committee, 1).is_err());
    for invalid in ["00".repeat(32), "bad".into(), "gg".repeat(32)] {
        std::env::set_var("BRIDGE_SIGNER_DKG_CEREMONY_ID", invalid);
        assert!(ceremony_tag(b"pgw", &committee, 1).is_err());
    }
    std::env::set_var("BRIDGE_SIGNER_DKG_CEREMONY_ID", "01".repeat(32));
    assert!(ceremony_tag(b"pgw", &committee, 1).is_ok());
}
