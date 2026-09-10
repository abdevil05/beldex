#!/usr/bin/env bash
# Deterministic/mock-chain regressions plus real localhost socket/MPC tests.
# No daemon, deployment, funded transaction or key files are required.
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 -B "$repo_dir/utils/local-devnet/test_outbox_maintenance.py"
cd "$repo_dir/bridge/signer"
cargo test --locked --all-features --bin beldex-bridge-signer
cargo test --locked --all-features --test dkg_tag_validation
for suite in config implementation_pin http_deadline dkg_tag evm_watcher beldex_watcher watch orchestrator coordinator reconcile rotation_ack committee session; do
  cargo test --locked --all-features --lib "$suite::tests"
done
cargo test --locked --all-features --lib share_store::atomic_tests
cargo test --locked --all-features --lib cggmp21_driver::tests::barrier_send_and_poll_failures_are_returned_immediately
for test in omq_mesh::tests::two_node_plain_roundtrip omq_mesh::tests::two_node_curve_roundtrip cggmp21_driver::tests::cggmp21_keygen_over_the_mesh_agrees cggmp21_sign_driver::tests::cggmp21_signing_over_the_mesh_recovers_wbdx_address; do
  cargo test --locked --all-features --lib "$test" -- --ignored --exact --test-threads=1
done
echo "Signer regression subset passed; this is not live-chain end-to-end acceptance."
