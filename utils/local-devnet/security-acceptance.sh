#!/usr/bin/env bash
# Local regression harness: never deploys, rotates keys, spends funds or resets state.
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "${1:-}" in
  ""|--real-mpc) ;;
  *) echo "usage: bash $0 [--real-mpc]" >&2; exit 2 ;;
esac
cd "$repo_dir/bridge/relayer"
cargo test --all-features
cd "$repo_dir/bridge/signer"
cargo test --all-features --bin beldex-bridge-signer
for suite in dkg_tag evm_watcher orchestrator coordinator reconcile rotation_ack; do
  cargo test --all-features --lib "$suite::tests"
done
if [ "${1:-}" = "--real-mpc" ]; then
  cargo test --all-features --lib cggmp21_driver::tests::cggmp21_keygen_over_the_mesh_agrees -- --ignored
  cargo test --all-features --lib cggmp21_sign_driver::tests::cggmp21_signing_over_the_mesh_recovers_wbdx_address -- --ignored
else
  echo "NOT RUN: real CGGMP21 protocol tests; add --real-mpc to include them."
fi
if [ -n "${NATIVE_UNIT_TEST_BINARY:-}" ]; then
  "$NATIVE_UNIT_TEST_BINARY" --gtest_filter='GatewayBridge*.*:GatewayWithdrawal.*'
else
  echo "NOT RUN: native gateway tests; set NATIVE_UNIT_TEST_BINARY to your built unit_tests binary."
fi
cd "$repo_dir/../bridge-contract"
forge test
echo "Selected local regressions passed. This is NOT seven-finding closure."
echo "Still required: full native owner handoff, live rotation-ack/bond settlement,"
echo "adversarial crash/reorg/MPC tests and independent finality/custody infrastructure."
