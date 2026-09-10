#!/usr/bin/env bash
# Local regression harness: never deploys, rotates keys, spends funds or resets state.
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "${1:-}" in
  ""|--real-mpc) ;;
  *) echo "usage: bash $0 [--real-mpc]" >&2; exit 2 ;;
esac
cd "$repo_dir/bridge/relayer"
cargo test --locked --all-features
# --real-mpc is retained for command compatibility; these tests are mandatory now.
bash "$repo_dir/utils/local-devnet/signer-security-tests.sh"
if [ -n "${NATIVE_UNIT_TEST_BINARY:-}" ]; then
  "$NATIVE_UNIT_TEST_BINARY" --gtest_filter='GatewayBridge*.*:GatewayWithdrawal.*:*ReadOnlyLegacyGatewayIndexFailsClosed'
else
  echo "NOT RUN: native gateway tests; set NATIVE_UNIT_TEST_BINARY to your built unit_tests binary."
fi
cd "$repo_dir/../bridge-contract"
forge test
echo "Selected local regressions passed. This is NOT seven-finding closure."
echo "Still required: full native owner handoff, live rotation-ack/bond settlement,"
echo "adversarial crash/reorg/MPC tests and independent finality/custody infrastructure."
