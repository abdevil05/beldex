#!/usr/bin/env bash
# Retired Phase L entry point: never deploy through obsolete security defaults.
set -euo pipefail
echo "This legacy deployment path is retired; no transaction was submitted." >&2
echo "Use bridge-contract/devnet/01-deploy.sh with the current committee signer." >&2
echo "Review guardian, network, minimum redemption, timelock and backing inputs." >&2
echo "See bridge/test/e2e/README.md. Anvil does not establish security closure." >&2
exit 2
