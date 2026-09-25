#!/usr/bin/env bash
# Journaled, forward-only dual-share promotion. Rerun to recover an interruption.
# Requires GATEWAY_ID, PROXY; RPC/BELDEX_RPC default to local devnet endpoints.
# --dry-run validates without moving shares; --status reports the durable record.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${TESTDATA_DIR:-$SCRIPT_DIR/testdata}"
if [ -f "$ROOT/../devnet-bridge.env" ]; then
  set -a
  . "$ROOT/../devnet-bridge.env"
  set +a
fi
exec python3 "$SCRIPT_DIR/share_promotion.py" "$@"
