#!/usr/bin/env bash
# serve-live.sh — start the COORDINATED autonomous signer (`serve --live`) on exactly
# the signer-set nodes of the local devnet (bridge/test/e2e/AUTONOMOUS_ROUNDTRIP.md).
#
#     GATEWAY_ID=<64-char hex id> VIEW_SECRET=<64hex> RELEASE_GATEWAY=<gwB…|hex> \
#     WBDX=<0x…20-byte> EVM_RPC=http://127.0.0.1:8545 CHAIN_ID=31337 \
#     runlog ./serve-live.sh
#
# Which nodes run: by default EVERY node that holds dkg shares (each node dir's own
# devnet/shares/pgw-<i>.keypackage carries its committee index). Each duty's signing
# round runs among the session's canonical ACK set — the lowest t+1 committee indices
# that independently verified that duty — so more nodes serving just means more
# failover headroom. Set NODES=0,1,2 to start a subset (needs >= t+1 for liveness).
#
# Two devnet-only knobs this script sets for you, both of which a local chain needs and
# a real network does not — see the block above each in the launch env below:
#   * BRIDGE_SIGNER_BELDEX_CONFIRMATIONS — deposit finality on a chain that never
#     checkpoints (every devnet). Without it NO deposit can ever mint, silently.
#   * BRIDGE_SIGNER_SIGN_SIGNERS — lets committee indices >= t+1 start at all.
#
# Stop with:  pkill -f 'beldex-bridge-signer serve'
# Logs:       testdata/serve-<node>.log   (watch the `tick N: opened/acked/...` lines)

set -euo pipefail
cd "$(dirname "$0")"

# This launcher intentionally collapses every operator onto one host, uses a
# reversible EVM and (normally) a non-checkpointing native devnet. Keep those
# acknowledgements behind one loud, local-only switch so none can leak into a
# deployment by accident.
if [ "${ALLOW_UNSAFE_LOCAL_AUTONOMY:-0}" != "1" ]; then
  echo "!! autonomous value movement on this single-host devnet is disabled by default." >&2
  echo "   For local security/function tests only, re-run with:" >&2
  echo "     ALLOW_UNSAFE_LOCAL_AUTONOMY=1" >&2
  echo "   Never copy that variable to a shared or public deployment." >&2
  exit 1
fi

# GATEWAY_ID must be the 32-byte HEX id, not the gwB… address: the signer parses it
# with parse_hex32 (bridge/signer/src/config.rs:127) and a base58 address dies at
# startup with "config key gateway_id is not 32-byte hex". simplewallet prints the
# hex next to the address at registration, on the `Gateway id  :` line.
: "${GATEWAY_ID:?set GATEWAY_ID (64-char hex gateway id — the gwB… address is rejected)}"
: "${VIEW_SECRET:?set VIEW_SECRET (64-char hex gateway view secret — decrypts A.5 memos)}"
# Single-gateway model (the intended one): one account registered as
#   register_gateway_address <view_secret> eddsa <Pgw group vk>
# receives deposits (id = view pubkey) AND pays releases (owner = threshold key),
# so RELEASE_GATEWAY defaults to GATEWAY_ID. Override only for a split setup.
# Unlike GATEWAY_ID this one accepts EITHER form — it is passed through as the RPC
# `source` field, and core_rpc_server.cpp:3771 tries get_gateway_address_from_str
# first and falls back to hex_to_type.
RELEASE_GATEWAY="${RELEASE_GATEWAY:-$GATEWAY_ID}"
: "${WBDX:?set WBDX (deployed WrappedBDX address, 0x…)}"
EVM_RPC="${EVM_RPC:-http://127.0.0.1:8545}"
CHAIN_ID="${CHAIN_ID:-31337}"
NODES="${NODES:-all}"          # which committee indices to start (default: all with shares)
THRESHOLD="${THRESHOLD:-4}"    # t+1, for the liveness warning below

# Genesis hash: binds release canonical ids (S6) and the mint-bus publish signatures.
# Auto-fetched from the pinned daemon when not provided.
if [ -z "${BRIDGE_SIGNER_GENESIS_HASH:-}" ]; then
  BRIDGE_SIGNER_GENESIS_HASH=$(curl -s http://127.0.0.1:19191/json_rpc \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_block_header_by_height","params":{"height":0}}' \
    | sed -n 's/.*"hash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
fi
if [ -n "$BRIDGE_SIGNER_GENESIS_HASH" ]; then
  echo "genesis: $BRIDGE_SIGNER_GENESIS_HASH"
else
  echo "!! could not fetch the genesis hash — live mode refuses an unbound network domain" >&2
  exit 1
fi
RELEASE_FEE="${RELEASE_FEE:-100000000}"
# Mint hand-off: which node(s) auto-broadcast the signed mint payload, and with what.
# Releases self-submit from every signer; MINTS need a gas key, which the signer never holds
# — so a relayer command is piped the payload instead. Default: only committee index 0 does
# it (one broadcaster = no duplicate-revert gas). Set RELAY_NODES=all for redundancy, and
# then RELAY_STAGGER_MS so they don't fire simultaneously. Empty RELAY_CMD = log only.
RELAY_CMD="${RELAY_CMD:-}"
RELAY_NODES="${RELAY_NODES:-0}"
RELAY_STAGGER_MS="${RELAY_STAGGER_MS:-2000}"
START_HEIGHT="${START_HEIGHT:-0}"
POLL_SECS="${POLL_SECS:-5}"
MESH_USE_CURVE="${BRIDGE_SIGNER_MESH_USE_CURVE:-true}"
if [ "$MESH_USE_CURVE" = "false" ] || [ "$MESH_USE_CURVE" = "0" ]; then
  [ "${ALLOW_PLAINTEXT_MESH:-0}" = "1" ] || {
    echo "!! plaintext signing mesh refused; set ALLOW_PLAINTEXT_MESH=1 only for an explicit insecure test" >&2
    exit 1
  }
fi
ALLOW_REVERSIBLE_EVM=1
if [ "${SHARE_SUBDIR:-shares}" = "shares-pool" ] && [ "${ALLOW_POOLED_SHARES:-0}" != "1" ]; then
  echo "!! pooled shares collapse the threshold boundary and are disabled by default." >&2
  echo "   Fix committee/share indexing; set ALLOW_POOLED_SHARES=1 only for an explicit insecure test." >&2
  exit 1
fi

# Read the registry values from the deployed proxy. The hardened signer refuses to
# start when an operator-supplied epoch or cap drifts from live contract state.
num() { printf '%s' "$1" | sed -n 's/^\([0-9][0-9]*\).*/\1/p'; }
KEY_EPOCH="$(num "$(cast call "$WBDX" 'keyEpoch()(uint64)' --rpc-url "$EVM_RPC")")"
PER_TX_MAX="$(num "$(cast call "$WBDX" 'perTxMax()(uint256)' --rpc-url "$EVM_RPC")")"
WINDOW_MINT_CAP="$(num "$(cast call "$WBDX" 'windowMintCap()(uint256)' --rpc-url "$EVM_RPC")")"
CONTRACT_BACKING="$(num "$(cast call "$WBDX" 'bondBackingCapLimit()(uint256)' --rpc-url "$EVM_RPC")")"
for value in "$KEY_EPOCH" "$PER_TX_MAX" "$WINDOW_MINT_CAP" "$CONTRACT_BACKING"; do
  [ -n "$value" ] || { echo "!! could not read epoch/caps from $WBDX at $EVM_RPC" >&2; exit 1; }
done
GLOBAL_BOND_BACKING="${GLOBAL_BOND_BACKING:-}"
[ -n "$GLOBAL_BOND_BACKING" ] || {
  echo "!! set GLOBAL_BOND_BACKING to an independently verified native bond allocation." >&2
  echo "   The contract's governance-set bondBackingCapLimit cannot prove its own backing." >&2
  exit 1
}
case "$GLOBAL_BOND_BACKING" in ''|*[!0-9]*) echo "!! GLOBAL_BOND_BACKING must be decimal" >&2; exit 1;; esac

# Deposit finality. The signer's production rule is `get_info.immutable_height` — the
# master-node checkpoint below which the chain cannot reorg. beldexd emits that field
# only when `db.get_immutable_checkpoint` succeeds (core_rpc_server.cpp), and a
# checkpointing quorum is only generated once the network has CHECKPOINT_QUORUM_SIZE
# active masternodes — 20 in a normal build (master_node_rules.h; the value is 5 only
# under BELDEX_ENABLE_INTEGRATION_TEST_HOOKS, i.e. -DBUILD_INTEGRATION=ON). This devnet
# runs 6, so it never checkpoints, the field is absent from every get_info, and the
# watcher's finality gate never opens: deposits confirm on chain, gateway_get_history is
# never called, and no mint duty is ever created — with no error in the serve log,
# because service.rs treats a poll error as transient. See DEVNET_FINALITY_BLOCKER.md.
#
# BRIDGE_SIGNER_BELDEX_CONFIRMATIONS=N falls back to `top_height - N` in exactly that
# case. It is a strict either/or, not a max: a daemon that DOES report a checkpoint
# ignores this outright, so it can never widen finality on a real network. Unset it
# (BELDEX_CONFIRMATIONS= ) to restore strict behaviour and watch the gate stay shut.
BELDEX_CONFIRMATIONS="${BELDEX_CONFIRMATIONS-10}"
if [ -n "$BELDEX_CONFIRMATIONS" ] && [ "${ALLOW_NONCHECKPOINT_FINALITY:-0}" != "1" ]; then
  echo "!! confirmation-only native finality is disabled by default." >&2
  echo "   Run a checkpoint-capable network, or set ALLOW_NONCHECKPOINT_FINALITY=1 for an explicit devnet canary." >&2
  exit 1
fi

# Startup signer-set gate. `build_live_signers` (main.rs) refuses to start a node whose
# committee index is not in BRIDGE_SIGNER_SIGN_SIGNERS, and the default when the variable
# is unset is `0..threshold` — so on a 6-of-4 devnet indices 4 and 5 die instantly with
#   serve: this node (4) is not in the signer set [0, 1, 2, 3]
# and this script then exits 1 with two dead children. That default is a leftover from the
# one-shot `sign` subcommand: under coordinated autonomy the participants of each signing
# round are the session's canonical ACK set, passed per duty into pgw_sign/pevm_sign — the
# LiveSigners.signers field is never read again after this check. Listing the whole
# committee here therefore only widens the startup gate; it does not change who signs, and
# it is what AUTONOMOUS_ROUNDTRIP.md §1 describes.
SIGN_SIGNERS="${SIGN_SIGNERS:-0,1,2,3,4,5}"

# Chain registry for the EVM watcher. The keys are exactly the ones
# evm_watcher.rs::parse_evm_chains reads: chain_id, contract, confirmations, rpc,
# key_epoch, per_tx_max, per_epoch_cap, and the optional start_block. Two traps here, both of
# which cost a devnet run:
#   * the endpoint key is `rpc`, NOT `rpc_url` — the wrong spelling aborts every
#     signer at startup with "chain[0]: missing/invalid `rpc`";
#   * unrecognised keys are silently dropped, so a typo'd or invented key (this
#     block used to carry an `epoch_blocks` that nothing ever read) looks applied
#     and is not. `start_block` is the real name for "skip ahead".
# Caps gate resolve_mint, not the contract. Twelve EVM confirmations are the local default;
# Anvil rollback remains arbitrary and is separately blocked unless explicitly acknowledged.
EVM_START_BLOCK="${EVM_START_BLOCK:-0}"
EVM_CONFIRMATIONS="${EVM_CONFIRMATIONS:-12}"
if [ "${REQUIRE_DISTINCT_EVM_RPCS:-0}" = "1" ]; then
  RPC_LIST=""
  for rpc_index in 0 1 2 3 4 5; do
    rpc_value="$(printenv "EVM_RPC_$rpc_index" 2>/dev/null || true)"
    [ -n "$rpc_value" ] || {
      echo "!! REQUIRE_DISTINCT_EVM_RPCS=1 needs EVM_RPC_$rpc_index" >&2; exit 1; }
    RPC_LIST="$RPC_LIST\n$rpc_value"
  done
  RPC_UNIQUE="$(printf '%b\n' "$RPC_LIST" | grep -v '^$' | sort -u | wc -l | tr -d ' ')"
  [ "$RPC_UNIQUE" -eq 6 ] || {
    echo "!! EVM_RPC_0..5 are not six distinct endpoints" >&2; exit 1; }
else
  echo "WARNING: EVM RPC independence is not enforced; set REQUIRE_DISTINCT_EVM_RPCS=1 with EVM_RPC_0..5 to test oracle fault isolation"
fi
cd testdata

SIGNER="${SIGNER:-$(git rev-parse --show-toplevel)/bridge/signer/target/debug/beldex-bridge-signer}"
[ -x "$SIGNER" ] || { echo "build first: cargo build -p beldex-bridge-signer --features serve-live"; exit 1; }
SIGNER_ROOT="$(git rev-parse --show-toplevel)"
if find "$SIGNER_ROOT/bridge/signer/src" "$SIGNER_ROOT/bridge/signer/Cargo.toml" \
    "$SIGNER_ROOT/bridge/signer/Cargo.lock" -newer "$SIGNER" -print -quit 2>/dev/null | grep -q .; then
  echo "!! signer source/dependency metadata is newer than $SIGNER" >&2
  echo "   rebuild: cargo build --manifest-path bridge/signer/Cargo.toml --features serve-live" >&2
  exit 1
fi
echo "signer source : $(git -C "$SIGNER_ROOT" rev-parse HEAD)$(git -C "$SIGNER_ROOT" diff --quiet && echo '' || echo '-dirty')"
echo "signer sha256 : $(sha256sum "$SIGNER" | awk '{print $1}')"
ANY32=$(printf '11%.0s' {1..32})

pkill -f 'beldex-bridge-signer serve' 2>/dev/null || true
sleep 1
rm -f serve-*.log

started=0
PIDS=()
for d in beldex-127.0.0.1-*/; do
  sock="$PWD/${d}devnet/beldexd.sock"; key="$PWD/${d}devnet/key_ed25519"
  # SHARE_SUBDIR: which per-node share tree the signer loads from (default `shares`).
  # `shares-pool` is the devnet-only workaround for EPOCH_RESHUFFLE_ORPHANS_SHARES.md —
  # a symlinked pool holding every node's share, so a node whose live committee index no
  # longer matches its dkg index can still open the share for the seat it now occupies.
  # Same knob name as sign-pevm.sh, deliberately.
  share="$PWD/${d}devnet/${SHARE_SUBDIR:-shares}"
  [ -S "$sock" ] && [ -f "$key" ] || continue
  share_mode="$(stat -c '%a' "$share" 2>/dev/null || true)"
  [ "$share_mode" = "700" ] || {
    echo "skip ${d%/}: share directory mode is ${share_mode:-unknown}, require 700"; continue; }
  private_bad=0
  for private in "$share"/pevm-*.keyshare "$share"/pgw-*.keypackage; do
    [ -f "$private" ] || continue
    private_mode="$(stat -c '%a' "$private" 2>/dev/null || true)"
    case "$private_mode" in 400|600) ;; *) private_bad=1 ;; esac
  done
  [ "$private_bad" -eq 0 ] || {
    echo "skip ${d%/}: private share files must be mode 400 or 600"; continue; }

  # This node's committee index, from its own dkg share filename.
  # `|| true` is load-bearing: under `set -euo pipefail` the failing `ls` in this
  # command substitution aborts the whole script, so a node dir with no pgw share
  # killed the loop before the guard below could skip it — and every node after it
  # in glob order never started.
  # NB: read from the node's OWN `shares` tree, never from $share — under SHARE_SUBDIR=shares-pool
  # every node sees all six keypackages and `head -1` would report index 0 for all of them,
  # silently collapsing the NODES filter and handing RELAY_CMD to the whole fleet.
  idx=$(ls "$PWD/${d}devnet/shares"/pgw-*.keypackage 2>/dev/null | sed -E 's/.*pgw-([0-9]+)\.keypackage/\1/' | head -1) || true
  [ -n "$idx" ] || { echo "skip ${d%/}: no pgw share (did dkg run here?)"; continue; }
  if [ "$NODES" != "all" ]; then
    case ",$NODES," in
      *",$idx,"*) ;;
      *) echo "skip ${d%/}: committee index $idx not in NODES={$NODES}"; continue ;;
    esac
  fi

  node_port="${d%/}"; node_port="${node_port##*-}"
  node_beldex_rpc="http://127.0.0.1:$node_port"
  node_evm_rpc="$EVM_RPC"
  node_evm_var="EVM_RPC_$idx"
  node_evm_override="$(printenv "$node_evm_var" 2>/dev/null || true)"
  [ -z "$node_evm_override" ] || node_evm_rpc="$node_evm_override"
  node_evm_chains="[{\"chain_id\":${CHAIN_ID},\"rpc\":\"${node_evm_rpc}\",\"contract\":\"${WBDX}\",\"key_epoch\":${KEY_EPOCH},\"confirmations\":${EVM_CONFIRMATIONS},\"per_epoch_cap\":\"${WINDOW_MINT_CAP}\",\"per_tx_max\":\"${PER_TX_MAX}\",\"start_block\":${EVM_START_BLOCK}}]"

  # Give the relay hook only to the chosen node(s).
  node_relay=""
  if [ -n "$RELAY_CMD" ]; then
    case "$RELAY_NODES" in
      all) node_relay="$RELAY_CMD" ;;
      *) case ",$RELAY_NODES," in *",$idx,"*) node_relay="$RELAY_CMD" ;; esac ;;
    esac
  fi

  echo "start ${d%/}: committee index $idx${node_relay:+  (relays mints)}"
  BRIDGE_SIGNER_GENESIS_HASH="$BRIDGE_SIGNER_GENESIS_HASH" \
  BRIDGE_SIGNER_MINT_BUS_ENDPOINT="ipc://$PWD/beldex-127.0.0.1-19191/devnet/beldexd.sock" \
  BRIDGE_SIGNER_RELAY_CMD="$node_relay" \
  RELAYER_STATE_DIR="${RELAYER_STATE_DIR:-$PWD/relayer-state}" \
  BRIDGE_SIGNER_RELAY_STAGGER_MS="$RELAY_STAGGER_MS" \
  BRIDGE_SIGNER_SERVE_LIVE=1 \
  BRIDGE_SIGNER_BELDEXD_RPC_URL="$node_beldex_rpc" \
  BRIDGE_SIGNER_OXENMQ_ENDPOINT="ipc://$sock" \
  BRIDGE_SIGNER_SELF_MN_PUBKEY="$ANY32" \
  BRIDGE_SIGNER_BRIDGE_EPOCH_BLOCKS=120 BRIDGE_SIGNER_COMMITTEE_THRESHOLD=4 \
  BRIDGE_SIGNER_MN_KEY_FILE="$key" BRIDGE_SIGNER_SHARE_DIR="$share" \
  BRIDGE_SIGNER_ALLOW_FILE_SHARES=1 \
  BRIDGE_SIGNER_MINT_OUTBOX_DIR="$PWD/${d}devnet/mint-outbox" \
  BRIDGE_SIGNER_RELEASE_OUTBOX_DIR="$PWD/${d}devnet/release-outbox" \
  BRIDGE_SIGNER_WATCH_STATE_FILE="$PWD/${d}devnet/watch.state" \
  BRIDGE_SIGNER_GLOBAL_BOND_BACKING="$GLOBAL_BOND_BACKING" \
  BRIDGE_SIGNER_MESH_PORT_BASE=6000 BRIDGE_SIGNER_MESH_PEVM_OFFSET=100 \
  BRIDGE_SIGNER_MESH_COORD_OFFSET=200 BRIDGE_SIGNER_MESH_BIND_HOST=127.0.0.1 BRIDGE_SIGNER_MESH_USE_CURVE="$MESH_USE_CURVE" \
  BRIDGE_SIGNER_ALLOW_REVERSIBLE_EVM="$ALLOW_REVERSIBLE_EVM" \
  BRIDGE_SIGNER_ALLOW_DEPTH_FINALITY=1 \
  BRIDGE_SIGNER_ALLOW_SINGLE_HOST_COMMITTEE=1 \
  BRIDGE_SIGNER_SIGN_TIMEOUT_SECS="${BRIDGE_SIGNER_SIGN_TIMEOUT_SECS:-600}" \
  BRIDGE_SIGNER_STAGE_TIMEOUT_TICKS="${STAGE_TIMEOUT_TICKS:-4}" \
  BRIDGE_SIGNER_SIGN_SIGNERS="$SIGN_SIGNERS" \
  BRIDGE_SIGNER_GATEWAY_ID="$GATEWAY_ID" \
  BRIDGE_SIGNER_GATEWAY_VIEW_SECRET="$VIEW_SECRET" \
  BRIDGE_SIGNER_BELDEX_START_HEIGHT="$START_HEIGHT" \
  BRIDGE_SIGNER_BELDEX_CONFIRMATIONS="$BELDEX_CONFIRMATIONS" \
  BRIDGE_SIGNER_EVM_CHAINS="$node_evm_chains" \
  BRIDGE_SIGNER_WATCH_POLL_SECS="$POLL_SECS" \
  BRIDGE_SIGNER_RELEASE_GATEWAY="$RELEASE_GATEWAY" \
  BRIDGE_SIGNER_RELEASE_FEE="$RELEASE_FEE" \
  BRIDGE_SIGNER_RELEASE_MAX_FEE="$RELEASE_FEE" \
    "$SIGNER" serve > "serve-${d%/}.log" 2>&1 &
  PIDS+=("$!:${d%/}")
  started=$((started + 1))
done

# Launching is not running. A bad GATEWAY_ID or a malformed BRIDGE_SIGNER_EVM_CHAINS
# kills every child within a second, and without this check the script still exits 0
# and reports "6 signer(s) serving" over six dead processes. Give them a moment, then
# ask the kernel rather than guessing from log text.
sleep 2
alive=0; dead=()
# `${PIDS[@]+...}` guard: under `set -u`, bash 3.2 — which is what /bin/bash is on
# macOS — treats "${EMPTY[@]}" as an unbound variable and aborts.
for entry in ${PIDS[@]+"${PIDS[@]}"}; do
  pid="${entry%%:*}"; node="${entry#*:}"
  if kill -0 "$pid" 2>/dev/null; then alive=$((alive + 1)); else dead+=("$node"); fi
done

echo
if [ "${#dead[@]}" -gt 0 ]; then
  echo "!! $alive of $started still alive after 2s — these exited immediately:"
  for node in ${dead[@]+"${dead[@]}"}; do
    echo "   $node: $(grep -v '^(no .env file' "serve-${node}.log" | head -2 | tr '\n' ' ')"
  done
  echo "   full output: testdata/serve-<node>.log"
  exit 1
fi

echo "$alive signer(s) serving (need >= $THRESHOLD observing the same event to sign)"
echo "watch:  tail -f testdata/serve-*.log"
echo "stop:   pkill -f 'beldex-bridge-signer serve'"
[ "$alive" -ge "$THRESHOLD" ] || \
  echo "!! only $alive started — below t+1=$THRESHOLD, duties will stay pending"
