#!/usr/bin/env bash
# bootstrap-bridge.sh — take a FRESHLY STARTED devnet all the way to running bridge signers,
# in one pass. Run this after `master_node_network.py` is up (it wipes testdata on restart,
# so everything below must be redone each time — this script IS that redo).
#
#     runlog ./bootstrap-bridge.sh
#
# What it does, in order:
#   1. waits for an ACTIVE 6-member bridge committee
#   2. starts the background miner (finality needs a moving chain)
#   3. runs the initial dual DKG (dkg-init.sh) → PGW_GROUP_VK
#   4. derives the Pevm signer address (pure-python point decompression + `cast keccak`)
#   5. deploys WrappedBDX on anvil with that signer → WBDX
#   6. generates VIEW_SECRET and registers ONE bridge gateway (owner = Pgw key,
#      bridge_reserve flag) via a funded devnet wallet-rpc
#   7. writes everything to devnet-bridge.env and launches serve-live.sh
#
# Idempotence: each step checks its outcome and stops loudly on failure. Re-running after
# a partial failure is safe — completed steps detect their artifacts and skip.

set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.foundry/bin:$PATH"
umask 077

RPC=http://127.0.0.1:19191
ROOT="$(git rev-parse --show-toplevel)"
BC="${BC:-$(dirname "$ROOT")/bridge-contract}"
ENVFILE="$PWD/devnet-bridge.env"

jrpc() { # jrpc <method> [params-json]
  # params defaults to {} via an explicit branch, NOT `${2:-{\}}`. Under bash 3.2 — which is
  # what macOS ships as /bin/bash, and what `#!/usr/bin/env bash` resolves to unless
  # /opt/homebrew/bin precedes /usr/local/bin on PATH — the backslash in that expansion is
  # not removed, so the body goes out as `"params":{\}` and the daemon answers -32700 Parse
  # error for EVERY call. Silent under the old caller, which read the failure as 0 members.
  local params="${2-}"
  [ -n "$params" ] || params='{}'
  curl -s "$RPC/json_rpc" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"$1\",\"params\":$params}"
}
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# The miner comes FIRST, deliberately. The bridge quorum only exists at epoch-boundary
# heights, so the committee wait below needs a chain that is moving. With the miner
# started after it, a harness sitting on a static tip deadlocks the two steps against
# each other: nothing advances the chain because the step that would is queued behind
# the step waiting on it.
# ── 1. miner ─────────────────────────────────────────────────────────────────
say "background miner"
if pgrep -f 'mine.sh loop' >/dev/null 2>&1; then
  echo "already running"
else
  nohup ./mine.sh loop > testdata/mine-loop.log 2>&1 &
  echo "started (log testdata/mine-loop.log)"
fi

# ── 2. committee ─────────────────────────────────────────────────────────────
say "waiting for an active 6-member bridge committee"
for i in $(seq 1 120); do
  RESP=$(jrpc bridge_get_committee) || RESP=''
  # -2 = no response yet; -1 = the bridge is inactive (below the activation floor), which is
  # a different failure from "active, but nobody seated". Never launder an unreadable
  # response into a count: a masked RPC/parse error reading as 0 is indistinguishable from
  # an empty committee, and you wait ten minutes for a diagnosis you already had.
  if [ -z "$RESP" ]; then
    # No response at all — the daemon's RPC is not up yet. This script is meant to be run
    # straight after the harness, so keep waiting rather than aborting on a startup race.
    N=-2
  else
    N=$(printf '%s' "$RESP" | python3 -c \
        'import sys,json; r=json.load(sys.stdin)["result"]; print(len(r["members"]) if r.get("active") else -1)') \
      || { echo "!! bridge_get_committee answered, but the response is unreadable:"; \
           echo "   ${RESP:0:300}"; exit 1; }
  fi
  [ "$N" = "6" ] && break
  [ "$i" = "1" ] && echo "   (committee reports $N members; waiting — is the harness fully up?)"
  sleep 5
done
[ "$N" = "6" ] || { echo "!! no 6-member committee after 10min (last count: $N) — check the harness"; exit 1; }
echo "committee active (6 members)"

# Build the exact signer source in this working tree before generating any key material.
# This prevents a green run against an older target/debug binary left by a prior checkout.
say "build + attest bridge signer"
cargo build --manifest-path "$ROOT/bridge/signer/Cargo.toml" --features serve-live
SIGNER_BIN="$ROOT/bridge/signer/target/debug/beldex-bridge-signer"
[ -x "$SIGNER_BIN" ] || { echo "!! signer build produced no executable" >&2; exit 1; }
echo "source commit : $(git -C "$ROOT" rev-parse HEAD)$(git -C "$ROOT" diff --quiet && echo '' || echo '-dirty')"
echo "signer sha256 : $(sha256sum "$SIGNER_BIN" | awk '{print $1}')"

# A successful link does not prove that the system libzmq was compiled with libsodium.
# Probe before any DKG traffic so a secure ceremony cannot fail halfway through. The
# only bypass is an intentionally noisy local-canary mode requiring two independent
# opt-ins; neither variable is defaulted here.
if ! "$SIGNER_BIN" check-curve; then
  if [ "${ALLOW_PLAINTEXT_MESH:-0}" = "1" ] \
      && [ "${BRIDGE_SIGNER_MESH_USE_CURVE:-true}" = "false" ]; then
    echo "!! INSECURE LOCAL CANARY: CURVE unavailable and plaintext mesh explicitly enabled" >&2
  else
    echo "!! encrypted signer mesh is unavailable; refusing to start DKG" >&2
    echo "   Install/rebuild libzmq with libsodium, or for a disposable localhost-only canary set:" >&2
    echo "   ALLOW_PLAINTEXT_MESH=1 BRIDGE_SIGNER_MESH_USE_CURVE=false" >&2
    exit 1
  fi
fi

# ── 3. dual DKG ──────────────────────────────────────────────────────────────
say "dual DKG"
PGW_COUNT="$(find testdata -path '*/devnet/shares/pgw-*.keypackage' -type f | wc -l | tr -d ' ')"
PEVM_COUNT="$(find testdata -path '*/devnet/shares/pevm-*.keyshare' -type f | wc -l | tr -d ' ')"
if [ "$PGW_COUNT" -eq 6 ] && [ "$PEVM_COUNT" -eq 6 ]; then
  echo "six complete dual-share trees already present — validating before reuse"
elif [ "$PGW_COUNT" -ne 0 ] || [ "$PEVM_COUNT" -ne 0 ]; then
  echo "!! partial/stale DKG state: Pgw=$PGW_COUNT Pevm=$PEVM_COUNT (expected 6/6 or 0/0)" >&2
  echo "   Refusing to combine keys from different ceremonies; wipe testdata and restart." >&2
  exit 1
else
  ./dkg-init.sh
fi
GVK_FILE="$(ls testdata/beldex-127.0.0.1-*/devnet/shares/pgw-*.groupvk | head -1)"
PGW_GROUP_VK="$(od -An -v -tx1 < "$GVK_FILE" | tr -d ' \n')"
# all nodes must agree
DISTINCT=$(for f in testdata/beldex-127.0.0.1-*/devnet/shares/pgw-*.groupvk; do od -An -v -tx1 < "$f" | tr -d ' \n'; echo; done | sort -u | wc -l | tr -d ' ')
[ "$DISTINCT" = "1" ] || { echo "!! nodes disagree on the Pgw group key — do not proceed"; exit 1; }
PEVM_DISTINCT=$(for f in testdata/beldex-127.0.0.1-*/devnet/shares/pevm-*.groupkey; do od -An -v -tx1 < "$f" | tr -d ' \n'; echo; done | sort -u | wc -l | tr -d ' ')
[ "$PEVM_DISTINCT" = "1" ] || { echo "!! nodes disagree on the Pevm group key — do not proceed"; exit 1; }
echo "PGW_GROUP_VK=$PGW_GROUP_VK"

# ── 4. Pevm signer address ───────────────────────────────────────────────────
say "Pevm signer address"
GK_FILE="$(ls testdata/beldex-127.0.0.1-*/devnet/shares/pevm-*.groupkey | head -1)"
GK_HEX="$(od -An -v -tx1 < "$GK_FILE" | tr -d ' \n')"
# Decompress the secp256k1 point in pure python (no deps), keccak with foundry's cast.
UNCOMPRESSED=$(python3 - "$GK_HEX" <<'EOF'
import sys
c = bytes.fromhex(sys.argv[1])
p = 2**256 - 2**32 - 977
x = int.from_bytes(c[1:], 'big')
y = pow((pow(x, 3, p) + 7) % p, (p + 1) // 4, p)
if (y & 1) != (c[0] & 1): y = p - y
print((x.to_bytes(32,'big') + y.to_bytes(32,'big')).hex())
EOF
)
PEVM_ADDR="0x$(cast keccak "0x$UNCOMPRESSED" | sed 's/^0x//' | cut -c25-64)"
echo "PEVM_ADDR=$PEVM_ADDR"

# ── 5. deploy wBDX ───────────────────────────────────────────────────────────
say "deploy WrappedBDX"
[ -d "$BC" ] || { echo "!! bridge-contract repo not found at $BC (set BC=…)"; exit 1; }
CUR=""; REUSE_CONTRACT=0
if [ -f "$BC/devnet/mint.env" ]; then
  PROXY_OLD=$(grep '^PROXY=' "$BC/devnet/mint.env" | cut -d= -f2)
  CUR=$(cast call "$PROXY_OLD" 'currentSigner()(address)' --rpc-url http://127.0.0.1:8545 2>/dev/null \
        | tr 'A-Z' 'a-z' || true)
  ADMIN_OLD=$(cast call "$PROXY_OLD" 'admin()(address)' --rpc-url http://127.0.0.1:8545 2>/dev/null | tr 'A-Z' 'a-z' || true)
  GUARDIAN_OLD=$(cast call "$PROXY_OLD" 'guardian()(address)' --rpc-url http://127.0.0.1:8545 2>/dev/null | tr 'A-Z' 'a-z' || true)
  NETWORK_OLD=$(cast call "$PROXY_OLD" 'beldexNetwork()(uint8)' --rpc-url http://127.0.0.1:8545 2>/dev/null | sed -n 's/^\([0-9][0-9]*\).*/\1/p')
  MIN_REDEEM_OLD=$(cast call "$PROXY_OLD" 'minRedeemAmount()(uint256)' --rpc-url http://127.0.0.1:8545 2>/dev/null | sed -n 's/^\([0-9][0-9]*\).*/\1/p')
  TAG_OLD=$(cast call "$PROXY_OLD" 'MINT_TAG()(bytes32)' --rpc-url http://127.0.0.1:8545 2>/dev/null | tr 'A-Z' 'a-z' || true)
  ADMIN_CODE=$(cast code "$ADMIN_OLD" --rpc-url http://127.0.0.1:8545 2>/dev/null || true)
  EXPECT_GUARDIAN=$(grep '^GUARDIAN=' "$BC/devnet/mint.env" | cut -d= -f2 | tr 'A-Z' 'a-z')
  EXPECT_IMPL=$(grep '^IMPL=' "$BC/devnet/mint.env" | cut -d= -f2 | tr 'A-Z' 'a-z')
  IMPL_SLOT=$(cast storage "$PROXY_OLD" 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url http://127.0.0.1:8545 2>/dev/null | tr 'A-Z' 'a-z' || true)
  LIVE_IMPL="0x${IMPL_SLOT: -40}"
  EXPECT_TAG=0x26d48d33d413c44fc6f4279483ab40c9931aecbd2d2b355f503e48d69e40dbf1
  if [ -n "$CUR" ] \
      && [ "$CUR" = "$(echo "$PEVM_ADDR" | tr 'A-Z' 'a-z')" ] \
      && [ -n "$ADMIN_OLD" ] && [ "$ADMIN_CODE" != "0x" ] && [ -n "$ADMIN_CODE" ] \
      && [ "$GUARDIAN_OLD" = "$EXPECT_GUARDIAN" ] && [ "$NETWORK_OLD" = "2" ] \
      && [ "${MIN_REDEEM_OLD:-0}" -gt 0 ] && [ "$TAG_OLD" = "$EXPECT_TAG" ] \
      && [ "$LIVE_IMPL" = "$EXPECT_IMPL" ]; then
    REUSE_CONTRACT=1
  fi
fi
if [ "$REUSE_CONTRACT" -eq 1 ]; then
  WBDX="$PROXY_OLD"
  echo "validated existing timelocked devnet deployment for this committee: $WBDX"
else
  (cd "$BC" && SIGNER_ADDR="$PEVM_ADDR" ./devnet/01-deploy.sh)
  WBDX=$(grep '^PROXY=' "$BC/devnet/mint.env" | cut -d= -f2)
fi
echo "WBDX=$WBDX"

# ── 6. gateway ───────────────────────────────────────────────────────────────
say "bridge gateway"
EXISTING=$(jrpc get_all_gateways | python3 -c 'import sys,json; r=json.load(sys.stdin)["result"]; print(r.get("total",0))')
if [ "$EXISTING" != "0" ] && [ -f "$ENVFILE" ] && grep -q VIEW_SECRET "$ENVFILE"; then
  # shellcheck disable=SC1090
  . "$ENVFILE"
  INFO=$(jrpc get_gateway_info "{\"gateway_address\":\"$GATEWAY_ID\"}")
  INFO_CHECK=$(python3 - "$PGW_GROUP_VK" "$INFO" <<'PY'
import json,sys
want=sys.argv[1].lower(); r=json.loads(sys.argv[2]).get("result",{})
ok=(r.get("registered") is True and r.get("bridge_reserve") is True and
    r.get("frozen") is False and r.get("owner_key_type")==2 and
    str(r.get("owner_key","")).lower()==want)
print("ok" if ok else json.dumps(r,sort_keys=True))
PY
  )
  [ "$INFO_CHECK" = "ok" ] || {
    echo "!! persisted gateway does not match the active Pgw bridge reserve:" >&2
    echo "   $INFO_CHECK" >&2; exit 1; }
  echo "validated existing bridge gateway and view-secret binding — reusing"
elif [ "$EXISTING" != "0" ]; then
  echo "!! $EXISTING gateway(s) exist but no validated $ENVFILE binding is available." >&2
  echo "   Refusing to guess that the newest gateway belongs to this ceremony." >&2
  exit 1
else
  VIEW_SECRET="$(openssl rand -hex 31)00"
  # a funded devnet wallet-rpc (Mike = the one with a balance)
  WPORT=""
  for p in $(ls -d testdata/wallet-127.0.0.1-* 2>/dev/null | grep -v stderr | sed 's/.*-//' | sort -n); do
    BAL=$(curl -s "http://127.0.0.1:$p/json_rpc" -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":"0","method":"get_balance","params":{"account_index":0}}' \
      | python3 -c 'import sys,json; print(json.load(sys.stdin).get("result",{}).get("unlocked_balance",0))' 2>/dev/null || echo 0)
    [ "${BAL:-0}" -gt 100000000000 ] 2>/dev/null && { WPORT=$p; break; }
  done
  [ -n "$WPORT" ] || { echo "!! no funded wallet-rpc found — mine more blocks first (./mine.sh 30)"; exit 1; }
  echo "registering via funded wallet on port $WPORT (bridge_reserve = true)"
  REG=$(curl -s "http://127.0.0.1:$WPORT/json_rpc" -H 'Content-Type: application/json' -d "{
    \"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"register_gateway_address\",
    \"params\":{\"gateway_secret\":\"$VIEW_SECRET\",\"owner_key_type\":\"eddsa\",
                \"owner_key\":\"$PGW_GROUP_VK\",\"bridge_reserve\":true,
                \"meta_info\":\"devnet bridge reserve\",\"priority\":1}}")
  echo "$REG" | grep -q '"tx_hash"' || { echo "!! registration failed: $REG"; exit 1; }
  echo "registration tx submitted; mining it in…"
  ./mine.sh 12 >/dev/null
fi
# Read the gateway back. Existing-state reuse was validated above; a newly registered
# fresh chain has exactly one gateway, so there is no ambiguous "last one wins" binding.
GWJSON=$(jrpc get_all_gateways)
GATEWAY_ID=$(echo "$GWJSON"   | python3 -c 'import sys,json; g=json.load(sys.stdin)["result"]["gateways"]; print(g[-1]["gateway_id"])')
GATEWAY_ADDR=$(echo "$GWJSON" | python3 -c 'import sys,json; g=json.load(sys.stdin)["result"]["gateways"]; print(g[-1]["address"])')
echo "GATEWAY_ID=$GATEWAY_ID"
echo "GATEWAY_ADDR=$GATEWAY_ADDR"
FINAL_INFO=$(jrpc get_gateway_info "{\"gateway_address\":\"$GATEWAY_ID\"}")
python3 - "$PGW_GROUP_VK" "$FINAL_INFO" <<'PY'
import json,sys
want=sys.argv[1].lower(); r=json.loads(sys.argv[2]).get("result",{})
assert r.get("registered") is True, "gateway not registered"
assert r.get("bridge_reserve") is True, "gateway is not bridge_reserve"
assert r.get("frozen") is False, "gateway is frozen"
assert r.get("owner_key_type")==2, "gateway owner is not EdDSA"
assert str(r.get("owner_key","")).lower()==want, "gateway owner != active Pgw"
PY

# ── 7. persist + launch ──────────────────────────────────────────────────────
say "persist + launch"
cat > "$ENVFILE" <<EOF
# generated by bootstrap-bridge.sh — the bridge identity for THIS devnet chain.
# Wiped state (harness restart) invalidates all of it; re-run the bootstrap.
PGW_GROUP_VK=$PGW_GROUP_VK
PEVM_ADDR=$PEVM_ADDR
WBDX=$WBDX
VIEW_SECRET=$VIEW_SECRET
GATEWAY_ID=$GATEWAY_ID
GATEWAY_ADDR=$GATEWAY_ADDR
EOF
chmod 600 "$ENVFILE"
echo "wrote $ENVFILE"

GATEWAY_ID="$GATEWAY_ID" VIEW_SECRET="$VIEW_SECRET" WBDX="$WBDX" ./serve-live.sh

cat <<EOF

────────────────────────────────────────────────────────────────────────────
Bridge is up. Next, from a CLI wallet (fund it per DEVNET_SETUP.md §4):

  transfer $GATEWAY_ADDR 50 31337:0x<20-byte evm address>

Signed mint payloads are written under each node's configured mint-outbox
directory. Relay them only after checking their chain ID, contract, epoch,
deposit ID, output index, recipient and amount. See the local DKG runbook.

Watch:  tail -f testdata/serve-*.log
────────────────────────────────────────────────────────────────────────────
EOF
