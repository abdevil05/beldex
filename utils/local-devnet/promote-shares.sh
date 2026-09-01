#!/usr/bin/env bash
# promote-shares.sh — step 7 of the H.6 rotation: make the successor committee the LIVE one.
#
#   runlog ./promote-shares.sh            # promote shares-next -> shares
#   runlog ./promote-shares.sh --dry-run  # show what would move, touch nothing
#
# `dkg-next.sh` rotates Pevm only. Pgw remains the native gateway owner until an explicit,
# separately-authorized owner re-point occurs. Before swapping trees this script therefore
# carries each node's matching Pgw material forward. It refuses index/membership drift:
# that case needs a dual-key ceremony plus a native owner change, not a directory rename.
#
# This exists as a script rather than a paste-into-your-terminal loop for two reasons:
#   * macOS defaults to zsh, where an unmatched glob is a hard error that aborts the command
#     (bash quietly passes the pattern through). A loop that is correct in one shell is broken
#     in the other. A file with a bash shebang has one, known shell.
#   * the swap is irreversible-ish and easy to half-do. Guards belong somewhere they can be
#     reviewed, not retyped.
#
# Env:
#   ARCHIVE   name for the retired tree (default: first free shares-gen<N>)
#   SUBDIR    the incoming tree (default shares-next)
#   TESTDATA_DIR override the testdata root (used by isolated script tests)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${TESTDATA_DIR:-$SCRIPT_DIR/testdata}"

SUBDIR="${SUBDIR:-shares-next}"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

# `find`, not a glob: this has to give the same answer under bash and zsh, and under zsh a
# no-match glob raises an error rather than expanding to nothing. See the header.
has_shares() { [ -n "$(find "$1" -name 'pevm-*.keyshare' -print -quit 2>/dev/null)" ]; }
groupkey()   { od -An -v -tx1 < "$(find "$1" -name 'pevm-*.groupkey' -print -quit)" | tr -d ' \n'; }
one_index() {
  prefix="$1"; suffix="$2"; dir="$3"
  files="$(find "$dir" -maxdepth 1 -name "$prefix-*.$suffix" -print 2>/dev/null | sort)"
  count="$(printf '%s\n' "$files" | grep -c . || true)"
  [ "$count" -eq 1 ] || return 1
  printf '%s\n' "$files" | sed -E "s|.*/$prefix-([0-9]+)\..*|\1|"
}

# --- who actually has an incoming tree ---------------------------------------------------------
INCOMING=""
NONMEMBER=""
for d in beldex-127.0.0.1-*/devnet; do
  [ -d "$d" ] || continue
  if has_shares "$d/$SUBDIR"; then INCOMING="$INCOMING $d"
  elif [ -d "$d/$SUBDIR" ];   then NONMEMBER="$NONMEMBER $d"
  fi
done

if [ -z "$INCOMING" ]; then
  # Not an error. Re-running after a successful promotion is the most likely way to get here,
  # and it should read as "already done", not as a failure.
  echo "  nothing to promote — no node has keyshares in $SUBDIR."
  echo ""
  echo "── current state ─────────────────────────────────────────────────────"
  for d in beldex-127.0.0.1-*/devnet; do
    [ -d "$d" ] || continue
    printf '  %-26s' "${d%%/*}"
    for s in shares shares-gen0 shares-gen1 shares-gen2; do
      [ -d "$d/$s" ] || continue
      has_shares "$d/$s" && printf ' %s(%s)' "$s" "$(groupkey "$d/$s" | cut -c1-10)…" || printf ' %s(empty)' "$s"
    done
    echo ""
  done
  echo ""
  echo "  If you already ran this after activating the rotation, that is the expected result:"
  echo "  shares holds the new key, shares-gen0 the retired one. Confirm with"
  echo ""
  echo "      runlog ./sign-pevm.sh raw 0x$(printf 'ab%.0s' {1..32})"
  echo ""
  echo "  the 'wBDX signer' line must equal currentSigner() on chain."
  exit 0
fi

# --- the incoming committee must agree on one key ------------------------------------------------
# Promoting a tree the participants never converged on installs a key that cannot sign, and the
# only way back is the admin break-glass.
FIRST=""; MISMATCH=0; N=0
for d in $INCOMING; do
  f="$(find "$d/$SUBDIR" -name 'pevm-*.groupkey' -print -quit 2>/dev/null || true)"
  [ -n "$f" ] || { echo "!! $d/$SUBDIR has a keyshare but no group key — refusing." >&2; exit 1; }
  [ "$(wc -c < "$f" | tr -d ' ')" -eq 33 ] || {
    echo "!! $f is not a 33-byte compressed Pevm group key — refusing." >&2; exit 1; }
  N=$(( N + 1 ))
  if [ -z "$FIRST" ]; then FIRST="$f"; continue; fi
  cmp -s "$FIRST" "$f" || MISMATCH=1
done
if [ "$MISMATCH" -ne 0 ]; then
  echo "!! participants disagree on the $SUBDIR group key — do NOT promote it." >&2
  exit 1
fi
NEWKEY="$(od -An -v -tx1 < "$FIRST" | tr -d ' \n')"

# A Pevm-only rotation must preserve the live Pgw authority byte-for-byte. Require the
# incoming Pevm index to match the old Pgw index on every participant; otherwise this is a
# membership change and promotion would either brick releases or retain authority for the
# wrong committee. Also require one common Pgw group key across every incoming node.
PGW_FIRST=""; PGW_MISMATCH=0
for d in $INCOMING; do
  pevm_idx="$(one_index pevm keyshare "$d/$SUBDIR" || true)"
  pgw_idx="$(one_index pgw keypackage "$d/shares" || true)"
  if [ -z "$pevm_idx" ] || [ -z "$pgw_idx" ] || [ "$pevm_idx" != "$pgw_idx" ]; then
    echo "!! $d cannot carry Pgw forward safely (incoming Pevm index '${pevm_idx:-none}', live Pgw index '${pgw_idx:-none}')." >&2
    echo "   Committee membership/index changed. Run an explicit dual-key DKG and native" >&2
    echo "   gateway owner re-point; do not use this Pevm-only promotion path." >&2
    exit 1
  fi
  pgw_vk="$d/shares/pgw-$pgw_idx.groupvk"
  pgw_kp="$d/shares/pgw-$pgw_idx.keypackage"
  pgw_pub="$d/shares/pgw-$pgw_idx.pubkeypackage"
  [ -f "$pgw_vk" ] && [ -f "$pgw_kp" ] && [ -f "$pgw_pub" ] || {
    echo "!! $d/shares has incomplete Pgw material — refusing promotion." >&2; exit 1; }
  [ "$(wc -c < "$pgw_vk" | tr -d ' ')" -eq 32 ] || {
    echo "!! $pgw_vk is not a 32-byte Pgw group key — refusing." >&2; exit 1; }
  if [ -z "$PGW_FIRST" ]; then PGW_FIRST="$pgw_vk"
  elif ! cmp -s "$PGW_FIRST" "$pgw_vk"; then PGW_MISMATCH=1
  fi
done
[ "$PGW_MISMATCH" -eq 0 ] || { echo "!! live nodes disagree on the Pgw group key." >&2; exit 1; }
PGWKEY="$(od -An -v -tx1 < "$PGW_FIRST" | tr -d ' \n')"

OLDKEY=""
for d in $INCOMING; do
  if has_shares "$d/shares"; then OLDKEY="$(groupkey "$d/shares")"; break; fi
done

if [ -n "$OLDKEY" ] && [ "$OLDKEY" = "$NEWKEY" ]; then
  echo "!! $SUBDIR holds the SAME group key as shares — there is nothing to rotate to." >&2
  echo "   Did dkg-next.sh actually run with a fresh keygen number?" >&2
  exit 1
fi

# --- pick an archive name that is not already taken -------------------------------------------------
# Name it after the DKG generation being retired. Never reuse a name: the old tree is the only
# record of what the previous committee was, and mv-ing onto an existing directory nests it
# instead of replacing it, which quietly buries the older one.
if [ -z "${ARCHIVE:-}" ]; then
  i=0
  while :; do
    taken=0
    for d in $INCOMING; do [ -e "$d/shares-gen$i" ] && taken=1; done
    [ "$taken" -eq 0 ] && break
    i=$(( i + 1 ))
  done
  ARCHIVE="shares-gen$i"
fi
for d in $INCOMING; do
  if [ -e "$d/$ARCHIVE" ]; then
    echo "!! $d/$ARCHIVE already exists — pick another name with ARCHIVE=..." >&2
    exit 1
  fi
done

echo "  incoming tree : $(printf '%-12s' "$SUBDIR") ($N node(s), group key 0x${NEWKEY:0:12}…)"
echo "  Pgw retained  : $(printf '%-12s' shares) (owner key 0x${PGWKEY:0:12}…)"
echo "  retiring to   : $(printf '%-12s' "$ARCHIVE") (group key 0x${OLDKEY:0:12}…)"
[ "$DRY" -eq 1 ] && echo "  MODE          : dry run, nothing will be moved"
if [ -n "$NONMEMBER" ]; then
  echo ""
  echo "  skipping (empty $SUBDIR — not on the bridge committee):"
  for d in $NONMEMBER; do echo "    ${d%%/*}"; done
fi
echo ""

# --- swap ------------------------------------------------------------------------------------------
for d in $INCOMING; do
  pevm_idx="$(one_index pevm keyshare "$d/$SUBDIR")"
  if [ "$DRY" -ne 1 ]; then
    cp -p "$d/shares/pgw-$pevm_idx.keypackage" "$d/$SUBDIR/"
    cp -p "$d/shares/pgw-$pevm_idx.pubkeypackage" "$d/$SUBDIR/"
    cp -p "$d/shares/pgw-$pevm_idx.groupvk" "$d/$SUBDIR/"
    chmod 600 "$d/$SUBDIR/pgw-$pevm_idx.keypackage" \
      "$d/$SUBDIR/pgw-$pevm_idx.pubkeypackage" "$d/$SUBDIR/pgw-$pevm_idx.groupvk"
  fi
  if ! [ -d "$d/shares" ]; then
    # A node that joined the committee at this rotation has an incoming tree but nothing to
    # retire. Moving it in is still correct; there is just no archive step.
    echo "  ${d%%/*}: no existing shares/ to archive (new committee member)"
    [ "$DRY" -eq 1 ] || mv "$d/$SUBDIR" "$d/shares"
    continue
  fi
  echo "  ${d%%/*}: shares -> $ARCHIVE, $SUBDIR -> shares"
  [ "$DRY" -eq 1 ] && continue
  mv "$d/shares" "$d/$ARCHIVE"
  mv "$d/$SUBDIR" "$d/shares"
done

if [ "$DRY" -eq 1 ]; then
  echo ""
  echo "  dry run complete — re-run without --dry-run to apply."
  exit 0
fi

echo ""
echo "── promoted ──────────────────────────────────────────────────────────"
echo "  $(printf '%-12s' shares) : 0x$NEWKEY"
echo "  $(printf '%-12s' 'Pgw owner') : 0x$PGWKEY   (unchanged)"
echo "  $(printf '%-12s' "$ARCHIVE") : 0x$OLDKEY   (retained)"
echo ""
echo "  The retired tree is kept, not deleted: it is the only record of what the previous"
echo "  committee was, and share material cannot be regenerated."
echo ""
echo "Confirm the default signing path now uses the key the contract holds:"
echo ""
echo "    runlog ./sign-pevm.sh raw 0x$(printf 'ab%.0s' {1..32})"
echo ""
echo "The 'wBDX signer' line must equal currentSigner() on chain."
