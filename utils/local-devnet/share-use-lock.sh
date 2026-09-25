# Sourced by local share consumers BEFORE discovery, generation, or cleanup.
# Keep fd open for the complete script and its children, including legacy binaries.
share_handoff_root="$(pwd)/testdata"
if [ -d "$share_handoff_root" ]; then
  [ ! -L "$share_handoff_root/.share-promotion.lock" ] || { echo 'symlinked handoff lock' >&2; exit 1; }
  exec {SHARE_HANDOFF_FD}>>"$share_handoff_root/.share-promotion.lock"
  flock -sn "$SHARE_HANDOFF_FD" || { echo 'share promotion is running; retry after it completes' >&2; exit 1; }
  [ ! -e "$share_handoff_root/.share-promotion.pending" ] || {
    echo 'incomplete share handoff; resume promote-shares.sh before signing or DKG' >&2
    exit 1
  }
fi
