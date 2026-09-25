# Recoverable local share handoff

`promote-shares.sh` coordinates a forward-only handoff of the local devnet's dual
Pevm/Pgw share directories. It now calls `share_promotion.py`; rerunning it resumes
the same recorded operation instead of rediscovering only the nodes not yet moved.

## Lifecycle

1. Stop signer and DKG processes. Promotion takes an exclusive POSIX file lock.
   Updated signer `dkg`, `sign`, and `serve` processes hold the matching shared
   lock for their entire lifetime, including while key material is in memory.
   Local signing and DKG scripts also hold a shared lock before accessing files.
2. Validate complete successor material, matching group keys, unique participant
   indices, safe paths, and unused archive destinations. Record every continuing,
   joining, and departing participant; departing nodes also lose their active
   share directory. File content hashes detect unexpected changes during recovery.
3. Verify checkpoint-finalized native Pgw ownership and finalized EVM
   `currentSigner()` at the configured proxy. EVM signer and epoch reads use the
   same finalized block hash. Record chain ID and key epoch. Repeat these checks
   on recovery; a changed authority or conflicting configuration stops recovery.
4. Sync share files and directories, then durably write a private pending journal
   before the first rename. Archive old trees and install successors using
   same-directory renames, syncing each participant directory after each move.
5. Reconcile every participant against its recorded final state. Only then rename
   the pending journal to the completed record and sync the root directory.
   This is the signing-availability commit point.

The moves across nodes are not one atomic filesystem operation. Instead, signing
is unavailable throughout the partial state. A crash releases the exclusive
lock, but the durable pending journal prevents new signing or DKG. Recovery
recognizes whether each rename happened and completes the same operation without
replacing existing archives. It also syncs recovered directories before committing.

## Operation and recovery

Requires Python 3.11+, POSIX flock/fsync support, shell `flock`, and Foundry `cast`.
The EVM RPC must support the finalized block tag and historical calls by hash.

```sh
GATEWAY_ID=... PROXY=... RPC=... BELDEX_RPC=... ./promote-shares.sh --dry-run
GATEWAY_ID=... PROXY=... RPC=... BELDEX_RPC=... ./promote-shares.sh
./promote-shares.sh --status
```

`TESTDATA_DIR` overrides the promotion root. `SUBDIR` defaults to `shares-next`;
`ARCHIVE` defaults to the first unused `shares-genN` across all affected nodes.
On an interrupted run, omit overrides or use exactly the recorded values.
The pending journal retains the endpoints and gateway/proxy needed for recovery.
Do not run a new DKG, delete the lock/journal, or manually move directories to
bypass a pending handoff. Fix a reported RPC or file-integrity problem, stop share
consumers, and rerun promotion. Rerunning an already completed operation verifies
its final state and does not create another archive.

The ceremony's step 7 obtains the retired archive name from the completed journal,
so a restarted ceremony does not rely on seeing a newly created directory.

## Scope and limits

This is a local filesystem protocol for the managed
`beldex-127.0.0.1-*/devnet/<share-tree>` layout, not distributed atomic activation
across independent remote hosts. POSIX durability depends on the filesystem and
storage honoring fsync. Tests simulate process death, not hardware power loss.
All participants must use the updated tools; stop already running older binaries
before upgrading because they do not participate in the new locking protocol.
Standalone custody paths outside this layout are not covered by this coordinator.

Archives retain retired private material for the existing handoff proof workflow.
They are not secure erasure, and this patch does not implement production
Vault/HSM custody or the separate rotation-ack observation/submission and
bond-settlement service. Chain authority checks rely on the configured RPCs.
No live promotion, RPC transaction, deployment, or key deletion is performed by
the regression tests.

## Verification

`test_share_promotion.py` covers process death at 15 preparation/move/commit
boundaries, recovery, joins and departures, modified files, bad paths and
symlinks, duplicate indices, missing material, concurrent readers/promoters,
shell guards, dry runs, completed retries, and chain-authority refusal.
The Rust handoff test checks lock compatibility with Python and rejection of
pending journals. Run these via `signer-security-tests.sh` or individually.
