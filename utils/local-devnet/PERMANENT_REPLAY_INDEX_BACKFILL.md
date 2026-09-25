# Permanent gateway replay-index backfill

Writable startup now requires a completion marker for `gateway_release_refs`.
An existing table is not sufficient: earlier versions could create an empty
one even when canonical history contained gateway releases.

When the table or marker is missing, startup rebuilds the table from canonical
blocks. For bridge-era blocks it resolves every referenced transaction through
the transaction index, reads its retained transaction base, derives the release
reference using the same function as live processing, and records each source
gateway with the canonical block height. Prunable transaction data and rolling
gateway-account reference windows are not needed.

The rebuild and completion marker are written in one LMDB transaction. A parse
error, missing historical record, or database write failure aborts startup and
rolls back the rebuild. The node cannot use a partially populated index. After
the underlying problem is resolved, writable startup retries. Missing history
must be recovered from a valid database or by resynchronization; never work
around the error by inserting the marker manually.

Read-only startup does not migrate anything. Replay queries fail explicitly if
the table or valid marker is absent. Normal completed startup skips the rebuild.
Resetting the database certifies an empty index together with the empty history.

This is a local database migration, not a new transaction format or hard fork.
Initial writable startup scans historical blocks and requires time and LMDB
space for the atomic rebuild. Very large histories can hit LMDB transaction or
map limits; such failures stop startup without certifying an incomplete index.
No production database is modified merely by building or running unit tests.

Regression coverage uses temporary real LMDB databases and verifies missing and
existing-empty tables, historical reference heights, pruned transaction data,
read-only refusal, failure after a reference has been processed, rollback of
both rows and marker, successful retry, persistence, removal, and database reset.
