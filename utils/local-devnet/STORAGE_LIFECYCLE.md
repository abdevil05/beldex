# Bridge storage lifecycle (local setup)

This is an operational policy, not a production-readiness statement. Never prune
native `gateway_release_refs`, processed-deposit identifiers, execution reservations
associated with existing shares, or unsettled outbox/duty records to save space.
Doing so can reopen replay or lose recoverable payments. The historical replay-index
backfill remains a separate, unimplemented migration.

## Measure and forecast

With an absolute canonical outbox directory, run the read-only inventory:

```bash
python3 utils/local-devnet/outbox-maintenance.py /absolute/path/to/outbox
```

It emits JSON counts and logical bytes for pending/finalized/other regular files,
plus available filesystem bytes. It does not inspect keys, connect to chains or
delete anything. Inventory ignores subdirectories: measure each archive separately.
Use `du -s --block-size=1 /absolute/path/to/archive` and the same command against
the native database directory to track allocated bytes, including LMDB overhead.

Record daily values and count of newly settled releases. Forecast annual growth as
`365 * daily releases * measured bytes per release`, adding outbox/archive growth,
backups and a safety margin. The replay index alone has a 64-byte key plus an
8-byte height per entry: at 100,000 new references/day, raw payload is 2.628 GB/year
(decimal), before LMDB pages, indexes and backups. This is a sizing example, not a
measured deployment estimate. Filesystem free bytes are not the LMDB map-size limit.

Suggested local alert policy: warn at 70% disk utilization or under 30 days of
forecast headroom; stop new work using the documented coordinated pause procedure
at 85% or under 7 days. Operators must wire monitoring/alerts themselves, measure
the LMDB map headroom separately and test full-disk recovery. Never auto-delete
unsettled records or resize/migrate a live database from a maintenance script.

## Recoverable finalized-outbox archival

1. Stop **all** signer/relayer processes writing the selected outbox. Verify they
   stopped. The tool cannot enforce this itself; do not run alongside live writers.
2. Back up the directory and confirm only the reconciler creates `.finalized.json`
   markers. A transaction hash, relay success or unfinalized receipt is insufficient.
   Do not manually rename pending records to make them eligible.
3. Create a separate empty archive directory on the same filesystem, owned by the
   current operator, mode 0700. Use a dated directory to keep archives manageable.
4. Run inventory, then explicitly archive:

   ```bash
   python3 utils/local-devnet/outbox-maintenance.py /absolute/path/to/outbox \
     --archive /absolute/path/to/archive --offline-confirmed
   ```

5. Only private, regular `.finalized.json` objects are moved. The script creates an
   exclusive hard link, syncs the archive, removes the hot-directory link and syncs
   the source. A crash between those steps is restartable. Conflicting archive
   names and symlinks cause an error. Previously moved records remain recoverable.
6. Re-run inventories and resume services. Pending records remain untouched. Keep
   archived records for incident investigation; do not feed them back as pending.

This compacts the **active directory**, not total retained bytes. Archive retention,
off-host backups and native offline compaction remain operator-controlled. No
automatic archive deletion or permanent replay-index expiration is implemented.
