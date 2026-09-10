#!/usr/bin/env python3
"""Report storage usage; optionally archive finalized records with all writers stopped.

No replay database or pending duty is pruned. Archive is recoverable, on the same
filesystem. Finalized filename markers are trusted local reconciler output,
not independent proof of chain settlement. Never rename pending files manually.
"""
import argparse
import json
import os
from pathlib import Path
import stat


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ValueError(f"require an owned, private, non-symlink directory: {path}")
    if path.absolute() != path.resolve():
        raise ValueError("use a canonical directory path without symlink ancestors")
    return path


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def inventory(directory):
    totals = {kind: {"files": 0, "bytes": 0} for kind in ("pending", "finalized", "other")}
    for path in directory.iterdir():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            continue
        kind = next((k for k in ("pending", "finalized") if path.name.endswith(f".{k}.json")), "other")
        totals[kind]["files"] += 1
        totals[kind]["bytes"] += info.st_size
    capacity = os.statvfs(directory)
    return {"records": totals, "available_bytes": capacity.f_bavail * capacity.f_frsize}


def archive_finalized(source, archive):
    source, archive = private_directory(source), private_directory(archive)
    if source.resolve() == archive.resolve() or source.stat().st_dev != archive.stat().st_dev:
        raise ValueError("archive must be a different directory on the same filesystem")
    moved = 0
    for path in source.iterdir():
        if not path.name.endswith(".finalized.json"):
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError(f"unsafe finalized record: {path}")
        with path.open() as record:
            if not isinstance(json.load(record), dict):
                raise ValueError(f"not a JSON object: {path}")
            os.fsync(record.fileno())
        target = archive / path.name
        try:
            os.link(path, target, follow_symlinks=False)  # exclusive; no overwrite
        except FileExistsError:
            if target.is_symlink() or not os.path.samestat(path.stat(), target.stat()):
                raise ValueError(f"archive collision: {target}")
        fsync_dir(archive)  # durable archive before removing the active copy
        path.unlink()
        fsync_dir(source)
        moved += 1
    return moved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("outbox", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--offline-confirmed", action="store_true")
    args = parser.parse_args()
    source = private_directory(args.outbox)
    if args.archive:
        if not args.offline_confirmed:
            parser.error("archival requires stopped writers and --offline-confirmed")
        print(json.dumps({"archived_files": archive_finalized(source, args.archive)}))
    print(json.dumps(inventory(source), sort_keys=True))


if __name__ == "__main__":
    main()
