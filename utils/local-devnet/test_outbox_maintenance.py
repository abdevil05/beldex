import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("maintenance", Path(__file__).with_name("outbox-maintenance.py"))
maintenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(maintenance)


class ArchiveTests(unittest.TestCase):
    def test_archive_preserves_pending_and_is_restartable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source, archive = root / "outbox", root / "archive"
            source.mkdir(mode=0o700)
            archive.mkdir(mode=0o700)
            for name in ("a.pending.json", "b.finalized.json"):
                record = source / name
                record.write_text('{"kind":"mint"}')
                record.chmod(0o600)
            self.assertEqual(maintenance.inventory(source)["records"]["pending"]["files"], 1)
            # Crash after archive link but before source unlink.
            os.link(source / "b.finalized.json", archive / "b.finalized.json")
            self.assertEqual(maintenance.archive_finalized(source, archive), 1)
            self.assertTrue((source / "a.pending.json").exists())
            self.assertTrue((archive / "b.finalized.json").exists())
            self.assertEqual(maintenance.archive_finalized(source, archive), 0)

    def test_symlinks_and_collisions_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source, archive = root / "outbox", root / "archive"
            source.mkdir(mode=0o700)
            archive.mkdir(mode=0o700)
            record = source / "a.finalized.json"
            record.symlink_to(root / "secret")
            with self.assertRaises(ValueError):
                maintenance.archive_finalized(source, archive)
            record.unlink()
            record.write_text("{}")
            record.chmod(0o600)
            target = archive / record.name
            target.write_text("different")
            with self.assertRaises(ValueError):
                maintenance.archive_finalized(source, archive)
            self.assertEqual(target.read_text(), "different")
            self.assertTrue(record.exists())


if __name__ == "__main__":
    unittest.main()
