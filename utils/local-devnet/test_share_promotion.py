#!/usr/bin/env python3
"""All keys are dummy bytes in temporary directories; no daemon or live shares."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import share_promotion as promotion


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {'GATEWAY_ID': 'fixture', 'PROXY': '0x' + '11'*20,
                                           'TESTDATA_DIR': str(self.root)}, clear=True)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def tree(self, node, subdir, generation, idx):
        path = self.root / f'beldex-127.0.0.1-{node}/devnet' / subdir
        path.mkdir(parents=True, mode=0o700)
        files = {f'pevm-{idx}.keyshare': b'fixture-private-pevm' + bytes([generation]),
                 f'pevm-{idx}.groupkey': b'\x02' + bytes([generation])*32,
                 f'pgw-{idx}.keypackage': b'fixture-private-pgw' + bytes([generation]),
                 f'pgw-{idx}.pubkeypackage': b'fixture-public-pgw' + bytes([generation]),
                 f'pgw-{idx}.groupvk': bytes([generation])*32}
        for name, content in files.items():
            (path / name).write_bytes(content)
        return path

    def fixture(self):
        for node in (1, 2):
            self.tree(node, 'shares', 1, node)
            self.tree(node, 'shares-next', 2, node)
        self.tree(3, 'shares-next', 2, 3)  # joins
        self.tree(4, 'shares', 1, 4)      # departs
        return promotion.prepare(self.root, 'shares-next')

    def assert_complete(self, plan):
        self.assertFalse((self.root / promotion.PENDING).exists())
        self.assertTrue((self.root / promotion.LAST).exists())
        for node in plan['nodes']:
            self.assertEqual(promotion.state(self.root, plan, node), 'done')
            directory = self.root / node['path']
            self.assertEqual(promotion.manifest(directory / 'shares'), node['new'])
            self.assertEqual(promotion.manifest(directory / plan['archive']), node['old'])

    def test_process_death_at_every_move_and_commit_boundary_recovers(self):
        # Two continuing members, one join, one departure: 12 rename/fsync
        # boundaries, plus before/after commit. Also die just after preparation.
        for stop in range(15):
            with self.subTest(stop=stop), tempfile.TemporaryDirectory() as directory:
                previous, self.root = self.root, Path(directory)
                plan = self.fixture()
                promotion.write_journal(self.root, plan)
                code = '''
import json,os,sys
from pathlib import Path
import share_promotion as p
root=Path(sys.argv[1]); stop=int(sys.argv[2]); count=0
if stop==0: os._exit(77)
def hook(stage):
 global count
 count+=1
 if count==stop: os._exit(77)
p.apply(root,json.loads((root/p.PENDING).read_text()),hook)
'''
                result = subprocess.run([sys.executable, '-B', '-c', code, str(self.root), str(stop)],
                                        cwd=Path(promotion.__file__).parent, env={'PATH': os.defpath})
                self.assertEqual(result.returncode, 77)
                if (self.root / promotion.PENDING).exists():
                    promotion.apply(self.root, json.loads((self.root / promotion.PENDING).read_text()))
                self.assert_complete(plan)
                self.root = previous

    def test_mutated_successor_refused_before_any_move(self):
        plan = self.fixture()
        promotion.write_journal(self.root, plan)
        (self.root / plan['nodes'][1]['path'] / 'shares-next/pevm-2.keyshare').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            promotion.apply(self.root, plan)
        self.assertFalse((self.root / plan['nodes'][0]['path'] / plan['archive']).exists())
        self.assertTrue((self.root / promotion.PENDING).exists())

    def test_active_reader_and_second_promoter_exclude_promotion(self):
        with open(self.root / promotion.LOCK, 'w') as reader:
            fcntl.flock(reader, fcntl.LOCK_SH)
            with self.assertRaises(ValueError):
                with promotion.locked(self.root):
                    pass
        with promotion.locked(self.root):
            with self.assertRaises(ValueError):
                with promotion.locked(self.root):
                    pass

    def test_shell_consumers_refuse_pending_or_running_promotion(self):
        root = self.root / 'testdata'
        root.mkdir()
        guard = Path(promotion.__file__).with_name('share-use-lock.sh')
        command = ['bash', '-c', '. "$1"', 'guard-test', str(guard)]
        with promotion.locked(root):
            result = subprocess.run(command, cwd=self.root, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        (root / promotion.PENDING).write_text('fixture journal')
        result = subprocess.run(command, cwd=self.root, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'incomplete share handoff', result.stderr)
        (root / promotion.PENDING).unlink()
        self.assertEqual(subprocess.run(command, cwd=self.root, capture_output=True).returncode, 0)

    def test_bad_names_symlinks_and_duplicate_participants_refused(self):
        for name in ('../outside', 'shares', '/tmp/x', 'shares-next/x'):
            with self.assertRaises(ValueError):
                promotion.prepare(self.root, name)
        plan = self.fixture()
        with self.assertRaises(ValueError):
            promotion.prepare(self.root, 'shares-next', 'shares-next')
        directory = self.root / plan['nodes'][0]['path'] / 'shares-next'
        target = directory / 'pevm-1.keyshare'
        target.unlink()
        target.symlink_to(directory / 'pevm-1.groupkey')
        with self.assertRaises(OSError):
            promotion.prepare(self.root, 'shares-next')

    def test_duplicate_index_and_incomplete_dual_key_refused(self):
        self.tree(1, 'shares-next', 2, 1)
        second = self.tree(2, 'shares-next', 2, 1)
        with self.assertRaises(ValueError):
            promotion.prepare(self.root, 'shares-next')
        (second / 'pgw-1.keypackage').unlink()
        with self.assertRaises(ValueError):
            promotion.prepare(self.root, 'shares-next')

    def test_dry_run_and_completed_rerun_do_not_move_again(self):
        plan = self.fixture()
        with patch.object(promotion, 'verify_authority'), patch.object(sys, 'argv', ['promotion', '--dry-run']), contextlib.redirect_stdout(io.StringIO()):
            promotion.main()
        self.assertFalse((self.root / promotion.PENDING).exists())
        self.assertEqual(promotion.state(self.root, plan, plan['nodes'][0]), 'archive')
        promotion.write_journal(self.root, plan)
        promotion.apply(self.root, plan)
        with patch.object(promotion, 'verify_authority'), patch.object(sys, 'argv', ['promotion']), contextlib.redirect_stdout(io.StringIO()):
            promotion.main()
        self.assert_complete(plan)

    def test_pending_rechecks_authority_and_rejects_configuration_changes(self):
        plan = self.fixture()
        promotion.write_journal(self.root, plan)
        with patch.object(promotion, 'verify_authority', side_effect=ValueError('not finalized')), patch.object(sys, 'argv', ['promotion']):
            with self.assertRaises(ValueError):
                promotion.main()
        self.assertEqual(promotion.state(self.root, plan, plan['nodes'][0]), 'archive')
        with patch.dict(os.environ, {'PROXY': 'different'}), patch.object(sys, 'argv', ['promotion']):
            with self.assertRaises(ValueError):
                promotion.main()

    def test_chain_authority_checks_native_finality_evm_signer_and_epoch(self):
        plan = self.fixture()
        calls = []
        def rpc(*args):
            calls.append(args)
            if args[0] == 'chain-id': return '1'
            if args[0] == 'block': return '0xabc'
            if args[2] == 'currentSigner()(address)': return '0xapproved'
            return '8'
        def native(final=True):
            return io.BytesIO(json.dumps({'result': {'owner_key_finalized': final, 'owner_key': plan['pgw']}}).encode())
        with patch.object(promotion, 'cast', side_effect=rpc), patch.object(promotion, 'evm_address', return_value='0xapproved'):
            with patch.object(promotion.urllib.request, 'urlopen', return_value=native(False)):
                with self.assertRaises(ValueError): promotion.verify_authority(plan)
            self.assertEqual(calls, [])
            with patch.object(promotion.urllib.request, 'urlopen', return_value=native()):
                promotion.verify_authority(plan)
            self.assertEqual(plan['epoch'], '8')
            self.assertTrue(all('--block' in c and '0xabc' in c for c in calls if c[0] == 'call'))
            plan['epoch'] = '7'
            with patch.object(promotion.urllib.request, 'urlopen', return_value=native()):
                with self.assertRaises(ValueError): promotion.verify_authority(plan)
            plan['epoch'] = '8'
            with patch.object(promotion, 'evm_address', return_value='0xwrong'), patch.object(promotion.urllib.request, 'urlopen', return_value=native()):
                with self.assertRaises(ValueError): promotion.verify_authority(plan)


if __name__ == '__main__':
    unittest.main()
