#!/usr/bin/env python3
"""Durable, forward-only local share handoff. Never copies or logs secret bytes."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

PENDING = '.share-promotion.pending'
LAST = '.share-promotion.last.json'
LOCK = '.share-promotion.lock'


def component(value):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', value) or value in ('shares', '.', '..'):
        raise ValueError('unsafe or reserved share directory name')
    return value


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def manifest(path, sync=False):
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f'not a real share directory: {path}')
    result = {}
    for file in sorted(path.iterdir()):
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            import stat
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError(f'non-regular share file: {file}')
            result[file.name] = hashlib.file_digest(stream, 'sha256').hexdigest()
            if sync:
                os.fsync(stream.fileno())
    if sync:
        sync_dir(path)
        sync_dir(path.parent)
    return result


def keys(path):
    pevm = list(path.glob('pevm-*.keyshare'))
    if len(pevm) != 1:
        raise ValueError(f'exactly one Pevm share required: {path}')
    match = re.fullmatch(r'pevm-([0-9]+).keyshare', pevm[0].name)
    if not match:
        raise ValueError('invalid share index')
    idx = match[1]
    required = [f'pevm-{idx}.keyshare', f'pevm-{idx}.groupkey',
                f'pgw-{idx}.keypackage', f'pgw-{idx}.pubkeypackage', f'pgw-{idx}.groupvk']
    if set(manifest(path)) != set(required):
        raise ValueError(f'incomplete or ambiguous dual share set: {path}')
    if any((path / name).stat().st_size == 0 for name in required):
        raise ValueError('empty share material')
    evm = (path / required[1]).read_bytes()
    pgw = (path / required[4]).read_bytes()
    if len(evm) != 33 or evm[0] not in (2, 3) or len(pgw) != 32:
        raise ValueError('invalid group-key encoding')
    return evm.hex(), pgw.hex(), int(idx)


def cast(*args):
    return subprocess.check_output(['cast', *args], text=True, timeout=30).strip()


def evm_address(compressed):
    key = bytes.fromhex(compressed)
    p = 2**256 - 2**32 - 977
    x = int.from_bytes(key[1:], 'big')
    y = pow((x*x*x + 7) % p, (p+1)//4, p)
    if x >= p or y*y % p != (x*x*x + 7) % p:
        raise ValueError('invalid secp256k1 point')
    if y % 2 != key[0] % 2:
        y = p-y
    digest = cast('keccak', '0x' + (key[1:] + y.to_bytes(32, 'big')).hex())
    return '0x' + digest[-40:].lower()


def verify_authority(plan):
    """Recheck both chain authorities on preparation AND every recovery attempt."""
    payload = json.dumps({'jsonrpc': '2.0', 'id': '0', 'method': 'get_gateway_info',
                          'params': {'gateway_address': plan['gateway']}}).encode()
    request = urllib.request.Request(plan['native_rpc'].rstrip('/') + '/json_rpc', payload,
                                     {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        info = json.load(response).get('result', {})
    if info.get('owner_key_finalized') is not True or info.get('owner_key', '').lower() != plan['pgw']:
        raise ValueError('successor native owner is not checkpoint-finalized')
    rpc, proxy = plan['evm_rpc'], plan['proxy']
    chain = cast('chain-id', '--rpc-url', rpc)
    block = cast('block', 'finalized', '--field', 'hash', '--rpc-url', rpc)
    signer = cast('call', proxy, 'currentSigner()(address)', '--block', block, '--rpc-url', rpc).lower()
    epoch = cast('call', proxy, 'keyEpoch()(uint64)', '--block', block, '--rpc-url', rpc).split()[0]
    if signer != evm_address(plan['pevm']):
        raise ValueError('successor EVM signer is not finalized at the configured proxy')
    if 'chain_id' in plan and (plan['chain_id'] != chain or plan['epoch'] != epoch):
        raise ValueError('EVM chain or key epoch changed since handoff preparation')
    plan.update(chain_id=chain, epoch=epoch, finalized_evm_block=block)


def write_journal(root, plan):
    fd, name = tempfile.mkstemp(prefix='.share-promotion.tmp-', dir=root)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(plan, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, root / PENDING)
        sync_dir(root)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def prepare(root, subdir, archive=None):
    component(subdir)
    nodes = []
    group = None
    indices = set()
    for directory in sorted(root.glob('beldex-127.0.0.1-*/devnet')):
        if directory.is_symlink() or directory.parent.is_symlink() or not directory.is_dir():
            raise ValueError('symlinked or invalid participant directory')
        old = manifest(directory / 'shares', sync=True)
        new = manifest(directory / subdir, sync=True)
        if new:
            evm, pgw, idx = keys(directory / subdir)
            if group is not None and group != (evm, pgw):
                raise ValueError('successor participants disagree on group keys')
            if idx in indices:
                raise ValueError('duplicate successor participant index')
            indices.add(idx)
            group = (evm, pgw)
            if old and any(a == b for a, b in zip(keys(directory / 'shares')[:2], group)):
                raise ValueError('successor is already the active dual key')
        if old is not None or new:
            nodes.append({'path': str(directory.relative_to(root)), 'old': old, 'new': new or None})
    if group is None:
        raise ValueError('no successor shares; use --status to inspect the last handoff')
    if archive is None:
        i = 0
        while any(os.path.lexists(root / node['path'] / f'shares-gen{i}') for node in nodes):
            i += 1
        archive = f'shares-gen{i}'
    component(archive)
    if archive == subdir:
        raise ValueError('archive and successor directory must differ')
    for node in nodes:
        if os.path.lexists(root / node['path'] / archive):
            raise ValueError('archive destination already exists')
    return {'version': 1, 'subdir': subdir, 'archive': archive, 'nodes': nodes,
            'pevm': group[0], 'pgw': group[1],
            'gateway': os.environ['GATEWAY_ID'],
            'native_rpc': os.environ.get('BELDEX_RPC', 'http://127.0.0.1:19191'),
            'evm_rpc': os.environ.get('RPC', 'http://127.0.0.1:8545'),
            'proxy': os.environ['PROXY']}


def validate_plan(plan):
    if plan.get('version') != 1 or not plan.get('nodes'):
        raise ValueError('invalid handoff journal')
    component(plan['subdir'])
    component(plan['archive'])
    if plan['subdir'] == plan['archive']:
        raise ValueError('invalid journal directory names')
    paths = [node['path'] for node in plan['nodes']]
    if len(paths) != len(set(paths)) or any(not re.fullmatch(r'beldex-127\.0\.0\.1-[0-9]+/devnet', p) for p in paths):
        raise ValueError('invalid journal participant paths')


def state(root, plan, node):
    directory = root / node['path']
    if directory.is_symlink() or directory.parent.is_symlink():
        raise ValueError('symlinked participant')
    live = manifest(directory / 'shares')
    incoming = manifest(directory / plan['subdir'])
    archive = manifest(directory / plan['archive'])
    old, new = node['old'], node['new']
    # Empty incoming directories on departing members are harmless, never activated.
    if new is None:
        incoming = incoming or None
    if old is not None and live == old and archive is None and incoming == new:
        return 'archive'
    if archive == old and live is None and incoming == new:
        return 'install' if new is not None else 'done'
    if archive == old and live == new and incoming is None:
        return 'done'
    raise ValueError(f"share trees differ from recorded handoff: {node['path']}")


def apply(root, plan, checkpoint=lambda stage: None):
    validate_plan(plan)
    # Check every participant before changing any of them.
    for node in plan['nodes']:
        state(root, plan, node)
    for node in plan['nodes']:
        directory = root / node['path']
        step = state(root, plan, node)
        if step == 'archive':
            os.rename(directory / 'shares', directory / plan['archive'])
            checkpoint('archive-renamed')
            sync_dir(directory)
            checkpoint('archive-durable')
            step = 'install' if node['new'] is not None else 'done'
        if step == 'install':
            os.rename(directory / plan['subdir'], directory / 'shares')
            checkpoint('successor-renamed')
            sync_dir(directory)
            checkpoint('successor-durable')
    for node in plan['nodes']:
        if state(root, plan, node) != 'done':
            raise ValueError('handoff incomplete')
        # Also sync directories recovered from a rename-before-fsync interruption.
        sync_dir(root / node['path'])
    checkpoint('before-complete')
    os.replace(root / PENDING, root / LAST)
    checkpoint('complete-renamed')
    sync_dir(root)


@contextlib.contextmanager
def locked(root):
    fd = os.open(root / LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('stop all signer/DKG processes before promotion; share lock is held') from None
        yield


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--status', action='store_true')
    args = parser.parse_args()
    root = Path(os.environ.get('TESTDATA_DIR', Path(__file__).parent / 'testdata')).resolve(strict=True)
    with locked(root):
        pending = root / PENDING
        if args.status:
            path = pending if pending.exists() else root / LAST
            plan = json.loads(path.read_text())
            print(json.dumps({'pending': pending.exists(), 'archive': plan['archive'],
                              'pevm': plan['pevm'], 'pgw': plan['pgw']}, indent=2))
            return
        if pending.exists():
            plan = json.loads(pending.read_text())
            validate_plan(plan)
            for variable, field in [('SUBDIR', 'subdir'), ('ARCHIVE', 'archive'), ('GATEWAY_ID', 'gateway'),
                                    ('PROXY', 'proxy'), ('RPC', 'evm_rpc'), ('BELDEX_RPC', 'native_rpc')]:
                if variable in os.environ and os.environ[variable] != plan[field]:
                    raise ValueError(f'{variable} differs from pending handoff; refusing a different rotation')
        else:
            subdir = component(os.environ.get('SUBDIR', 'shares-next'))
            has_incoming = any(manifest(d / subdir) for d in root.glob('beldex-127.0.0.1-*/devnet'))
            if not has_incoming and (root / LAST).exists():
                plan = json.loads((root / LAST).read_text())
                validate_plan(plan)
                verify_authority(plan)
                if any(state(root, plan, node) != 'done' for node in plan['nodes']):
                    raise ValueError('completed handoff no longer matches share trees')
                print('Handoff already complete; archive:', plan['archive'])
                return
            plan = prepare(root, subdir, os.environ.get('ARCHIVE'))
        verify_authority(plan)
        for node in plan['nodes']:
            print(f"{node['path']}: {state(root, plan, node)}")
        print('Archive:', plan['archive'])
        if args.dry_run:
            return
        if not pending.exists():
            write_journal(root, plan)
        apply(root, plan)
        print('Handoff complete; retired shares are archived, not securely erased.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f'promotion refused: {exc}', file=sys.stderr)
        sys.exit(1)
