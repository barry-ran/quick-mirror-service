#!/usr/bin/env python3
"""Real production Peerloom management HTTP/TLS + QM worker; isolated CI only."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peerloom', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    repo = args.peerloom.resolve()
    root = Path(__file__).resolve().parents[1]
    sha = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    if len(args.commit) != 40 or sha != args.commit:
        raise SystemExit('Peerloom checkout must match pinned complete commit')
    if subprocess.check_output(['git', '-C', str(repo), 'status', '--porcelain', '--untracked-files=no']):
        raise SystemExit('Peerloom tracked checkout must be clean')
    if not os.environ.get('QM_TEST_DATABASE_URL') or os.name != 'posix':
        raise SystemExit('Linux/macOS and isolated QM_TEST_DATABASE_URL required')
    os.umask(0o077)
    # Build a test-only command inside the checked-out module to respect Go internal imports.
    source = repo / 'src/device-server/cmd/qm-renewal-runtime-fixture'
    source.mkdir(mode=0o700)  # Refuse pre-existing paths.
    try:
        shutil.copyfile(root / 'scripts/fixtures/peerloom-renewal/main.go.txt', source / 'main.go')
        with tempfile.TemporaryDirectory(prefix='qm-renewal-runtime-') as raw:
            work = Path(raw)
            binary = work / 'fixture'
            subprocess.run(['go', '-C', str(repo / 'src/device-server'), 'build', '-o', str(binary),
                            './cmd/qm-renewal-runtime-fixture'], check=True, timeout=180)
            private = work / 'private'
            private.mkdir(mode=0o700)
            with (work / 'fixture.log').open('wb') as log:
                process = subprocess.Popen([str(binary), str(repo / 'infra/migrations'), str(private)],
                                           stdin=subprocess.PIPE, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 90
                    while not (private / 'ready.json').exists():
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError('isolated management fixture did not become ready')
                        time.sleep(0.1)
                    env = dict(os.environ, QM_RENEWAL_RUNTIME_DIR=str(private))
                    subprocess.run(['go', 'test', '-race', '-tags', 'runtimeintegration',
                                    './internal/peerloom', '-run', '^TestRealPeerloomRenewalWorker$', '-count=1'],
                                   cwd=root, env=env, check=True, timeout=180)
                finally:
                    if process.stdin:
                        process.stdin.close()
                    try:
                        process.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=10)
            if process.returncode:
                raise RuntimeError('fixture failed to cleanly finish')
    finally:
        # Only the exact new test command is removed, never the checkout or database.
        (source / 'main.go').unlink(missing_ok=True)
        source.rmdir()
    print('Real Peerloom management TLS + QM worker renewal/restart/revocation passed; not full device-server deployment.')

if __name__ == '__main__':
    main()
