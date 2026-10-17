#!/usr/bin/env python3
"""Run bounded synthetic parser campaigns; save identities and actual results."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(directory):
    return {str(path.relative_to(directory)): digest(path)
            for path in sorted(directory.rglob('*')) if path.is_file()}


def bounded(command, log, timeout):
    started = time.monotonic()
    with log.open('wb') as stream:
        process = subprocess.Popen(command, cwd=ROOT, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            code = 'timeout'
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
    return {'command': command, 'exit_code': code,
            'elapsed_seconds': round(time.monotonic() - started, 2),
            'log_sha256': digest(log)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new private evidence directory')
    parser.add_argument('--seconds-per-target', type=int, default=60)
    parser.add_argument('--toolchain', default='nightly-2026-10-17')
    args = parser.parse_args()
    if not 1 <= args.seconds_per_target <= 3600:
        parser.error('seconds per target must be between 1 and 3600')
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    corpus = output / 'corpus'
    cargo = ['cargo', '+' + args.toolchain]
    version = lambda command: subprocess.check_output(command, cwd=ROOT, text=True).strip()
    # Path dependencies compile the working tree. Refuse to attribute a modified
    # production source to HEAD; the separately hashed harness may be uncommitted.
    production_paths = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'crates']
    changed = version(['git', 'diff', '--name-only', 'HEAD', '--', *production_paths])
    if changed:
        parser.error('production sources differ from HEAD; commit the candidate first')
    untracked = version(['git', 'ls-files', '--others', '--exclude-standard', '--', *production_paths])
    if untracked:
        parser.error('untracked production inputs prevent candidate attribution')
    names = version(['git', 'ls-files', '--', *production_paths]).splitlines()
    production = {name: digest(ROOT / name) for name in names}
    # Validate resolution before cargo-fuzz, whose build interface lacks --locked.
    subprocess.run(cargo + ['metadata', '--locked', '--manifest-path', 'fuzz/Cargo.toml',
                            '--no-deps', '--format-version', '1'], cwd=ROOT,
                   check=True, stdout=subprocess.DEVNULL)
    lock_digest = digest(ROOT / 'fuzz/Cargo.lock')
    source = {str(path.relative_to(ROOT)): digest(path) for path in sorted((ROOT / 'fuzz').rglob('*'))
              if path.is_file() and (path.suffix in ('.rs', '.toml', '.py') or path.name == 'Cargo.lock')
              and not any(part in ('target', 'corpus', 'artifacts', 'coverage') for part in path.relative_to(ROOT / 'fuzz').parts)}
    summary = {'schema': 1, 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'source_commit': version(['git', 'rev-parse', 'HEAD']),
               'rustc': version(['rustc', '+' + args.toolchain, '--version', '--verbose']),
               'cargo_fuzz': version(cargo + ['fuzz', '--version']),
               'production_sha256': production,
               'harness_sha256': source,
               'scope': 'pure record/config/PHC and IPC decoders; AddressSanitizer; no KDF, PAM, socket, account or TPM use',
               'checks': []}
    save = lambda: (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    command = cargo + ['run', '--locked', '--manifest-path', 'fuzz/Cargo.toml',
                       '--target-dir', str(output / 'seed-build'), '--example', 'seed_corpus', '--', str(corpus)]
    seeds = bounded(command, output / 'seeds.log', 600)
    summary['checks'].append({'name': 'seeds', **seeds})
    save()
    if seeds['exit_code'] != 0:
        return 1
    summary['initial_corpus_sha256'] = inventory(corpus)
    failed = False
    for target, length in [('records', 65537), ('streams', 8192), ('phc', 256)]:
        artifacts = output / 'artifacts' / target
        artifacts.mkdir(parents=True)
        log = output / (target + '.log')
        command = cargo + ['fuzz', 'run', target, str(corpus / target),
                           '--target-dir', str(output / 'build'), '--sanitizer', 'address', '--',
                           '-seed=9', '-max_total_time=' + str(args.seconds_per_target),
                           '-max_len=' + str(length), '-timeout=5', '-rss_limit_mb=2048',
                           '-artifact_prefix=' + str(artifacts) + '/', '-print_final_stats=1']
        result = bounded(command, log, args.seconds_per_target + 600)
        text = log.read_text(errors='replace')
        iterations = re.search(r'stat::number_of_executed_units:\s*(\d+)', text)
        result['executed_units'] = int(iterations[1]) if iterations else None
        result['instrumented'] = 'Loaded 1 modules' in text and 'inline 8-bit counters' in text
        result['artifacts'] = inventory(artifacts)
        result['lockfile_unchanged'] = digest(ROOT / 'fuzz/Cargo.lock') == lock_digest
        failed |= (result['exit_code'] != 0 or not result['instrumented']
                   or not result['executed_units'] or not result['lockfile_unchanged'])
        summary['checks'].append({'name': target, **result})
        save()
        print(json.dumps({'name': target, **result}), flush=True)
    summary['final_corpus_sha256'] = inventory(corpus)
    summary['production_unchanged'] = all(digest(ROOT / name) == value
                                          for name, value in production.items())
    failed |= not summary['production_unchanged']
    summary['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
