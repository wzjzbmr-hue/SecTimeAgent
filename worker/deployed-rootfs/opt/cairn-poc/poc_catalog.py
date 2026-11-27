#!/usr/bin/env python3
"""Pinned PoC assets: prepare once, search/check offline; never execute source code."""
import argparse
import ast
import datetime
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
TEXT_EXT = {'.md', '.yaml', '.yml', '.py', '.sh', '.js', '.java', '.c', '.rb', '.php', '.txt'}
CVE = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.I)


def git(path, *args):
    result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(path), *args],
                            capture_output=True, timeout=300)
    if result.returncode:
        raise RuntimeError('git ' + args[0] + ' failed: ' + result.stderr.decode(errors='replace')[-600:])
    return result.stdout.decode('utf-8', errors='replace').strip()


def file_hash(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_lock(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data['schema_version'] != 1:
        raise ValueError('unsupported lock schema')
    datetime.date.fromisoformat(data['as_of'])
    seen = set()
    for source in data['sources']:
        if not re.fullmatch(r'[A-Za-z0-9_-]+', source['id']) or source['id'] in seen:
            raise ValueError('invalid/duplicate source id')
        seen.add(source['id'])
        if not re.fullmatch(r'[0-9a-f]{40}', source['commit']):
            raise ValueError('full commit required')
        if not re.fullmatch(r'https://github.com/[\w.-]+/[\w.-]+\.git', source['url']):
            raise ValueError('only explicit official GitHub HTTPS remotes supported')
        rel = PurePosixPath(source['path'])
        if not rel.parts or rel.is_absolute() or '..' in rel.parts or '\\' in source['path'] or ':' in source['path']:
            raise ValueError('source path must remain within prefix')
    return data


def source_root(prefix, source):
    prefix = Path(prefix).resolve()
    path = prefix / source['path']
    if path.is_symlink() or not path.resolve().is_relative_to(prefix):
        raise ValueError('source path escapes prefix')
    return path


def identity(root, source):
    if git(root, 'rev-parse', 'HEAD') != source['commit']:
        raise ValueError(source['id'] + ': commit mismatch')
    if git(root, 'remote', 'get-url', 'origin') != source['url']:
        raise ValueError(source['id'] + ': origin mismatch')
    if git(root, 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError(source['id'] + ': tracked files changed')


def sync(lock, prefix, ids, offline):
    if ids and not set(ids) <= {s['id'] for s in lock['sources']}:
        raise ValueError('unknown source')
    for source in lock['sources']:
        if ids and source['id'] not in ids:
            continue
        root = source_root(prefix, source)
        if root.exists():
            if git(root, 'remote', 'get-url', 'origin') != source['url']:
                raise ValueError(source['id'] + ': refusing unexpected remote')
            if git(root, 'status', '--porcelain', '--untracked-files=no'):
                raise ValueError(source['id'] + ': refusing dirty checkout')
            if git(root, 'rev-parse', 'HEAD') == source['commit']:
                identity(root, source)
                continue
        elif not offline:
            root.mkdir(parents=True)
            git(root, 'init')
            git(root, 'remote', 'add', 'origin', source['url'])
        if offline:
            raise ValueError(source['id'] + ': unavailable pinned snapshot in offline mode')
        # Fixed hash only. No moving branch, submodules, LFS, hooks or source execution.
        git(root, '-c', 'fetch.recurseSubmodules=false', 'fetch', '--depth=1', 'origin', source['commit'])
        git(root, 'checkout', '--detach', source['commit'])
        identity(root, source)


def analyze_python(raw, root, path):
    try:
        tree = ast.parse(raw, filename=str(path))
    except (SyntaxError, ValueError, UnicodeError) as error:
        return {'syntax': 'failed', 'error': str(error)[:200], 'imports': []}
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(n.name.split('.')[0] for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imports.add(node.module.split('.')[0])
    external = sorted(n for n in imports if n not in sys.stdlib_module_names
                      and not (path.parent / (n + '.py')).exists()
                      and not (root / (n + '.py')).exists()
                      and not (path.parent / n / '__init__.py').exists())
    # Static approximation: conditional imports can be optional, and dynamic ones invisible.
    return {'syntax': 'passed', 'imports': sorted(imports), 'external_imports': external}


def load_review(lock):
    path = HERE / 'review.json'
    if not path.exists():
        return None
    review = json.loads(path.read_text(encoding='utf-8'))
    source = next((s for s in lock['sources'] if s['id'] == review['source']), None)
    if source is None:
        return None
    if source['commit'] != review['commit']:
        raise ValueError('review belongs to another source commit; review changes first')
    return review


def records(lock, prefix, review=None):
    year = int(lock['as_of'][:4])
    renamed = {r['new_path']: r for r in (review or {}).get('renamed', [])}
    diagnostics = {r['path']: r for r in (review or {}).get('known_warnings', [])}
    reviewed_source = (review or {}).get('source')
    for source in lock['sources']:
        root = source_root(prefix, source)
        identity(root, source)
        filenames = git(root, 'ls-files', '-z').split('\0')
        for rel in sorted(filenames):
            path = root / rel
            if not rel or path.suffix.lower() not in TEXT_EXT:
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                continue
            raw = path.read_bytes()
            if len(raw) > 2 * 1024 * 1024:
                continue
            text = raw.decode('utf-8', errors='replace')
            cves = sorted(set(CVE.findall(rel.upper()) + CVE.findall(text.upper())))
            invalid = [c for c in cves if int(c[4:8]) > year]
            kind = source['kind']
            if path.suffix.lower() == '.md':
                kind = 'knowledge'
            elif source['kind'] == 'environment':
                kind = 'environment'
            item = {'source': source['id'], 'commit': source['commit'], 'path': rel,
                    'kind': kind, 'historical': source['historical'],
                    'cves': [c for c in cves if c not in invalid],
                    'warnings': ['future_cve_identifier:' + c for c in invalid],
                    'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
                    'title': next((line.strip('# \t')[:180] for line in text.splitlines() if line.strip()), rel),
                    'verification': 'unverified',
                    'search_text': (rel + '\n' + text[:65536]).casefold()}
            if path.suffix == '.py':
                item['python'] = analyze_python(raw, root, path)
            if source['id'] == reviewed_source and rel in renamed:
                relation = renamed[rel]
                if item['sha256'] != relation['new_sha256']:
                    raise ValueError('reviewed target changed: ' + rel)
                item['historical_identifiers'] = [relation['old_cve']]
                item['review_note'] = relation['note']
            if source['id'] == reviewed_source and rel in diagnostics:
                diagnostic = diagnostics[rel]
                if item['sha256'] != diagnostic['sha256']:
                    raise ValueError('warning template changed: ' + rel)
                item['validation_note'] = diagnostic['cause']
            yield item
        if source['id'] == reviewed_source:
            for withdrawn in review.get('withdrawn', []):
                yield {'source': source['id'], 'commit': source['commit'], 'path': withdrawn['old_path'],
                       'kind': 'knowledge', 'availability': 'withdrawn', 'historical': False,
                       'cves': [withdrawn['cve']], 'verification': 'requires_target_specific_verification',
                       'warnings': ['generic_template_withdrawn'], 'review_note': withdrawn['reason'],
                       'reference': withdrawn['reference'], 'vendor_advisory': withdrawn['vendor_advisory'],
                       'search_text': (withdrawn['cve'] + ' Apache CXF Aegis SOAP SSRF ' + withdrawn['reason']).casefold()}


def build_index(lock, prefix, output, review=None):
    if review is None:
        review = load_review(lock)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    counts = {}; blocked = 0
    fd, temp = tempfile.mkstemp(dir=output.parent, prefix='.poc-index-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            for item in records(lock, prefix, review):
                counts[item['source']] = counts.get(item['source'], 0) + 1
                blocked += item.get('python', {}).get('syntax') == 'failed'
                stream.write(json.dumps(item, ensure_ascii=False) + '\n')
        os.replace(temp, output)
    finally:
        if Path(temp).exists():
            Path(temp).unlink()
    meta = {'schema_version': 1, 'lock_sha256': hashlib.sha256(json.dumps(lock, sort_keys=True).encode()).hexdigest(),
            'review_sha256': hashlib.sha256(json.dumps(review, sort_keys=True).encode()).hexdigest(),
            'counts': counts, 'python_syntax_failures': blocked,
            'index_sha256': file_hash(output)}
    output.with_suffix('.meta.json').write_text(json.dumps(meta, indent=2), encoding='utf-8')
    return meta


def read_index(index, lock):
    index = Path(index)
    meta = json.loads(index.with_suffix('.meta.json').read_text(encoding='utf-8'))
    if meta['lock_sha256'] != hashlib.sha256(json.dumps(lock, sort_keys=True).encode()).hexdigest():
        raise ValueError('index belongs to another lock; rebuild')
    review = load_review(lock)
    if review is not None and meta.get('review_sha256') != hashlib.sha256(json.dumps(review, sort_keys=True).encode()).hexdigest():
        raise ValueError('index belongs to another review; rebuild')
    if meta['index_sha256'] != file_hash(index):
        raise ValueError('index checksum mismatch')
    with index.open(encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def search(args, lock):
    found = 0
    for item in read_index(args.index, lock):
        if item['historical'] and not args.include_historical:
            continue
        if args.kind and item['kind'] != args.kind:
            continue
        if args.cve and args.cve.upper() not in item['cves'] + item.get('historical_identifiers', []):
            continue
        if not all(q.casefold() in item['search_text'] for q in args.query):
            continue
        item.pop('search_text')
        if args.cve:
            item['matched_by'] = 'historical_identifier' if args.cve.upper() in item.get('historical_identifiers', []) else 'current_content'
        print(json.dumps(item, ensure_ascii=False))
        found += 1
        if found >= args.limit:
            break


def check(args, lock):
    for item in read_index(args.index, lock):
        if item['source'] != args.source or item['path'] != args.path:
            continue
        source = next(s for s in lock['sources'] if s['id'] == args.source)
        root = source_root(args.prefix, source)
        identity(root, source)
        if item.get('availability') == 'withdrawn':
            item.pop('search_text')
            print(json.dumps(dict(item, preflight='blocked'), ensure_ascii=False))
            return 2
        path = root / item['path']
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError('asset escapes source')
        if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('asset changed after indexing')
        checks = item.get('python', {})
        missing = [name for name in checks.get('external_imports', [])
                   if importlib.machinery.PathFinder.find_spec(name) is None]
        blocked = checks.get('syntax') == 'failed' or bool(missing) or bool(item['warnings'])
        print(json.dumps({'source': args.source, 'path': args.path, 'kind': item['kind'],
                          'syntax': checks.get('syntax', 'not_checked'),
                          'missing_imports': missing, 'warnings': item['warnings'],
                          'preflight': 'blocked' if blocked else 'static_checks_passed',
                          'verification': 'unverified',
                          'note': 'No source executed. Static imports are approximate; inspect target/version/auth/effects and validate separately.'}, ensure_ascii=False))
        return 2 if blocked else 0
    raise ValueError('asset not in catalog')


def validation_verdict(exit_code, log, known):
    warnings = [line.split('[WRN]', 1)[1].strip() for line in log.splitlines() if '[WRN]' in line]
    if exit_code or any(message not in [k['message'] for k in known] for message in warnings):
        return 'failed'
    return 'passed_with_known_warning' if warnings else 'passed'


def validate(args, lock):
    review = load_review(lock)
    if not review:
        raise ValueError('review required for template validation')
    source = next(s for s in lock['sources'] if s['id'] == review['source'])
    root = source_root(args.prefix, source)
    identity(root, source)
    known = review.get('known_warnings', [])
    for case in known:
        if file_hash(root / case['path']) != case['sha256']:
            raise ValueError('known-warning asset changed')
    version = subprocess.run(['nuclei', '-version'], capture_output=True, text=True, timeout=15)
    if not re.search(r'Engine Version:\s*' + re.escape(review['engine_version']) + r'(?:\s|$)', version.stdout + version.stderr):
        raise ValueError('engine version changed; review warning classification again')
    common = ['nuclei', '-validate', '-duc', '-ni', '-nc']
    # Partition, rather than accepting this message globally: all other templates must be warning-free.
    results = []
    # -validate does not honor -et here. Explicit original paths keep workflow
    # resolution unchanged and avoid the out-of-tree warning of a temporary view.
    excluded = {k['path'] for k in known}
    paths = [str(p) for p in sorted(root.rglob('*.yaml')) if p.relative_to(root).as_posix() not in excluded]
    batches = []
    batch = []
    for path in paths:
        if batch and (len(batch) >= 200 or sum(len(p.encode()) + 1 for p in batch) + len(path.encode()) > 24000):
            batches.append(batch); batch = []
        batch.append(path)
    if batch:
        batches.append(batch)
    parts = [('remaining_templates_batch_' + str(i + 1), common + ['-t', ','.join(batch)], []) for i, batch in enumerate(batches)]
    parts += [(case['path'], common + ['-t', str(root / case['path'])], [case]) for case in known]
    for name, argv, allow in parts:
        process = subprocess.run(argv, capture_output=True, text=True, timeout=180)
        log = process.stdout + process.stderr
        verdict = validation_verdict(process.returncode, log, allow)
        if 'All templates validated successfully' not in log:
            verdict = 'failed'
        results.append({'scope': name, 'status': verdict, 'log': log})
    print(json.dumps({'status': 'failed' if any(r['status'] == 'failed' for r in results) else 'passed_with_documented_diagnostic',
                      'source_commit': source['commit'], 'results': results,
                      'note': 'Schema/diagnostic checks only. Original signatures preserved. Runtime random expansion is separately covered by test_nuclei_random.py.'}, ensure_ascii=False))
    return 1 if any(r['status'] == 'failed' for r in results) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', default=str(HERE / 'sources.lock.json'))
    parser.add_argument('--prefix', default='/home/kali')
    parser.add_argument('--index', default=str(HERE / 'index.jsonl'))
    commands = parser.add_subparsers(dest='command', required=True)
    cmd = commands.add_parser('sync', help='build/debug only; fetch pinned commits, never run PoCs')
    cmd.add_argument('--source', action='append')
    cmd.add_argument('--offline', action='store_true')
    commands.add_parser('index', help='offline static index; verifies pinned checkouts')
    commands.add_parser('validate', help='offline template validation with scoped, reviewed diagnostics')
    cmd = commands.add_parser('search', help='offline search; historical sources opt-in')
    cmd.add_argument('query', nargs='*')
    cmd.add_argument('--cve')
    cmd.add_argument('--kind', choices=['template', 'script', 'knowledge', 'environment'])
    cmd.add_argument('--include-historical', action='store_true')
    cmd.add_argument('--limit', type=int, default=10)
    cmd = commands.add_parser('check', help='static checks only, not proof of exploitability')
    cmd.add_argument('source')
    cmd.add_argument('path')
    args = parser.parse_args()
    try:
        lock = load_lock(args.lock)
        if args.command == 'sync':
            sync(lock, args.prefix, args.source, args.offline)
        elif args.command == 'index':
            print(json.dumps(build_index(lock, args.prefix, args.index)))
        elif args.command == 'search':
            if not 1 <= args.limit <= 100:
                raise ValueError('limit must be 1..100')
            search(args, lock)
        elif args.command == 'validate':
            return validate(args, lock)
        else:
            return check(args, lock)
    except (ValueError, RuntimeError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
