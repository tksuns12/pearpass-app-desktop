#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Install an evaluation-only tree from locked commits without Git prepare hooks.
Original package.json/package-lock.json are never rewritten. Git dependencies are
fetched as exact-commit HTTPS archives; this is a derived install, not npm-ci
reproduction of upstream. SHA512 receipts detect subsequent local changes, not
independent publisher authenticity. Does not launch the app or run install hooks.
"""
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / '.evaluation-install'
GIT_RE = re.compile(r'git\+ssh://git@github.com/(.+?)(?:\.git)?#([0-9a-f]{40})$')

def digest(data):
    return 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()

def run():
    version = subprocess.check_output(['node', '--version'], text=True).strip()
    parts = tuple(int(n) for n in version.lstrip('v').split('.'))
    if parts[0] != 22 or parts < (22, 23, 2):
        raise RuntimeError('Select isolated Node 22.23.2 or a reviewed later 22.x runtime.')
    if (STAGE / 'node_modules').exists():
        raise RuntimeError('Existing installation found; inspect it before another install.')
    original = (ROOT / 'package-lock.json').read_bytes()
    original_sha = hashlib.sha256(original).hexdigest()
    lock = json.loads(original)
    pkg = json.loads((ROOT / 'package.json').read_text())
    STAGE.mkdir(exist_ok=True)
    archives = STAGE / 'archives'
    archives.mkdir(exist_ok=True)
    entries = []
    for name, meta in lock['packages'].items():
        resolved = meta.get('resolved', '')
        match = GIT_RE.fullmatch(resolved)
        if match:
            repository, commit = match.groups()
            entries.append((name, repository, commit))
        elif resolved.startswith(('git+', 'git:')):
            raise ValueError('Unsupported Git source: ' + name)
    def download(entry):
        name, repository, commit = entry
        filename = repository.replace('/', '--') + '--' + commit + '.tgz'
        source = 'https://codeload.github.com/' + repository + '/tar.gz/' + commit
        archive = archives / filename
        data = urllib.request.urlopen(source, timeout=60).read()
        archive.write_bytes(data)
        return {'package': name, 'repository': repository, 'commit': commit,
                'source': source, 'resolved': 'file:' + str(archive),
                'integrity': digest(data)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        receipts = list(pool.map(download, entries))
    replacements = {}
    for receipt in receipts:
        repository = receipt['repository']
        if repository in replacements and replacements[repository] != receipt['resolved']:
            raise ValueError('Multiple revisions require explicit edge resolution: ' + repository)
        replacements[repository] = receipt['resolved']
    def rewrite(value):
        if isinstance(value, dict): return {key: rewrite(v) for key, v in value.items()}
        if isinstance(value, list): return [rewrite(v) for v in value]
        if not isinstance(value, str): return value
        for repository, replacement in replacements.items():
            bases = ['git+https://github.com/' + repository,
                     'git+ssh://git@github.com/' + repository, 'github:' + repository]
            if any(value == b or value.startswith(b + '.git') or value.startswith(b + '#') for b in bases):
                return replacement
        return value
    pkg = rewrite(pkg)
    lock = rewrite(lock)
    for receipt in receipts:
        meta = lock['packages'][receipt['package']]
        meta['resolved'] = receipt['resolved']
        meta['integrity'] = receipt['integrity']
    pkg['scripts'] = {}
    pkg['private'] = True
    pkg['name'] = 'local-vault-evaluation-dependencies'
    lock['name'] = pkg['name']
    lock['packages']['']['name'] = pkg['name']
    (STAGE / 'package.json').write_text(json.dumps(pkg, indent=2) + '\n')
    (STAGE / 'package-lock.json').write_text(json.dumps(lock, indent=2) + '\n')
    (STAGE / '.npmrc').write_text('ignore-scripts=true\nlegacy-peer-deps=true\naudit=false\nfund=false\n')
    empty = STAGE / 'empty.npmrc'
    empty.write_text('')
    env = os.environ.copy()
    env.update({'npm_config_userconfig': str(empty), 'npm_config_ignore_scripts': 'true',
                'npm_config_cache': str(ROOT.parent / '.tools/npm-cache'),
                'GIT_TERMINAL_PROMPT': '0', 'HUSKY': '0'})
    for key in ['NODE_OPTIONS', 'NPM_TOKEN', 'NODE_AUTH_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN']:
        env.pop(key, None)
    command = ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund']
    started = time.monotonic()
    with (STAGE / 'install.log').open('w') as log:
        child = subprocess.Popen(command, cwd=STAGE, env=env, stdout=log,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try: code = child.wait(timeout=240)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait(timeout=15)
            code = 124
    text = (STAGE / 'install.log').read_text(errors='replace')
    hook_lines = [line for line in text.splitlines() if re.search(r'^> .* (prepare|postinstall|install|preinstall)$', line)]
    assert hashlib.sha256((ROOT / 'package-lock.json').read_bytes()).hexdigest() == original_sha
    report = {'scope': 'derived exact-commit archive installation', 'command': ' '.join(command),
              'exit_code': code, 'seconds': round(time.monotonic() - started, 2),
              'original_lock_sha256': original_sha, 'git_archives': receipts,
              'observed_lifecycle_headers': hook_lines, 'original_lock_unchanged': True,
              'node': subprocess.check_output(['node', '--version'], text=True).strip()}
    (STAGE / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    print('\n'.join(text.splitlines()[-30:]), flush=True)
    print('DERIVED_INSTALL_EXIT', code, 'LIFECYCLE_HEADERS', len(hook_lines), flush=True)
    if code or hook_lines: return code or 1
    target = ROOT / 'node_modules'
    if target.exists() or target.is_symlink():
        raise RuntimeError('Install succeeded; refusing to replace an existing node_modules automatically.')
    target.symlink_to(Path('.evaluation-install/node_modules'), target_is_directory=True)
    print('LINKED_EVALUATION_DEPENDENCIES', flush=True)
    return 0

if __name__ == '__main__':
    try: sys.exit(run())
    except Exception as error:
        print('INSTALL_BLOCKED:', str(error), file=sys.stderr)
        sys.exit(1)
