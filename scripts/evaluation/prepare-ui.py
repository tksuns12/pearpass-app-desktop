#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the upstream UI kit using registry-only dependencies from its own lock.
The extra packages are build tools, not upgrades to the app's original lockfile.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / 'node_modules/@tetherto/pearpass-lib-ui-kit'
TOOLS = ROOT / '.evaluation-install/ui-build-tools'

def main():
    source = (KIT / 'package-lock.json').read_bytes()
    original = json.loads(source)
    packages = original['packages']
    roots = ['react-native', 'react-native-svg', 'react-native-reanimated']
    selected = {}
    def resolve(owner, name):
        owner = PurePosixPath(owner)
        for parent in [owner, *owner.parents]:
            if parent.name == 'node_modules': continue
            candidate = str(parent / 'node_modules' / name)
            if candidate in packages: return candidate
        raise KeyError(name + ' from ' + str(owner))
    def visit(key):
        if key in selected: return
        meta = packages[key]
        resolved = meta.get('resolved', '')
        if not resolved.startswith('https://registry.npmjs.org/') or not meta.get('integrity'):
            raise ValueError('Only integrity-locked registry archives allowed: ' + key)
        selected[key] = meta
        for name in meta.get('dependencies', {}): visit(resolve(key, name))
        for name in meta.get('optionalDependencies', {}):
            try: child = resolve(key, name)
            except KeyError: continue
            visit(child)
    for name in roots: visit('node_modules/' + name)
    pkg = {'name': 'local-vault-evaluation-ui-build-tools', 'version': '0.0.0',
           'private': True, 'dependencies': {name: packages['node_modules/' + name]['version'] for name in roots}}
    lock = {'name': pkg['name'], 'version': pkg['version'], 'lockfileVersion': 3,
            'requires': True, 'packages': {'': pkg, **selected}}
    TOOLS.mkdir(exist_ok=True)
    (TOOLS / 'package.json').write_text(json.dumps(pkg, indent=2) + '\n')
    (TOOLS / 'package-lock.json').write_text(json.dumps(lock, indent=2) + '\n')
    (TOOLS / '.npmrc').write_text('ignore-scripts=true\nlegacy-peer-deps=true\naudit=false\nfund=false\n')
    env = os.environ.copy()
    env.update({'npm_config_ignore_scripts': 'true', 'HUSKY': '0',
                'npm_config_userconfig': str(ROOT / '.evaluation-install/empty.npmrc'),
                'npm_config_cache': str(ROOT.parent / '.tools/npm-cache')})
    for key in ['NPM_TOKEN', 'NODE_AUTH_TOKEN', 'NODE_OPTIONS', 'GH_TOKEN', 'GITHUB_TOKEN']:
        env.pop(key, None)
    with (TOOLS / 'install.log').open('w') as output:
        result = subprocess.run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'],
            cwd=TOOLS, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=150)
    print('UI_TOOL_INSTALL_EXIT', result.returncode, 'LOCKED_PACKAGES', len(selected), flush=True)
    if result.returncode:
        print((TOOLS / 'install.log').read_text()[-6000:]);return result.returncode
    nested = KIT / 'node_modules'
    desired = TOOLS / 'node_modules'
    if nested.is_symlink():
        if nested.resolve() != desired.resolve(): raise ValueError('Unexpected existing UI dependency link')
    elif nested.exists(): raise ValueError('Refusing to overwrite existing UI dependencies')
    else: nested.symlink_to(os.path.relpath(desired.resolve(), KIT.resolve()), target_is_directory=True)
    with (TOOLS / 'build.log').open('w') as output:
        result = subprocess.run(['node', str(ROOT / 'node_modules/typescript/bin/tsc'), '--project', 'tsconfig.build.json'],
            cwd=KIT, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=90)
    receipt = {'ui_source_lock_sha256': hashlib.sha256(source).hexdigest(),
        'scope': 'build-only, dependency closure of upstream UI-kit lock',
        'versions': pkg['dependencies'], 'locked_packages': len(selected),
        'build_exit_code': result.returncode, 'install_hooks_enabled': False,
        'original_app_lock_modified': False}
    (TOOLS / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2), flush=True)
    if result.returncode: print((TOOLS / 'build.log').read_text()[-6000:])
    return result.returncode

if __name__ == '__main__':
    try: sys.exit(main())
    except Exception as error:
        print('UI_PREPARATION_FAILED:', str(error), file=sys.stderr);sys.exit(1)
