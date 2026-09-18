/* SPDX-License-Identifier: Apache-2.0 */
const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const vm = require('node:vm')
const { configureEvaluationProfile: configure, PRODUCT_NAME, DIRECTORY_NAME, MARKER_NAME, MARKER } = require('../../electron/evaluation-profile.cjs')
const ROOT = path.resolve(__dirname, '../..')
const consent = { LOCALVAULT_EVALUATION_ACK: 'dummy-data-only' }
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'localvault-test-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const paths = {}
  const app = {
    isPackaged: false,
    getPath: (key) => { assert.equal(key, 'appData'); return root },
    setPath: (key, value) => { paths[key] = value },
    setName: (value) => { paths.name = value }
  }
  return { root, app, paths, pkg: { productName: PRODUCT_NAME }, config: {} }
}
test('no acknowledgement: no profile is created', (t) => {
  const f = fixture(t)
  assert.throws(() => configure(f.app, f.pkg, f.config, {}), /CONSENT_REQUIRED/)
  assert.deepEqual(fs.readdirSync(f.root), [])
})
test('packaged builds fail closed', (t) => {
  const f = fixture(t); f.app.isPackaged = true
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /RELEASE_BLOCKED/)
  assert.deepEqual(fs.readdirSync(f.root), [])
})
test('wrong product identity fails closed', (t) => {
  const f = fixture(t); f.pkg.productName = 'PearPass'
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /IDENTITY_MISMATCH/)
})
for (const location of ['pkg', 'config']) {
  for (const field of ['upgrade', 'legacyChannelLink']) {
    test(`rejects upstream ${location}.${field}`, (t) => {
      const f = fixture(t); f[location][field] = 'pear://dummy-test-channel'
      assert.throws(() => configure(f.app, f.pkg, f.config, consent), /UPSTREAM_CHANNEL/)
      assert.deepEqual(fs.readdirSync(f.root), [])
    })
  }
}
test('separate profile preserves existing original profile', (t) => {
  const f = fixture(t); const original = path.join(f.root, 'PearPass')
  fs.mkdirSync(original); fs.writeFileSync(path.join(original, 'sentinel'), 'DUMMY-ORIGINAL')
  const profile = configure(f.app, f.pkg, f.config, consent)
  assert.equal(profile, path.join(f.root, DIRECTORY_NAME))
  assert.equal(f.paths.userData, profile)
  assert.equal(f.paths.sessionData, path.join(profile, 'session'))
  assert.equal(f.paths.name, PRODUCT_NAME)
  assert.equal(fs.readFileSync(path.join(original, 'sentinel'), 'utf8'), 'DUMMY-ORIGINAL')
  assert.equal(fs.readFileSync(path.join(profile, MARKER_NAME), 'utf8'), MARKER)
  if (process.platform !== 'win32') assert.equal(fs.statSync(profile).mode & 0o777, 0o700)
})
test('marked profile is reusable without deleting data', (t) => {
  const f = fixture(t); const profile = configure(f.app, f.pkg, f.config, consent)
  fs.writeFileSync(path.join(profile, 'dummy'), 'DUMMY-RECORD')
  assert.equal(configure(f.app, f.pkg, f.config, consent), profile)
  assert.equal(fs.readFileSync(path.join(profile, 'dummy'), 'utf8'), 'DUMMY-RECORD')
})
test('unmarked existing directory is not adopted', (t) => {
  const f = fixture(t); fs.mkdirSync(path.join(f.root, DIRECTORY_NAME))
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /UNOWNED_PROFILE/)
})
test('existing file is not adopted as profile', (t) => {
  const f = fixture(t); fs.writeFileSync(path.join(f.root, DIRECTORY_NAME), 'DUMMY')
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /UNSAFE_PROFILE/)
})
test('modified marker is rejected', (t) => {
  const f = fixture(t); const profile = configure(f.app, f.pkg, f.config, consent)
  fs.writeFileSync(path.join(profile, MARKER_NAME), 'NOT-OURS')
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /UNOWNED_PROFILE/)
})
test('profile symlinks are rejected', { skip: process.platform === 'win32' }, (t) => {
  const f = fixture(t); const outside = path.join(f.root, 'other'); fs.mkdirSync(outside)
  fs.symlinkSync(outside, path.join(f.root, DIRECTORY_NAME))
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /UNSAFE_PROFILE/)
  assert.deepEqual(fs.readdirSync(outside), [])
})
test('marker symlinks are rejected', { skip: process.platform === 'win32' }, (t) => {
  const f = fixture(t); const profile = configure(f.app, f.pkg, f.config, consent)
  fs.unlinkSync(path.join(profile, MARKER_NAME))
  const target = path.join(f.root, 'marker-target'); fs.writeFileSync(target, MARKER)
  fs.symlinkSync(target, path.join(profile, MARKER_NAME))
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /UNOWNED_PROFILE/)
})
test('session directory symlinks are rejected', { skip: process.platform === 'win32' }, (t) => {
  const f = fixture(t); const profile = configure(f.app, f.pkg, f.config, consent)
  fs.rmdirSync(path.join(profile, 'session'))
  const outside = path.join(f.root, 'other'); fs.mkdirSync(outside)
  fs.symlinkSync(outside, path.join(profile, 'session'))
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /UNSAFE_PROFILE/)
})
test('relative appData path is rejected', (t) => {
  const f = fixture(t); f.app.getPath = () => 'relative-path'
  assert.throws(() => configure(f.app, f.pkg, f.config, consent), /INVALID_APP_DATA/)
})
// Execute actual function bodies with doubles, not a replacement synchronization model.
function actualFunction(name, context) {
  const source = fs.readFileSync(path.join(ROOT, 'electron/main.cjs'), 'utf8')
  const marker = `${name === 'registerIPC' ? '' : 'async '}function ${name}(`
  const start = source.indexOf(marker); assert.notEqual(start, -1)
  const end = source.indexOf('\n}\n', start); assert.notEqual(end, -1)
  return vm.runInNewContext(`(${source.slice(start, end + 2)})`, context, { timeout: 1000 })
}
for (const upgrade of [null, undefined, '']) {
  test(`actual resolver with upgrade=${String(upgrade)} avoids legacy lookup`, async () => {
    let legacyLookups = 0
    const resolve = actualFunction('resolveRuntimeStorageDir', {
      runtimeConfig: { upgrade, legacyChannelLink: null },
      getStorageDir: () => '/dummy/evaluation-profile',
      getPearRuntimeLegacyStorage: () => { legacyLookups++; throw new Error('MUST NOT RUN') }
    })
    assert.equal(await resolve(), '/dummy/evaluation-profile')
    assert.equal(legacyLookups, 0)
  })
}
test('actual update IPC returns false without runtime', async () => {
  const handlers = new Map()
  const register = actualFunction('registerIPC', {
    ipcMain: { handle: (name, fn) => handlers.set(name, fn), on: () => {} },
    pearRuntime: null, logger: { info: () => {} }
  })
  register()
  assert.equal(await handlers.get('runtime:applyUpdate')(), false)
})
test('config and startup ordering retain guards', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'))
  assert.equal(pkg.productName, PRODUCT_NAME)
  assert.equal(pkg.upgrade, null); assert.equal(pkg.legacyChannelLink, null)
  assert.deepEqual(pkg.build.publish, [])
  const main = fs.readFileSync(path.join(ROOT, 'electron/main.cjs'), 'utf8')
  const configureAt = main.indexOf('configureEvaluationProfile(app, pkg, runtimeConfig)')
  assert.ok(configureAt !== -1 && configureAt < main.indexOf('= setupLogging('))
  for (const [name, command] of Object.entries(pkg.scripts)) {
    if (name.startsWith('dist:') || name.startsWith('pear:build:') || name === 'make') {
      assert.equal(command, 'node scripts/evaluation/block-release.mjs')
    }
  }
})
