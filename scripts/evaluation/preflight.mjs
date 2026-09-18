// SPDX-License-Identifier: Apache-2.0
// Read-only checks. Never installs packages, opens vaults, or starts a network service.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const readJSON = (name) => JSON.parse(fs.readFileSync(path.join(ROOT, name), 'utf8'))
export function runPreflight() {
  const pkg = readJSON('package.json')
  const baseline = readJSON('docs/evaluation/upstream-baseline.json')
  const original = baseline.repositories.find((r) => r.name === 'pearpass-app-desktop')
  const lock = readJSON('package-lock.json')
  const checks = []
  const add = (id, status, detail) => checks.push({ id, status, detail })
  const required = fs.readFileSync(path.join(ROOT, '.nvmrc'), 'utf8').trim()
  const wanted = required.split('.').map(Number)
  const actual = process.versions.node.split('.').map(Number)
  const supported = actual[0] === wanted[0] && (actual[1] > wanted[1] || (actual[1] === wanted[1] && actual[2] >= wanted[2]))
  add('NODE_BASELINE', supported ? 'PASS' : 'BLOCKED', `actual=${process.versions.node}; upstream=${required}; same-major >= baseline required; select a reviewed patched runtime`)
  const hash = createHash('sha256').update(fs.readFileSync(path.join(ROOT, 'package-lock.json'))).digest('hex')
  add('LOCKFILE_UNCHANGED', hash === original.lockfile_sha256 ? 'PASS' : 'BLOCKED', hash)
  const dependencyKeys = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'overrides']
  const unchanged = dependencyKeys.every((key) => JSON.stringify(pkg[key] || {}) === JSON.stringify(original.dependency_declarations[key] || {}))
  add('DEPENDENCIES_UNCHANGED', unchanged ? 'PASS' : 'BLOCKED', 'No dependency upgrade is part of this bootstrap')
  const channelsOff = !pkg.upgrade && !pkg.legacyChannelLink && Array.isArray(pkg.build?.publish) && pkg.build.publish.length === 0
  add('UPSTREAM_OTA_OFF', channelsOff ? 'PASS' : 'BLOCKED', 'App OTA channels and package publish targets must be empty')
  const releaseScripts = Object.entries(pkg.scripts).filter(([key]) => key.startsWith('dist:') || key.startsWith('pear:build:') || key === 'make')
  add('RELEASE_SCRIPTS_BLOCKED', releaseScripts.length > 0 && releaseScripts.every(([, value]) => value === 'node scripts/evaluation/block-release.mjs') ? 'PASS' : 'BLOCKED', 'Supported package/release scripts must fail closed')
  const missing = ['node_modules/electron/package.json', 'node_modules/@tetherto/pearpass-lib-vault-core/package.json'].filter((name) => !fs.existsSync(path.join(ROOT, name)))
  add('DEPENDENCIES_PRESENT', missing.length ? 'BLOCKED' : 'PASS', missing.length ? `not installed: ${missing.join(', ')}` : 'Presence only, not native-binary or runtime verification')
  const core = lock.packages?.['node_modules/@tetherto/pearpass-lib-vault-core']?.resolved || ''
  const head = baseline.repositories.find((r) => r.name === 'pearpass-lib-vault-core').commit
  add('CORE_BASELINE_DIVERGENCE', core.endsWith(`#${head}`) ? 'PASS' : 'REVIEW', `app lock=${core.split('#').at(-1)}; fork main=${head}; do not silently substitute`)
  add('NETWORK_ISOLATION', 'NOT_RUN', 'Disabling OTA is NOT proof of LAN-only or zero external infrastructure')
  for (const [id, status] of Object.entries(baseline.integration_gates)) add(id, status, 'Requires actual app/core integration tests; not covered by profile unit tests')
  return { schema_version: 1, scope: 'evaluation-bootstrap', node: process.versions.node, checks, blocked: checks.some((c) => c.status === 'BLOCKED') }
}
export function printReport(report) {
  for (const c of report.checks) console.log(`[${c.status}] ${c.id}: ${c.detail}`)
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = runPreflight()
    if (process.argv.includes('--json')) console.log(JSON.stringify(report, null, 2))
    else printReport(report)
    process.exitCode = report.blocked ? 1 : 0
  } catch (error) {
    console.error(`PREFLIGHT_ERROR: ${error.message}`)
    process.exitCode = 2
  }
}
