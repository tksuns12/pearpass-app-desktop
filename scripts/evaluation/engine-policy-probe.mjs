// SPDX-License-Identifier: Apache-2.0
// Characterization of the locked ENGINE, not the complete app's security verdict.
// Uses fake values, pre-provisioned keys and in-memory replication transports.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
const require = createRequire(import.meta.url)
const Autopass = require('autopass')
const Corestore = require('corestore')
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const reports = path.join(ROOT, '.evaluation-reports')
await mkdir(reports, { recursive: true })
const dir = await mkdtemp(path.join(reports, 'policy-'))
const peers = []
let streams = []
const result = { scope: 'locked Autopass engine only; not QR/UI/OS end-to-end',
  versions: Object.fromEntries(['autopass', 'autobase', 'corestore'].map(name => [name, require(name + '/package.json').version])) }
let exitCode = 0
function disconnect() { for (const stream of streams) stream.destroy(); streams = [] }
function connect(a, b) {
  const x = a.pass.base.replicate(true), y = b.pass.base.replicate(false)
  x.on('error', () => {}); y.on('error', () => {})
  streams = [x, y]; x.pipe(y).pipe(x)
}
async function wait(label, predicate, timeout = 10000) {
  const end = Date.now() + timeout
  let nextAck = 0
  do {
    await Promise.all(peers.map(p => p.pass.base.update()))
    if (await predicate()) return true
    if (Date.now() > nextAck) { for (const p of peers) await p.pass.base.ack(); nextAck = Date.now() + 250 }
    await sleep(25)
  } while (Date.now() < end)
  throw new Error('Timed out: ' + label)
}
async function open(name, opts = {}) {
  const store = new Corestore(path.join(dir, name))
  const pass = new Autopass(store, { ...opts, replicate: false })
  const peer = { store, pass }; peers.push(peer)
  await pass.ready(); assert.equal(pass.swarm, null)
  return peer
}
try {
  const a = await open('A')
  await a.pass.add('baseline', 'DUMMY_BASELINE')
  const b = await open('B', { key: a.pass.key, encryptionKey: a.pass.encryptionKey })
  connect(a, b)
  await a.pass.addWriter(b.pass.writerKey)
  await wait('membership setup', async () => b.pass.writable && (await b.pass.get('baseline'))?.value === 'DUMMY_BASELINE')
  disconnect()
  await a.pass.add('conflict', 'DUMMY_EDIT_A')
  await b.pass.add('conflict', 'DUMMY_EDIT_B')
  assert.notEqual((await a.pass.get('conflict')).value, (await b.pass.get('conflict')).value)
  connect(a, b)
  await wait('concurrent values converge', async () => (await a.pass.get('conflict')).value === (await b.pass.get('conflict')).value)
  const visible = await a.pass.get('conflict')
  result.concurrent_edit = { converged: true, current_view: visible,
    current_view_exposes_both_versions: false,
    history_erasure: 'NOT_TESTED', app_conflict_handling: 'NOT_TESTED',
    requirement_status: 'NEEDS_EXPLICIT_CONFLICT_POLICY' }
  const before = Buffer.from(a.pass.encryptionKey)
  await a.pass.removeWriter(b.pass.writerKey)
  await wait('B is no longer writable', () => !b.pass.writable)
  await a.pass.add('after-removal', 'DUMMY_CREATED_AFTER_WRITER_REMOVAL')
  let received = false
  try {
    await wait('removed writer receives later value', async () => (await b.pass.get('after-removal'))?.value === 'DUMMY_CREATED_AFTER_WRITER_REMOVAL', 5000)
    received = true
  } catch (error) {
    if (!error.message.startsWith('Timed out:')) throw error
  }
  result.writer_removal = { removed_peer_writable: b.pass.writable,
    base_encryption_key_changed: !before.equals(a.pass.encryptionKey),
    removed_peer_read_new_value: received,
    secrecy_revocation_requirement: received ? 'FAIL' : 'NOT_PROVEN',
    app_rekey_workflow: 'NOT_TESTED' }
  if (received) exitCode = 2 // Expected policy gap is NOT reported as success.
} catch (error) {
  result.error = error.message
  exitCode = 1
} finally {
  disconnect()
  for (const p of [...peers].reverse()) { await p.pass.close(); await p.store.close() }
  await rm(dir, { recursive: true, force: true })
}
result.exit_code = exitCode
await writeFile(path.join(reports, 'engine-policy.json'), JSON.stringify(result, null, 2) + '\n')
console.log(JSON.stringify(result, null, 2))
process.exitCode = exitCode
