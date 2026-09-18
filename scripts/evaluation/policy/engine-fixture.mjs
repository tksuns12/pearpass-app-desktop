// SPDX-License-Identifier: Apache-2.0
// Actual locked engine, separate disk stores, no Hyperswarm/network discovery.
import { createRequire } from 'node:module'
import { mkdtemp, mkdir, rm } from 'node:fs/promises'
import { setTimeout as sleep } from 'node:timers/promises'
import path from 'node:path'
const require = createRequire(import.meta.url)
const Autopass = require('autopass'), Corestore = require('corestore')
export async function fixture(t) {
  const reports = path.resolve('.evaluation-reports')
  await mkdir(reports, { recursive: true })
  const directory = await mkdtemp(path.join(reports, 'policy-engine-'))
  const peers = [], links = new Set()
  const versions = Object.fromEntries(['autopass', 'autobase', 'corestore', 'hypercore'].map(name =>
    [name, require(name + '/package.json').version]))
  const lock = require(path.resolve('package-lock.json'))
  for (const [name, version] of Object.entries(versions)) {
    if (version !== lock.packages['node_modules/' + name].version) throw Error('ENGINE_VERSION_MISMATCH')
  }
  async function open(name, options = {}) {
    const store = new Corestore(path.join(directory, name))
    const peer = { name, store, pass: new Autopass(store, { ...options, replicate: false }), closed: false }
    peers.push(peer); await peer.pass.ready()
    if (peer.pass.swarm !== null) throw Error('NETWORK_NOT_ALLOWED')
    return peer
  }
  async function close(peer) {
    if (peer.closed) return
    await peer.pass.close(); await peer.store.close(); peer.closed = true
  }
  function connect(a, b) {
    const left = (a.pass?.base || a.store).replicate(true)
    const right = (b.pass?.base || b.store).replicate(false)
    const link = { errors: [], closed: false, disconnect() {
      this.closed = true; left.destroy(); right.destroy(); links.delete(this)
    } }
    for (const s of [left, right]) s.on('error', e => { if (!link.closed) link.errors.push(e) })
    links.add(link); left.pipe(right).pipe(left); return link
  }
  async function eventually(label, active, predicate) {
    const deadline = Date.now() + 12000
    let ack = 0
    do {
      for (const peer of active) await peer.pass.base.update()
      if (await predicate()) return
      if (Date.now() > ack) {
        for (const peer of active) await peer.pass.base.ack()
        ack = Date.now() + 250
      }
      await sleep(20)
    } while (Date.now() < deadline)
    throw Error('TIMEOUT: ' + label)
  }
  t.after(async () => {
    for (const link of [...links]) link.disconnect()
    for (const peer of [...peers].reverse()) await close(peer)
    await rm(directory, { recursive: true, force: true })
  })
  return { open, close, connect, eventually, versions }
}
export const credentials = peer => ({ key: Buffer.from(peer.pass.key), encryptionKey: Buffer.from(peer.pass.encryptionKey) })
export async function publish(peer, revision) {
  await peer.pass.add('revision/' + revision.id, JSON.stringify(revision))
}
export async function readRevisions(peer, log) {
  for await (const row of peer.pass.list()) {
    if (!row.key.startsWith('revision/')) continue
    const r = JSON.parse(row.value)
    if (row.key !== 'revision/' + r.id) throw Error('REVISION_KEY_MISMATCH')
    log.ingest(r)
  }
  return log
}
