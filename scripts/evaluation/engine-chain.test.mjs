// SPDX-License-Identifier: Apache-2.0
// Real, locked Autopass/Corestore storage and replication; only the transport is
// an in-process duplex connection. Keys/membership are provisioned by the fixture.
// This does NOT test QR approval, NAT traversal, OS backgrounding or revocation.
import test from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdtemp, mkdir, rm } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as sleep } from 'node:timers/promises'
const require = createRequire(import.meta.url)
const Autopass = require('autopass')
const Corestore = require('corestore')
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const lock = require(path.join(ROOT, 'package-lock.json'))

async function eventually(label, peers, predicate, timeout = 12000) {
  const deadline = Date.now() + timeout
  let nextAck = 0
  do {
    await Promise.all(peers.filter(p => !p.closed).map(p => p.pass.base.update()))
    if (await predicate()) return
    if (Date.now() > nextAck) {
      for (const p of peers.filter(p => !p.closed)) await p.pass.base.ack()
      nextAck = Date.now() + 250
    }
    await sleep(25)
  } while (Date.now() < deadline)
  throw new Error('Timed out: ' + label)
}

test('locked engine relays A→B→C after A closes and B restarts; reverse relay survives C close', { timeout: 55000 }, async t => {
  for (const name of ['autopass', 'autobase', 'corestore', 'hypercore']) {
    const actual = require(name + '/package.json').version
    assert.equal(actual, lock.packages['node_modules/' + name].version)
    t.diagnostic(name + '=' + actual)
  }
  const reports = path.join(ROOT, '.evaluation-reports')
  await mkdir(reports, { recursive: true })
  const directory = await mkdtemp(path.join(reports, 'chain-'))
  const peers = []
  const links = new Set()
  const history = []
  async function open(name, fixture = {}) {
    const store = new Corestore(path.join(directory, name))
    const pass = new Autopass(store, { ...fixture, replicate: false })
    const peer = { name, store, pass, closed: false }
    peers.push(peer)
    await pass.ready()
    assert.equal(pass.swarm, null, 'No Hyperswarm instance in this experiment')
    return peer
  }
  async function close(peer) {
    if (peer.closed) return
    await peer.pass.close()
    await peer.store.close()
    peer.closed = true
  }
  function connect(a, b) {
    assert.ok(!a.closed && !b.closed)
    const pair = [a.name, b.name].sort().join('-')
    assert.ok(['A-B', 'B-C'].includes(pair), 'Direct A-C connection is forbidden')
    const left = a.pass.base.replicate(true)
    const right = b.pass.base.replicate(false)
    const errors = []
    left.on('error', e => { if (!link.closed) errors.push(e.message) })
    right.on('error', e => { if (!link.closed) errors.push(e.message) })
    const link = { pair, closed: false, errors,
      disconnect() {
        if (this.closed) return
        this.closed = true
        left.destroy()
        right.destroy()
        links.delete(this)
      }
    }
    links.add(link)
    history.push(pair)
    left.pipe(right).pipe(left)
    return link
  }
  t.after(async () => {
    for (const link of [...links]) link.disconnect()
    for (const peer of [...peers].reverse()) await close(peer)
    await rm(directory, { recursive: true, force: true })
  })
  const a = await open('A')
  await a.pass.add('fixture', 'DUMMY_FIXTURE')
  const fixture = { key: Buffer.from(a.pass.key), encryptionKey: Buffer.from(a.pass.encryptionKey) }
  let b = await open('B', fixture)
  const ab = connect(a, b)
  await a.pass.addWriter(b.pass.writerKey)
  await eventually('B writer admitted', [a, b], () => b.pass.writable)
  const c = await open('C', fixture)
  await a.pass.addWriter(c.pass.writerKey)
  const bcSetup = connect(b, c)
  await eventually('C writer and fixture arrive through B', [a, b, c], async () => c.pass.writable && (await c.pass.get('fixture'))?.value === 'DUMMY_FIXTURE')
  bcSetup.disconnect()
  await a.pass.add('chain-secret', 'DUMMY_FROM_A_NOT_A_PASSWORD')
  await eventually('B receives A edit', [a, b], async () => (await b.pass.get('chain-secret'))?.value === 'DUMMY_FROM_A_NOT_A_PASSWORD')
  assert.equal(await c.pass.get('chain-secret'), null)
  ab.disconnect()
  await close(a)
  await close(b)
  b = await open('B', fixture)
  assert.equal((await b.pass.get('chain-secret'))?.value, 'DUMMY_FROM_A_NOT_A_PASSWORD')
  const bc = connect(b, c)
  await eventually('C receives persisted A edit from restarted B', [b, c], async () => (await c.pass.get('chain-secret'))?.value === 'DUMMY_FROM_A_NOT_A_PASSWORD')
  assert.equal(a.closed, true)
  t.diagnostic('PASS: A closed, B reopened from disk, C received A edit through B only')
  await c.pass.add('reverse-secret', 'DUMMY_FROM_C_NOT_A_PASSWORD')
  await eventually('B receives C edit', [b, c], async () => (await b.pass.get('reverse-secret'))?.value === 'DUMMY_FROM_C_NOT_A_PASSWORD')
  bc.disconnect()
  await close(c)
  const aRestored = await open('A', fixture)
  assert.equal(await aRestored.pass.get('reverse-secret'), null)
  const abReverse = connect(aRestored, b)
  await eventually('A receives C edit through B', [aRestored, b], async () => (await aRestored.pass.get('reverse-secret'))?.value === 'DUMMY_FROM_C_NOT_A_PASSWORD')
  assert.equal(c.closed, true)
  assert.ok(history.every(pair => pair !== 'A-C'))
  assert.deepEqual(ab.errors, [])
  assert.deepEqual(bcSetup.errors, [])
  assert.deepEqual(bc.errors, [])
  assert.deepEqual(abReverse.errors, [])
  t.diagnostic('PASS: reverse C→B→A after C closed; no A-C stream was ever created')
})
