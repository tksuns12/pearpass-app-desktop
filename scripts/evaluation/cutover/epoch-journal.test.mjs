// SPDX-License-Identifier: Apache-2.0
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, realpathSync, rmSync, readFileSync, readdirSync, chmodSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { signEpoch, keyCommitment } from '../policy/signed-policy.mjs'
import { EpochJournal } from './epoch-journal.mjs'
import { fixture, materializerStub } from './test-fixture.mjs'
const rejected = (fn, code) => assert.throws(fn, e => e.code === code)
function setup(t) {
  const f = fixture(), root = realpathSync(mkdtempSync(path.join(tmpdir(), 'lv-journal-test-')))
  const location = path.join(root, 'state'), sessions = []
  function open(create = false, overrides = {}) {
    const j = new EpochJournal({ directory: location, create, genesis: f.genesis, trust: f.trust(), ...overrides })
    sessions.push(j); return j
  }
  t.after(() => { for (const j of sessions) j.close(); rmSync(root, { recursive:true, force:true }) })
  return { ...f, root, location, open, j: open(true) }
}
test('prepare persists and denies both old and new writes until activation', t => {
  const f = setup(t)
  f.j.enqueue(f.genesisEpoch.id, Buffer.from('DUMMY_BEFORE'))
  assert.equal(f.j.prepare(f.next), 'prepared')
  assert.equal(f.j.snapshot().phase, 'prepared')
  rejected(() => f.j.enqueue(f.genesisEpoch.id, Buffer.from('DUMMY_OLD')), 'CUTOVER_IN_PROGRESS')
  rejected(() => f.j.enqueue(f.nextEpoch.id, Buffer.from('DUMMY_NEW')), 'CUTOVER_IN_PROGRESS')
  f.j.close(); const reopened = f.open()
  assert.equal(reopened.snapshot().pending.epoch.id, f.nextEpoch.id)
  rejected(() => reopened.enqueue(f.genesisEpoch.id, Buffer.from('DUMMY_OLD')), 'CUTOVER_IN_PROGRESS')
})
test('activation persists; old generation stays retired after reopen', async t => {
  const f = setup(t)
  f.j.enqueue(f.genesisEpoch.id, Buffer.from('DUMMY_BEFORE'))
  f.j.prepare(f.next)
  assert.equal(await f.j.resume(materializerStub), 'activated')
  f.j.close(); const reopened = f.open()
  assert.equal(reopened.snapshot().active.epoch.id, f.nextEpoch.id)
  rejected(() => reopened.enqueue(f.genesisEpoch.id, Buffer.from('DUMMY_OLD')), 'EPOCH_RETIRED')
  reopened.enqueue(f.nextEpoch.id, Buffer.from('DUMMY_NEW'))
  assert.deepEqual(reopened.outboxCounts(), {current:1,quarantined:1,dispatchBlocked:false})
})
test('repeat prepare and resume are idempotent without another generation', async t => {
  const f = setup(t)
  assert.equal(f.j.prepare(f.next), 'prepared')
  assert.equal(f.j.prepare(f.next), 'already-prepared')
  await f.j.resume(materializerStub)
  assert.equal(f.j.prepare(f.next), 'already-active')
  assert.equal(await f.j.resume(async () => { throw Error('must not run') }), 'already-active')
  assert.equal(f.j.snapshot().active.epoch.body.generation, 1)
})
test('materializer failure leaves durable prepared state, never returns to old writes', async t => {
  const f = setup(t); f.j.prepare(f.next)
  await assert.rejects(f.j.resume(async () => { throw Error('storage unavailable') }), /storage unavailable/)
  f.j.close(); const reopened = f.open()
  assert.equal(reopened.snapshot().phase, 'prepared')
  rejected(() => reopened.enqueue(f.genesisEpoch.id, Buffer.from('DUMMY')), 'CUTOVER_IN_PROGRESS')
  assert.equal(await reopened.resume(materializerStub), 'activated')
})
test('mismatched storage receipt cannot activate', async t => {
  const f = setup(t); f.j.prepare(f.next)
  await assert.rejects(f.j.resume(async ({epoch}) => ({epoch:epoch.id,storageKey:'a'.repeat(64),checkpoint:[]})), e => e.code === 'CHECKPOINT_NOT_VERIFIED')
  assert.equal(f.j.snapshot().phase, 'prepared')
})
test('a missing checkpoint is rejected even for correct target storage', async t => {
  const f = setup(t), key = randomBytes(32)
  const epoch = signEpoch({ ...f.nextEpoch.body, keyCommitment:keyCommitment(key), checkpoint:['b'.repeat(64)] }, f.admin.privateKey)
  const next = f.entry(epoch, key); f.j.prepare(next)
  await assert.rejects(f.j.resume(async ({epoch:e}) => ({epoch:e.id,storageKey:e.body.storageKey,checkpoint:[]})), e => e.code === 'CHECKPOINT_NOT_VERIFIED')
  assert.equal(f.j.snapshot().phase, 'prepared')
})
test('unwrapping key is wiped after materializer success and failure', async t => {
  const f = setup(t); f.j.prepare(f.next)
  let borrowed
  await assert.rejects(f.j.resume(async ({key}) => {borrowed=key; throw Error('failure')}))
  assert.deepEqual(borrowed, Buffer.alloc(32))
  await f.j.resume(async options => {borrowed=options.key; assert.deepEqual(borrowed, f.newKey); return materializerStub(options)})
  assert.deepEqual(borrowed, Buffer.alloc(32))
})
test('concurrent connections cannot use a cached old epoch or branch a pending transition', async t => {
  const f = setup(t), second = f.open()
  f.j.prepare(f.next)
  rejected(() => second.enqueue(f.genesisEpoch.id, Buffer.from('DUMMY')), 'CUTOVER_IN_PROGRESS')
  const key = randomBytes(32)
  const other = signEpoch({...f.nextEpoch.body,storageKey:randomBytes(32).toString('hex'),keyCommitment:keyCommitment(key)}, f.admin.privateKey)
  rejected(() => second.prepare(f.entry(other,key)), 'TRANSITION_ALREADY_PENDING')
  await second.resume(materializerStub)
  rejected(() => f.j.enqueue(f.genesisEpoch.id, Buffer.from('DUMMY')), 'EPOCH_RETIRED')
})
test('two materializers race without reverting or activating different epochs', async t => {
  const f = setup(t), second = f.open(); f.j.prepare(f.next)
  let resolve
  const delayed = f.j.resume(options => new Promise(r => { resolve = () => r(materializerStub(options)) }))
  assert.equal(await second.resume(materializerStub),'activated')
  resolve(); assert.equal(await delayed, 'already-active')
  assert.equal(f.j.snapshot().active.epoch.id, f.nextEpoch.id)
})
test('stale signed epoch cannot roll the active state backward', async t => {
  const f = setup(t); f.j.prepare(f.next); await f.j.resume(materializerStub)
  rejected(() => f.j.prepare(f.genesis), 'STALE_OR_FORKED_EPOCH')
})
test('tampered envelope does not freeze a healthy current epoch', t => {
  const f = setup(t), next = structuredClone(f.next)
  next.envelope.body.tag = '0'.repeat(32)
  rejected(() => f.j.prepare(next), 'ENVELOPE_HASH')
  assert.equal(f.j.snapshot().phase,'active')
  f.j.enqueue(f.genesisEpoch.id,Buffer.from('DUMMY_STILL_CURRENT'))
})
test('journal on disk contains neither raw key nor queued plaintext', t => {
  const f = setup(t), plaintext=Buffer.from('DUMMY_PLAINTEXT_SHOULD_NOT_APPEAR_ON_DISK_1263')
  f.j.enqueue(f.genesisEpoch.id,plaintext); f.j.prepare(f.next)
  for(const name of readdirSync(f.location)) {
    const raw=readFileSync(path.join(f.location,name))
    for(const secret of [plaintext,f.oldKey,f.newKey,Buffer.from(f.oldKey.toString('hex')),Buffer.from(f.newKey.toString('base64'))]) {
      assert.equal(raw.includes(secret),false, name+' contains unwrapped secret')
    }
  }
})
test('cross-device opening is rejected by the persistent binding', t => {
  const f=setup(t)
  const otherGenesis=f.entry(f.genesisEpoch,f.oldKey,f.devices[0])
  rejected(() => f.open(false,{genesis:otherGenesis,trust:f.trust(f.devices[0])}), 'JOURNAL_BINDING')
})
test('missing DB never silently reinitializes an existing profile', t => {
  const f=setup(t); f.j.close(); rmSync(path.join(f.location,'epochs.sqlite'))
  rejected(() => f.open(), 'MISSING_JOURNAL')
})
test('existing directory cannot be adopted with create=true', t => {
  const f=setup(t)
  assert.throws(()=>f.open(true), e=>e.code==='EEXIST')
})
test('directory and database symlinks fail closed', t => {
  const f=setup(t); f.j.close()
  const link=path.join(f.root,'alias');symlinkSync(f.location,link)
  rejected(()=>f.open(false,{directory:link}),'UNSAFE_JOURNAL_DIRECTORY')
  rmSync(path.join(f.location,'epochs.sqlite'))
  const target=path.join(f.root,'other');writeFileSync(target,'not sqlite',{mode:0o600})
  symlinkSync(target,path.join(f.location,'epochs.sqlite'))
  rejected(()=>f.open(),'UNSAFE_JOURNAL_FILE')
})
test('world-readable existing database rejected', t => {
  const f=setup(t); f.j.close(); chmodSync(path.join(f.location,'epochs.sqlite'),0o644)
  rejected(()=>f.open(),'UNSAFE_JOURNAL_FILE')
})
test('damaged persisted signed state does not recover to genesis', t => {
  const f=setup(t); f.j.close(); const db = new DatabaseSync(path.join(f.location,'epochs.sqlite'))
  const bad=structuredClone(f.genesis);bad.epoch.body.storageKey='0'.repeat(64)
  db.prepare('UPDATE state SET active=?').run(JSON.stringify(bad));db.close()
  rejected(()=>f.open(),'HASH_MISMATCH')
})
