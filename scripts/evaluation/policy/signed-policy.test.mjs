// SPDX-License-Identifier: Apache-2.0
// All keys and values in this suite are ephemeral test fixtures.
import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { RevisionLog, identity, signEpoch, verifyEpoch, acceptEpoch, keyCommitment,
  verifyEpochKey, signRevision } from './signed-policy.mjs'

function fixture() {
  const admin = generateKeyPairSync('ed25519')
  const peers = Array.from({ length: 3 }, () => generateKeyPairSync('ed25519'))
  const key = randomBytes(32), ids = peers.map(p => identity(p.publicKey))
  const epoch = signEpoch({ vault: 'DUMMY_VAULT', generation: 0,
    storageKey: randomBytes(32).toString('hex'), keyCommitment: keyCommitment(key), members: ids }, admin.privateKey)
  const makeLog = (e = epoch) => new RevisionLog(e, admin.publicKey, peers.map(p => p.publicKey))
  const revision = (peer, value, parents = [], record = 'DUMMY_RECORD', e = epoch, action = 'put') =>
    signRevision({ vault: e.body.vault, epoch: e.id, record, value, parents, action }, peers[peer].privateKey)
  const next = (overrides = {}, signer = admin.privateKey) => signEpoch({ vault: epoch.body.vault, generation: 1,
    previous: epoch.id, storageKey: randomBytes(32).toString('hex'), keyCommitment: keyCommitment(randomBytes(32)),
    members: ids.slice(0, 2), checkpoint: [], ...overrides }, signer)
  return { admin, peers, key, ids, epoch, makeLog, revision, next }
}
const rejected = (fn, code) => assert.throws(fn, error => error.code === code)

test('signed epoch roundtrip and key commitment', () => {
  const f = fixture()
  assert.deepEqual(verifyEpoch(JSON.parse(JSON.stringify(f.epoch)), f.admin.publicKey), f.epoch)
  assert.equal(verifyEpochKey(f.epoch, f.key, f.admin.publicKey), true)
  rejected(() => verifyEpochKey(f.epoch, randomBytes(32), f.admin.publicKey), 'WRONG_EPOCH_KEY')
})
test('remaining peer accepts next epoch; excluded peer does not', () => {
  const f = fixture(), next = f.next()
  assert.equal(acceptEpoch(f.epoch, next, f.admin.publicKey, f.ids[0]).id, next.id)
  rejected(() => acceptEpoch(f.epoch, next, f.admin.publicKey, f.ids[2]), 'DEVICE_REVOKED')
})
for (const [name, overrides, code] of [
  ['old key reuse', f => ({ keyCommitment: f.epoch.body.keyCommitment }), 'REKEY_REQUIRED'],
  ['old storage reuse', f => ({ storageKey: f.epoch.body.storageKey }), 'REKEY_REQUIRED'],
  ['skipped generation', () => ({ generation: 2 }), 'STALE_OR_FORKED_EPOCH'],
  ['forked predecessor', () => ({ previous: 'a'.repeat(64) }), 'STALE_OR_FORKED_EPOCH'],
  ['cross-vault', () => ({ vault: 'OTHER' }), 'WRONG_VAULT']
]) test('rejects ' + name, () => {
  const f = fixture()
  rejected(() => acceptEpoch(f.epoch, f.next(overrides(f)), f.admin.publicKey, f.ids[0]), code)
})
test('replayed old epoch cannot replace the accepted epoch', () => {
  const f = fixture(), next = f.next()
  rejected(() => acceptEpoch(next, f.epoch, f.admin.publicKey, f.ids[0]), 'STALE_OR_FORKED_EPOCH')
})
test('member cannot forge administrator transition', () => {
  const f = fixture()
  rejected(() => acceptEpoch(f.epoch, f.next({}, f.peers[0].privateKey), f.admin.publicKey, f.ids[0]), 'INVALID_SIGNATURE')
})
test('unsigned roster modification and unknown schema fields are rejected', () => {
  const f = fixture(), changed = structuredClone(f.epoch)
  changed.body.members = f.ids.slice(0, 1)
  rejected(() => verifyEpoch(changed, f.admin.publicKey), 'HASH_MISMATCH')
  rejected(() => verifyEpoch({ ...f.epoch, extra: true }, f.admin.publicKey), 'INVALID_SCHEMA')
})
test('causal edits preserve history, verify authors and deduplicate', () => {
  const f = fixture(), log = f.makeLog(), root = f.revision(0, 'DUMMY_0')
  assert.equal(log.ingest(root), true); assert.equal(log.ingest(root), false)
  log.ingest(f.revision(1, 'DUMMY_1', [root.id]))
  assert.equal(log.state('DUMMY_RECORD').status, 'ready')
  assert.equal(log.state('DUMMY_RECORD').versions[0].value, 'DUMMY_1')
  assert.equal(log.export().length, 2)
})
test('concurrent edits retain both values, even if equal', () => {
  for (const value of ['DUMMY_B', 'DUMMY_A']) {
    const f = fixture(), log = f.makeLog()
    log.ingest(f.revision(0, 'DUMMY_A')); log.ingest(f.revision(1, value))
    const state = log.state('DUMMY_RECORD')
    assert.equal(state.status, 'conflict'); assert.equal(state.versions.length, 2)
    assert.equal(Object.hasOwn(state, 'value'), false)
  }
})
test('delete/edit conflict and explicit resolution preserve tombstone and history', () => {
  const f = fixture(), log = f.makeLog(), root = f.revision(0, 'DUMMY_0')
  log.ingest(root)
  log.ingest(f.revision(0, null, [root.id], 'DUMMY_RECORD', f.epoch, 'delete'))
  log.ingest(f.revision(1, 'DUMMY_OFFLINE', [root.id]))
  assert.equal(log.state('DUMMY_RECORD').status, 'conflict')
  assert.ok(log.state('DUMMY_RECORD').versions.some(r => r.action === 'delete'))
  log.ingest(f.revision(0, 'DUMMY_CHOSEN', log.state('DUMMY_RECORD').heads))
  assert.equal(log.state('DUMMY_RECORD').status, 'ready')
  assert.equal(log.export().length, 4)
})
test('stale resolution does not hide a later-delivered concurrent edit', () => {
  const f = fixture(), log = f.makeLog(), a = f.revision(0, 'DUMMY_A'), b = f.revision(1, 'DUMMY_B')
  log.ingest(a); log.ingest(b)
  log.ingest(f.revision(0, 'DUMMY_RESOLUTION', log.state('DUMMY_RECORD').heads))
  log.ingest(f.revision(2, 'DUMMY_LATE'))
  assert.equal(log.state('DUMMY_RECORD').status, 'conflict')
})
test('missing parent blocks readiness until it arrives', () => {
  const f = fixture(), log = f.makeLog(), root = f.revision(0, 'DUMMY_0')
  log.ingest(f.revision(1, 'DUMMY_1', [root.id]))
  assert.equal(log.state('DUMMY_RECORD').status, 'incomplete')
  log.ingest(root)
  assert.equal(log.state('DUMMY_RECORD').status, 'ready')
})
test('cross-record parent cannot authorize a ready value', () => {
  const f = fixture(), log = f.makeLog(), other = f.revision(0, 'DUMMY_OTHER', [], 'OTHER')
  log.ingest(other); log.ingest(f.revision(1, 'DUMMY_1', [other.id]))
  assert.equal(log.state('DUMMY_RECORD').status, 'incomplete')
})
test('old epoch and revoked author changes rejected', () => {
  const f = fixture(), next = f.next(), log = f.makeLog(next)
  rejected(() => log.ingest(f.revision(0, 'DUMMY_OLD')), 'WRONG_EPOCH')
  rejected(() => log.ingest(f.revision(2, 'DUMMY_REVOKED', [], 'DUMMY_RECORD', next)), 'UNAUTHORIZED_AUTHOR')
})
test('tamper and caller mutation cannot change accepted history', () => {
  const f = fixture(), log = f.makeLog(), item = structuredClone(f.revision(0, 'DUMMY_0'))
  log.ingest(item); item.body.value = 'DUMMY_TAMPERED'
  rejected(() => log.ingest(item), 'HASH_MISMATCH')
  assert.equal(log.state('DUMMY_RECORD').versions[0].value, 'DUMMY_0')
})
test('retired local log refuses additional ingest', () => {
  const f = fixture(), log = f.makeLog(); log.retire()
  rejected(() => log.ingest(f.revision(0, 'DUMMY_0')), 'EPOCH_RETIRED')
})
test('parent duplicates and oversized payload rejected before signing', () => {
  const f = fixture()
  rejected(() => f.revision(0, 'DUMMY', ['a'.repeat(64), 'a'.repeat(64)]), 'IDS_NOT_SORTED_UNIQUE')
  rejected(() => f.revision(0, 'D'.repeat(32769)), 'VALUE_TOO_LARGE')
})
test('20 deterministic delivery permutations converge with duplicates', () => {
  const f = fixture(), root = f.revision(0, 'DUMMY_ROOT')
  const changes = [root, f.revision(0, 'DUMMY_A', [root.id]), f.revision(1, 'DUMMY_B', [root.id]),
    f.revision(2, null, [root.id], 'DUMMY_RECORD', f.epoch, 'delete')]
  let expected
  for (let seed = 1; seed <= 20; seed++) {
    let rng = seed; const order = changes.slice()
    for (let i = order.length - 1; i > 0; i--) {
      rng = (Math.imul(rng, 1664525) + 1013904223) >>> 0
      const j = rng % (i + 1); [order[i], order[j]] = [order[j], order[i]]
    }
    const log = f.makeLog()
    for (const r of [...order, ...order]) log.ingest(r)
    const state = log.state('DUMMY_RECORD')
    assert.equal(state.status, 'conflict')
    if (expected) assert.deepEqual(state, expected)
    else expected = state
  }
})
