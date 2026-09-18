// SPDX-License-Identifier: Apache-2.0
import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { RevisionLog, signEpoch, signRevision, identity, keyCommitment, automaticValue } from './signed-policy.mjs'
function fixture() {
  const k = generateKeyPairSync('ed25519')
  const e = signEpoch({ vault: 'DUMMY', generation: 0, storageKey: 'a'.repeat(64),
    keyCommitment: keyCommitment(randomBytes(32)), members: [identity(k.publicKey)] }, k.privateKey)
  const log = new RevisionLog(e, k.publicKey, [k.publicKey])
  const add = (value, parents = [], action = 'put') => log.ingest(signRevision({
    vault: 'DUMMY', epoch: e.id, record: 'DUMMY', value, parents, action }, k.privateKey))
  return { log, add }
}
for (const state of ['empty', 'conflict', 'deleted', 'incomplete', 'retired']) {
  test('automatic use refuses ' + state, () => {
    const { log, add } = fixture()
    if (state === 'conflict') { add('DUMMY_A'); add('DUMMY_B') }
    if (state === 'deleted') add(null, [], 'delete')
    if (state === 'incomplete') add('DUMMY', ['f'.repeat(64)])
    if (state === 'retired') { add('DUMMY'); log.retire() }
    assert.throws(() => automaticValue(log, 'DUMMY'), {
      code: state === 'retired' ? 'EPOCH_RETIRED' : 'AUTOMATIC_USE_BLOCKED'
    })
  })
}
test('automatic use returns the only ready value', () => {
  const { log, add } = fixture(); add('DUMMY_READY')
  assert.equal(automaticValue(log, 'DUMMY'), 'DUMMY_READY')
})
