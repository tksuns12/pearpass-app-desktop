// SPDX-License-Identifier: Apache-2.0
// These are fixture-level experiments, not app rekey or onboarding tests.
import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { createRequire } from 'node:module'
import { fixture, credentials, publish, readRevisions } from './engine-fixture.mjs'
import { RevisionLog, signEpoch, acceptEpoch, signRevision, identity, keyCommitment } from './signed-policy.mjs'
const require = createRequire(import.meta.url)
const { EncryptionView } = require('autobase/lib/encryption.js')
const keyPair = () => generateKeyPairSync('ed25519')
function manifest(peer, admin, members, generation = 0, previous = null) {
  return signEpoch({ vault: 'DUMMY_VAULT', generation, previous,
    storageKey: peer.pass.key.toString('hex'), keyCommitment: keyCommitment(peer.pass.encryptionKey),
    members: members.map(p => identity(p.publicKey)) }, admin.privateKey)
}
function revision(epoch, member, value, parents = []) {
  return signRevision({ vault: epoch.body.vault, epoch: epoch.id, record: 'DUMMY_RECORD', parents, value }, member.privateKey)
}

test('real engine persists both offline edits and explicit resolution without overwriting history', { timeout: 45000 }, async t => {
  const fx = await fixture(t), admin = keyPair(), members = [keyPair(), keyPair()]
  const a = await fx.open('A'), creds = credentials(a), epoch = manifest(a, admin, members)
  const root = revision(epoch, members[0], 'DUMMY_ROOT')
  await publish(a, root)
  let b = await fx.open('B', creds)
  let link = fx.connect(a, b)
  await a.pass.addWriter(b.pass.writerKey)
  await fx.eventually('B ready', [a, b], async () => b.pass.writable && !!await b.pass.get('revision/' + root.id))
  link.disconnect()
  const editA = revision(epoch, members[0], 'DUMMY_A', [root.id])
  const editB = revision(epoch, members[1], 'DUMMY_B', [root.id])
  await publish(a, editA); await publish(b, editB)
  link = fx.connect(a, b)
  await fx.eventually('both revisions replicated', [a, b], async () =>
    !!await a.pass.get('revision/' + editB.id) && !!await b.pass.get('revision/' + editA.id))
  const logA = await readRevisions(a, new RevisionLog(epoch, admin.publicKey, members.map(p => p.publicKey)))
  const logB = await readRevisions(b, new RevisionLog(epoch, admin.publicKey, members.map(p => p.publicKey)))
  assert.deepEqual(logA.state('DUMMY_RECORD'), logB.state('DUMMY_RECORD'))
  assert.equal(logA.state('DUMMY_RECORD').status, 'conflict')
  link.disconnect(); await fx.close(a); await fx.close(b)
  b = await fx.open('B', creds)
  const restored = await readRevisions(b, new RevisionLog(epoch, admin.publicKey, members.map(p => p.publicKey)))
  assert.equal(restored.state('DUMMY_RECORD').status, 'conflict')
  const resolved = revision(epoch, members[1], 'DUMMY_CHOSEN', restored.state('DUMMY_RECORD').heads)
  await publish(b, resolved)
  await readRevisions(b, restored)
  assert.equal(restored.state('DUMMY_RECORD').status, 'ready')
  assert.equal(restored.state('DUMMY_RECORD').versions[0].value, 'DUMMY_CHOSEN')
  assert.equal(restored.export().length, 4)
  assert.deepEqual(link.errors, [])
  t.diagnostic('Both signed versions survived B disk reopen; four revisions retained after resolution.')
})

test('fresh epoch key protects an actual replicated writer block against the old key', { timeout: 45000 }, async t => {
  const fx = await fixture(t), admin = keyPair(), members = [keyPair(), keyPair(), keyPair()]
  const oldA = await fx.open('OLD_A'), oldCredentials = credentials(oldA)
  const oldEpoch = manifest(oldA, admin, members)
  await oldA.pass.add('dummy', 'DUMMY_OLD')
  const revoked = await fx.open('REVOKED', oldCredentials)
  const oldLink = fx.connect(oldA, revoked)
  await oldA.pass.addWriter(revoked.pass.writerKey)
  await fx.eventually('revoked device once had legitimate access', [oldA, revoked], async () =>
    (await revoked.pass.get('dummy'))?.value === 'DUMMY_OLD')
  oldLink.disconnect()
  // Separate stores: never replace a key in an already-written log.
  const freshA = await fx.open('NEW_A'), freshCredentials = credentials(freshA)
  const next = manifest(freshA, admin, members.slice(0, 2), 1, oldEpoch.id)
  assert.notDeepEqual(freshCredentials.encryptionKey, oldCredentials.encryptionKey)
  acceptEpoch(oldEpoch, next, admin.publicKey, identity(members[1].publicKey))
  assert.throws(() => acceptEpoch(oldEpoch, next, admin.publicKey, identity(members[2].publicKey)), { code: 'DEVICE_REVOKED' })
  // Test-only trusted provisioning; this is NOT the production key-delivery protocol.
  const freshB = await fx.open('NEW_B', freshCredentials), newLink = fx.connect(freshA, freshB)
  await freshA.pass.addWriter(freshB.pass.writerKey)
  await fx.eventually('remaining peer admitted', [freshA, freshB], () => freshB.pass.writable)
  const marker = 'DUMMY_AFTER_C_REVOKED', change = revision(next, members[0], marker)
  await publish(freshA, change)
  await fx.eventually('new-key peer reads new revision', [freshA, freshB], async () =>
    !!await freshB.pass.get('revision/' + change.id))
  const log = await readRevisions(freshB, new RevisionLog(next, admin.publicKey, members.map(p => p.publicKey)))
  assert.equal(log.state('DUMMY_RECORD').versions[0].value, marker)
  // Deliberately give the old-key device ciphertext and all public core metadata.
  // Only the old vault key, not the new key, is used for this decoding attempt.
  const observer = revoked.store.get({ key: freshA.pass.writerKey, writable: false })
  await observer.ready()
  const wire = fx.connect(freshA, { store: revoked.store })
  const oldKeyProvider = new EncryptionView({ bootstrap: freshA.pass.base.bootstrap,
    encryptionKey: oldCredentials.encryptionKey }, null).getWriterEncryption()
  let examined = 0
  for (let index = 0; index < freshA.pass.base.local.length; index++) {
    const raw = await observer.get(index, { raw: true, timeout: 5000 })
    const source = await freshA.pass.base.local.get(index, { raw: true })
    assert.deepEqual(raw, source, 'Ciphertext actually arrived at the old-key store')
    if (observer.manifest.version > 1) {
      assert.equal(raw[0], 1, 'Versioned encryption required')
      assert.equal(raw.readUInt32LE(4), 0, 'Genesis encryption descriptor required')
    } else {
      assert.equal(oldKeyProvider.isCompat(observer.core), true)
    }
    const correct = Buffer.from(raw), wrong = Buffer.from(raw)
    await freshA.pass.base.getWriterEncryption().decrypt(index, correct, observer.core)
    await oldKeyProvider.decrypt(index, wrong, observer.core)
    if (correct.includes(Buffer.from(marker))) {
      examined++
      assert.equal(raw.includes(Buffer.from(marker)), false)
      assert.equal(wrong.includes(Buffer.from(marker)), false)
      assert.notDeepEqual(wrong, correct)
    }
  }
  assert.ok(examined > 0, 'Positive control found a real new revision payload')
  assert.deepEqual(wire.errors, []); assert.deepEqual(newLink.errors, [])
  wire.disconnect(); await observer.close()
  t.diagnostic('New-key peer read the revision; old-key attempt failed on the same received ciphertext.')
  t.diagnostic('Fixture provisioning only: no GUI, device key envelopes, migration, durable cutover or LAN tested.')
})
