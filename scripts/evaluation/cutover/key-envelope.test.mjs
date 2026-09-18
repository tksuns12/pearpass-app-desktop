// SPDX-License-Identifier: Apache-2.0
import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, generateKeyPairSync, createHash, sign } from 'node:crypto'
import { openEpochKey, verifyKeyEnvelope, verifyDeviceBox, sealEpochKey, generateBoxKeys, signDeviceBox } from './key-envelope.mjs'
import { fixture } from './test-fixture.mjs'
const rejected = (fn, code) => assert.throws(fn, e => e.code === code)
function resign(envelope, key) {
  const b = envelope.body
  const raw = Buffer.from(JSON.stringify(['evaluation-X25519-HKDF-SHA256-AES256GCM-Ed25519-v1',
    b.epoch, b.recipient, b.deviceDocument, b.ephemeralPublicKey, b.nonce, b.ciphertext, b.tag]))
  envelope.signature = sign(null, raw, key).toString('hex')
  envelope.id = createHash('sha256').update(Buffer.concat([raw, Buffer.from(envelope.signature, 'hex')])).digest('hex')
  return envelope
}
test('approved recipient unwraps fresh epoch key', () => {
  const f = fixture(), received = JSON.parse(JSON.stringify(f.next))
  const opened = openEpochKey({ ...f.trust(), ...received })
  assert.deepEqual(opened, f.newKey); opened.fill(0)
})
test('same key produces distinct independently decryptable envelopes', () => {
  const f = fixture(), two = f.entry(f.nextEpoch, f.newKey)
  assert.notEqual(two.envelope.body.ephemeralPublicKey, f.next.envelope.body.ephemeralPublicKey)
  assert.notEqual(two.envelope.body.ciphertext, f.next.envelope.body.ciphertext)
  assert.deepEqual(openEpochKey({ ...f.trust(), ...two }), f.newKey)
})
test('nonrecipient cannot open the same unmodified ciphertext', () => {
  const f = fixture()
  rejected(() => openEpochKey({ ...f.trust(f.devices[0]), ...f.next }), 'ENVELOPE_CONTEXT')
  rejected(() => openEpochKey({ ...f.trust(), ...f.next, boxPrivateKey: f.devices[0].box.privateKey }), 'RECIPIENT_KEY_MISMATCH')
})
test('revoked device receives no next-generation envelope', () => {
  const f = fixture()
  rejected(() => f.entry(f.nextEpoch, f.newKey, f.devices[2]), 'DEVICE_REVOKED')
  rejected(() => openEpochKey({ ...f.trust(f.devices[2]), ...f.next }), 'DEVICE_REVOKED')
})
test('sender refuses a key that disagrees with the signed commitment', () => {
  const f = fixture()
  rejected(() => f.entry(f.nextEpoch, randomBytes(32)), 'WRONG_EPOCH_KEY')
})
test('unapproved replacement box key cannot substitute for a registered document', () => {
  const f = fixture(), d = f.devices[1]
  const replacement = signDeviceBox(d.signing.privateKey, generateBoxKeys().publicKey)
  rejected(() => verifyDeviceBox(replacement, d.signing.publicKey, d.document.id), 'DEVICE_PIN_MISMATCH')
  rejected(() => verifyDeviceBox(replacement, d.signing.publicKey, undefined), 'DEVICE_PIN_REQUIRED')
})
test('an outsider cannot impersonate an approved device signer', () => {
  const f = fixture()
  rejected(() => verifyDeviceBox(f.devices[1].document, f.devices[0].signing.publicKey, f.devices[1].document.id), 'ENVELOPE_SIGNATURE')
})
for (const field of ['epoch', 'recipient', 'deviceDocument', 'nonce', 'ciphertext', 'tag']) {
  test('unsigned modification rejected: ' + field, () => {
    const f = fixture(), envelope = structuredClone(f.next.envelope)
    const s = envelope.body[field]; envelope.body[field] = (s[0] === '0' ? '1' : '0') + s.slice(1)
    rejected(() => openEpochKey({ ...f.trust(), epoch: f.nextEpoch, envelope }), 'ENVELOPE_HASH')
  })
}
test('wrong administrator signature rejected even with recomputed envelope ID', () => {
  const f = fixture(), badAdmin = generateKeyPairSync('ed25519')
  const envelope = resign(structuredClone(f.next.envelope), badAdmin.privateKey)
  rejected(() => openEpochKey({ ...f.trust(), epoch: f.nextEpoch, envelope }), 'ENVELOPE_SIGNATURE')
})
test('valid sender signature does not bypass AEAD integrity', () => {
  const f = fixture(), envelope = structuredClone(f.next.envelope)
  envelope.body.tag = '0'.repeat(32); resign(envelope, f.admin.privateKey)
  assert.throws(() => openEpochKey({ ...f.trust(), epoch: f.nextEpoch, envelope }), /authenticate|authenticat/i)
})
test('epoch replay fails when presented with a different expected epoch', () => {
  const f = fixture()
  rejected(() => verifyKeyEnvelope({ ...f.trust(), epoch: f.nextEpoch, envelope: f.genesis.envelope }), 'ENVELOPE_CONTEXT')
})
for (const [label, modify, code] of [
  ['extra field', e => { e.body.extra = true }, 'ENVELOPE_SCHEMA'],
  ['version downgrade', e => { e.body.version = 0 }, 'ENVELOPE_ENCODING'],
  ['oversized ciphertext', e => { e.body.ciphertext += '00' }, 'ENVELOPE_ENCODING'],
  ['noncanonical hex', e => { e.body.ciphertext = 'FF'.repeat(32) }, 'ENVELOPE_ENCODING'],
  ['wrong public key type', e => { e.body.ephemeralPublicKey = generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'der'}).toString('hex') }, 'KEY_TYPE']
]) test('strict input validation: ' + label, () => {
  const f = fixture(), envelope = structuredClone(f.next.envelope); modify(envelope)
  rejected(() => openEpochKey({ ...f.trust(), epoch: f.nextEpoch, envelope }), code)
})
test('only public metadata and ciphertext are serialized', () => {
  const f = fixture(), text = JSON.stringify(f.next)
  for (const value of [f.newKey.toString('hex'), f.newKey.toString('base64'),
    f.devices[1].box.privateKey.export({ type:'pkcs8', format:'der' }).toString('hex')]) assert.equal(text.includes(value), false)
})
