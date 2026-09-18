// SPDX-License-Identifier: Apache-2.0
// Experimental, independently reviewable envelope. NOT HPKE or a production protocol.
// Node/OpenSSL primitives only; no npm installation or network I/O.
import {
  createHash, createPublicKey, generateKeyPairSync, diffieHellman, hkdfSync,
  randomBytes, createCipheriv, createDecipheriv, sign, verify
} from 'node:crypto'
import { PolicyError, identity, verifyEpoch, verifyEpochKey } from '../policy/signed-policy.mjs'
const fail = code => { throw new PolicyError(code) }
const hash = b => createHash('sha256').update(b).digest()
const bytes = fields => Buffer.from(JSON.stringify(fields), 'utf8')
const hex = (s, n) => typeof s === 'string' && s.length === n && /^[a-f0-9]+$/.test(s)
const SUITE = 'evaluation-X25519-HKDF-SHA256-AES256GCM-Ed25519-v1'
function exact(o, keys) {
  if (!o || Object.getPrototypeOf(o) !== Object.prototype ||
      Object.keys(o).sort().join(',') !== [...keys].sort().join(',')) fail('ENVELOPE_SCHEMA')
}
function pub(key, type) {
  const value = key?.type === 'public' ? key : createPublicKey(key)
  if (value.asymmetricKeyType !== type) fail('KEY_TYPE')
  return value
}
const exportX = key => pub(key, 'x25519').export({ type: 'spki', format: 'der' }).toString('hex')
function importX(encoded) {
  if (!hex(encoded, 88)) fail('X25519_ENCODING')
  const value = pub({ key: Buffer.from(encoded, 'hex'), type: 'spki', format: 'der' }, 'x25519')
  if (exportX(value) !== encoded) fail('X25519_ENCODING')
  return value
}
function seal(body, raw, privateKey) {
  if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') fail('SIGNING_KEY_REQUIRED')
  const signature = sign(null, raw, privateKey).toString('hex')
  return Object.freeze({ body: Object.freeze(body), signature,
    id: hash(Buffer.concat([raw, Buffer.from(signature, 'hex')])).toString('hex') })
}
function authenticate(e, raw, key) {
  exact(e, ['body', 'signature', 'id'])
  if (!hex(e.signature, 128) || !hex(e.id, 64)) fail('ENVELOPE_ENCODING')
  const sig = Buffer.from(e.signature, 'hex')
  if (hash(Buffer.concat([raw, sig])).toString('hex') !== e.id) fail('ENVELOPE_HASH')
  if (!verify(null, raw, pub(key, 'ed25519'), sig)) fail('ENVELOPE_SIGNATURE')
}
function deviceBytes(b) {
  exact(b, ['version', 'device', 'boxPublicKey'])
  if (b.version !== 1 || !hex(b.device, 64)) fail('DEVICE_SCHEMA')
  importX(b.boxPublicKey)
  return bytes(['local-vault/evaluation/device-box/1', b.device, b.boxPublicKey])
}
export const generateBoxKeys = () => generateKeyPairSync('x25519')
export function signDeviceBox(signingPrivateKey, boxPublicKey) {
  const body = { version: 1, device: identity(signingPrivateKey), boxPublicKey: exportX(boxPublicKey) }
  return seal(body, deviceBytes(body), signingPrivateKey)
}
// Both pins come from a trusted registration, not from the received message.
// This function verifies a binding; it does NOT perform QR approval or key possession.
export function verifyDeviceBox(document, pinnedSigningKey, pinnedDocumentId) {
  if (!hex(pinnedDocumentId, 64)) fail('DEVICE_PIN_REQUIRED')
  authenticate(document, deviceBytes(document?.body), pinnedSigningKey)
  if (document.body.device !== identity(pinnedSigningKey) || document.id !== pinnedDocumentId) fail('DEVICE_PIN_MISMATCH')
  return Object.freeze({ ...document, body: Object.freeze({ ...document.body }) })
}
function context(body) {
  return bytes([SUITE, body.epoch, body.recipient, body.deviceDocument, body.ephemeralPublicKey, body.nonce])
}
function envelopeBytes(b) {
  exact(b, ['version', 'epoch', 'recipient', 'deviceDocument', 'ephemeralPublicKey', 'nonce', 'ciphertext', 'tag'])
  if (b.version !== 1 || !hex(b.epoch, 64) || !hex(b.recipient, 64) || !hex(b.deviceDocument, 64) ||
      !hex(b.nonce, 24) || !hex(b.ciphertext, 64) || !hex(b.tag, 32)) fail('ENVELOPE_ENCODING')
  importX(b.ephemeralPublicKey)
  return bytes([SUITE, b.epoch, b.recipient, b.deviceDocument, b.ephemeralPublicKey, b.nonce, b.ciphertext, b.tag])
}
function approvedRecipient(epoch, document, signingKey, pin) {
  const device = verifyDeviceBox(document, signingKey, pin)
  if (!epoch.body.members.includes(device.body.device)) fail('DEVICE_REVOKED')
  return device
}
function derive(privateKey, publicKey, aad) {
  if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'x25519') fail('BOX_PRIVATE_KEY_REQUIRED')
  const shared = diffieHellman({ privateKey, publicKey })
  try {
    return Buffer.from(hkdfSync('sha256', shared, hash(aad), Buffer.from(SUITE + '/wrap-key'), 32))
  } finally { shared.fill(0) }
}
export function sealEpochKey({ epoch, key, adminPrivateKey, deviceDocument,
  deviceSigningPublicKey, pinnedDeviceDocumentId }) {
  verifyEpochKey(epoch, key, pub(adminPrivateKey, 'ed25519'))
  const device = approvedRecipient(epoch, deviceDocument, deviceSigningPublicKey, pinnedDeviceDocumentId)
  const ephemeral = generateBoxKeys()
  const body = { version: 1, epoch: epoch.id, recipient: device.body.device, deviceDocument: device.id,
    ephemeralPublicKey: exportX(ephemeral.publicKey), nonce: randomBytes(12).toString('hex') }
  const aad = context(body), wrappingKey = derive(ephemeral.privateKey, importX(device.body.boxPublicKey), aad)
  const plaintext = Buffer.from(key)
  try {
    const cipher = createCipheriv('aes-256-gcm', wrappingKey, Buffer.from(body.nonce, 'hex'))
    cipher.setAAD(aad)
    body.ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]).toString('hex')
    body.tag = cipher.getAuthTag().toString('hex')
    return seal(body, envelopeBytes(body), adminPrivateKey)
  } finally { plaintext.fill(0); wrappingKey.fill(0) }
}
export function verifyKeyEnvelope({ epoch, envelope, adminPublicKey, deviceDocument,
  deviceSigningPublicKey, pinnedDeviceDocumentId }) {
  verifyEpoch(epoch, adminPublicKey)
  const device = approvedRecipient(epoch, deviceDocument, deviceSigningPublicKey, pinnedDeviceDocumentId)
  authenticate(envelope, envelopeBytes(envelope?.body), adminPublicKey)
  if (envelope.body.epoch !== epoch.id || envelope.body.recipient !== device.body.device ||
      envelope.body.deviceDocument !== device.id) fail('ENVELOPE_CONTEXT')
  return Object.freeze({ ...envelope, body: Object.freeze({ ...envelope.body }) })
}
export function openEpochKey(options) {
  const { epoch, adminPublicKey, deviceDocument, boxPrivateKey } = options
  const envelope = verifyKeyEnvelope(options), body = envelope.body
  if (exportX(boxPrivateKey) !== deviceDocument.body.boxPublicKey) fail('RECIPIENT_KEY_MISMATCH')
  const aad = context(body), wrappingKey = derive(boxPrivateKey, importX(body.ephemeralPublicKey), aad)
  let unverified, plaintext
  try {
    const decipher = createDecipheriv('aes-256-gcm', wrappingKey, Buffer.from(body.nonce, 'hex'))
    decipher.setAAD(aad); decipher.setAuthTag(Buffer.from(body.tag, 'hex'))
    unverified = decipher.update(Buffer.from(body.ciphertext, 'hex'))
    plaintext = Buffer.concat([unverified, decipher.final()])
    verifyEpochKey(epoch, plaintext, adminPublicKey)
    return Buffer.from(plaintext)
  } finally { wrappingKey.fill(0); unverified?.fill(0); plaintext?.fill(0) }
}
