// SPDX-License-Identifier: Apache-2.0
// EXPERIMENTAL: not app-integrated, not a production wire format.
// Signatures authenticate policy. Autopass supplies data encryption.
import { createHash, createPublicKey, sign, verify } from 'node:crypto'
export class PolicyError extends Error {
  constructor(code) { super(code); this.name = 'PolicyError'; this.code = code }
}
const fail = code => { throw new PolicyError(code) }
const hex = (s, n = 64) => typeof s === 'string' && new RegExp(`^[0-9a-f]{${n}}$`).test(s)
const token = s => typeof s === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(s)
const digest = b => createHash('sha256').update(b).digest('hex')
const bytes = fields => Buffer.from(JSON.stringify(fields), 'utf8')
function exact(o, keys) {
  if (!o || Object.getPrototypeOf(o) !== Object.prototype ||
      Object.keys(o).sort().join(',') !== [...keys].sort().join(',')) fail('INVALID_SCHEMA')
}
function identifiers(items, max) {
  if (!Array.isArray(items) || items.length > max || items.some(x => !hex(x))) fail('INVALID_IDS')
  if (items.some((x, i) => i > 0 && items[i - 1] >= x)) fail('IDS_NOT_SORTED_UNIQUE')
}
function publicKey(key) {
  const pub = key?.type === 'public' ? key : createPublicKey(key)
  if (pub.asymmetricKeyType !== 'ed25519') fail('ED25519_REQUIRED')
  return pub
}
export function identity(key) {
  return digest(publicKey(key).export({ type: 'spki', format: 'der' }))
}
function freezeEnvelope(e) {
  for (const v of Object.values(e.body)) if (Array.isArray(v)) Object.freeze(v)
  Object.freeze(e.body)
  return Object.freeze(e)
}
function seal(body, encode, privateKey) {
  if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') fail('PRIVATE_KEY_REQUIRED')
  const raw = encode(body), signature = sign(null, raw, privateKey).toString('hex')
  return freezeEnvelope({ body, signature, id: digest(Buffer.concat([raw, Buffer.from(signature, 'hex')])) })
}
function authenticate(e, encode, key) {
  exact(e, ['body', 'signature', 'id'])
  if (!hex(e.signature, 128) || !hex(e.id)) fail('INVALID_ENVELOPE')
  const raw = encode(e.body), sig = Buffer.from(e.signature, 'hex')
  if (digest(Buffer.concat([raw, sig])) !== e.id) fail('HASH_MISMATCH')
  if (!verify(null, raw, publicKey(key), sig)) fail('INVALID_SIGNATURE')
}
function epochBytes(b) {
  exact(b, ['vault', 'generation', 'previous', 'admin', 'storageKey', 'keyCommitment', 'members', 'checkpoint'])
  if (!token(b.vault) || !Number.isSafeInteger(b.generation) || b.generation < 0 ||
      !hex(b.admin) || !hex(b.storageKey) || !hex(b.keyCommitment)) fail('INVALID_EPOCH')
  if (b.generation === 0 ? b.previous !== null : !hex(b.previous)) fail('INVALID_PREVIOUS')
  identifiers(b.members, 64); identifiers(b.checkpoint, 4096)
  if (!b.members.length || (b.generation === 0 && b.checkpoint.length)) fail('INVALID_EPOCH')
  return bytes(['local-vault/evaluation/epoch/1', b.vault, b.generation, b.previous,
    b.admin, b.storageKey, b.keyCommitment, b.members, b.checkpoint])
}
export function keyCommitment(key) {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) fail('KEY_LENGTH')
  return digest(Buffer.concat([Buffer.from('local-vault/evaluation/key/1\0'), Buffer.from(key)]))
}
export function signEpoch({ vault, generation, previous = null, storageKey, keyCommitment: commitment,
  members, checkpoint = [] }, adminPrivateKey) {
  return seal({ vault, generation, previous, admin: identity(adminPrivateKey), storageKey,
    keyCommitment: commitment, members: [...members].sort(), checkpoint: [...checkpoint].sort() }, epochBytes, adminPrivateKey)
}
export function verifyEpoch(e, pinnedAdminPublicKey) {
  authenticate(e, epochBytes, pinnedAdminPublicKey)
  if (e.body.admin !== identity(pinnedAdminPublicKey)) fail('UNTRUSTED_ADMIN')
  return freezeEnvelope(structuredClone(e))
}
export function acceptEpoch(current, next, pinnedAdminPublicKey, deviceId) {
  const old = verifyEpoch(current, pinnedAdminPublicKey), fresh = verifyEpoch(next, pinnedAdminPublicKey)
  if (old.body.vault !== fresh.body.vault) fail('WRONG_VAULT')
  if (fresh.body.generation !== old.body.generation + 1 || fresh.body.previous !== old.id) fail('STALE_OR_FORKED_EPOCH')
  if (fresh.body.storageKey === old.body.storageKey || fresh.body.keyCommitment === old.body.keyCommitment) fail('REKEY_REQUIRED')
  if (!fresh.body.members.includes(deviceId)) fail('DEVICE_REVOKED')
  return fresh
}
export function verifyEpochKey(epoch, key, pinnedAdminPublicKey) {
  verifyEpoch(epoch, pinnedAdminPublicKey)
  if (epoch.body.keyCommitment !== keyCommitment(key)) fail('WRONG_EPOCH_KEY')
  return true
}
function revisionBytes(b) {
  exact(b, ['vault', 'epoch', 'record', 'author', 'parents', 'action', 'value'])
  if (!token(b.vault) || !token(b.record) || !hex(b.epoch) || !hex(b.author)) fail('INVALID_REVISION')
  identifiers(b.parents, 128)
  if (!['put', 'delete'].includes(b.action)) fail('INVALID_ACTION')
  if (b.action === 'delete' ? b.value !== null : typeof b.value !== 'string') fail('INVALID_VALUE')
  if (typeof b.value === 'string' && Buffer.byteLength(b.value, 'utf8') > 32768) fail('VALUE_TOO_LARGE')
  return bytes(['local-vault/evaluation/revision/1', b.vault, b.epoch, b.record,
    b.author, b.parents, b.action, b.value])
}
export function signRevision({ vault, epoch, record, parents = [], action = 'put', value = null }, authorKey) {
  return seal({ vault, epoch, record, author: identity(authorKey), parents: [...parents].sort(), action, value }, revisionBytes, authorKey)
}
// Trusted epoch pins roster and signing keys. Storage/key delivery are outside this module.
export class RevisionLog {
  #epoch; #keys; #revisions = new Map(); #retired = false
  constructor(epoch, pinnedAdminPublicKey, memberPublicKeys) {
    this.#epoch = verifyEpoch(epoch, pinnedAdminPublicKey)
    this.#keys = new Map()
    for (const key of memberPublicKeys) {
      const pub = publicKey(key)
      this.#keys.set(identity(pub), pub)
    }
    if (this.#epoch.body.members.some(id => !this.#keys.has(id))) fail('MISSING_MEMBER_KEY')
  }
  get epoch() { return this.#epoch }
  get retired() { return this.#retired }
  retire() { this.#retired = true }
  ingest(envelope) {
    if (this.#retired) fail('EPOCH_RETIRED')
    const item = structuredClone(envelope)
    exact(item, ['body', 'signature', 'id'])
    revisionBytes(item.body)
    const b = item.body
    if (b.vault !== this.#epoch.body.vault || b.epoch !== this.#epoch.id) fail('WRONG_EPOCH')
    if (!this.#epoch.body.members.includes(b.author)) fail('UNAUTHORIZED_AUTHOR')
    authenticate(item, revisionBytes, this.#keys.get(b.author))
    if (this.#revisions.has(item.id)) return false
    if (this.#revisions.size >= 4096) fail('REVISION_LIMIT')
    this.#revisions.set(item.id, freezeEnvelope(item))
    return true
  }
  export() { return [...this.#revisions.values()].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0) }
  state(record) {
    if (!token(record)) fail('INVALID_RECORD')
    const nodes = new Map(this.export().filter(r => r.body.record === record).map(r => [r.id, r]))
    const counts = new Map(), children = new Map(), queue = [], accepted = new Set(), heads = new Set()
    for (const [id, r] of nodes) {
      counts.set(id, r.body.parents.length)
      if (!r.body.parents.length) queue.push(id)
      for (const p of r.body.parents) {
        if (!children.has(p)) children.set(p, [])
        children.get(p).push(id)
      }
    }
    // Missing/cross-record parents stay unresolved; never hide a conflict.
    for (let i = 0; i < queue.length; i++) {
      const id = queue[i], r = nodes.get(id)
      accepted.add(id); heads.add(id)
      for (const p of r.body.parents) heads.delete(p)
      for (const child of children.get(id) || []) {
        counts.set(child, counts.get(child) - 1)
        if (counts.get(child) === 0) queue.push(child)
      }
    }
    const pending = [...nodes.keys()].filter(id => !accepted.has(id)).sort()
    const ordered = [...heads].sort()
    const versions = ordered.map(id => {
      const b = nodes.get(id).body
      return Object.freeze({ id, author: b.author, action: b.action, value: b.value })
    })
    const status = pending.length ? 'incomplete' : ordered.length > 1 ? 'conflict' :
      ordered.length === 0 ? 'empty' : versions[0].action === 'delete' ? 'deleted' : 'ready'
    return Object.freeze({ status, heads: Object.freeze(ordered), versions: Object.freeze(versions), pending: Object.freeze(pending) })
  }
  #create(record, action, value, parents, key) {
    const revision = signRevision({ vault: this.#epoch.body.vault, epoch: this.#epoch.id, record,
      action, value, parents }, key)
    this.ingest(revision)
    return revision
  }
}

// Reference selector only: the app/extension does not call this module yet.
export function automaticValue(log, record) {
  if (!(log instanceof RevisionLog)) fail('INVALID_LOG')
  if (log.retired) fail('EPOCH_RETIRED')
  const state = log.state(record)
  if (state.status !== 'ready') fail('AUTOMATIC_USE_BLOCKED')
  return state.versions[0].value
}
