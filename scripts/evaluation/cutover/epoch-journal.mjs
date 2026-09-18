// SPDX-License-Identifier: Apache-2.0
// Evaluation-only SQLite adapter (node:sqlite is experimental in Node 22).
// One local journal is authoritative for this API; it does not fence existing
// PearPass writers, network sends already in flight, or a restored whole disk.
import {
  mkdirSync, writeFileSync, lstatSync, readFileSync, realpathSync,
  openSync, closeSync, fsyncSync, constants
} from 'node:fs'
import path from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { randomBytes, createCipheriv, hkdfSync } from 'node:crypto'
import { PolicyError, identity, verifyEpoch, acceptEpoch } from '../policy/signed-policy.mjs'
import { verifyDeviceBox, verifyKeyEnvelope, openEpochKey } from './key-envelope.mjs'
const MARKER = 'local-vault/evaluation/epoch-journal/1\n'
const MAX_ENTRY_BYTES = 350000
const fail = code => { throw new PolicyError(code) }
const encode = value => JSON.stringify(value)
function exact(o, keys) {
  if (!o || Object.getPrototypeOf(o) !== Object.prototype ||
      Object.keys(o).sort().join(',') !== [...keys].sort().join(',')) fail('JOURNAL_SCHEMA')
}
function present(filename) {
  try { return lstatSync(filename) } catch (error) {
    if (error.code === 'ENOENT') return null
    throw error
  }
}
function privateFile(filename) {
  const st = lstatSync(filename)
  if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1 ||
      (st.mode & 0o077) || st.uid !== process.getuid()) fail('UNSAFE_JOURNAL_FILE')
}
function directory(filename, create) {
  if (!['linux', 'darwin'].includes(process.platform)) fail('UNVALIDATED_FILESYSTEM_PLATFORM')
  if (!path.isAbsolute(filename)) fail('ABSOLUTE_DIRECTORY_REQUIRED')
  if (create) {
    mkdirSync(filename, { mode: 0o700 }) // Exclusive; never adopt an existing folder.
    writeFileSync(path.join(filename, '.evaluation-journal'), MARKER, { flag: 'wx', mode: 0o600 })
  }
  const st = lstatSync(filename)
  if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o077) ||
      st.uid !== process.getuid() || realpathSync(filename) !== filename) fail('UNSAFE_JOURNAL_DIRECTORY')
  const marker = path.join(filename, '.evaluation-journal')
  privateFile(marker)
  if (readFileSync(marker, 'utf8') !== MARKER) fail('JOURNAL_MARKER')
  // Trusted same-user private directory required. This is not an OS sandbox
  // or a defence against a same-UID adversary swapping entries after this check.
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    const file = path.join(filename, 'epochs.sqlite' + suffix)
    if (present(file)) privateFile(file)
  }
  const database = path.join(filename, 'epochs.sqlite')
  if (create) closeSync(openSync(database, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600))
  else if (!present(database)) fail('MISSING_JOURNAL')
  return database
}

export class EpochJournal {
  #db; #trust; #binding; #checkpointHook; #closed = false
  constructor({ directory: location, create = false, genesis, trust, checkpointHook = () => {} }) {
    // Copy public inputs. Caller retains responsibility for private KeyObjects.
    const document = verifyDeviceBox(trust.deviceDocument, trust.deviceSigningPublicKey, trust.pinnedDeviceDocumentId)
    const initial = verifyEpoch(genesis.epoch, trust.adminPublicKey)
    if (initial.body.generation !== 0 || initial.id !== trust.genesisId ||
        !initial.body.members.includes(document.body.device)) fail('GENESIS_PIN_MISMATCH')
    this.#trust = { ...trust, deviceDocument: document }
    this.#checkpointHook = checkpointHook
    this.#binding = encode([1, initial.id, identity(trust.adminPublicKey), document.body.device, document.id])
    const database = directory(location, create)
    try {
      this.#db = new DatabaseSync(database)
      this.#db.exec('PRAGMA busy_timeout=1000; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;')
      if (this.#db.prepare('PRAGMA synchronous').get().synchronous !== 2 ||
          this.#db.prepare('PRAGMA journal_mode').get().journal_mode !== 'wal') fail('DURABILITY_SETTINGS')
      if (create) {
        this.#db.exec(`CREATE TABLE state (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL,
          active TEXT NOT NULL, pending TEXT
        ) STRICT;
        CREATE TABLE outbox (
          id TEXT PRIMARY KEY, epoch TEXT NOT NULL, sealed TEXT NOT NULL
        ) STRICT; PRAGMA user_version=1;`)
        const entry = this.#checked(genesis, true)
        this.#transaction('initialize', () => this.#db.prepare(
          'INSERT INTO state(singleton,binding,active,pending) VALUES (1,?,?,NULL)'
        ).run(this.#binding, encode(entry)))
        // fsync directory entries after initial DB/marker creation.
        const fd = openSync(location, constants.O_RDONLY)
        try { fsyncSync(fd) } finally { closeSync(fd) }
      } else if (this.#db.prepare('PRAGMA user_version').get().user_version !== 1) fail('JOURNAL_VERSION')
      this.snapshot()
    } catch (error) { this.#db?.close(); this.#closed = true; throw error }
  }
  #checked(entry, decrypt = false) {
    exact(entry, ['epoch', 'envelope'])
    if (Buffer.byteLength(encode(entry)) > MAX_ENTRY_BYTES) fail('JOURNAL_ENTRY_SIZE')
    const epoch = verifyEpoch(entry.epoch, this.#trust.adminPublicKey)
    const envelope = verifyKeyEnvelope({ ...this.#trust, epoch, envelope: entry.envelope })
    if (epoch.body.vault !== this.#trust.vault) fail('WRONG_VAULT')
    if (decrypt) {
      const key = openEpochKey({ ...this.#trust, epoch, envelope })
      key.fill(0)
    }
    return { epoch, envelope }
  }
  #row() {
    if (this.#closed) fail('JOURNAL_CLOSED')
    const row = this.#db.prepare('SELECT binding, active, pending FROM state WHERE singleton=1').get()
    if (!row || row.binding !== this.#binding) fail('JOURNAL_BINDING')
    if (row.active.length > MAX_ENTRY_BYTES || (row.pending?.length || 0) > MAX_ENTRY_BYTES) fail('JOURNAL_ENTRY_SIZE')
    const active = this.#checked(JSON.parse(row.active))
    const pending = row.pending === null ? null : this.#checked(JSON.parse(row.pending))
    if (pending) acceptEpoch(active.epoch, pending.epoch, this.#trust.adminPublicKey, this.#trust.deviceDocument.body.device)
    return { active, pending }
  }
  #transaction(name, fn) {
    if (this.#closed) fail('JOURNAL_CLOSED')
    this.#db.exec('BEGIN IMMEDIATE')
    let committed = false
    try {
      const result = fn()
      this.#checkpointHook(name + ':before-commit')
      this.#db.exec('COMMIT'); committed = true
      this.#checkpointHook(name + ':after-commit')
      return result
    } catch (error) {
      if (!committed) { try { this.#db.exec('ROLLBACK') } catch {} }
      throw error
    }
  }
  snapshot() {
    const { active, pending } = this.#row()
    return { phase: pending ? 'prepared' : 'active', active, pending }
  }
  prepare(next) {
    const candidate = this.#checked(next, true)
    return this.#transaction('prepare', () => {
      const { active, pending } = this.#row()
      if (active.epoch.id === candidate.epoch.id) return 'already-active'
      acceptEpoch(active.epoch, candidate.epoch, this.#trust.adminPublicKey, this.#trust.deviceDocument.body.device)
      if (pending) {
        if (pending.epoch.id !== candidate.epoch.id) fail('TRANSITION_ALREADY_PENDING')
        return 'already-prepared'
      }
      this.#db.prepare('UPDATE state SET pending=? WHERE singleton=1').run(encode(candidate))
      return 'prepared'
    })
  }
  // The materializer is a TRUSTED adapter: it must open the new encrypted store,
  // verify every checkpoint revision, flush it, and return this exact receipt.
  // A peer-provided boolean/receipt is NOT acceptable. No automatic abort-to-old.
  async resume(materializeAndVerify) {
    if (typeof materializeAndVerify !== 'function') fail('MATERIALIZER_REQUIRED')
    const start = this.#row()
    if (!start.pending) return 'already-active'
    const target = start.pending
    const key = openEpochKey({ ...this.#trust, ...target })
    let receipt
    try { receipt = await materializeAndVerify({ epoch: target.epoch, key }) }
    finally { key.fill(0) }
    exact(receipt, ['epoch', 'storageKey', 'checkpoint'])
    if (receipt.epoch !== target.epoch.id || receipt.storageKey !== target.epoch.body.storageKey ||
        encode(receipt.checkpoint) !== encode(target.epoch.body.checkpoint)) fail('CHECKPOINT_NOT_VERIFIED')
    return this.#transaction('activate', () => {
      const current = this.#row()
      if (current.active.epoch.id === target.epoch.id) return 'already-active'
      if (current.active.epoch.id !== start.active.epoch.id || current.pending?.epoch.id !== target.epoch.id) fail('TRANSITION_CHANGED')
      this.#db.prepare('UPDATE state SET active=pending,pending=NULL WHERE singleton=1').run()
      return 'activated'
    })
  }
  // Only this durable queue is fenced. Existing Corestore/API writes do not use
  // it yet. No transport dispatch is implemented; old outbox rows are retained.
  enqueue(expectedEpoch, plaintext) {
    if (!(plaintext instanceof Uint8Array) || plaintext.byteLength === 0 || plaintext.byteLength > 32768) fail('OUTBOX_PAYLOAD')
    return this.#transaction('enqueue', () => {
      const { active, pending } = this.#row()
      if (pending) fail('CUTOVER_IN_PROGRESS')
      if (active.epoch.id !== expectedEpoch) fail('EPOCH_RETIRED')
      if (this.#db.prepare('SELECT count(*) AS n FROM outbox').get().n >= 4096) fail('OUTBOX_LIMIT')
      const key = openEpochKey({ ...this.#trust, ...active })
      const purpose = Buffer.from('local-vault/evaluation/local-outbox/1')
      const dataKey = Buffer.from(hkdfSync('sha256', key, Buffer.from(expectedEpoch, 'hex'), purpose, 32))
      const id = randomBytes(32).toString('hex'), nonce = randomBytes(12)
      const aad = Buffer.from(encode(['local-vault/evaluation/local-outbox/1', expectedEpoch, id, this.#trust.deviceDocument.body.device]))
      try {
        const cipher = createCipheriv('aes-256-gcm', dataKey, nonce)
        cipher.setAAD(aad)
        const sealed = { nonce: nonce.toString('hex'),
          ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]).toString('hex'),
          tag: cipher.getAuthTag().toString('hex') }
        this.#db.prepare('INSERT INTO outbox(id,epoch,sealed) VALUES (?,?,?)').run(id, expectedEpoch, encode(sealed))
        return id
      } finally { key.fill(0); dataKey.fill(0) }
    })
  }
  outboxCounts() {
    const { active, pending } = this.#row()
    const current = this.#db.prepare('SELECT count(*) AS n FROM outbox WHERE epoch=?').get(active.epoch.id).n
    const total = this.#db.prepare('SELECT count(*) AS n FROM outbox').get().n
    return { current, quarantined: total - current, dispatchBlocked: !!pending }
  }
  close() {
    if (!this.#closed) { this.#db.close(); this.#closed = true }
  }
}
