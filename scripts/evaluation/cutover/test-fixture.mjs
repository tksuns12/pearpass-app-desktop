// SPDX-License-Identifier: Apache-2.0
// Dummy data and ephemeral keys ONLY. Never writes private fixture keys to disk.
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { identity, keyCommitment, signEpoch } from '../policy/signed-policy.mjs'
import { generateBoxKeys, signDeviceBox, sealEpochKey } from './key-envelope.mjs'
export function fixture() {
  const admin = generateKeyPairSync('ed25519')
  const devices = Array.from({ length: 3 }, () => {
    const signing = generateKeyPairSync('ed25519'), box = generateBoxKeys()
    const document = signDeviceBox(signing.privateKey, box.publicKey)
    return { signing, box, document, id: identity(signing.publicKey) }
  })
  const oldKey = randomBytes(32), newKey = randomBytes(32)
  const genesisEpoch = signEpoch({ vault: 'DUMMY_VAULT', generation: 0,
    storageKey: randomBytes(32).toString('hex'), keyCommitment: keyCommitment(oldKey),
    members: devices.map(d => d.id) }, admin.privateKey)
  const nextEpoch = signEpoch({ vault: 'DUMMY_VAULT', generation: 1, previous: genesisEpoch.id,
    storageKey: randomBytes(32).toString('hex'), keyCommitment: keyCommitment(newKey),
    members: devices.slice(0, 2).map(d => d.id) }, admin.privateKey)
  function entry(epoch, key, device = devices[1]) {
    return { epoch, envelope: sealEpochKey({ epoch, key, adminPrivateKey: admin.privateKey,
      deviceDocument: device.document, deviceSigningPublicKey: device.signing.publicKey,
      pinnedDeviceDocumentId: device.document.id }) }
  }
  function trust(device = devices[1]) {
    return { adminPublicKey: admin.publicKey, genesisId: genesisEpoch.id, vault: genesisEpoch.body.vault,
      deviceDocument: device.document, deviceSigningPublicKey: device.signing.publicKey,
      pinnedDeviceDocumentId: device.document.id, boxPrivateKey: device.box.privateKey }
  }
  const genesis = entry(genesisEpoch, oldKey), next = entry(nextEpoch, newKey)
  return { admin, devices, oldKey, newKey, genesisEpoch, nextEpoch, genesis, next, entry, trust }
}
// Journal-only fixture; not a real storage materializer or migration test.
export const materializerStub = async ({ epoch }) => ({ epoch: epoch.id,
  storageKey: epoch.body.storageKey, checkpoint: [...epoch.body.checkpoint] })
