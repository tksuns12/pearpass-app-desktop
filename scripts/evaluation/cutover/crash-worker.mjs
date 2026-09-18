// SPDX-License-Identifier: Apache-2.0
// Child of crash-recovery.test.mjs ONLY. Kills only itself at an explicit test boundary.
// Dummy private keys arrive on IPC, never through argv, environment, files or logs.
import { createPublicKey, createPrivateKey } from 'node:crypto'
import { writeSync } from 'node:fs'
import { EpochJournal } from './epoch-journal.mjs'
import { materializerStub } from './test-fixture.mjs'
if (!process.send) throw Error('TEST_IPC_REQUIRED')
process.once('message', async message => {
  let journal
  try {
    const { directory, genesis, next, trust: wire, stage } = message
    const trust = { ...wire, adminPublicKey: createPublicKey(wire.adminPublicKey),
      deviceSigningPublicKey: createPublicKey(wire.deviceSigningPublicKey),
      boxPrivateKey: createPrivateKey(wire.boxPrivateKey) }
    const killAt = point => {
      if (point !== stage) return
      writeSync(1, 'FAULT_BOUNDARY=' + point + '\n')
      process.kill(process.pid, 'SIGKILL')
      throw Error('SIGKILL_FAILED')
    }
    journal = new EpochJournal({ directory, genesis, trust, checkpointHook: killAt })
    if (stage.startsWith('prepare:')) journal.prepare(next)
    else if (stage.startsWith('activate:') || stage.startsWith('materialize:')) {
      await journal.resume(async options => {
        killAt('materialize:before-return')
        return materializerStub(options)
      })
    } else if (stage.startsWith('enqueue:')) {
      journal.enqueue(next.epoch.id, Buffer.from('DUMMY_CRASH_OUTBOX_PAYLOAD'))
    } else throw Error('UNKNOWN_FAULT_BOUNDARY')
    throw Error('FAULT_NOT_REACHED')
  } catch (error) {
    // Codes only; do not include the message input or any keys in diagnostics.
    process.send({ error: error.code || 'WORKER_FAILURE' })
    journal?.close(); process.exitCode = 1; process.disconnect()
  }
})
