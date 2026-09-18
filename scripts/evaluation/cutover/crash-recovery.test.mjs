// SPDX-License-Identifier: Apache-2.0
// Real process kills and reopened on-disk SQLite, NOT simulated exceptions.
// Does not model physical power loss, fsync lies, disk rollback, or Autopass migration.
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { fork } from 'node:child_process'
import { EpochJournal } from './epoch-journal.mjs'
import { fixture, materializerStub } from './test-fixture.mjs'
const worker = fileURLToPath(new URL('./crash-worker.mjs', import.meta.url))
function publicPem(key) { return key.export({type:'spki',format:'pem'}) }
async function runCrash(message) {
  return await new Promise((resolve, reject) => {
    const child = fork(worker, [], { stdio:['ignore','pipe','pipe','ipc'], execArgv:[] })
    let stdout='', stderr='', timedOut=false, fault
    child.stdout.on('data', data=>{stdout+=data})
    child.stderr.on('data', data=>{stderr+=data})
    child.on('message', data=>{fault=data})
    child.once('error', reject)
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL')},8000)
    child.once('close',(code,signal)=>{
      clearTimeout(timer)
      if(timedOut) reject(Error('Crash worker timed out'))
      else resolve({code,signal,stdout,stderr,fault})
    })
    child.send(message)
  })
}
for (const stage of ['prepare:before-commit','prepare:after-commit',
  'materialize:before-return','activate:before-commit','activate:after-commit',
  'enqueue:before-commit','enqueue:after-commit']) {
  test('SIGKILL recovery at '+stage, {timeout:15000}, async t=>{
    const f=fixture(), root=realpathSync(mkdtempSync(path.join(tmpdir(),'lv-real-crash-'))), directory=path.join(root,'state')
    const sessions=[]
    const open=(create=false)=>{
      const j=new EpochJournal({directory,create,genesis:f.genesis,trust:f.trust()});sessions.push(j);return j
    }
    t.after(()=>{for(const j of sessions)j.close();rmSync(root,{recursive:true,force:true})})
    const j=open(true)
    if(!stage.startsWith('prepare:')) j.prepare(f.next)
    if(stage.startsWith('enqueue:')) await j.resume(materializerStub)
    j.close()
    const trust=f.trust()
    const result=await runCrash({directory,genesis:f.genesis,next:f.next,stage,trust:{...trust,
      adminPublicKey:publicPem(trust.adminPublicKey),deviceSigningPublicKey:publicPem(trust.deviceSigningPublicKey),
      boxPrivateKey:trust.boxPrivateKey.export({type:'pkcs8',format:'pem'})}})
    assert.equal(result.signal,'SIGKILL')
    assert.equal(result.fault,undefined)
    assert.ok(result.stdout.includes('FAULT_BOUNDARY='+stage))
    const recovered=open(), state=recovered.snapshot()
    if(stage==='prepare:before-commit') {
      assert.equal(state.phase,'active')
      assert.equal(state.active.epoch.id,f.genesisEpoch.id)
      // Prepare did not commit, so no transition acknowledgement may have been sent.
      recovered.prepare(f.next)
    } else if(['prepare:after-commit','materialize:before-return','activate:before-commit'].includes(stage)) {
      assert.equal(state.phase,'prepared')
      assert.equal(state.active.epoch.id,f.genesisEpoch.id)
      assert.equal(state.pending.epoch.id,f.nextEpoch.id)
      assert.throws(()=>recovered.enqueue(f.genesisEpoch.id,Buffer.from('DUMMY')),e=>e.code==='CUTOVER_IN_PROGRESS')
    } else {
      assert.equal(state.phase,'active')
      assert.equal(state.active.epoch.id,f.nextEpoch.id)
    }
    if(stage.startsWith('enqueue:')) {
      assert.equal(recovered.outboxCounts().current,stage==='enqueue:after-commit'?1:0)
    }
    await recovered.resume(materializerStub)
    assert.equal(recovered.snapshot().active.epoch.id,f.nextEpoch.id)
    assert.throws(()=>recovered.enqueue(f.genesisEpoch.id,Buffer.from('DUMMY_OLD')),e=>e.code==='EPOCH_RETIRED')
    t.diagnostic('Reached named boundary; worker died by SIGKILL; reopened SQLite and checked epoch fence.')
  })
}
