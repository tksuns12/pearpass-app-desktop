// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs'
import { spawn } from 'node:child_process'
import { runPreflight, printReport } from './preflight.mjs'
try {
  const report = runPreflight()
  printReport(report)
  if (report.blocked) {
    console.error('EVALUATION_START_BLOCKED: resolve preflight blockers first. No packages were installed and no app was launched.')
    process.exitCode = 1
  } else {
    const npmCli = process.env.npm_execpath
    if (!npmCli || !fs.existsSync(npmCli)) throw new Error('Invoke using npm run dev:eval')
    console.error('DUMMY DATA ONLY. Not a production password manager; network isolation remains unverified.')
    const child = spawn(process.execPath, [npmCli, 'run', 'dev'], {
      stdio: 'inherit', shell: false,
      env: { ...process.env, LOCALVAULT_EVALUATION_ACK: 'dummy-data-only' }
    })
    child.on('error', (error) => { console.error(error.message); process.exitCode = 1 })
    child.on('exit', (code, signal) => { process.exitCode = code ?? (signal ? 1 : 0) })
  }
} catch (error) {
  console.error(`EVALUATION_START_BLOCKED: ${error.message}`)
  process.exitCode = 1
}
