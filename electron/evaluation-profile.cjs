/* Independent evaluation addition, 2026-09-18. SPDX-License-Identifier: Apache-2.0 */
const fs = require('node:fs')
const path = require('node:path')
const PRODUCT_NAME = 'Local Vault Evaluation'
const DIRECTORY_NAME = 'LocalVault-Evaluation-tksuns12'
const MARKER_NAME = '.localvault-evaluation-profile'
const MARKER = 'localvault-evaluation-profile-v1\n'
function assertRealDirectory(directory) {
  const stat = fs.lstatSync(directory)
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('EVALUATION_UNSAFE_PROFILE: expected a non-symlink directory')
  }
}
// Accidental-data-mixing guard; NOT an operating-system or network sandbox.
function configureEvaluationProfile(app, pkg, runtimeConfig, env = process.env) {
  if (env.LOCALVAULT_EVALUATION_ACK !== 'dummy-data-only') {
    throw new Error('EVALUATION_CONSENT_REQUIRED: use npm run dev:eval; dummy data only')
  }
  if (app.isPackaged) throw new Error('EVALUATION_RELEASE_BLOCKED')
  if (pkg.productName !== PRODUCT_NAME) throw new Error('EVALUATION_IDENTITY_MISMATCH')
  if (pkg.upgrade || pkg.legacyChannelLink || runtimeConfig.upgrade || runtimeConfig.legacyChannelLink) {
    throw new Error('EVALUATION_UPSTREAM_CHANNEL: OTA and legacy storage must be disabled')
  }
  const appData = app.getPath('appData')
  if (!path.isAbsolute(appData)) throw new Error('EVALUATION_INVALID_APP_DATA_PATH')
  const profile = path.join(appData, DIRECTORY_NAME)
  let created = false
  try { fs.mkdirSync(profile, { mode: 0o700 }); created = true } catch (error) {
    if (error.code !== 'EEXIST') throw error
  }
  assertRealDirectory(profile)
  const marker = path.join(profile, MARKER_NAME)
  if (created) {
    fs.writeFileSync(marker, MARKER, { flag: 'wx', mode: 0o600 })
  } else {
    let stat
    try { stat = fs.lstatSync(marker) } catch { throw new Error('EVALUATION_UNOWNED_PROFILE') }
    if (stat.isSymbolicLink() || !stat.isFile() || fs.readFileSync(marker, 'utf8') !== MARKER) {
      throw new Error('EVALUATION_UNOWNED_PROFILE')
    }
  }
  const session = path.join(profile, 'session')
  try { fs.mkdirSync(session, { mode: 0o700 }) } catch (error) {
    if (error.code !== 'EEXIST') throw error
  }
  assertRealDirectory(session)
  app.setName(PRODUCT_NAME)
  app.setPath('userData', profile)
  app.setPath('sessionData', session)
  return profile
}
module.exports = { configureEvaluationProfile, PRODUCT_NAME, DIRECTORY_NAME, MARKER_NAME, MARKER }
