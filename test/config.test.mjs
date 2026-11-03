import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { normalizeConfig, DEFAULTS } from '../lib/config.mjs'

const PLUGIN_DIR = 'C:/Users/tester/.dsh/plugins/dsh-push-privacy-guard'

test('defaults are complete and absolute paths resolve against the plugin dir', () => {
  const config = normalizeConfig({}, PLUGIN_DIR)
  assert.equal(config.enabled, true)
  assert.equal(config.interceptCommit, true)
  assert.equal(config.interceptPush, true)
  assert.equal(config.fullScanOnFirstPush, 'ask')
  assert.equal(config.whitelistOnApprove, true)
  assert.equal(config.requireApprovalOnIncompleteScan, true)
  assert.deepEqual(config.disableRules, [])
  assert.deepEqual(config.extraRules, [])
  assert.ok(config.ignorePaths.some(p => p.includes('node_modules')))
  assert.equal(config.whitelistFile, path.join(PLUGIN_DIR, 'state', 'whitelist.json'))
  assert.equal(config.repoStateFile, path.join(PLUGIN_DIR, 'state', 'repos.json'))
  assert.equal(config.logFile, path.join(PLUGIN_DIR, 'state', 'push-privacy-guard.log'))
  assert.equal(config.maxTotalBytes, DEFAULTS.maxTotalBytes)
  assert.deepEqual(config.warnings, [])
})

test('custom relative paths resolve against the plugin dir; absolute paths stay', () => {
  const relative = normalizeConfig({ whitelistFile: 'state/custom.json' }, PLUGIN_DIR)
  assert.equal(relative.whitelistFile, path.join(PLUGIN_DIR, 'state', 'custom.json'))
  const absolutePath = process.platform === 'win32' ? 'D:/shared/whitelist.json' : '/shared/whitelist.json'
  const absolute = normalizeConfig({ whitelistFile: absolutePath }, PLUGIN_DIR)
  assert.equal(absolute.whitelistFile, absolutePath)
})

test('invalid enum and booleans fall back with warnings', () => {
  const config = normalizeConfig(
    { fullScanOnFirstPush: 'sometimes', enabled: 'no', whitelistOnApprove: 'yes' },
    PLUGIN_DIR,
  )
  assert.equal(config.fullScanOnFirstPush, 'ask')
  assert.equal(config.enabled, false) // "no" is a recognizable false-y string
  assert.equal(config.whitelistOnApprove, true) // "yes" is a recognizable true-y string
  assert.equal(config.warnings.length, 3)
})

test('invalid numbers fall back to defaults with warnings', () => {
  const config = normalizeConfig({ maxTotalBytes: -5, gitTimeoutMs: 'fast', maxFiles: 0 }, PLUGIN_DIR)
  assert.equal(config.maxTotalBytes, DEFAULTS.maxTotalBytes)
  assert.equal(config.gitTimeoutMs, DEFAULTS.gitTimeoutMs)
  assert.equal(config.maxFiles, DEFAULTS.maxFiles)
  assert.equal(config.warnings.length, 3)
})

test('disableRules normalizes to a clean array', () => {
  const config = normalizeConfig({ disableRules: ['email', ' email ', 42, ''] }, PLUGIN_DIR)
  assert.deepEqual(config.disableRules, ['email'])
  assert.equal(config.warnings.length, 1)
})

test('extraRules keeps valid entries and warns about invalid ones', () => {
  const config = normalizeConfig(
    {
      extraRules: [
        { id: 'tenant-id', label: 'Tenant id', pattern: 'TENANT_[A-Z0-9]{8}', severity: 'medium' },
        { id: 'broken', pattern: '(', label: 'Broken' },
        { id: 'no-pattern', label: 'No pattern' },
        { id: 'tenant-id', pattern: 'X+', label: 'Duplicate id' },
      ],
    },
    PLUGIN_DIR,
  )
  assert.deepEqual(config.extraRules.map(rule => rule.id), ['tenant-id'])
  assert.equal(config.warnings.length, 3)
})

test('ignorePaths adds defaults and user entries, rejecting non-strings', () => {
  const config = normalizeConfig({ ignorePaths: ['**/fixtures/**', 7] }, PLUGIN_DIR)
  assert.ok(config.ignorePaths.includes('**/fixtures/**'))
  assert.ok(config.ignorePaths.some(p => p.includes('node_modules')))
  assert.equal(config.warnings.length, 1)
})
