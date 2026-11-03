import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Config } from '../lib/schema.mjs'
import { DEFAULTS, normalizeConfig } from '../lib/config.mjs'

const PLUGIN_DIR = 'C:/Users/tester/.dsh/plugins/dsh-push-privacy-guard'

test('Config exposes a Schemastery standard schema and validates defaults', () => {
  assert.equal(Config['~standard'].vendor, 'schemastery')
  const result = Config['~standard'].validate({})
  assert.equal(result.issues, undefined)
  const value = key => (result.value[key]?.get ? result.value[key].get() : result.value[key])
  assert.equal(value('enabled'), true)
  assert.equal(value('fullScanOnFirstPush'), 'ask')
  assert.equal(value('persistentShellCommits'), 'deny')
})

test('Config rejects invalid enum values instead of silently accepting them', () => {
  const result = Config['~standard'].validate({ persistentShellCommits: 'maybe' })
  assert.ok(Array.isArray(result.issues) && result.issues.length > 0)
})

test('Config defaults match the documented DEFAULTS table', () => {
  const parsed = Config({})
  for (const [key, expected] of Object.entries(DEFAULTS)) {
    const actual = parsed[key] && typeof parsed[key].get === 'function' ? parsed[key].get() : parsed[key]
    if (Array.isArray(expected)) {
      assert.deepEqual(actual, expected, `default for ${key}`)
    } else {
      assert.equal(actual, expected, `default for ${key}`)
    }
  }
})

test('volatile fields are live references and normalizeConfig unwraps them', () => {
  const parsed = Config({ enabled: false, maxFiles: 7 })
  assert.equal(typeof parsed.enabled?.get, 'function')
  assert.equal(parsed.enabled.get(), false)
  assert.equal(parsed.maxFiles.get(), 7)

  const config = normalizeConfig(parsed, PLUGIN_DIR)
  assert.equal(config.enabled, false)
  assert.equal(config.maxFiles, 7)
  assert.equal(config.interceptCommit, true)
})
