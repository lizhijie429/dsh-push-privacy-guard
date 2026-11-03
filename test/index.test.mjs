import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { apply, Config, inject, name } from '../index.mjs'

test('the module exports the Cordis metadata and a schema', () => {
  assert.equal(name, 'push-privacy-guard')
  assert.deepEqual(inject, ['tools'])
  assert.equal(Config['~standard'].vendor, 'schemastery')
})

test('a volatile config update refreshes the running snapshot without remounting', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-guard-index-'))
  const listeners = new Map()
  const effects = []
  const ctx = {
    on(event, listener) {
      const list = listeners.get(event) ?? []
      list.push(listener)
      listeners.set(event, list)
      return () => {}
    },
    effect(callback) {
      const disposer = callback()
      effects.push(disposer)
      return () => {}
    },
    get() {
      return undefined
    },
    logger: { warn() {} },
  }

  const enabled = {
    value: true,
    get() {
      return this.value
    },
  }
  const logFile = path.join(dir, 'guard.log')
  apply(ctx, {
    enabled,
    logFile,
    whitelistFile: path.join(dir, 'whitelist.json'),
    repoStateFile: path.join(dir, 'repos.json'),
    disableRules: [],
    extraRules: [],
    ignorePaths: [],
  })

  assert.ok(listeners.has('tools/pre-execute'), 'pre-execute handler registered')
  assert.ok(listeners.has('loader/volatile-update'), 'volatile config listener registered')

  enabled.value = false
  for (const listener of listeners.get('loader/volatile-update')) listener({ paths: ['enabled'] })
  const log = fs.readFileSync(logFile, 'utf8')
  assert.match(log, /plugin\.mounted/)
  assert.match(log, /config\.volatile-update enabled=false/)

  for (const disposer of effects) {
    if (typeof disposer === 'function') disposer()
  }
  fs.rmSync(dir, { recursive: true, force: true })
})
