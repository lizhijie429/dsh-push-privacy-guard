import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { normalizeConfig } from '../lib/config.mjs'
import { rememberPending, sessionEntries } from '../lib/scopes.mjs'
import { createPrivacyTool, registerPrivacyTool } from '../lib/tool.mjs'

const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-tool-'))
const config = normalizeConfig({}, path.join(DIR, 'plugin'))

function makeCtx(outcomes = ['allowed-once']) {
  const requests = []
  return {
    requests,
    get(name) {
      if (name !== 'approval') return undefined
      return {
        request: async request => {
          requests.push(request)
          return outcomes.length > 1 ? outcomes.shift() : outcomes[0]
        },
      }
    },
  }
}

const exec = {
  name: 'privacy_guard',
  callId: 'call-1',
  agent: { session: { id: 'tool-session', header: { cwd: DIR } } },
  signal: new AbortController().signal,
}

test('the tool definition exposes a model-facing schema and text output', () => {
  const ctx = makeCtx()
  const tool = createPrivacyTool({ ctx, config })
  assert.equal(tool.name, 'privacy_guard')
  assert.equal(tool.parameters.properties.action.enum.includes('allow'), true)
  assert.equal(tool.output.schema.properties.ok.type, 'boolean')
  assert.deepEqual(tool.output.render({}, { ok: true, text: 'hi' }), [{ type: 'text', text: 'hi' }])
})

test('pending lists recent findings without leaking raw values', async () => {
  const ctx = makeCtx()
  rememberPending('tool-session', [
    { identity: 'c1c2c3c4c5c6c7c8', ruleId: 'openai-key', label: 'OpenAI API Key', masked: 'sk-c…34', file: 'a.ts' },
  ])
  const tool = createPrivacyTool({ ctx, config })
  const value = await tool.execute({ action: 'pending' }, exec)
  assert.equal(value.ok, true)
  assert.match(value.text, /c1c2c3c4c5c6c7c8/)
  assert.match(value.text, /sk-c…34/)
  assert.ok(!value.text.includes('sk-c4f5'))
})

test('allow session mutates only after the user approves', async () => {
  const ctx = makeCtx(['rejected'])
  const tool = createPrivacyTool({ ctx, config })
  const denied = await tool.execute({ action: 'allow', scope: 'session', target: 'last' }, exec)
  assert.equal(denied.ok, false)
  assert.equal(ctx.requests.length, 1)
  assert.equal(sessionEntries('tool-session').length, 0)

  const approvedCtx = makeCtx(['allowed-once'])
  const approvedTool = createPrivacyTool({ ctx: approvedCtx, config })
  const allowed = await approvedTool.execute({ action: 'allow', scope: 'session', target: 'last' }, exec)
  assert.equal(allowed.ok, true)
  assert.equal(sessionEntries('tool-session')[0].id, 'c1c2c3c4c5c6c7c8')
})

test('revoke requires approval and removes the session entry', async () => {
  const ctx = makeCtx(['allowed-once'])
  const tool = createPrivacyTool({ ctx, config })
  const value = await tool.execute({ action: 'revoke', scope: 'session', target: 'c1c2' }, exec)
  assert.equal(value.ok, true)
  assert.equal(sessionEntries('tool-session').length, 0)
})

test('registerPrivacyTool uses the host tool registry', () => {
  const registered = []
  const ctx = {
    tools: { register: definition => {
      registered.push(definition)
      return () => {}
    } },
    get() {
      return undefined
    },
  }
  registerPrivacyTool(ctx, { config })
  assert.equal(registered.length, 1)
  assert.equal(registered[0].name, 'privacy_guard')
})

test('unknown identities are rejected instead of becoming manual allows', async () => {
  const ctx = makeCtx()
  const tool = createPrivacyTool({ ctx, config })
  const value = await tool.execute({ action: 'allow', scope: 'session', target: 'deadbeefdeadbeef' }, exec)
  assert.equal(value.ok, false)
  assert.match(value.text, /pending/)
  assert.equal(ctx.requests.length, 0)
})

test('the approval prompt shows masked items, rule and file', async () => {
  const ctx = makeCtx(['allowed-once'])
  const tool = createPrivacyTool({ ctx, config })
  const value = await tool.execute({ action: 'allow', scope: 'session', target: 'last' }, exec)
  assert.equal(value.ok, true)
  const request = ctx.requests[0]
  assert.match(request.displayReason.zh, /openai-key/)
  assert.match(request.displayReason.zh, /sk-c…34/)
  assert.match(request.displayReason.zh, /a.ts/)
})

test('session mutations fail closed without a session id', async () => {
  const ctx = makeCtx()
  const tool = createPrivacyTool({ ctx, config })
  const noSession = { ...exec, agent: { session: { header: { cwd: DIR } } } }
  const value = await tool.execute({ action: 'allow', scope: 'session', target: 'last' }, noSession)
  assert.equal(value.ok, false)
  assert.match(value.text, /session id/)
  assert.equal(ctx.requests.length, 0)
})