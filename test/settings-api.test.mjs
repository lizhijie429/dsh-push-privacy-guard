import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { normalizeConfig } from '../lib/config.mjs'
import { addApproved, loadWhitelist } from '../lib/whitelist.mjs'
import { rememberPending } from '../lib/scopes.mjs'
import {
  CONFIG_FIELDS,
  buildStatus,
  createApiHandler,
  createPageHandler,
} from '../lib/settings-api.mjs'

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-settings-'))
after(() => {
  try {
    fs.rmSync(ROOT, { recursive: true, force: true })
  } catch {
    /* best effort */
  }
})

const AUTH = 'test-token'
const finding = (identity = 'abcabcabcabcabca') => ({
  identity,
  ruleId: 'openai-key',
  label: 'OpenAI API Key',
  masked: 'sk-a鈥?4',
  file: 'src/config.ts',
})

function makeConfig() {
  const dir = fs.mkdtempSync(path.join(ROOT, 'case-'))
  return normalizeConfig(
    {
      whitelistFile: path.join(dir, 'state', 'whitelist.json'),
      repoStateFile: path.join(dir, 'state', 'repos.json'),
      logFile: path.join(dir, 'state', 'guard.log'),
    },
    path.join(dir, 'plugin'),
  )
}

function makeCtx(edits = [], { authenticated = true } = {}) {
  return {
    get(name) {
      if (name === 'configEditor') {
        return {
          edit: async (_entry, change) => {
            edits.push(change({}))
          },
        }
      }
      if (name === 'webServer') return { protocol: 'http:' }
      if (name === 'connection') {
        return {
          admit: () => (authenticated ? { peer: { id: 'test-peer' } } : { rejection: 401 }),
        }
      }
      return undefined
    },
    fiber: { entry: { id: 'push-privacy-guard' } },
  }
}

function invoke(handler, { method = 'GET', url = '/privacy-guard/api', headers = {}, body = undefined } = {}) {
  return new Promise((resolve, reject) => {
    const req = new EventEmitter()
    req.method = method
    req.url = url
    req.headers = { ...headers }
    let status = 0
    const responseHeaders = {}
    let payload = ''
    const res = {
      writeHead(code, values) {
        status = code
        Object.assign(responseHeaders, values)
      },
      end(data) {
        if (data !== undefined) payload += Buffer.isBuffer(data) ? data.toString('utf8') : String(data)
        let parsed
        try {
          parsed = JSON.parse(payload)
        } catch {
          parsed = undefined
        }
        resolve({ status, headers: responseHeaders, body: payload, json: parsed })
      },
    }
    Promise.resolve(handler(req, res)).catch(reject)
    setImmediate(() => {
      if (body !== undefined) req.emit('data', Buffer.from(JSON.stringify(body)))
      req.emit('end')
    })
  })
}

test('the settings API returns masked status, config fields and pending items only with the token', async () => {
  const config = makeConfig()
  await addApproved(config.whitelistFile, [finding()])
  rememberPending('settings-session', [finding('defdefdefdefdefd')])
  const ctx = makeCtx()
  const handler = createApiHandler({ ctx, config, rules: [], token: AUTH })

  const denied = await invoke(handler)
  assert.equal(denied.status, 403)

  const crossOrigin = await invoke(handler, {
    headers: { 'x-privacy-guard-token': AUTH, origin: 'https://evil.example', host: '127.0.0.1:1234' },
  })
  assert.equal(crossOrigin.status, 403)

  const ok = await invoke(handler, { headers: { 'x-privacy-guard-token': AUTH } })
  assert.equal(ok.status, 200)
  assert.equal(ok.json.ok, true)
  assert.equal(ok.json.global.entries.length, 1)
  assert.equal(ok.json.pending.length, 1)
  assert.ok(ok.json.fields.some(field => field.key === 'approvalScope'))
  assert.equal(ok.json.fields.length, CONFIG_FIELDS.length)
})

test('the settings API saves only declared volatile fields through the config editor', async () => {
  const config = makeConfig()
  const edits = []
  const handler = createApiHandler({ ctx: makeCtx(edits), config, rules: [], token: AUTH })
  const saved = await invoke(handler, {
    method: 'POST',
    headers: { 'x-privacy-guard-token': AUTH },
    body: { action: 'save-config', values: { enabled: false, approvalScope: 'project', maxApprovalItems: 25 } },
  })
  assert.equal(saved.status, 200)
  assert.equal(saved.json.ok, true)
  assert.deepEqual(edits[0], { enabled: false, approvalScope: 'project', maxApprovalItems: 25 })

  const invalid = await invoke(handler, {
    method: 'POST',
    headers: { 'x-privacy-guard-token': AUTH },
    body: { action: 'save-config', values: { approvalScope: 'nope' } },
  })
  assert.equal(invalid.status, 400)

  const unknown = await invoke(handler, {
    method: 'POST',
    headers: { 'x-privacy-guard-token': AUTH },
    body: { action: 'save-config', values: { unknownField: true } },
  })
  assert.equal(unknown.status, 400)
})

test('the settings API allows only pending items and projects must resolve to a real repository', async () => {
  const config = makeConfig()
  rememberPending('settings-session', [finding('aaaabbbbccccdddd')])
  const handler = createApiHandler({ ctx: makeCtx(), config, rules: [], token: AUTH })

  const unknown = await invoke(handler, {
    method: 'POST',
    headers: { 'x-privacy-guard-token': AUTH },
    body: { action: 'allow', scope: 'global', target: 'ffffffffffffffff' },
  })
  assert.equal(unknown.status, 400)

  const allowed = await invoke(handler, {
    method: 'POST',
    headers: { 'x-privacy-guard-token': AUTH },
    body: { action: 'allow', scope: 'global', target: 'aaaabbbbccccdddd' },
  })
  assert.equal(allowed.status, 200)
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 1)

  const repo = path.join(ROOT, 'repo-api')
  fs.mkdirSync(repo, { recursive: true })
  execFileSync('git', ['init'], { cwd: repo, stdio: 'ignore' })
  fs.mkdirSync(path.join(repo, '.dsh'), { recursive: true })
  fs.writeFileSync(
    path.join(repo, '.dsh/privacy-guard-whitelist.json'),
    JSON.stringify({ version: 1, entries: [{ id: '1234123412341234', rule: 'email', masked: 'a***@b.c', allowed: true }] }),
  )
  const status = await invoke(handler, {
    headers: { 'x-privacy-guard-token': AUTH },
    url: `/privacy-guard/api?cwd=${encodeURIComponent(repo)}`,
  })
  assert.equal(status.status, 200)
  assert.equal(status.json.project.entries.length, 1)

  const clear = await invoke(handler, {
    method: 'POST',
    headers: { 'x-privacy-guard-token': AUTH },
    body: { action: 'clear', scope: 'project', cwd: repo },
  })
  assert.equal(clear.status, 200)
  assert.equal(JSON.parse(fs.readFileSync(path.join(repo, '.dsh/privacy-guard-whitelist.json'), 'utf8')).entries.length, 0)

  const bad = await invoke(handler, {
    method: 'POST',
    headers: { 'x-privacy-guard-token': AUTH },
    body: { action: 'allow', scope: 'project', target: 'aaaabbbbccccdddd', cwd: path.join(ROOT, 'missing') },
  })
  assert.equal(bad.status, 400)
})

test('the standalone page embeds the token and the API endpoint', async () => {
  const page = createPageHandler({ ctx: makeCtx(), token: AUTH, config: makeConfig() })
  const response = await new Promise((resolve, reject) => {
    let payload = ''
    let status = 0
    const req = { method: 'GET' }
    const res = {
      writeHead(code) {
        status = code
      },
      end(data) {
        if (data !== undefined) payload += String(data)
        resolve({ status, body: payload })
      },
    }
    Promise.resolve(page(req, res)).catch(reject)
  })
  assert.equal(response.status, 200)
  assert.match(response.body, /privacy-guard\/api/)
  assert.match(response.body, new RegExp(AUTH))
  assert.match(response.body, /项目白名单/)
})

test('buildStatus does not require a repository and reports config warnings', async () => {
  const config = makeConfig()
  const status = await buildStatus({ ctx: makeCtx(), config, rules: [], cwd: '' })
  assert.equal(status.project, null)
  assert.equal(status.repoState.error, '未填写仓库路径')
  assert.equal(status.config.approvalScope, 'global')
})
test('the package ships a web settings section client bundle', async () => {
  const manifest = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  assert.equal(manifest.exports['./client'], './client.js')
  assert.ok(manifest.files.includes('client.js'))
  assert.equal(manifest.dsh.client.platform, 'web')
  assert.equal(manifest.dsh.client.immediately, true)
  assert.ok(manifest.dsh.client.inject.includes('@deepseek-ai/dsh-client-ui-settings'))
  const client = fs.readFileSync(new URL('../client.js', import.meta.url), 'utf8')
  assert.match(client, /__ModuleLoader__\.load/)
  assert.match(client, /settings\.section/)
  assert.match(client, /privacy-guard\/settings/)
})
test('routes register only on a loopback web server', async () => {
  const routes = []
  const makeCtx = (host) => ({
    get: () => undefined,
    inject(_names, callback) {
      callback({
        webServer: {
          host,
          register(route) {
            routes.push(route)
            return () => {}
          },
        },
        connection: { admit: () => ({ peer: { id: 'route-test' } }) },
        effect(fn) { fn() },
      })
    },
  })
  const config = makeConfig()
  const specs = {}
  const { registerSettingsWeb } = await import('../lib/settings-api.mjs')
  registerSettingsWeb(makeCtx('127.0.0.1'), { config, rules: [], log: () => {} })
  assert.deepEqual(routes.map(route => route.path).sort(), ['/privacy-guard/api', '/privacy-guard/settings'])
  routes.length = 0
  registerSettingsWeb(makeCtx('0.0.0.0'), { config, rules: [], log: () => {} })
  assert.equal(routes.length, 0)
})
test('the settings page and API reject requests that lack Host connection authentication', async () => {
  const config = makeConfig()
  const unauthenticated = makeCtx([], { authenticated: false })
  const handler = createApiHandler({ ctx: unauthenticated, config, rules: [], token: AUTH })
  const api = await invoke(handler, { headers: { 'x-privacy-guard-token': AUTH } })
  assert.equal(api.status, 401)

  const page = createPageHandler({ ctx: unauthenticated, token: AUTH, config })
  const response = await invoke(page, { url: '/privacy-guard/settings' })
  assert.equal(response.status, 401)
  assert.ok(!response.body.includes(AUTH))

  const noConnection = makeCtx([], { authenticated: true })
  noConnection.get = name => (name === 'webServer' ? { protocol: 'http:' } : undefined)
  const noConnectionApi = createApiHandler({ ctx: noConnection, config, rules: [], token: AUTH })
  assert.equal((await invoke(noConnectionApi, { headers: { 'x-privacy-guard-token': AUTH } })).status, 401)
})