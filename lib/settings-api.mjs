/**
 * HTTP API + standalone graphical settings page for the Web GUI.
 *
 * The page is served from the DSH web server on loopback, same-origin with the
 * GUI. Mutations require a per-process random token and a same-origin Origin
 * header; the token is embedded only in the page HTML. All data returned is
 * masked (no raw secrets).
 *
 * @module dsh-push-privacy-guard/settings-api
 */

import { randomUUID } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

import { loadWhitelist } from './whitelist.mjs'
import { addApproved, clearWhitelist, removeByPrefix } from './whitelist.mjs'
import {
  addProjectApproved,
  clearProjectWhitelist,
  effectiveApprovedIds,
  loadProjectWhitelist,
  pendingSummaries,
  removeProjectByPrefix,
} from './scopes.mjs'
import { detectRepo } from './scan.mjs'
import { createGitRunner } from './git.mjs'
import { renderSettingsPage } from './settings-page.mjs'

const API_PATH = '/privacy-guard/api'
const PAGE_PATH = '/privacy-guard/settings'
const MAX_BODY_BYTES = 256 * 1024

/** Editable volatile configuration surfaced by the page. */
const CONFIG_FIELDS = [
  { key: 'enabled', type: 'boolean', group: 'basic', zh: '启用插件', en: 'Enable plugin' },
  { key: 'interceptCommit', type: 'boolean', group: 'basic', zh: '检查 git commit', en: 'Check git commit' },
  { key: 'interceptPush', type: 'boolean', group: 'basic', zh: '检查 git push / gh repo sync', en: 'Check git push / gh repo sync' },
  { key: 'fullScanOnFirstPush', type: 'enum', group: 'basic', options: ['ask', 'always', 'never'], zh: '首次推送全仓扫描', en: 'First-push full scan' },
  { key: 'unresolvedRepo', type: 'enum', group: 'policy', options: ['deny', 'allow'], zh: '无法定位仓库', en: 'Unresolved repository' },
  { key: 'persistentShellCommits', type: 'enum', group: 'policy', options: ['deny', 'allow'], zh: '持久终端提交/推送', en: 'Persistent-terminal commits' },
  { key: 'whitelistOnApprove', type: 'boolean', group: 'policy', zh: '审批后记住到白名单', en: 'Remember approvals' },
  { key: 'requireApprovalOnIncompleteScan', type: 'boolean', group: 'policy', zh: '扫描不完整时需审批', en: 'Approve incomplete scans' },
  { key: 'approvalScope', type: 'enum', group: 'policy', options: ['global', 'project', 'session'], zh: '审批后记住范围', en: 'Approval scope' },
  { key: 'projectWhitelistFile', type: 'string', group: 'project', zh: '项目白名单文件（相对仓库根）', en: 'Project whitelist file (repo-relative)' },
  { key: 'projectWhitelistEnabled', type: 'boolean', group: 'project', zh: '启用项目白名单', en: 'Enable project whitelist' },
  { key: 'trustProjectWhitelist', type: 'boolean', group: 'project', zh: '信任仓库自带的放行条目', en: 'Trust repository allow entries' },
  { key: 'maxApprovalItems', type: 'number', group: 'limits', min: 1, max: 100, zh: '审批面板最多展示条数', en: 'Max findings shown in approval' },
  { key: 'gitTimeoutMs', type: 'number', group: 'limits', min: 1000, max: 120000, zh: '单次 git 超时（毫秒）', en: 'Git command timeout (ms)' },
]

/**
 * Register the settings routes when the web server service is composed.
 *
 * @param {any} ctx plugin context
 * @param {{config:object,rules:Array,log:Function}} deps
 */
export function registerSettingsWeb(ctx, { config, rules, log = () => {} }) {
  if (typeof ctx?.inject !== 'function') return
  try {
    ctx.inject(['webServer'], sub => {
      try {
        if (!isLoopbackHost(sub.webServer.host)) {
          log(`settings-web.skip reason=non-loopback-host host=${sub.webServer.host}`)
          return
        }
        const auth = randomUUID()
        const handler = createApiHandler({ ctx, config, rules, token: auth, log })
        const page = createPageHandler({ token: auth, config })
        sub.effect(() => sub.webServer.register({ kind: 'exact', path: API_PATH, handler }), 'push-privacy-guard: settings api')
        sub.effect(() => sub.webServer.register({ kind: 'exact', path: PAGE_PATH, handler: page }), 'push-privacy-guard: settings page')
        log(`settings-web.registered api=${API_PATH} page=${PAGE_PATH}`)
      } catch (error) {
        log(`settings-web.register-failed ${safeMessage(error)}`)
      }
    })
  } catch (error) {
    log(`settings-web.inject-failed ${safeMessage(error)}`)
  }
}

function createPageHandler({ token, config }) {
  return async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return send(res, 405, 'text/plain; charset=utf-8', 'Method Not Allowed')
    }
    const html = renderSettingsPage({ token, pluginVersion: readVersion(), config })
    return send(res, 200, 'text/html; charset=utf-8', html, { 'Cache-Control': 'no-store', 'X-Frame-Options': 'SAMEORIGIN' }, req.method === 'HEAD')
  }
}

function createApiHandler({ ctx, config, rules, token, log }) {
  return async (req, res) => {
    try {
      if (!sameOrigin(req, ctx)) return json(res, 403, { ok: false, error: 'forbidden origin' })
      if (req.method === 'GET') {
        if (req.headers['x-privacy-guard-token'] !== token) return json(res, 403, { ok: false, error: 'missing or invalid token' })
        const url = new URL(req.url ?? API_PATH, 'http://localhost')
        const cwd = String(url.searchParams.get('cwd') ?? '').trim()
        const data = await buildStatus({ ctx, config, rules, cwd })
        return json(res, 200, { ok: true, ...data })
      }
      if (req.method === 'POST') {
        if (req.headers['x-privacy-guard-token'] !== token) return json(res, 403, { ok: false, error: 'missing or invalid token' })
        const body = await readJson(req)
        if (body === null) return json(res, 400, { ok: false, error: 'invalid JSON body' })
        const result = await applyAction({ ctx, config, body })
        return json(res, result.status ?? 200, result)
      }
      return json(res, 405, { ok: false, error: 'method not allowed' })
    } catch (error) {
      log(`settings-api.error ${safeMessage(error)}`)
      return json(res, 500, { ok: false, error: safeMessage(error) })
    }
  }
}

async function buildStatus({ ctx, config, rules, cwd }) {
  const global = loadWhitelist(config.whitelistFile)
  const repo = await resolveRepo(ctx, config, cwd)
  const project = repo.root === null ? null : loadProjectWhitelist(repo.root, config)
  const approved = effectiveApprovedIds({ config, root: repo.root ?? undefined, globalDocument: global })
  return {
    fields: describeFields(config),
    config: {
      enabled: config.enabled !== false,
      approvalScope: config.approvalScope,
      projectWhitelistFile: config.projectWhitelistFile,
      projectWhitelistEnabled: config.projectWhitelistEnabled !== false,
      trustProjectWhitelist: config.trustProjectWhitelist !== false,
    },
    global: { file: config.whitelistFile, entries: global.entries.slice(0, 300) },
    project:
      project === null
        ? null
        : {
            cwd: repo.cwd,
            root: repo.root,
            file: project.file,
            entries: project.document.entries.slice(0, 300),
            warning: project.warning,
          },
    effective: { total: approved.ids.size, projectAllow: approved.projectAllow, projectDeny: approved.projectDeny },
    pending: pendingSummaries(100),
    rules: rules.map(rule => ({ id: rule.id, label: rule.label, severity: rule.severity })),
    paths: { whitelistFile: config.whitelistFile, repoStateFile: config.repoStateFile, logFile: config.logFile },
    repoState: repo.root === null ? { error: repo.error } : { root: repo.root },
  }
}

async function applyAction({ ctx, config, body }) {
  const action = String(body?.action ?? '')
  const scope = String(body?.scope ?? 'global')
  const target = String(body?.target ?? '')
  const cwd = String(body?.cwd ?? '').trim()

  if (action === 'save-config') {
    return saveConfig({ ctx, values: body?.values })
  }
  if (action === 'allow') {
    if (scope !== 'global' && scope !== 'project') return { ok: false, status: 400, error: 'settings page can only allow globally or to a project' }
    const finding = pendingSummaries(500).find(item => item.identity === target)
    if (finding === undefined) return { ok: false, status: 400, error: 'only a recently blocked (pending) item can be allowed' }
    if (scope === 'global') {
      const result = await addApproved(config.whitelistFile, [finding])
      return { ok: true, message: `已加入全局白名单：${result.added} 条` }
    }
    const repo = await resolveRepo(ctx, config, cwd)
    if (repo.root === null) return { ok: false, status: 400, error: `仓库路径无效：${repo.error}` }
    const result = await addProjectApproved(repo.root, config, [finding])
    if (result.error !== undefined) return { ok: false, status: 400, error: `项目白名单不可用：${result.error}` }
    return { ok: true, message: `已加入项目白名单：新增 ${result.added} 条，恢复 ${result.updated} 条` }
  }
  if (action === 'revoke') {
    if (typeof target !== 'string' || target.trim().length === 0) return { ok: false, status: 400, error: '缺少 id 前缀' }
    if (scope === 'global') {
      const result = await removeByPrefix(config.whitelistFile, target)
      return revokeResult(result, '全局白名单')
    }
    if (scope === 'project') {
      const repo = await resolveRepo(ctx, config, cwd)
      if (repo.root === null) return { ok: false, status: 400, error: `仓库路径无效：${repo.error}` }
      const result = await removeProjectByPrefix(repo.root, config, target)
      return revokeResult(result, '项目白名单', result.error)
    }
    return { ok: false, status: 400, error: '不支持的 scope' }
  }
  if (action === 'clear') {
    if (scope === 'global') {
      const result = await clearWhitelist(config.whitelistFile)
      return { ok: true, message: `已清空全局白名单，共删除 ${result.removed} 条` }
    }
    if (scope === 'project') {
      const repo = await resolveRepo(ctx, config, cwd)
      if (repo.root === null) return { ok: false, status: 400, error: `仓库路径无效：${repo.error}` }
      const result = await clearProjectWhitelist(repo.root, config)
      if (result.error !== undefined) return { ok: false, status: 400, error: `项目白名单不可用：${result.error}` }
      return { ok: true, message: `已清空项目白名单，共删除 ${result.removed} 条` }
    }
    return { ok: false, status: 400, error: '不支持的 scope' }
  }
  return { ok: false, status: 400, error: `未知 action：${action}` }
}

async function saveConfig({ ctx, values }) {
  if (values === null || typeof values !== 'object' || Array.isArray(values)) {
    return { ok: false, status: 400, error: 'values 必须是对象' }
  }
  const patch = {}
  for (const field of CONFIG_FIELDS) {
    if (!Object.hasOwn(values, field.key)) continue
    const value = values[field.key]
    if (field.type === 'boolean') {
      if (typeof value !== 'boolean') return { ok: false, status: 400, error: `${field.key} 必须是布尔值` }
      patch[field.key] = value
    } else if (field.type === 'enum') {
      if (!field.options.includes(String(value))) return { ok: false, status: 400, error: `${field.key} 选项无效` }
      patch[field.key] = String(value)
    } else if (field.type === 'number') {
      const number = Number(value)
      if (!Number.isInteger(number) || number < field.min || number > field.max) {
        return { ok: false, status: 400, error: `${field.key} 超出范围（${field.min}–${field.max}）` }
      }
      patch[field.key] = number
    } else {
      if (typeof value !== 'string' || value.trim().length === 0) return { ok: false, status: 400, error: `${field.key} 不能为空` }
      patch[field.key] = value.trim()
    }
  }
  if (Object.keys(patch).length === 0) return { ok: false, status: 400, error: '没有可保存的字段' }
  const entry = ctx?.fiber?.entry
  const editor = typeof ctx?.get === 'function' ? ctx.get('configEditor') : undefined
  if (entry === undefined || editor === undefined || typeof editor.edit !== 'function') {
    return { ok: false, status: 501, error: '当前 profile 不支持保存配置，请编辑 cordis.patch.yml' }
  }
  try {
    await editor.edit(entry, current => ({ ...(current ?? {}), ...patch }))
    return { ok: true, message: `已保存 ${Object.keys(patch).length} 项配置` }
  } catch (error) {
    return { ok: false, status: 400, error: `保存失败：${safeMessage(error)}` }
  }
}

function describeFields(config) {
  return CONFIG_FIELDS.map(field => ({
    ...field,
    value: config[field.key],
  }))
}

function revokeResult(result, label, extraError = '') {
  if (result.error === 'empty-prefix') return { ok: false, status: 400, error: 'id 前缀不能为空' }
  if (result.error === 'no-match') return { ok: false, status: 400, error: `${label}没有匹配条目` }
  if (result.error === 'ambiguous') return { ok: false, status: 400, error: '前缀匹配到多条，请提供更长的 id' }
  if (result.error !== undefined) return { ok: false, status: 400, error: extraError || `${label}不可用：${result.error}` }
  return { ok: true, message: `已从${label}删除 ${result.removed[0].id}` }
}

async function resolveRepo(ctx, config, cwd) {
  const candidate = String(cwd ?? '').trim()
  if (candidate.length === 0) return { cwd: '', root: null, error: '未填写仓库路径' }
  try {
    const runner = createGitRunner({ cwd: candidate, timeoutMs: config.gitTimeoutMs })
    const root = await detectRepo(runner, candidate)
    return root === null ? { cwd: candidate, root: null, error: '不是一个 git 仓库' } : { cwd: candidate, root }
  } catch (error) {
    return { cwd: candidate, root: null, error: safeMessage(error) }
  }
}

function sameOrigin(req, ctx) {
  const origin = req.headers.origin
  if (typeof origin !== 'string' || origin.length === 0) return true
  try {
    const parsed = new URL(origin)
    const expectedProtocol = ctx?.get?.('webServer')?.protocol ?? 'http:'
    return parsed.host === req.headers.host && parsed.protocol === expectedProtocol
  } catch {
    return false
  }
}

/** The settings routes expose local state, so never serve them on a LAN bind. */
function isLoopbackHost(host) {
  const value = String(host ?? '').trim().replace(/^\[|\]$/g, '')
  return value === 'localhost' || value === '::1' || value === '127.0.0.1' || value.startsWith('127.')
}

function readJson(req) {
  return new Promise(resolve => {
    let size = 0
    const chunks = []
    req.on('data', chunk => {
      size += chunk.length
      if (size > MAX_BODY_BYTES) {
        resolve(null)
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        resolve(null)
      }
    })
    req.on('error', () => resolve(null))
  })
}

function send(res, status, type, body, headers = {}, headOnly = false) {
  res.writeHead(status, { 'Content-Type': type, ...headers })
  res.end(headOnly ? undefined : body)
}

function json(res, status, payload) {
  send(res, status, 'application/json; charset=utf-8', JSON.stringify(payload), { 'Cache-Control': 'no-store' })
}

function readVersion() {
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, '..', 'package.json'), 'utf8'))
    return manifest.version
  } catch {
    return '0.0.0'
  }
}

export { API_PATH, PAGE_PATH, CONFIG_FIELDS, createApiHandler, createPageHandler, buildStatus, applyAction, saveConfig }

function safeMessage(error) {
  const message = error instanceof Error ? error.message : String(error)
  return message.replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ').slice(0, 200)
}