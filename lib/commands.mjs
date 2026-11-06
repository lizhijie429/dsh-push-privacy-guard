/**
 * `/privacy-guard` subcommands. User-only surface: these run from the Web UI
 * command plane and never become model messages, so the model cannot widen its
 * own permissions or edit the whitelist.
 *
 * @module dsh-push-privacy-guard/commands
 */

import path from 'node:path'
import { compileRules } from './rules.mjs'
import { readBlobsBatch } from './git.mjs'
import {
  dedupeFindings,
  detectRepo,
  scanCommit,
  scanFullRepo,
  splitWhitelisted,
} from './scan.mjs'
import { clearWhitelist, addApproved, loadWhitelist, removeByPrefix } from './whitelist.mjs'
import {
  addProjectApproved,
  addSessionEntries,
  clearSession,
  effectiveApprovedIds,
  loadProjectWhitelist,
  projectWhitelistPath,
  removeProjectByPrefix,
  removeSessionByPrefix,
  pendingFor,
  pendingMatch,
  sessionEntries,
} from './scopes.mjs'
import { isInitialized, loadRepoState, resetRepos } from './repo-state.mjs'
import {
  renderHelp,
  renderRepos,
  renderScanReport,
  renderStatus,
  renderWhitelist,
} from './messages.mjs'

/**
 * Execute one `/privacy-guard` line.
 *
 * @param {string} rawInput - text after the command name.
 * @param {{config:object,cwd?:string,createRunner?:(options:object)=>Function,scanRepository?:Function}} deps
 * @returns {Promise<{kind:'success'|'error',text:string}>}
 */
export async function executePrivacyCommand(rawInput, deps) {
  const { config, cwd, createRunner, scanRepository, sessionId } = deps
  const argv = String(rawInput ?? '')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
  const subcommand = (argv[0] ?? 'help').toLowerCase()

  try {
    switch (subcommand) {
      case 'list':
        return await listScoped(deps)
      case 'pending':
        return success(renderPending(pendingFor(sessionId)))
      case 'allow':
        return await allow(argv[1], argv[2], deps)
      case 'revoke':
        return await revoke(argv[1], argv[2], deps)
      case 'session':
        return await sessionCommand(argv, deps)
      case 'project':
        return await projectCommand(argv, deps)
      case 'remove':
        return await remove(argv[1], config)
      case 'clear':
        return await clear(argv[1], config)
      case 'status':
        return await status(deps)
      case 'repos':
        return success(renderRepos(loadRepoState(config.repoStateFile)))
      case 'reset':
        return await reset(argv[1], config)
      case 'scan':
        return await scan(deps, scanRepository)
      case 'help':
      default:
        return success(renderHelp())
    }
  } catch (error) {
    return { kind: 'error', text: `命令执行失败：${sanitize(error)}` }
  }
}

function success(text) {
  return { kind: 'success', text }
}

async function remove(prefix, config) {
  if (typeof prefix !== 'string' || prefix.trim().length === 0) {
    return { kind: 'error', text: '用法：/privacy-guard remove <id前缀>（可用 /privacy-guard list 查看 id）' }
  }
  const result = await removeByPrefix(config.whitelistFile, prefix)
  if (result.error === 'empty-prefix') return { kind: 'error', text: 'id 前缀不能为空。' }
  if (result.error === 'no-match') return { kind: 'error', text: `没有匹配 "${prefix}" 的白名单条目。` }
  if (result.error === 'ambiguous') {
    const candidates = result.candidates.map(entry => entry.id).join(', ')
    return { kind: 'error', text: `前缀 "${prefix}" 匹配到多条，请提供更长的 id：${candidates}` }
  }
  const entry = result.removed[0]
  return success(`已删除白名单条目 ${entry.id}（${entry.label ?? entry.rule}，${entry.masked ?? ''}）。`)
}

async function clear(confirmWord, config) {
  if (confirmWord !== 'confirm') {
    return { kind: 'error', text: '清空白名单需要确认：/privacy-guard clear confirm' }
  }
  const result = await clearWhitelist(config.whitelistFile)
  return success(`已清空白名单，共删除 ${result.removed} 条。`)
}

/** Resolve the current repository root, or null outside a repository. */
async function repoRoot({ cwd, createRunner }) {
  if (typeof cwd !== 'string' || cwd.length === 0 || typeof createRunner !== 'function') return null
  try {
    const runner = createRunner({ cwd })
    return await detectRepo(runner, cwd)
  } catch {
    return null
  }
}

async function listScoped(deps) {
  const { config, sessionId } = deps
  const global = loadWhitelist(config.whitelistFile)
  const parts = [renderWhitelist(global)]
  const root = await repoRoot(deps)
  if (root !== null) {
    const project = loadProjectWhitelist(root, config)
    parts.push(
      `项目白名单（${project.file}）：${project.document.entries.length} 条` +
        (project.document.entries.length === 0 ? '' : `\n${formatEntries(project.document.entries)}`),
    )
  } else {
    parts.push('项目白名单：当前目录不在 git 仓库内。')
  }
  const session = sessionEntries(sessionId)
  parts.push(`会话白名单：${session.length} 条${session.length === 0 ? '' : `\n${formatEntries(session)}`}`)
  return success(parts.join('\n\n'))
}

function formatEntries(entries) {
  return entries
    .slice(0, 50)
    .map(entry => `- ${entry.id}  [${entry.rule}]  ${entry.masked ?? ''}  ${entry.firstFile ?? ''}`)
    .join('\n')
}

function renderPending(findings) {
  if (findings.length === 0) return '最近没有待处理的命中。先执行一次被拦截的提交/推送后，再用 /privacy-guard pending 查看。'
  const lines = [`最近一次被拦截的命中（${findings.length} 条）：`]
  for (const finding of findings.slice(0, 20)) {
    lines.push(`- ${finding.identity}  [${finding.ruleId}]  ${finding.masked ?? ''}  ${finding.file ?? ''}`)
  }
  lines.push('', '放行：/privacy-guard allow <id前缀|last> [global|project|session]')
  return lines.join('\n')
}

function resolveTargetFindings(sessionId, target) {
  const match = pendingMatch(sessionId, target)
  if (match.error === 'empty-target') return { error: '请提供 id 前缀或 last。' }
  if (match.error === 'no-pending') return { error: '最近没有待处理命中，无法使用 last。' }
  if (match.error === 'no-match') {
    const raw = String(target ?? '').trim().toLowerCase()
    if (/^[0-9a-f]{8,64}$/.test(raw)) {
      return { findings: [{ identity: raw, ruleId: 'manual', label: 'manual', masked: '', file: '' }] }
    }
    return { error: `没有匹配 "${target}" 的待处理命中。` }
  }
  if (match.error === 'ambiguous') {
    return { error: `前缀 "${target}" 匹配到多条，请提供更长的 id：${match.candidates.map(item => item.identity).join(', ')}` }
  }
  return { findings: match.findings }
}

async function allow(target, scopeArg, deps) {
  const { config, sessionId } = deps
  const scope = normalizeScope(scopeArg ?? config.approvalScope)
  const resolved = resolveTargetFindings(sessionId, target)
  if (resolved.error !== undefined) return { kind: 'error', text: resolved.error }
  const findings = resolved.findings
  if (scope === 'session') {
    addSessionEntries(sessionId, findings)
    return success(`已加入会话白名单：${findings.length} 条（仅当前会话有效）。`)
  }
  if (scope === 'project') {
    const root = await repoRoot(deps)
    if (root === null) return { kind: 'error', text: '当前目录不在 git 仓库内，无法写入项目白名单。' }
    try {
      const result = addProjectApproved(root, config, findings)
      return success(`已加入项目白名单：${result.added} 条（${result.file}）。`)
    } catch (error) {
      return { kind: 'error', text: `写入项目白名单失败：${sanitize(error)}` }
    }
  }
  try {
    const result = await addApproved(config.whitelistFile, findings)
    return success(`已加入全局白名单：${result.added} 条。`)
  } catch (error) {
    return { kind: 'error', text: `写入全局白名单失败：${sanitize(error)}` }
  }
}

async function revoke(target, scopeArg, deps) {
  const { config, sessionId } = deps
  const scope = normalizeScope(scopeArg ?? config.approvalScope)
  if (typeof target !== 'string' || target.trim().length === 0) {
    return { kind: 'error', text: '用法：/privacy-guard revoke <id前缀> [global|project|session]' }
  }
  if (scope === 'session') {
    const result = removeSessionByPrefix(sessionId, target)
    return scopeResult(result, '会话白名单')
  }
  if (scope === 'project') {
    const root = await repoRoot(deps)
    if (root === null) return { kind: 'error', text: '当前目录不在 git 仓库内。' }
    return scopeResult(removeProjectByPrefix(root, config, target), '项目白名单')
  }
  const result = await removeByPrefix(config.whitelistFile, target)
  return scopeResult(result, '全局白名单')
}

function scopeResult(result, label) {
  if (result.error === 'empty-prefix') return { kind: 'error', text: 'id 前缀不能为空。' }
  if (result.error === 'no-match') return { kind: 'error', text: `${label}没有匹配条目。` }
  if (result.error === 'ambiguous') {
    return { kind: 'error', text: `前缀匹配到多条，请提供更长的 id：${result.candidates.map(item => item.id).join(', ')}` }
  }
  const entry = result.removed[0]
  return success(`已从${label}删除 ${entry.id}。`)
}

function normalizeScope(value) {
  const scope = String(value ?? '').trim().toLowerCase()
  return scope === 'project' || scope === 'session' ? scope : 'global'
}

async function sessionCommand(argv, deps) {
  const { config, sessionId } = deps
  const action = (argv[1] ?? 'list').toLowerCase()
  if (action === 'list') {
    const entries = sessionEntries(sessionId)
    return success(`会话白名单：${entries.length} 条${entries.length === 0 ? '' : `\n${formatEntries(entries)}`}`)
  }
  if (action === 'clear') {
    const result = clearSession(sessionId)
    return success(`已清空会话白名单，共删除 ${result.removed} 条。`)
  }
  if (action === 'allow') return allow(argv[2], 'session', deps)
  if (action === 'revoke') return revoke(argv[2], 'session', deps)
  return { kind: 'error', text: '用法：/privacy-guard session [list|allow <id|last>|revoke <id>|clear]' }
}

async function projectCommand(argv, deps) {
  const { config } = deps
  const action = (argv[1] ?? 'list').toLowerCase()
  const root = await repoRoot(deps)
  if (root === null) return { kind: 'error', text: '当前目录不在 git 仓库内。' }
  const project = loadProjectWhitelist(root, config)
  if (action === 'list') {
    return success(
      `项目白名单（${project.file}）：${project.document.entries.length} 条` +
        (project.document.entries.length === 0 ? '' : `\n${formatEntries(project.document.entries)}`),
    )
  }
  if (action === 'allow') return allow(argv[2], 'project', deps)
  if (action === 'revoke') return revoke(argv[2], 'project', deps)
  return { kind: 'error', text: '用法：/privacy-guard project [list|allow <id|last>|revoke <id>]' }
}

async function reset(query, config) {
  if (typeof query !== 'string' || query.trim().length === 0) {
    return { kind: 'error', text: '用法：/privacy-guard reset <仓库路径子串|all>' }
  }
  const result = await resetRepos(config.repoStateFile, query)
  if (result.error === 'empty-query') return { kind: 'error', text: '请提供仓库路径子串或 all。' }
  if (result.removed === 0) return success(`没有匹配 "${query}" 的仓库初始化记录。`)
  return success(`已清除 ${result.removed} 个仓库的初始化记录；这些仓库下次推送会重新询问是否全仓扫描。`)
}

async function status({ config, cwd, createRunner }) {
  const whitelist = loadWhitelist(config.whitelistFile)
  const repoState = loadRepoState(config.repoStateFile)
  const rules = compileRules(config)
  let currentRepo
  let initialized = false
  if (typeof cwd === 'string' && cwd.length > 0 && typeof createRunner === 'function') {
    const runner = createRunner({ cwd })
    const root = await detectRepo(runner, cwd)
    if (root !== null) {
      currentRepo = root
      initialized = isInitialized(repoState, root)
    }
  }
  return success(
    renderStatus({
      config,
      whitelist,
      repoState,
      rulesCount: rules.length,
      currentRepo,
      initialized,
    }),
  )
}

async function scan(deps, injectedScan) {
  const { config, cwd, createRunner } = deps
  if (typeof injectedScan === 'function') {
    const { root, result } = await injectedScan({ config, cwd })
    const findings = dedupeFindings(result.findings)
    const approved = effectiveApprovedIds({
      config,
      root,
      sessionId: deps.sessionId,
      globalDocument: loadWhitelist(config.whitelistFile),
    })
    const { blocked, whitelisted } = splitWhitelisted(findings, approved.ids)
    return success(renderScanReport({ root, result: { ...result, findings: blocked }, whitelistedCount: whitelisted.length }))
  }
  if (typeof cwd !== 'string' || cwd.length === 0) {
    return { kind: 'error', text: '无法确定当前会话工作目录。' }
  }
  if (typeof createRunner !== 'function') {
    return { kind: 'error', text: '扫描器不可用。' }
  }
  const runner = createRunner({ cwd })
  const root = await detectRepo(runner, cwd)
  if (root === null) return { kind: 'error', text: `当前目录不在 git 仓库内：${path.resolve(cwd)}` }

  const rules = compileRules(config)
  const full = await scanFullRepo(runner, {
    rules,
    config,
    cwd: root,
    readBlobs: options => readBlobsBatch({ ...options, timeoutMs: config.gitTimeoutMs }),
  })
  const staged = await scanCommit(runner, {
    op: { kind: 'commit', cwd, flags: { all: false }, messages: [], messageFile: undefined },
    rules,
    config,
  })
  if (full.error !== undefined) return { kind: 'error', text: `全仓扫描失败：${full.error}` }
  if (staged.error !== undefined) return { kind: 'error', text: `暂存区扫描失败：${staged.error}` }

  const merged = {
    findings: dedupeFindings([...full.findings, ...staged.findings]),
    incomplete: full.incomplete === true || staged.incomplete === true,
    notes: [...(full.notes ?? []), ...(staged.notes ?? [])],
    filesScanned: full.filesScanned ?? 0,
  }
  const approved = effectiveApprovedIds({
    config,
    root,
    sessionId: deps.sessionId,
    globalDocument: loadWhitelist(config.whitelistFile),
  })
  const { blocked, whitelisted } = splitWhitelisted(merged.findings, approved.ids)
  return success(
    renderScanReport({
      root,
      result: { ...merged, findings: blocked },
      whitelistedCount: whitelisted.length,
    }),
  )
}

/** Collapse control characters so command output stays one readable block. */
function sanitize(error) {
  const message = error instanceof Error ? error.message : String(error)
  return message.replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ').slice(0, 200)
}
