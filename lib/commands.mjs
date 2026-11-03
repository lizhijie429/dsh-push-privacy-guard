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
import { clearWhitelist, loadWhitelist, removeByPrefix, whitelistIds } from './whitelist.mjs'
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
  const { config, cwd, createRunner, scanRepository } = deps
  const argv = String(rawInput ?? '')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
  const subcommand = (argv[0] ?? 'help').toLowerCase()

  try {
    switch (subcommand) {
      case 'list':
        return success(renderWhitelist(loadWhitelist(config.whitelistFile)))
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

async function scan({ config, cwd, createRunner }, injectedScan) {
  if (typeof injectedScan === 'function') {
    const { root, result } = await injectedScan({ config, cwd })
    const findings = dedupeFindings(result.findings)
    const { blocked, whitelisted } = splitWhitelisted(findings, whitelistIds(loadWhitelist(config.whitelistFile)))
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
  const whitelist = whitelistIds(loadWhitelist(config.whitelistFile))
  const { blocked, whitelisted } = splitWhitelisted(merged.findings, whitelist)
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
