/**
 * Conversation-facing `privacy_guard` tool.
 *
 * Lets the user manage allow decisions from chat ("放行最后一条，本项目生效").
 * Mutations always require a fresh DSH approval, so a model cannot widen its
 * own permissions silently; `session` decisions live only in memory, `project`
 * decisions are written to the repository's project whitelist, and `global`
 * decisions go to the user-level whitelist.
 *
 * @module dsh-push-privacy-guard/tool
 */

import { addApproved, loadWhitelist } from './whitelist.mjs'
import {
  addProjectApproved,
  addSessionEntries,
  clearSession,
  loadProjectWhitelist,
  pendingFor,
  pendingMatch,
  projectWhitelistPath,
  removeProjectByPrefix,
  removeSessionByPrefix,
  sessionEntries,
  effectiveApprovedIds,
} from './scopes.mjs'
import { detectRepo } from './scan.mjs'
import { createGitRunner } from './git.mjs'
import { resolveSessionCwd } from './guard.mjs'

const ACTIONS = ['status', 'list', 'pending', 'allow', 'revoke']
const SCOPES = ['global', 'project', 'session']

const PARAMETERS = {
  type: 'object',
  additionalProperties: false,
  properties: {
    action: {
      type: 'string',
      enum: ACTIONS,
      description: 'Operation: status/list/pending inspect; allow/revoke change an allow decision.',
    },
    scope: {
      type: 'string',
      enum: SCOPES,
      description: 'global = user whitelist, project = repository whitelist (overrides global), session = current conversation only.',
    },
    target: {
      type: 'string',
      description: 'Identity id or unique id prefix from `pending`/`list`; use `last` for every finding of the most recent blocked command.',
    },
  },
  required: ['action'],
}

const OUTPUT = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ok: { type: 'boolean' },
    text: { type: 'string' },
  },
  required: ['ok', 'text'],
}

/**
 * Build the tool definition without importing `@deepseek-ai/dsh-tools`
 * (external plugins cannot resolve host packages).
 *
 * @param {{ctx:any,config:object,log?:(line:string)=>void}} options
 */
export function createPrivacyTool({ ctx, config, log = () => {} }) {
  return {
    name: 'privacy_guard',
    description:
      'Manage commit/push privacy decisions from the conversation. Inspect pending blocked items and allow or revoke them globally, per repository (overrides global), or for the current session only. Mutations always require user approval in the DSH approval panel.',
    parameters: PARAMETERS,
    timeoutMs: 120000,
    isConcurrencySafe: () => false,
    output: {
      schema: OUTPUT,
      render(_args, value) {
        return [{ type: 'text', text: value?.text ?? '' }]
      },
    },
    async execute(args, exec) {
      try {
        if (args === null || typeof args !== 'object' || Array.isArray(args)) {
          return result(false, '参数必须是对象。')
        }
        const action = String(args?.action ?? '')
        if (!ACTIONS.includes(action)) return result(false, `未知 action：${action}`)
        if (args.scope !== undefined && !SCOPES.includes(String(args.scope))) {
          return result(false, `未知 scope：${String(args.scope)}`)
        }
        if (action === 'allow' || action === 'revoke') {
          if (typeof args.target !== 'string' || args.target.trim().length === 0) {
            return result(false, 'allow/revoke 需要 target（id 前缀或 last）。')
          }
          const normalized = SCOPES.includes(String(args.scope)) ? String(args.scope) : config.approvalScope
          return await mutate({ ctx, config, log, action, scope: normalized, target: args.target.trim(), exec })
        }
        return await inspect({ ctx, config, action, exec })
      } catch (error) {
        log(`tool.error message=${sanitize(error)}`)
        return result(false, `privacy_guard 执行失败：${sanitize(error)}`)
      }
    },
  }
}

/** Register the tool on the host tool registry (disposer returned by tools.register). */
export function registerPrivacyTool(ctx, { config, log = () => {} }) {
  if (typeof ctx?.tools?.register !== 'function') {
    log('tool.register-failed reason=no-tools-registry')
    return () => {}
  }
  return ctx.tools.register(createPrivacyTool({ ctx, config, log }))
}

async function inspect({ ctx, config, action, exec }) {
  const { root } = await contextOf({ ctx, config, exec })
  const sessionId = sessionIdFrom(exec)
  if (action === 'status') {
    const global = loadWhitelist(config.whitelistFile)
    const approved = effectiveApprovedIds({ config, root, sessionId, globalDocument: global })
    const lines = [
      `enabled=${config.enabled} commit=${config.interceptCommit} push=${config.interceptPush} approvalScope=${config.approvalScope}`,
      `global=${global.entries.length} projectAllow=${approved.projectAllow} projectDeny=${approved.projectDeny} session=${approved.session}`,
      root === null ? '当前目录不在 git 仓库内。' : `仓库：${root}`,
    ]
    return result(true, lines.join('\n'))
  }
  if (action === 'pending') {
    const findings = pendingFor(sessionId)
    if (findings.length === 0) return result(true, '最近没有待处理的命中。')
    const lines = ['最近一次被拦截的命中：']
    for (const finding of findings.slice(0, 20)) {
      lines.push(`- ${finding.identity} [${finding.ruleId}] ${finding.masked ?? ''} ${finding.file ?? ''}`)
    }
    return result(true, lines.join('\n'))
  }
  const entries = sessionEntries(sessionId)
  const parts = [`全局白名单：${loadWhitelist(config.whitelistFile).entries.length} 条`]
  if (root !== null) {
    const project = loadProjectWhitelist(root, config)
    parts.push(
      `项目白名单（${project.file}）：${project.document.entries.length} 条` +
        (project.document.entries.length === 0 ? '' : `\n${formatEntries(project.document.entries)}`),
    )
  }
  parts.push(`会话白名单：${entries.length} 条${entries.length === 0 ? '' : `\n${formatEntries(entries)}`}`)
  return result(true, parts.join('\n\n'))
}

async function mutate({ ctx, config, action, scope, target, exec }) {
  if (exec?.agent === undefined) return result(false, '该工具需要 agent 会话。')
  const sessionId = sessionIdFrom(exec)
  if (sessionId === null && scope === 'session') {
    return result(false, '当前会话没有稳定的 session id，无法使用会话级放行；请改用 project 或 global。')
  }
  const resolved = resolveTarget(sessionId, target)
  if (resolved.error !== undefined) return result(false, resolved.error)
  const findings = resolved.findings
  const approval = await requestApproval(ctx, exec, {
    action,
    scope,
    findings,
    repo: (await contextOf({ ctx, config, exec })).root,
  })
  if (approval !== 'allowed-once') {
    return result(false, `用户未批准（${approval}），未修改放行配置。`)
  }
  if (action === 'allow') {
    if (scope === 'session') {
      const added = addSessionEntries(sessionId, findings)
      if (added.error !== undefined) return result(false, '会话级放行不可用。')
      return result(true, `已加入会话白名单：${added.added} 条（仅当前会话）。`)
    }
    if (scope === 'project') {
      const root = (await contextOf({ ctx, config, exec })).root
      if (root === null) return result(false, '当前目录不在 git 仓库内，无法写入项目白名单。')
      const added = await addProjectApproved(root, config, findings)
      if (added.error !== undefined) return result(false, `项目白名单不可用：${added.error}`)
      return result(true, `已加入项目白名单：新增 ${added.added} 条，恢复 ${added.updated} 条（${added.file}）。`)
    }
    const added = await addApproved(config.whitelistFile, findings)
    return result(true, `已加入全局白名单：${added.added} 条。`)
  }
  if (scope === 'session') {
    const removed = removeSessionByPrefix(sessionId, target)
    return revokeResult(removed, '会话白名单')
  }
  if (scope === 'project') {
    const root = (await contextOf({ ctx, config, exec })).root
    if (root === null) return result(false, '当前目录不在 git 仓库内。')
    return revokeResult(await removeProjectByPrefix(root, config, target), '项目白名单')
  }
  const { removeByPrefix } = await import('./whitelist.mjs')
  return revokeResult(await removeByPrefix(config.whitelistFile, target), '全局白名单')
}

function resolveTarget(sessionId, target) {
  if (sessionId === null) {
    return { error: '当前会话没有稳定的 session id，无法查看待处理命中。' }
  }
  const match = pendingMatch(sessionId, target)
  if (match.error === 'empty-target') return { error: '请提供 target（id 前缀或 last）。' }
  if (match.error === 'no-pending') return { error: '最近没有待处理命中。' }
  if (match.error === 'no-match') {
    return { error: `没有匹配 "${target}" 的待处理命中；只能放行 pending 中列出的条目。` }
  }
  if (match.error === 'ambiguous') {
    return { error: `前缀匹配到多条，请提供更长的 id：${match.candidates.map(item => item.identity).join(', ')}` }
  }
  return { findings: match.findings }
}

async function contextOf({ ctx, config, exec }) {
  const cwd = resolveSessionCwd(ctx, exec?.agent?.session)
  if (typeof cwd !== 'string' || cwd.length === 0) return { cwd, root: null }
  try {
    const runner = createGitRunner({ cwd, timeoutMs: config.gitTimeoutMs })
    return { cwd, root: await detectRepo(runner, cwd) }
  } catch {
    return { cwd, root: null }
  }
}

async function requestApproval(ctx, exec, { action, scope, findings, repo }) {
  let approval
  try {
    approval = ctx.get?.('approval')
  } catch {
    approval = undefined
  }
  if (approval === undefined || typeof approval.request !== 'function') return 'unavailable'
  const verbEn = action === 'allow' ? 'Add' : 'Remove'
  const verbZh = action === 'allow' ? '加入' : '撤销'
  const items = Array.isArray(findings) ? findings : []
  const shownEn = items
    .slice(0, 5)
    .map(item => `- [${item.ruleId}] ${item.masked ?? ''} (${item.file ?? 'unknown'}, id ${item.identity})`)
    .join('\n')
  const shownZh = items
    .slice(0, 5)
    .map(item => `- [${item.ruleId}] ${item.masked ?? ''}（${item.file ?? '未知文件'}，id ${item.identity}）`)
    .join('\n')
  const moreEn = items.length > 5 ? `\n… ${items.length - 5} more` : ''
  const moreZh = items.length > 5 ? `\n… 另有 ${items.length - 5} 条` : ''
  const reason =
    `Privacy guard: ${verbEn.toLowerCase()} ${items.length} allow decision(s) in scope "${scope}"` +
    (repo ? ` for repository ${repo}` : '') +
    `; items: ${items.map(item => `${item.ruleId}:${item.identity}`).join(', ')}`
  try {
    return await approval.request({
      agent: exec.agent,
      toolName: exec.name,
      callId: exec.callId,
      reason,
      displayReason: {
        en: `${verbEn} ${items.length} privacy allow decision(s) in scope "${scope}"${repo ? ` for ${repo}` : ''}?\n${shownEn}${moreEn}`,
        zh: `${verbZh} ${items.length} 条隐私放行配置（范围：${scope}${repo ? `，仓库：${repo}` : ''}）？\n${shownZh}${moreZh}`,
      },
      signal: exec.signal,
    })
  } catch (error) {
    return 'error'
  }
}

function sessionIdFrom(exec) {
  const session = exec?.agent?.session
  const id = session?.id ?? session?.header?.id
  return typeof id === 'string' && id.length > 0 ? id : null
}

function revokeResult(removed, label) {
  if (removed.error === 'no-match') return result(false, `${label}没有匹配条目。`)
  if (removed.error === 'empty-prefix') return result(false, 'id 前缀不能为空。')
  if (removed.error === 'ambiguous') {
    return result(false, `前缀匹配到多条：${removed.candidates.map(item => item.id).join(', ')}`)
  }
  return result(true, `已从${label}删除 ${removed.removed[0].id}。`)
}

function formatEntries(entries) {
  return entries
    .slice(0, 20)
    .map(entry => `- ${entry.id} [${entry.rule}] ${entry.masked ?? ''}`)
    .join('\n')
}

function result(ok, text) {
  return { ok, text }
}

function sanitize(error) {
  const message = error instanceof Error ? error.message : String(error)
  return message.replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ').slice(0, 200)
}

export { PARAMETERS as TOOL_PARAMETERS, OUTPUT as TOOL_OUTPUT, projectWhitelistPath, clearSession }
