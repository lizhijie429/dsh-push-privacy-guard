/**
 * Model- and human-facing text.
 *
 * Model-visible text never contains a matched value; approval and command text
 * use masked previews from the scanner. Both languages are provided for the
 * approval `displayReason` (`{ en, zh }`) so the Web UI can localize it.
 *
 * Pure module: no I/O, no Cordis.
 *
 * @module dsh-push-privacy-guard/messages
 */

const ACTION = {
  commit: { en: 'git commit', zh: 'git commit' },
  push: { en: 'git push', zh: 'git push' },
  sync: { en: 'gh repo sync', zh: 'gh repo sync' },
}

const NOTE_TEXT = {
  'diff-too-large': { en: 'the diff exceeded the scan size limit', zh: '差异超过扫描大小上限' },
  'commit-count-limit': { en: 'the commit count exceeded the limit, so only final content was scanned', zh: '待推送提交数超过上限，仅扫描了最终内容' },
  'file-limit': { en: 'the repository file-count limit was reached', zh: '全仓文件数达到上限' },
  'total-size-limit': { en: 'the total scan size limit was reached', zh: '全仓扫描总大小达到上限' },
  'finding-limit': { en: 'the finding count exceeded the limit', zh: '命中数量超过上限' },
  'branch-limit': { en: 'the branch limit was reached', zh: '分支数达到上限' },
  'mirror-ignores-tags': { en: 'mirror tag objects are not scanned', zh: '镜像推送的 tag 未单独扫描' },
  'message-file-unreadable': { en: 'the commit message file could not be read', zh: '提交信息文件无法读取' },
  'no-head': { en: 'the repository has no commits yet', zh: '仓库还没有提交' },
}

/** Human-readable reason for one scan note. */
export function describeNote(note, lang = 'zh') {
  const key = String(note)
  if (key.startsWith('files-skipped:')) {
    const count = key.slice('files-skipped:'.length)
    return lang === 'zh' ? `跳过了 ${count} 个过大或不可读的文件` : `skipped ${count} oversized or unreadable file(s)`
  }
  const text = NOTE_TEXT[key]
  return text === undefined ? key : text[lang] ?? text.en
}

/** Render the scan notes for one language. */
export function describeNotes(notes, lang = 'zh') {
  const items = (Array.isArray(notes) ? notes : []).map(note => describeNote(note, lang)).filter(Boolean)
  return items.length === 0 ? '' : items.join(lang === 'zh' ? '；' : '; ')
}

/** One bullet for a deduped finding; only masked / user-local previews appear. */
function renderFindingLine(finding, index, lang) {
  const location = Array.isArray(finding.locations) ? finding.locations[0] : undefined
  const preview = location?.preview ?? finding.preview ?? finding.masked ?? ''
  const place = location === undefined ? '' : `${location.file}:${location.line}`
  const count = finding.count > 1 ? (lang === 'zh' ? `（共 ${finding.count} 处）` : ` (${finding.count} places)`) : ''
  return `${index + 1}. [${finding.label}] ${preview}${place === '' ? '' : ` — ${place}`}${count}`
}

/**
 * Approval request for unapproved findings.
 *
 * @param {{action:'commit'|'push'|'sync',repo:string,findings:object[],whitelistedCount?:number,incomplete?:boolean,notes?:string[],maxItems?:number}} input
 * @returns {{reason:string,displayReason:{en:string,zh:string}}}
 */
export function buildFindingsApproval({
  action,
  repo,
  findings,
  whitelistedCount = 0,
  incomplete = false,
  whitelistOnApprove = true,
  approvalScope = 'global',
  projectWhitelistFile = '',
  notes = [],
  maxItems = 20,
}) {
  const items = Array.isArray(findings) ? findings : []
  const actionEn = ACTION[action]?.en ?? 'git push'
  const noteEn = describeNotes(notes, 'en')
  const noteZh = describeNotes(notes, 'zh')
  const scopeEn =
    approvalScope === 'project'
      ? `the project whitelist (${projectWhitelistFile || '.dsh/privacy-guard-whitelist.json'})`
      : approvalScope === 'session'
        ? 'this session only (in-memory)'
        : 'the global whitelist'
  const scopeZh =
    approvalScope === 'project'
      ? `项目级白名单（${projectWhitelistFile || '.dsh/privacy-guard-whitelist.json'}）`
      : approvalScope === 'session'
        ? '仅当前会话（内存）'
        : '全局白名单'

  // Nothing was matched, but the scan could not cover everything: ask for an
  // explicit decision without pretending there are findings.
  if (items.length === 0) {
    const reason =
      `Privacy guard: the privacy scan of ${actionEn} content (repository ${repo}) was incomplete; ` +
      'user approval required before continuing.'
    const en = [
      `Privacy check could not complete for ${actionEn} (repository ${repo}).`,
      `The scan was incomplete${noteEn === '' ? '' : ` (${noteEn})`}, so unapproved sensitive content may still be present.`,
      'Approve: continue with this command.',
      'Reject: block it.',
      `Whitelist: /privacy-guard pending | allow <id|last> [global|project|session]; approved items go to ${scopeEn}.`,
    ].join('\n')
    const zh = [
      `隐私检查未能完整扫描 ${actionEn}（仓库：${repo}）。`,
      `扫描不完整${noteZh === '' ? '' : `（${noteZh}）`}，可能仍含未授权的敏感信息。`,
      '批准：仍然继续本次命令；拒绝：阻止本次命令。',
      `白名单管理：/privacy-guard pending | allow <id|last> [global|project|session]；本次写入${scopeZh}。`,
    ].join('\n')
    return { reason, displayReason: { en, zh } }
  }

  const shown = items.slice(0, Math.max(1, maxItems))
  const hidden = items.length - shown.length

  const reason =
    `Privacy guard: ${items.length} unapproved sensitive item(s) in ${actionEn} content ` +
    `(repository ${repo}); user approval required.` +
    (incomplete ? ' The scan was incomplete.' : '')

  const en = [
    `Privacy check found ${items.length} unapproved sensitive item(s) in ${actionEn} (repository ${repo}):`,
    ...shown.map((finding, index) => renderFindingLine(finding, index, 'en')),
    hidden > 0 ? `… ${hidden} more item(s) not listed.` : '',
    whitelistOnApprove
      ? `Approve: continue this time and add these items to ${scopeEn}. Reject: block this command.`
      : 'Approve: continue this time (whitelist update is disabled). Reject: block this command.',
    incomplete ? `Note: the scan was incomplete${noteEn === '' ? '' : ` (${noteEn})`}.` : '',
    whitelistedCount > 0 ? `${whitelistedCount} already-whitelisted item(s) were skipped.` : '',
    'Manage: /privacy-guard pending | allow <id|last> [global|project|session], or ask the assistant to use the privacy_guard tool.',
  ]
    .filter(line => line.length > 0)
    .join('\n')

  const zh = [
    `隐私检查发现 ${items.length} 处未授权敏感信息（${actionEn}，仓库：${repo}）：`,
    ...shown.map((finding, index) => renderFindingLine(finding, index, 'zh')),
    hidden > 0 ? `… 另有 ${hidden} 处未列出。` : '',
    whitelistOnApprove
      ? `批准：本次放行，并将上述信息加入${scopeZh}；拒绝：阻止本次命令。`
      : '批准：本次放行（白名单自动写入已关闭）；拒绝：阻止本次命令。',
    incomplete ? `注意：扫描不完整${noteZh === '' ? '' : `（${noteZh}）`}。` : '',
    whitelistedCount > 0 ? `已跳过 ${whitelistedCount} 处白名单内信息。` : '',
    '管理：/privacy-guard pending | allow <id|last> [global|project|session]，或让助手调用 privacy_guard 工具。',
  ]
    .filter(line => line.length > 0)
    .join('\n')

  return { reason, displayReason: { en, zh } }
}

/**
 * Approval question used once per repository before its first push.
 *
 * @param {string} repo
 * @returns {{reason:string,displayReason:{en:string,zh:string}}}
 */
export function buildFullScanQuestion(repo) {
  return {
    reason:
      `Privacy guard: first push from repository ${repo}; approve to scan every tracked file first, ` +
      'reject to check only this push from now on.',
    displayReason: {
      en: [
        `This is the first push from this repository through DSH: ${repo}`,
        'Approve = scan all tracked files first (git-ignored content is automatically excluded), then check this push.',
        'Reject = check only this push now, and only the pushed content for this repository from now on.',
      ].join('\n'),
      zh: [
        `该仓库首次通过 DSH 推送：${repo}`,
        '批准 = 先全仓库扫描已跟踪文件（自动忽略 .gitignore 的内容），再检查本次推送；',
        '拒绝 = 只检查本次推送内容，之后该仓库都只检查本次推送。',
      ].join('\n'),
    },
  }
}

/**
 * Model-visible denial reason. Contains no matched values.
 *
 * @param {{action:'commit'|'push'|'sync',outcome:'rejected'|'cancelled'|'unavailable'|'scan-failed'|'error',count?:number,detail?:string}} input
 * @returns {string}
 */
export function buildDenyReason({ action, outcome, count = 0, detail = '' }) {
  const command = ACTION[action]?.en ?? 'git push'
  const cleanDetail = String(detail)
    .replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ')
    .slice(0, 200)
  switch (outcome) {
    case 'rejected':
      return `privacy guard: blocked "${command}": ${count} unapproved sensitive item(s) would be uploaded and the user did not authorize them. Inspect them with /privacy-guard pending or the privacy_guard tool, then allow or revoke them explicitly.`
    case 'cancelled':
      return `privacy guard: blocked "${command}": the approval request was cancelled. Inspect pending items with /privacy-guard pending or the privacy_guard tool.`
    case 'unavailable':
      return `privacy guard: blocked "${command}": no user approval channel is available in this session.`
    case 'repo-unresolved':
      return `privacy guard: blocked "${command}": the repository could not be located${cleanDetail === '' ? '' : ` (${cleanDetail})`}. Rerun with an explicit workdir or \`git -C <absolute path>\`, or set unresolvedRepo=allow in the plugin config.`
    case 'persistent-shell':
      return `privacy guard: blocked "${command}": commands sent to a persistent terminal cannot be matched to that terminal's current directory. Use the one-shot pwsh/bash tool with an explicit workdir, or set persistentShellCommits=allow in the plugin config.`
    case 'scan-failed':
      return `privacy guard: blocked "${command}": the privacy scan could not complete (${cleanDetail === '' ? 'unknown error' : cleanDetail}).`
    default:
      return `privacy guard: blocked "${command}": privacy check failed.`
  }
}

/** `/privacy-guard help` text. */
export function renderHelp() {
  return [
    '推送隐私检查命令：',
    '  /privacy-guard list              列出全局 / 项目 / 会话白名单',
    '  /privacy-guard pending           查看最近一次被拦截的命中（id/掩码/文件）',
    '  /privacy-guard allow <id|last> [global|project|session]  放行命中（默认 approvalScope）',
    '  /privacy-guard revoke <id> [global|project|session]      撤销放行',
    '  /privacy-guard session [list|allow <id|last>|revoke <id>|clear]  仅当前会话有效',
    '  /privacy-guard project [list|allow <id|last>|revoke <id>|clear]        当前仓库有效（项目级优先）',
    '  /privacy-guard remove <id前缀>   删除全局白名单单条（前缀需唯一）',
    '  /privacy-guard clear confirm     清空全局白名单（需 confirm）',
    '  /privacy-guard status            查看开关、文件路径与计数',
    '  /privacy-guard repos             列出已初始化仓库',
    '  /privacy-guard reset <子串|all>  清除仓库初始化记录（下次推送重新询问全仓扫描）',
    '  /privacy-guard scan              立即扫描当前会话仓库（全仓 + 暂存区），不推送',
    '  /privacy-guard help              本帮助',
  ].join('\n')
}

/** `/privacy-guard list` text. */
export function renderWhitelist(document, { maxItems = 50 } = {}) {
  const entries = Array.isArray(document?.entries) ? document.entries : []
  if (entries.length === 0) return '白名单为空。授权通过的敏感信息会自动加入；也可手动编辑 whitelist.json。'
  const shown = entries.slice(0, maxItems)
  const lines = [`白名单：${entries.length} 条`, '']
  for (const entry of shown) {
    lines.push(`${entry.id}  [${entry.label ?? entry.rule}]  ${entry.masked ?? ''}  ${entry.firstFile ?? ''}  ${entry.addedAt ?? ''}`)
  }
  if (entries.length > shown.length) lines.push(`… 另有 ${entries.length - shown.length} 条未列出`)
  lines.push('', '管理：/privacy-guard remove <id前缀> | clear confirm')
  return lines.join('\n')
}

/** `/privacy-guard repos` text. */
export function renderRepos(state) {
  const repos = Object.values(state?.repos ?? {})
  if (repos.length === 0) return '暂无已初始化仓库；首次推送时会询问是否全仓扫描。'
  const lines = [`已初始化仓库：${repos.length} 个`, '']
  for (const repo of repos) {
    lines.push(`- ${repo.root}  (${repo.mode}, ${repo.initializedAt})`)
  }
  lines.push('', '重新询问全仓扫描：/privacy-guard reset <路径子串|all>')
  return lines.join('\n')
}

/** `/privacy-guard status` text. */
export function renderStatus({
  config,
  whitelist,
  repoState,
  rulesCount,
  currentRepo,
  initialized,
  project = null,
  sessionCount = 0,
}) {
  const rows = [
    `推送隐私检查：${config.enabled ? '已启用' : '已禁用'}`,
    `检查项：commit=${config.interceptCommit ? '开' : '关'}，push=${config.interceptPush ? '开' : '关'}，首次全仓扫描=${config.fullScanOnFirstPush}`,
    `授权后入白名单：${config.whitelistOnApprove ? '是' : '否'}；作用域=${config.approvalScope}；扫描不完整需授权：${config.requireApprovalOnIncompleteScan ? '是' : '否'}`,
    `项目白名单：${config.projectWhitelistEnabled === false ? '已禁用' : `启用（信任仓库条目=${config.trustProjectWhitelist === false ? '否' : '是'}）`}`,
    `规则：${rulesCount} 条`,
    `全局白名单：${whitelist?.entries?.length ?? 0} 条（${config.whitelistFile}）`,
    `已初始化仓库：${Object.keys(repoState?.repos ?? {}).length} 个`,
    `会话白名单：${sessionCount} 条（仅当前会话）`,
  ]
  if (typeof currentRepo === 'string' && currentRepo.length > 0) {
    rows.push(`当前仓库：${currentRepo}（${initialized ? '已初始化' : '首次推送将询问全仓扫描'}）`)
  }
  if (project !== null && project !== undefined) {
    rows.push(
      `项目白名单文件：${project.file ?? '（不可用）'}；允许 ${project.allowed?.length ?? 0} 条，撤销 ${project.denied?.length ?? 0} 条` +
        (project.warning ? `；警告：${project.warning}` : ''),
    )
  }
  return rows.join('\n')
}

/** `/privacy-guard scan` text (informational only). */
export function renderScanReport({ root, result, whitelistedCount = 0 }) {
  const findings = Array.isArray(result?.findings) ? result.findings : []
  const lines = [`扫描仓库：${root}`, `发现：${findings.length} 处${whitelistedCount > 0 ? `（另有 ${whitelistedCount} 处已在白名单）` : ''}`]
  const noteText = describeNotes(result?.notes, 'zh')
  if (result?.incomplete === true) lines.push(`扫描不完整：${noteText === '' ? '是' : noteText}`)
  else if (noteText !== '') lines.push(`说明：${noteText}`)
  if (findings.length > 0) {
    lines.push('')
    findings.slice(0, 20).forEach((finding, index) => lines.push(renderFindingLine(finding, index, 'zh')))
    if (findings.length > 20) lines.push(`… 另有 ${findings.length - 20} 处未列出`)
    lines.push('', '本次检查不会写入白名单；批准/拒绝只会在实际提交或推送时发生。')
  }
  lines.push(`已扫描文件：${result?.filesScanned ?? 0} 个`)
  return lines.join('\n')
}
