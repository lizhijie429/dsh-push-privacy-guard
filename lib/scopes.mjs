/**
 * Scoped allow storage: process-global whitelist, per-repository project
 * whitelist, and per-session in-memory approvals.
 *
 * Precedence: project deny > session/global/project allow. A project file can
 * therefore tighten a globally approved value for that repository, which is the
 * "project overrides global" rule.
 *
 * @module dsh-push-privacy-guard/scopes
 */

import fs from 'node:fs'
import path from 'node:path'

import { emptyWhitelist, entryForFinding, loadWhitelist, whitelistIds } from './whitelist.mjs'
import { serialize, writeJsonAtomic } from './store.mjs'

/** Approved entries that live only in this process, keyed by session id. */
const sessionStore = new Map()

/** Most recent blocked findings per session, for `pending` / `allow last`. */
const pendingStore = new Map()

/** Resolve the project whitelist file for one repository root. */
export function projectWhitelistPath(root, config) {
  const configured = String(config?.projectWhitelistFile ?? '').trim()
  const relative = configured.length > 0 ? configured : '.dsh/privacy-guard-whitelist.json'
  return path.isAbsolute(relative) ? relative : path.join(root, relative)
}

/** Whether project-scoped whitelists are enabled by configuration. */
export function projectWhitelistEnabled(config) {
  return config?.projectWhitelistEnabled !== false && config?.projectWhitelistFile !== false
}

/** Whether repository-authored allow entries may be trusted automatically. */
export function projectWhitelistTrusted(config) {
  return config?.trustProjectWhitelist !== false
}

/**
 * Resolve the project whitelist file and prove it stays inside the repository.
 * Rejects `..` escapes and symlinked path components so a cloned repository
 * cannot redirect reads or writes outside its own root.
 *
 * @returns {{file:string|null,safe:boolean,reason?:string}}
 */
export function resolveProjectFile(root, config) {
  if (!projectWhitelistEnabled(config)) return { file: null, safe: false, reason: 'disabled' }
  let rootReal
  try {
    rootReal = fs.realpathSync(root)
  } catch {
    return { file: null, safe: false, reason: 'repository-unreadable' }
  }
  const candidate = path.resolve(projectWhitelistPath(root, config))
  const relative = path.relative(rootReal, candidate)
  if (relative.length === 0 || relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) {
    return { file: null, safe: false, reason: 'outside-repository' }
  }
  // Inspect the nearest existing ancestor: a symlinked `.dsh` directory would
  // pass lexical containment but still point outside the repository.
  let cursor = candidate
  while (!fs.existsSync(cursor)) {
    const parent = path.dirname(cursor)
    if (parent === cursor) break
    cursor = parent
  }
  try {
    const cursorReal = fs.realpathSync(cursor)
    const cursorRelative = path.relative(rootReal, cursorReal)
    if (cursorRelative.startsWith('..') || path.isAbsolute(cursorRelative)) {
      return { file: null, safe: false, reason: 'symlink-outside-repository' }
    }
    let current = rootReal
    for (const segment of relative.split(path.sep)) {
      current = path.join(current, segment)
      if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
        return { file: null, safe: false, reason: 'symlink-path' }
      }
    }
  } catch {
    return { file: null, safe: false, reason: 'path-unreadable' }
  }
  return { file: candidate, safe: true }
}

/**
 * Load a project whitelist document. Missing files are an empty document;
 * unsafe paths (outside the repository or via symlinks) and untrusted
 * repository-owned allow entries are ignored with a warning.
 */
export function loadProjectWhitelist(root, config) {
  const resolved = resolveProjectFile(root, config)
  if (!resolved.safe) {
    return {
      file: projectWhitelistPath(root, config),
      document: emptyWhitelist(),
      allowed: [],
      denied: [],
      warning: resolved.reason === 'disabled' ? undefined : `project whitelist ignored: ${resolved.reason}`,
    }
  }
  const document = loadWhitelist(resolved.file)
  if (!projectWhitelistTrusted(config) && document.entries.length > 0) {
    return {
      file: resolved.file,
      document: emptyWhitelist(),
      allowed: [],
      denied: [],
      warning: 'project allow entries ignored because trustProjectWhitelist=false',
    }
  }
  const allowed = []
  const denied = []
  for (const entry of document.entries) {
    if (entry.allowed === false) denied.push(entry)
    else allowed.push(entry)
  }
  return { file: resolved.file, document, allowed, denied, warning: document.warning }
}

/** Session id from an agent/session view; null when the host exposes no id. */
export function sessionIdOf(agentOrSession) {
  const session = agentOrSession?.session ?? agentOrSession
  const id = session?.id ?? session?.header?.id
  return typeof id === 'string' && id.length > 0 ? id : null
}

/** Whether a session bucket is usable (never fall back to a shared bucket). */
export function hasSession(sessionId) {
  return typeof sessionId === 'string' && sessionId.length > 0
}

/** Approved identities from the in-memory session bucket. */
export function sessionIds(sessionId) {
  if (!hasSession(sessionId)) return new Set()
  const entries = sessionStore.get(sessionId)
  return entries === undefined ? new Set() : new Set(entries.keys())
}

/** Session entries (for listing). */
export function sessionEntries(sessionId) {
  if (!hasSession(sessionId)) return []
  return [...(sessionStore.get(sessionId)?.values() ?? [])]
}

/** Add findings to a session bucket. */
export function addSessionEntries(sessionId, findings, options = {}) {
  if (!hasSession(sessionId)) return { added: 0, total: 0, error: 'no-session' }
  let entries = sessionStore.get(sessionId)
  if (entries === undefined) {
    entries = new Map()
    sessionStore.set(sessionId, entries)
  }
  let added = 0
  for (const finding of Array.isArray(findings) ? findings : []) {
    if (typeof finding?.identity !== 'string' || finding.identity.length === 0) continue
    if (entries.has(finding.identity)) continue
    entries.set(finding.identity, entryForFinding(finding, { source: 'session', ...options }))
    added += 1
  }
  return { added, total: entries.size }
}

/** Remove one session entry by id prefix. */
export function removeSessionByPrefix(sessionId, prefix) {
  if (!hasSession(sessionId)) return { removed: [], error: 'no-session' }
  const entries = sessionStore.get(sessionId)
  const query = String(prefix ?? '').trim().toLowerCase()
  if (entries === undefined) return { removed: [], error: 'no-match' }
  if (query.length === 0) return { removed: [], error: 'empty-prefix' }
  const matches = [...entries.values()].filter(entry => entry.id.toLowerCase().startsWith(query))
  if (matches.length === 0) return { removed: [], error: 'no-match' }
  if (matches.length > 1) return { removed: [], error: 'ambiguous', candidates: matches.slice(0, 10) }
  entries.delete(matches[0].id)
  return { removed: [matches[0]] }
}

/** Drop every session entry for one session. */
export function clearSession(sessionId) {
  if (!hasSession(sessionId)) return { removed: 0, error: 'no-session' }
  const entries = sessionStore.get(sessionId)
  const removed = entries === undefined ? 0 : entries.size
  sessionStore.delete(sessionId)
  return { removed }
}

/** Forget a session entirely (session/end cleanup hook). */
export function forgetSession(sessionId) {
  clearSession(sessionId)
  pendingStore.delete(sessionId)
}

/** Cap the number of remembered sessions to bound long-running memory. */
export function pruneSessions(maxSessions = 200) {
  if (sessionStore.size <= maxSessions) return 0
  const excess = sessionStore.size - maxSessions
  let removed = 0
  for (const key of sessionStore.keys()) {
    if (removed >= excess) break
    sessionStore.delete(key)
    pendingStore.delete(key)
    removed += 1
  }
  return removed
}

/** Remember the blocked findings of the last command for later `allow`. */
export function rememberPending(sessionId, blocked) {
  if (!hasSession(sessionId)) return 0
  const findings = new Map()
  for (const finding of Array.isArray(blocked) ? blocked : []) {
    if (typeof finding?.identity !== 'string' || finding.identity.length === 0) continue
    findings.set(finding.identity, {
      identity: finding.identity,
      ruleId: finding.ruleId,
      label: finding.label ?? finding.ruleId,
      masked: finding.masked ?? '',
      file: finding.file ?? '',
      line: finding.line,
      severity: finding.severity ?? 'high',
    })
  }
  pendingStore.set(sessionId, { at: Date.now(), findings })
}

/** Recent blocked findings for one session. */
export function pendingFor(sessionId) {
  if (!hasSession(sessionId)) return []
  return [...(pendingStore.get(sessionId)?.findings.values() ?? [])]
}

/** Recent blocked findings across sessions (settings page). */
export function pendingSummaries(limit = 100) {
  const seen = new Map()
  for (const [sessionId, state] of pendingStore) {
    for (const finding of state.findings.values()) {
      if (seen.has(finding.identity)) continue
      seen.set(finding.identity, { ...finding, sessionId })
      if (seen.size >= limit) return [...seen.values()]
    }
  }
  return [...seen.values()]
}

/** Resolve one identity prefix against the pending findings of a session. */
export function pendingMatch(sessionId, target) {
  if (!hasSession(sessionId)) return { error: 'no-session' }
  const query = String(target ?? '').trim().toLowerCase()
  if (query.length === 0) return { error: 'empty-target' }
  if (query === 'last') {
    const all = pendingFor(sessionId)
    return all.length === 0 ? { error: 'no-pending' } : { findings: all }
  }
  const matches = pendingFor(sessionId).filter(finding => finding.identity.toLowerCase().startsWith(query))
  if (matches.length === 0) return { error: 'no-match' }
  if (matches.length > 1) return { error: 'ambiguous', candidates: matches.slice(0, 10) }
  return { findings: matches }
}

/**
 * Effective approved identities for one repository plus session.
 *
 * @param {{config:object,root?:string,sessionId?:string,globalDocument?:object}} input
 * @returns {{ids:Set<string>,projectAllow:number,projectDeny:number,session:number,warnings:string[]}}
 */
export function effectiveApprovedIds({ config, root, sessionId, globalDocument }) {
  const ids = whitelistIds(globalDocument)
  const warnings = []
  const denied = new Set()
  let projectAllow = 0
  let projectDeny = 0
  if (typeof root === 'string' && root.length > 0 && config.projectWhitelistFile !== false) {
    const project = loadProjectWhitelist(root, config)
    if (project.warning !== undefined) warnings.push(project.warning)
    for (const entry of project.denied) {
      ids.delete(entry.id)
      denied.add(entry.id)
      projectDeny += 1
    }
    for (const entry of project.allowed) {
      ids.add(entry.id)
      projectAllow += 1
    }
  }
  if (typeof sessionId === 'string' && sessionId.length > 0) {
    for (const id of sessionIds(sessionId)) ids.add(id)
  }
  // Project revokes win over every allow source, including the session.
  for (const id of denied) ids.delete(id)
  return {
    ids,
    projectAllow,
    projectDeny,
    session: hasSession(sessionId) ? sessionIds(sessionId).size : 0,
    warnings,
  }
}

/** Persist approved findings into a project whitelist file. */
export function addProjectApproved(root, config, findings, options = {}) {
  const resolved = resolveProjectFile(root, config)
  if (!resolved.safe) {
    return Promise.resolve({ added: 0, updated: 0, total: 0, ids: [], file: null, error: resolved.reason })
  }
  return serialize(resolved.file, async () => {
    const document = loadWhitelist(resolved.file)
    const entries = [...document.entries]
    const index = new Map(entries.map((entry, position) => [entry.id, position]))
    const ids = []
    let updated = 0
    for (const finding of Array.isArray(findings) ? findings : []) {
      if (typeof finding?.identity !== 'string' || finding.identity.length === 0) continue
      const position = index.get(finding.identity)
      if (position !== undefined) {
        // A project revoke entry must be flippable back to allow; otherwise the
        // tool/command reports success while the item stays blocked.
        if (entries[position].allowed === false) {
          entries[position] = { ...entries[position], allowed: true, addedAt: options.now ?? new Date().toISOString(), source: 'project' }
          updated += 1
          ids.push(finding.identity)
        }
        continue
      }
      const entry = { ...entryForFinding(finding, { source: 'project', ...options }), allowed: true }
      entries.push(entry)
      index.set(entry.id, entries.length - 1)
      ids.push(entry.id)
    }
    ensureProjectDir(resolved.file)
    if (ids.length > 0) writeJsonAtomic(resolved.file, { version: 1, entries })
    return { added: ids.length - updated, updated, total: entries.length, ids, file: resolved.file }
  })
}

/** Remove one project entry by id prefix. */
export function removeProjectByPrefix(root, config, prefix) {
  const resolved = resolveProjectFile(root, config)
  if (!resolved.safe) return Promise.resolve({ removed: [], error: resolved.reason })
  return serialize(resolved.file, async () => {
    const document = loadWhitelist(resolved.file)
    const query = String(prefix ?? '').trim().toLowerCase()
    if (query.length === 0) return { removed: [], error: 'empty-prefix' }
    const matches = document.entries.filter(entry => entry.id.toLowerCase().startsWith(query))
    if (matches.length === 0) return { removed: [], error: 'no-match' }
    if (matches.length > 1) return { removed: [], error: 'ambiguous', candidates: matches.slice(0, 10) }
    const entries = document.entries.filter(entry => entry.id !== matches[0].id)
    writeJsonAtomic(resolved.file, { version: 1, entries })
    return { removed: [matches[0]] }
  })
}

/** Clear the project whitelist (keeps the file as an empty document). */
export function clearProjectWhitelist(root, config) {
  const resolved = resolveProjectFile(root, config)
  if (!resolved.safe) return Promise.resolve({ removed: 0, error: resolved.reason })
  return serialize(resolved.file, async () => {
    const document = loadWhitelist(resolved.file)
    const removed = document.entries.length
    writeJsonAtomic(resolved.file, { version: 1, entries: [] })
    return { removed }
  })
}

/** Ensure the project whitelist directory exists. */
function ensureProjectDir(file) {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true })
  } catch {
    /* writeJsonAtomic reports the real error */
  }
}

/** Empty document helper for tests/tools. */
export function emptyProjectWhitelist() {
  return emptyWhitelist()
}
