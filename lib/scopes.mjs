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
import { writeJsonAtomic } from './store.mjs'

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

/**
 * Load a project whitelist document. Missing files are an empty document;
 * corrupt files log a warning and count as empty (fail-open for read, but the
 * project file never grants more than it contains).
 */
export function loadProjectWhitelist(root, config) {
  const file = projectWhitelistPath(root, config)
  const document = loadWhitelist(file)
  const allowed = []
  const denied = []
  for (const entry of document.entries) {
    if (entry.allowed === false) denied.push(entry)
    else allowed.push(entry)
  }
  return { file, document, allowed, denied, warning: document.warning }
}

/** Session id from an agent/session view; falls back to one shared bucket. */
export function sessionIdOf(agentOrSession) {
  const session = agentOrSession?.session ?? agentOrSession
  const id = session?.id ?? session?.header?.id
  return typeof id === 'string' && id.length > 0 ? id : '__shared__'
}

/** Approved identities from the in-memory session bucket. */
export function sessionIds(sessionId) {
  const entries = sessionStore.get(sessionId)
  return entries === undefined ? new Set() : new Set(entries.keys())
}

/** Session entries (for listing). */
export function sessionEntries(sessionId) {
  return [...(sessionStore.get(sessionId)?.values() ?? [])]
}

/** Add findings to a session bucket. */
export function addSessionEntries(sessionId, findings, options = {}) {
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
  const entries = sessionStore.get(sessionId)
  const removed = entries === undefined ? 0 : entries.size
  sessionStore.delete(sessionId)
  return { removed }
}

/** Remember the blocked findings of the last command for later `allow`. */
export function rememberPending(sessionId, blocked) {
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
  return [...(pendingStore.get(sessionId)?.findings.values() ?? [])]
}

/** Resolve one identity prefix against the pending findings of a session. */
export function pendingMatch(sessionId, target) {
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
    session: sessionId === undefined ? 0 : sessionIds(sessionId).size,
    warnings,
  }
}

/** Persist approved findings into a project whitelist file. */
export function addProjectApproved(root, config, findings, options = {}) {
  const file = projectWhitelistPath(root, config)
  const document = loadWhitelist(file)
  const existing = new Set(document.entries.map(entry => entry.id))
  const ids = []
  const entries = [...document.entries]
  for (const finding of Array.isArray(findings) ? findings : []) {
    if (typeof finding?.identity !== 'string' || finding.identity.length === 0) continue
    if (existing.has(finding.identity)) continue
    const entry = { ...entryForFinding(finding, { source: 'project', ...options }), allowed: true }
    entries.push(entry)
    existing.add(entry.id)
    ids.push(entry.id)
  }
  ensureProjectDir(file)
  if (ids.length > 0) writeJsonAtomic(file, { version: 1, entries })
  return { added: ids.length, total: entries.length, ids, file }
}

/** Remove one project entry by id prefix. */
export function removeProjectByPrefix(root, config, prefix) {
  const file = projectWhitelistPath(root, config)
  const document = loadWhitelist(file)
  const query = String(prefix ?? '').trim().toLowerCase()
  if (query.length === 0) return { removed: [], error: 'empty-prefix' }
  const matches = document.entries.filter(entry => entry.id.toLowerCase().startsWith(query))
  if (matches.length === 0) return { removed: [], error: 'no-match' }
  if (matches.length > 1) return { removed: [], error: 'ambiguous', candidates: matches.slice(0, 10) }
  const entries = document.entries.filter(entry => entry.id !== matches[0].id)
  writeJsonAtomic(file, { version: 1, entries })
  return { removed: [matches[0]] }
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
