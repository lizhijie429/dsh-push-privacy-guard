/**
 * Per-repository initialization state.
 *
 * The first push from a repository may ask for a full-repository scan; whatever
 * the user chooses, the repository is then recorded here so later pushes only
 * check the content being pushed. `/privacy-guard reset` clears records so the
 * question is asked again.
 *
 * @module dsh-push-privacy-guard/repo-state
 */

import { createHash } from 'node:crypto'
import path from 'node:path'
import { readJson, serialize, writeJsonAtomic } from './store.mjs'

/** Current on-disk schema version. */
export const REPO_STATE_VERSION = 1

/** Stable short key for one repository root. */
export function repoKey(root) {
  let normalized = path.resolve(root).replace(/\\/g, '/')
  // Windows and default macOS filesystems are case-insensitive; POSIX is not,
  // so two paths differing only in case are different repositories there.
  if (process.platform === 'win32' || process.platform === 'darwin') normalized = normalized.toLowerCase()
  return createHash('sha1').update(normalized, 'utf8').digest('hex').slice(0, 12)
}

/** Empty repository-state document. */
export function emptyRepoState() {
  return { version: REPO_STATE_VERSION, repos: {} }
}

/**
 * Load repository state, tolerating missing or corrupt files.
 *
 * @param {string} file
 * @returns {{version:number,repos:object,warning?:string}}
 */
export function loadRepoState(file) {
  const { data, warning } = readJson(file)
  const result = emptyRepoState()
  if (warning !== undefined) {
    result.warning = `repository state unreadable: ${warning}`
    return result
  }
  if (data === null) return result
  if (typeof data !== 'object' || Array.isArray(data)) {
    result.warning = 'repository state is not an object'
    return result
  }
  if (data.version !== REPO_STATE_VERSION) {
    result.warning = `repository state version ${JSON.stringify(data.version)} is not ${REPO_STATE_VERSION}`
  }
  if (data.repos !== null && typeof data.repos === 'object' && !Array.isArray(data.repos)) {
    for (const [key, value] of Object.entries(data.repos)) {
      if (value === null || typeof value !== 'object') continue
      if (typeof value.root !== 'string' || value.root.length === 0) continue
      result.repos[key] = {
        root: value.root,
        mode: value.mode === 'full' ? 'full' : 'diff',
        initializedAt: typeof value.initializedAt === 'string' ? value.initializedAt : '',
      }
    }
  } else {
    result.warning = result.warning ?? 'repository state has no repos object'
  }
  return result
}

/** Whether this repository already passed the first-push question. */
export function isInitialized(state, root) {
  return Boolean(state?.repos?.[repoKey(root)])
}

/** List initialized repositories. */
export function listRepos(state) {
  return Object.entries(state?.repos ?? {}).map(([key, record]) => ({ key, ...record }))
}

/**
 * Record that a repository has been initialized.
 *
 * @param {string} file
 * @param {{root:string,mode?:'full'|'diff',now?:string}} options
 * @returns {Promise<{key:string,mode:string}>}
 */
export function markInitialized(file, { root, mode = 'diff', now = new Date().toISOString() }) {
  return serialize(file, async () => {
    const state = loadRepoState(file)
    const key = repoKey(root)
    state.repos[key] = {
      root: path.resolve(root),
      mode: mode === 'full' ? 'full' : 'diff',
      initializedAt: now,
    }
    writeJsonAtomic(file, { version: REPO_STATE_VERSION, repos: state.repos })
    return { key, mode: mode === 'full' ? 'full' : 'diff' }
  })
}

/**
 * Forget initialization records so the next push asks again.
 *
 * @param {string} file
 * @param {string} query - `all` or a case-insensitive root substring.
 * @returns {Promise<{removed:number,repos:object[],error?:string}>}
 */
export function resetRepos(file, query) {
  return serialize(file, async () => {
    const state = loadRepoState(file)
    const text = String(query ?? '').trim()
    if (text.length === 0) return { removed: 0, repos: listRepos(state), error: 'empty-query' }
    const all = text.toLowerCase() === 'all'
    const needle = text.toLowerCase()
    let removed = 0
    for (const [key, record] of Object.entries(state.repos)) {
      if (all || record.root.toLowerCase().includes(needle)) {
        delete state.repos[key]
        removed += 1
      }
    }
    if (removed > 0) writeJsonAtomic(file, { version: REPO_STATE_VERSION, repos: state.repos })
    return { removed, repos: listRepos(state) }
  })
}
