/**
 * Approved-item whitelist.
 *
 * Entries are keyed by the stable identity of `(rule, matched value)` and keep
 * only a masked preview — the raw secret is never written to disk. The file is
 * re-read on every check, so a manual edit takes effect immediately.
 *
 * @module dsh-push-privacy-guard/whitelist
 */

import { readJson, serialize, writeJsonAtomic } from './store.mjs'

/** Current on-disk schema version. */
export const WHITELIST_VERSION = 1

/** Empty whitelist document. */
export function emptyWhitelist() {
  return { version: WHITELIST_VERSION, entries: [] }
}

/**
 * Load a whitelist document, tolerating missing or corrupt files.
 *
 * @param {string} file
 * @returns {{version:number,entries:object[],warning?:string}}
 */
export function loadWhitelist(file) {
  const { data, warning } = readJson(file)
  const result = emptyWhitelist()
  if (warning !== undefined) {
    result.warning = `whitelist unreadable: ${warning}`
    return result
  }
  if (data === null) return result
  if (typeof data !== 'object' || Array.isArray(data)) {
    result.warning = 'whitelist is not an object'
    return result
  }
  if (data.version !== WHITELIST_VERSION) {
    result.warning = `whitelist version ${JSON.stringify(data.version)} is not ${WHITELIST_VERSION}`
  }
  if (!Array.isArray(data.entries)) {
    result.warning = result.warning ?? 'whitelist has no entries array'
    return result
  }
  result.entries = data.entries.filter(isWhitelistEntry)
  return result
}

/** Whether one parsed entry has the expected shape. */
export function isWhitelistEntry(entry) {
  return (
    entry !== null &&
    typeof entry === 'object' &&
    typeof entry.id === 'string' &&
    /^[0-9a-f]{8,64}$/.test(entry.id) &&
    typeof entry.rule === 'string'
  )
}

/** Set of approved identities. */
export function whitelistIds(document) {
  return new Set((document?.entries ?? []).map(entry => entry.id))
}

/**
 * Build the persisted entry for one finding. Masked preview only.
 *
 * @param {object} finding - deduped finding.
 * @param {{source?:string, now?:string}} [options]
 */
export function entryForFinding(finding, { source = 'approval', now = new Date().toISOString() } = {}) {
  const firstLocation = Array.isArray(finding?.locations) ? finding.locations[0] : undefined
  return {
    id: finding.identity,
    rule: finding.ruleId,
    label: finding.label ?? finding.ruleId,
    masked: finding.masked ?? '',
    firstFile: finding.file ?? firstLocation?.file ?? '',
    addedAt: now,
    source,
  }
}

/**
 * Add approved findings, skipping identities that already exist.
 *
 * @param {string} file
 * @param {object[]} findings
 * @param {{source?:string,now?:string}} [options]
 * @returns {Promise<{added:number,total:number,ids:string[]}>}
 */
export function addApproved(file, findings, options = {}) {
  return serialize(file, async () => {
    const document = loadWhitelist(file)
    const existing = new Set(document.entries.map(entry => entry.id))
    const ids = []
    for (const finding of Array.isArray(findings) ? findings : []) {
      if (finding === null || typeof finding !== 'object') continue
      if (typeof finding.identity !== 'string' || finding.identity.length === 0) continue
      if (existing.has(finding.identity)) continue
      const entry = entryForFinding(finding, options)
      document.entries.push(entry)
      existing.add(entry.id)
      ids.push(entry.id)
    }
    if (ids.length > 0) writeJsonAtomic(file, { version: WHITELIST_VERSION, entries: document.entries })
    return { added: ids.length, total: document.entries.length, ids }
  })
}

/**
 * Remove one entry by unique id prefix.
 *
 * @param {string} file
 * @param {string} prefix
 * @returns {Promise<{removed:object[],error?:string,candidates?:object[]}>}
 */
export function removeByPrefix(file, prefix) {
  return serialize(file, async () => {
    const document = loadWhitelist(file)
    const query = String(prefix ?? '').trim().toLowerCase()
    if (query.length === 0) return { removed: [], error: 'empty-prefix' }
    const matches = document.entries.filter(entry => entry.id.toLowerCase().startsWith(query))
    if (matches.length === 0) return { removed: [], error: 'no-match' }
    if (matches.length > 1) return { removed: [], error: 'ambiguous', candidates: matches.slice(0, 10) }
    const entries = document.entries.filter(entry => entry.id !== matches[0].id)
    writeJsonAtomic(file, { version: WHITELIST_VERSION, entries })
    return { removed: [matches[0]] }
  })
}

/**
 * Remove every whitelist entry.
 *
 * @param {string} file
 * @returns {Promise<{removed:number}>}
 */
export function clearWhitelist(file) {
  return serialize(file, async () => {
    const document = loadWhitelist(file)
    const removed = document.entries.length
    writeJsonAtomic(file, { version: WHITELIST_VERSION, entries: [] })
    return { removed }
  })
}
