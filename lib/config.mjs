/**
 * Configuration normalization for dsh-push-privacy-guard.
 *
 * Every tunable lives in the plugin's `config:` block so users change it in
 * their profile patch layer. Invalid values fall back to documented defaults
 * and are reported through `warnings` (logged once at mount) instead of
 * failing silently.
 *
 * Pure module: no I/O, no Cordis.
 *
 * @module dsh-push-privacy-guard/config
 */

import path from 'node:path'

/** Paths excluded from scanning by default (minified / generated / lock files). */
export const DEFAULT_IGNORE_PATHS = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/coverage/**',
  '**/*.min.js',
  '**/*.map',
  '**/pnpm-lock.yaml',
  '**/package-lock.json',
  '**/yarn.lock',
]

/** Modes for the first push in an unseen repository. */
export const FULL_SCAN_MODES = new Set(['ask', 'always', 'never'])

/** Documented defaults, mirrored by the README table. */
export const DEFAULTS = {
  enabled: true,
  interceptCommit: true,
  interceptPush: true,
  fullScanOnFirstPush: 'ask',
  whitelistOnApprove: true,
  requireApprovalOnIncompleteScan: true,
  disableRules: [],
  extraRules: [],
  ignorePaths: [],
  whitelistFile: '',
  repoStateFile: '',
  logFile: '',
  maxTotalBytes: 20 * 1024 * 1024,
  maxFileBytes: 1 * 1024 * 1024,
  maxFiles: 5000,
  maxCommits: 100,
  maxFindings: 200,
  maxMatchesPerLine: 5,
  maxApprovalItems: 20,
  gitTimeoutMs: 20000,
}

const BOOLEAN_FIELDS = [
  'enabled',
  'interceptCommit',
  'interceptPush',
  'whitelistOnApprove',
  'requireApprovalOnIncompleteScan',
]

const POSITIVE_INT_FIELDS = [
  'maxTotalBytes',
  'maxFileBytes',
  'maxFiles',
  'maxCommits',
  'maxFindings',
  'maxMatchesPerLine',
  'maxApprovalItems',
  'gitTimeoutMs',
]

const TRUE_STRINGS = new Set(['true', 'yes', 'on', '1'])
const FALSE_STRINGS = new Set(['false', 'no', 'off', '0'])

/**
 * Normalize the loader entry's `config:` block.
 *
 * @param {unknown} raw - the `config:` block, possibly absent/invalid.
 * @param {string} pluginDir - absolute plugin directory (default state root).
 * @returns {object} compiled configuration plus a `warnings` string array.
 */
export function normalizeConfig(raw, pluginDir) {
  const input = raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}
  const warnings = []
  const config = { ...DEFAULTS }

  for (const field of BOOLEAN_FIELDS) {
    config[field] = readBoolean(input, field, DEFAULTS[field], warnings)
  }

  config.fullScanOnFirstPush = readEnum(
    input,
    'fullScanOnFirstPush',
    FULL_SCAN_MODES,
    DEFAULTS.fullScanOnFirstPush,
    warnings,
  )

  for (const field of POSITIVE_INT_FIELDS) {
    config[field] = readPositiveInt(input, field, DEFAULTS[field], warnings)
  }

  config.disableRules = readStringArray(input.disableRules, 'disableRules', warnings, { fresh: true })
  config.extraRules = readExtraRules(input.extraRules, warnings)
  config.ignorePaths = dedupe([
    ...DEFAULT_IGNORE_PATHS,
    ...readStringArray(input.ignorePaths, 'ignorePaths', warnings, { fresh: true }),
  ])

  config.whitelistFile = resolveStatePath(input.whitelistFile, path.join(pluginDir, 'state', 'whitelist.json'), pluginDir)
  config.repoStateFile = resolveStatePath(input.repoStateFile, path.join(pluginDir, 'state', 'repos.json'), pluginDir)
  config.logFile = resolveStatePath(input.logFile, path.join(pluginDir, 'state', 'push-privacy-guard.log'), pluginDir)

  config.warnings = warnings
  return config
}

/** Parse a boolean, accepting recognizable strings with a warning. */
function readBoolean(input, field, fallback, warnings) {
  const value = input[field]
  if (value === undefined) return fallback
  if (typeof value === 'boolean') return value
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase()
    if (TRUE_STRINGS.has(normalized)) {
      warnings.push(`${field} should be a boolean, got ${JSON.stringify(value)}; interpreted as true`)
      return true
    }
    if (FALSE_STRINGS.has(normalized)) {
      warnings.push(`${field} should be a boolean, got ${JSON.stringify(value)}; interpreted as false`)
      return false
    }
  }
  warnings.push(`${field} should be a boolean, got ${JSON.stringify(value)}; falling back to ${fallback}`)
  return fallback
}

/** Parse one enum value, falling back on anything unknown. */
function readEnum(input, field, allowed, fallback, warnings) {
  const value = input[field]
  if (value === undefined) return fallback
  if (typeof value === 'string' && allowed.has(value.trim().toLowerCase())) {
    return value.trim().toLowerCase()
  }
  warnings.push(`${field} should be one of ${[...allowed].join('/')}, got ${JSON.stringify(value)}; falling back to ${fallback}`)
  return fallback
}

/** Parse a positive integer, falling back on non-numbers / non-positive values. */
function readPositiveInt(input, field, fallback, warnings) {
  const value = input[field]
  if (value === undefined) return fallback
  if (Number.isInteger(value) && value > 0) return value
  warnings.push(`${field} should be a positive integer, got ${JSON.stringify(value)}; falling back to ${fallback}`)
  return fallback
}

/** Read a flat string array, dropping non-strings with warnings. */
function readStringArray(raw, field, warnings, { fresh } = {}) {
  if (raw === undefined) return []
  if (!Array.isArray(raw)) {
    warnings.push(`${field} should be an array of strings; ignored`)
    return []
  }
  const out = []
  for (const entry of raw) {
    if (typeof entry !== 'string') {
      warnings.push(`${field} entry ${JSON.stringify(entry)} is not a string; ignored`)
      continue
    }
    const value = entry.trim()
    if (value.length > 0 && !out.includes(value)) out.push(value)
  }
  return out
}

/** Validate and normalize custom rules; invalid entries are dropped with warnings. */
function readExtraRules(raw, warnings) {
  if (raw === undefined) return []
  if (!Array.isArray(raw)) {
    warnings.push('extraRules should be an array; ignored')
    return []
  }
  const seen = new Set()
  const out = []
  for (const entry of raw) {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      warnings.push(`extraRules entry ${JSON.stringify(entry)} is not an object; ignored`)
      continue
    }
    const id = typeof entry.id === 'string' ? entry.id.trim() : ''
    if (id.length === 0) {
      warnings.push('extraRules entry has no id; ignored')
      continue
    }
    if (seen.has(id)) {
      warnings.push(`extraRules entry id ${JSON.stringify(id)} is duplicated; ignored`)
      continue
    }
    if (typeof entry.pattern !== 'string' || entry.pattern.length === 0) {
      warnings.push(`extraRules entry ${JSON.stringify(id)} has no pattern; ignored`)
      continue
    }
    try {
      new RegExp(entry.pattern, sanitizeFlags(entry.flags).replace('g', ''))
    } catch {
      warnings.push(`extraRules entry ${JSON.stringify(id)} has an invalid RegExp pattern; ignored`)
      continue
    }
    seen.add(id)
    out.push({
      id,
      label: typeof entry.label === 'string' && entry.label.trim().length > 0 ? entry.label.trim() : id,
      pattern: entry.pattern,
      flags: sanitizeFlags(entry.flags),
      severity: entry.severity === 'medium' ? 'medium' : 'high',
      mask: ['secret', 'full', 'path', 'email', 'phone', 'id'].includes(entry.mask) ? entry.mask : 'secret',
      capture: Number.isInteger(entry.capture) && entry.capture > 0 ? entry.capture : undefined,
      custom: true,
    })
  }
  return out
}

/** Keep only safe RegExp flags; `g` is always added by the compiler. */
function sanitizeFlags(raw) {
  if (typeof raw !== 'string') return ''
  return raw.replace(/[^imsu]/g, '')
}

/** Resolve a state-file config value against the plugin directory. */
function resolveStatePath(raw, fallback, pluginDir) {
  if (typeof raw !== 'string' || raw.trim().length === 0) return fallback
  const value = raw.trim()
  return path.isAbsolute(value) ? value : path.join(pluginDir, value)
}

/** De-duplicate while keeping first-seen order. */
function dedupe(values) {
  const seen = new Set()
  const out = []
  for (const value of values) {
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}
