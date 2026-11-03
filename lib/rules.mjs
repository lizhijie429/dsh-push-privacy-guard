/**
 * Built-in privacy rules, placeholder filtering, masking and stable identities.
 *
 * A rule is `{ id, label, severity, mask, pattern, flags, capture? }`.
 * `compileRules()` turns them into objects with a global RegExp so `matchLine`
 * can report every occurrence on a line.
 *
 * Pure module: no I/O, no Cordis.
 *
 * @module dsh-push-privacy-guard/rules
 */

import { createHash } from 'node:crypto'

/** Built-in rules. Order is stable for tests and reports. */
export const DEFAULT_RULES = [
  {
    id: 'private-key-block',
    label: '私钥块 / private key block',
    severity: 'high',
    mask: 'full',
    pattern: '-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----',
    flags: '',
  },
  {
    id: 'aws-access-key',
    label: 'AWS Access Key',
    severity: 'high',
    mask: 'secret',
    pattern: '(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
    flags: '',
  },
  {
    id: 'github-token',
    label: 'GitHub Token',
    severity: 'high',
    mask: 'secret',
    pattern: '\\bgh[pousr]_[A-Za-z0-9]{36,}',
    flags: '',
  },
  {
    id: 'openai-key',
    label: 'OpenAI API Key',
    severity: 'high',
    mask: 'secret',
    pattern: '\\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}',
    flags: '',
  },
  {
    id: 'slack-token',
    label: 'Slack Token',
    severity: 'high',
    mask: 'secret',
    pattern: '\\bxox[baprs]-[A-Za-z0-9-]{10,}',
    flags: '',
  },
  {
    id: 'google-api-key',
    label: 'Google API Key',
    severity: 'high',
    mask: 'secret',
    pattern: '\\bAIza[0-9A-Za-z_-]{35}',
    flags: '',
  },
  {
    id: 'jwt',
    label: 'JWT',
    severity: 'high',
    mask: 'secret',
    pattern: 'eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}',
    flags: '',
  },
  {
    id: 'bearer-token',
    label: 'Bearer Token',
    severity: 'high',
    mask: 'secret',
    pattern: '\\bBearer\\s+([A-Za-z0-9._~+/-]{16,}=*)',
    flags: 'i',
    capture: 1,
  },
  {
    id: 'assigned-secret',
    label: '密码 / 密钥赋值',
    severity: 'high',
    mask: 'secret',
    pattern:
      '\\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key)\\b\\s*[:=]\\s*["\'`]?([^\\s"\'`,;#]{6,})',
    flags: 'i',
    capture: 1,
  },
  {
    id: 'connection-string',
    label: '数据库 / 中间件连接串',
    severity: 'high',
    mask: 'secret',
    pattern:
      '\\b(?:mongodb(?:\\+srv)?|mysql|mariadb|postgres(?:ql)?|redis|amqp|jdbc:[a-z0-9]+)://[^\\s"\'`]+',
    flags: 'i',
  },
  {
    id: 'local-abs-path-win',
    label: 'Windows 本地绝对路径',
    severity: 'medium',
    mask: 'path',
    pattern: '\\b[A-Za-z]:\\\\(?:[^\\\\\\s"\'`<>|*?\\r\\n]+\\\\)*[^\\\\\\s"\'`<>|*?\\r\\n]*',
    flags: '',
  },
  {
    id: 'local-home-path-posix',
    label: 'POSIX 家目录路径',
    severity: 'medium',
    mask: 'path',
    pattern: '/(?:Users|home)/[A-Za-z0-9._-]+(?:/[^\\s"\'`<>|]*)?',
    flags: '',
  },
  {
    id: 'email',
    label: '邮箱地址',
    severity: 'medium',
    mask: 'email',
    pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}',
    flags: '',
  },
  {
    id: 'cn-mobile',
    label: '手机号',
    severity: 'medium',
    mask: 'phone',
    pattern: '(?<!\\d)1[3-9]\\d{9}(?!\\d)',
    flags: '',
  },
  {
    id: 'cn-id-card',
    label: '身份证号',
    severity: 'high',
    mask: 'id',
    pattern: '(?<!\\d)\\d{17}[\\dXx](?!\\d)',
    flags: '',
  },
  {
    id: 'internal-url',
    label: '内网地址',
    severity: 'medium',
    mask: 'secret',
    pattern:
      '\\bhttps?://(?:10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|[A-Za-z0-9-]+\\.(?:local|internal|corp))(?::\\d+)?[^\\s"\'`]*',
    flags: 'i',
  },
]

/** Values that are obviously templates, env references or documentation. */
const PLACEHOLDER_RE =
  /^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|<[^>]*>|\$[A-Za-z_][\w]*|%[A-Za-z_][\w]*%|os\.environ[^\s]*|process\.env[^\s]*|env\([^)]*\)|x{3,}|X{3,}|\*{3,}|\.{3,}|-+|_+|changeme|change[-_]?me|your[-_].*|example.*|placeholder.*|todo|fixme|null|none|true|false|undefined|0+)$/i

/** Placeholder mail domains / role addresses that must not flag. */
const PLACEHOLDER_MAIL_DOMAINS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'test.com',
  'test.org',
  'localhost',
  'invalid',
])

/** Role addresses that are repository metadata, not personal information. */
const ROLE_ADDRESSES = new Set([
  'git@github.com',
  'git@gitlab.com',
  'git@bitbucket.org',
  'git@gitee.com',
])

/** Identity normalization only for values that are case-insensitive. */
const LOWERCASE_RULE_IDS = new Set(['email', 'local-abs-path-win', 'local-home-path-posix', 'internal-url'])

const ID_CARD_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
const ID_CARD_CHECK = '10X98765432'

/**
 * Compile built-in + custom rules into matchers with a global RegExp.
 *
 * @param {{disableRules?: string[], extraRules?: object[]}} config
 * @returns {object[]} compiled rules.
 */
export function compileRules(config = {}) {
  const disabled = new Set(Array.isArray(config.disableRules) ? config.disableRules : [])
  const builtInIds = new Set(DEFAULT_RULES.map(rule => rule.id))
  const rules = []
  for (const rule of DEFAULT_RULES) {
    if (!disabled.has(rule.id)) rules.push(compileRule(rule))
  }
  for (const rule of Array.isArray(config.extraRules) ? config.extraRules : []) {
    if (!rule || typeof rule !== 'object') continue
    if (typeof rule.id !== 'string' || rule.id.length === 0) continue
    if (builtInIds.has(rule.id) || disabled.has(rule.id)) continue
    rules.push(compileRule(rule))
  }
  return rules
}

/** Compile one rule and validate its pattern. */
function compileRule(rule) {
  const flags = typeof rule.flags === 'string' ? rule.flags : ''
  const globalFlags = flags.includes('g') ? flags : `${flags}g`
  return {
    id: rule.id,
    label: rule.label ?? rule.id,
    severity: rule.severity === 'medium' ? 'medium' : 'high',
    mask: rule.mask ?? 'secret',
    capture: Number.isInteger(rule.capture) && rule.capture > 0 ? rule.capture : undefined,
    custom: rule.custom === true,
    re: new RegExp(rule.pattern, globalFlags),
  }
}

/**
 * Find every rule match on one line.
 *
 * @param {object[]} rules - compiled rules.
 * @param {string} line
 * @returns {Array<{ruleId:string,label:string,severity:string,value:string,index:number,masked:string,preview:string}>}
 */
export function matchLine(rules, line) {
  if (typeof line !== 'string' || line.length === 0) return []
  const findings = []
  for (const rule of rules) {
    const re = rule.re
    re.lastIndex = 0
    const seenValues = new Set()
    let match
    while ((match = re.exec(line)) !== null) {
      const value = String(rule.capture !== undefined ? match[rule.capture] ?? '' : match[0]).trim()
      if (value.length === 0) {
        if (match.index === re.lastIndex) re.lastIndex += 1
        continue
      }
      if (value.length > 400) {
        if (match.index === re.lastIndex) re.lastIndex += 1
        continue
      }
      if (isPlaceholder(rule, value, line)) continue
      if (seenValues.has(value)) continue
      seenValues.add(value)
      const captured = rule.capture !== undefined ? match[0] : value
      const index = captured.indexOf(value) >= 0 ? match.index + Math.max(0, captured.indexOf(value)) : match.index
      findings.push({
        ruleId: rule.id,
        label: rule.label,
        severity: rule.severity,
        value,
        index,
        masked: maskValue(rule, value),
        preview: rule.mask === 'path' ? truncate(value, 120) : maskValue(rule, value),
      })
      if (match.index === re.lastIndex) re.lastIndex += 1
    }
  }
  findings.sort((a, b) => a.index - b.index)
  return findings
}

/**
 * Whether a matched value is a template/env reference/known example.
 *
 * @param {object} rule - rule (needs `id`).
 * @param {string} value
 * @param {string} [line]
 * @returns {boolean}
 */
export function isPlaceholder(rule, value, line = '') {
  const trimmed = value.trim()
  if (PLACEHOLDER_RE.test(trimmed)) return true
  if (/^[.\-_/*#\s]+$/.test(trimmed)) return true

  switch (rule.id) {
    case 'local-abs-path-win':
      return /^[A-Za-z]:\\?$/.test(trimmed) || trimmed.length < 5
    case 'local-home-path-posix':
      return trimmed === '/home' || trimmed === '/Users' || trimmed.length < 7
    case 'email': {
      const lower = trimmed.toLowerCase()
      if (ROLE_ADDRESSES.has(lower)) return true
      const at = lower.lastIndexOf('@')
      if (at < 1) return true
      const domain = lower.slice(at + 1)
      if (PLACEHOLDER_MAIL_DOMAINS.has(domain)) return true
      if (domain.endsWith('.invalid') || domain.endsWith('.test') || domain.endsWith('.example')) return true
      if (lower.endsWith('@users.noreply.github.com')) return true
      if (lower.includes('${') || lower.includes('{{')) return true
      return false
    }
    case 'cn-id-card':
      return !isValidIdCard(trimmed)
    case 'cn-mobile':
      // 11-digit numbers inside timestamps/ids are already excluded by lookarounds.
      return trimmed.length !== 11
    case 'assigned-secret':
      return isWeakAssignedValue(trimmed, line)
    case 'connection-string':
      return /(?:user|password|passwd|pwd)=?\{\{|\$\{/.test(trimmed)
    default:
      return false
  }
}

/** Weak assigned values such as `password = "example"` or `secret: test`. */
function isWeakAssignedValue(value, line) {
  if (value.length < 6) return true
  if (PLACEHOLDER_RE.test(value)) return true
  if (/^(?:test|demo|sample|dummy|fake|foo|bar|baz|abc|123)\w*$/i.test(value)) return true
  if (/^[^A-Za-z0-9]+$/.test(value)) return true
  // A value that only repeats one character is not a real credential.
  if (new Set(value).size <= 2) return true
  // `token`/`secret` identifiers in prose ("the secret: token") are not values.
  if (/(?:^|\s)(?:the|a|an|is|are|this|that|my|your)\s+(?:password|secret|token|key)$/i.test(line)) return true
  return false
}

/** Validate the PRC resident id checksum before reporting it. */
export function isValidIdCard(value) {
  if (!/^\d{17}[\dXx]$/.test(value)) return false
  let sum = 0
  for (let index = 0; index < 17; index += 1) {
    sum += Number(value[index]) * ID_CARD_WEIGHTS[index]
  }
  return ID_CARD_CHECK[sum % 11] === value[17].toUpperCase()
}

/**
 * Mask one matched value for whitelist storage and audit logs.
 *
 * @param {{mask?:string}} rule - rule with a mask kind.
 * @param {string} value
 * @returns {string}
 */
export function maskValue(rule, value) {
  const mask = rule?.mask ?? 'secret'
  switch (mask) {
    case 'full':
      return '[redacted]'
    case 'path':
      return maskPath(value)
    case 'email': {
      const at = value.lastIndexOf('@')
      if (at < 1) return truncate(value, 24)
      return `${value[0]}***@${value.slice(at + 1)}`
    }
    case 'phone':
      return value.length >= 11 ? `${value.slice(0, 3)}****${value.slice(-4)}` : truncateMiddle(value)
    case 'id':
      return value.length >= 18 ? `${value.slice(0, 4)}**********${value.slice(-4)}` : truncateMiddle(value)
    case 'secret':
    default:
      return truncateMiddle(value)
  }
}

/** Mask the user-name segment of an absolute path. */
function maskPath(value) {
  const masked = value.replace(/([\\/])(?:Users|home)([\\/])[^\\/]+/i, (_all, slash1, slash2) => `${slash1}Users${slash2}***`)
  if (masked !== value) return truncate(masked, 160)
  return truncate(value, 160)
}

/** `sk-ab…yz` style masking. */
function truncateMiddle(value) {
  if (value.length <= 8) return `${value.slice(0, 2)}…`
  return `${value.slice(0, 4)}…${value.slice(-2)}`
}

/** Truncate to a maximum length with an ellipsis. */
function truncate(value, max) {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`
}

/**
 * Stable whitelist identity for one rule + value pair.
 *
 * @param {string} ruleId
 * @param {string} value
 * @returns {string} 16 lowercase hex characters.
 */
export function identityOf(ruleId, value) {
  const normalized = normalizeIdentity(ruleId, value)
  return createHash('sha256').update(`${ruleId}\u0000${normalized}`, 'utf8').digest('hex').slice(0, 16)
}

/** Normalize a value before hashing (paths/identities are case-insensitive). */
function normalizeIdentity(ruleId, value) {
  const trimmed = String(value).trim().replace(/\s+/g, ' ')
  if (LOWERCASE_RULE_IDS.has(ruleId)) return trimmed.toLowerCase().replace(/\//g, '\\')
  return trimmed
}
