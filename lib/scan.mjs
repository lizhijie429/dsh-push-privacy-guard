/**
 * Content scanning over read-only git output.
 *
 * Three scan modes share one rule engine:
 *   - commit: added lines of `git diff --cached` / `git diff HEAD`, plus the
 *     commit messages the caller is about to use;
 *   - push: added lines between the computed push base and the pushed head,
 *     plus the messages of the commits being pushed;
 *   - full: every blob of the tracked `HEAD` tree (ignored/untracked files are
 *     never part of a commit, so `.gitignore` is honoured by construction).
 *
 * All git access goes through an injected `runGit(args, options)` function so
 * the scanner can be unit-tested with canned output and integration-tested
 * against a real repository.
 *
 * @module dsh-push-privacy-guard/scan
 */

import path from 'node:path'
import { identityOf, matchLine } from './rules.mjs'

/** Well-known empty tree id: the base of the first commit in any repository. */
export const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'

const HUNK_RE = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/

/* ------------------------------------------------------------------ */
/* Glob / ignore helpers                                              */
/* ------------------------------------------------------------------ */

/**
 * Convert a gitignore-ish glob (`**`, `*`, `?`) to a RegExp.
 *
 * @param {string} glob
 * @returns {RegExp}
 */
export function globToRegExp(glob) {
  let source = ''
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index]
    if (char === '*') {
      const isDouble = glob[index + 1] === '*'
      if (isDouble) {
        source += '.*'
        index += 1
        if (glob[index + 1] === '/') index += 1
      } else {
        source += '[^/]*'
      }
      continue
    }
    if (char === '?') {
      source += '[^/]'
      continue
    }
    if ('\\^$.|+()[]{}'.includes(char)) {
      source += `\\${char}`
      continue
    }
    source += char
  }
  return new RegExp(`^${source}$`)
}

/**
 * Whether a repository-relative path matches one of the ignore globs.
 *
 * @param {string} file - repository-relative path (forward or back slashes).
 * @param {string[]} ignorePaths
 * @returns {boolean}
 */
export function isIgnoredPath(file, ignorePaths) {
  if (!Array.isArray(ignorePaths) || ignorePaths.length === 0) return false
  const normalized = file.replace(/\\/g, '/')
  for (const glob of ignorePaths) {
    if (typeof glob !== 'string' || glob.length === 0) continue
    try {
      if (globToRegExp(glob).test(normalized)) return true
    } catch {
      /* a broken user glob must never break scanning */
    }
  }
  return false
}

/* ------------------------------------------------------------------ */
/* Patch parsing                                                      */
/* ------------------------------------------------------------------ */

/**
 * Extract added lines from a unified diff with their new-file line numbers.
 *
 * @param {string} patchText
 * @returns {Array<{file:string,line:number,text:string}>}
 */
export function parsePatch(patchText) {
  const added = []
  if (typeof patchText !== 'string' || patchText.length === 0) return added
  let file = null
  let newLine = 0
  for (const line of patchText.split(/\r?\n/)) {
    if (line.startsWith('diff --git ')) {
      file = null
      continue
    }
    if (line.startsWith('+++ ')) {
      file = unquoteGitPath(line.slice(4))
      continue
    }
    if (line.startsWith('@@')) {
      const match = HUNK_RE.exec(line)
      if (match !== null) newLine = Number(match[1])
      continue
    }
    if (line.startsWith('+') && !line.startsWith('+++')) {
      if (file !== null) added.push({ file, line: newLine, text: line.slice(1) })
      newLine += 1
      continue
    }
    if (line.startsWith(' ')) {
      newLine += 1
      continue
    }
  }
  return added
}

/** Strip `b/` and git's C-style quoting from a `+++` header path. */
function unquoteGitPath(raw) {
  const trimmed = raw.trim()
  if (trimmed === '/dev/null') return null
  let value = trimmed
  if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
    value = value
      .slice(1, -1)
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, '\\')
      .replace(/\\t/g, '\t')
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\([0-7]{1,3})/g, (_all, octal) => String.fromCharCode(Number.parseInt(octal, 8)))
  }
  if (value.startsWith('b/')) value = value.slice(2)
  return value
}

/* ------------------------------------------------------------------ */
/* Line scanning                                                      */
/* ------------------------------------------------------------------ */

/**
 * Scan text lines, returning raw findings with file/line/identity.
 *
 * @param {Array<{text:string,file:string,line:number}>} lines
 * @param {object[]} rules
 * @param {object} config
 * @returns {{findings:object[],truncated:boolean}}
 */
function scanLines(lines, rules, config) {
  const maxFindings = config.maxFindings
  const findings = []
  let truncated = false
  for (const entry of lines) {
    if (findings.length >= maxFindings) {
      truncated = true
      break
    }
    const matches = matchLine(rules, entry.text)
    for (const match of matches) {
      if (findings.length >= maxFindings) {
        truncated = true
        break
      }
      findings.push({
        ruleId: match.ruleId,
        label: match.label,
        severity: match.severity,
        value: match.value,
        masked: match.masked,
        preview: match.preview,
        identity: identityOf(match.ruleId, match.value),
        file: entry.file,
        line: entry.line,
      })
    }
  }
  return { findings, truncated }
}

/**
 * Scan one text blob (used for commit messages and tests).
 *
 * @param {string} text
 * @param {{file?:string,rules:object[],config:object}} options
 * @returns {{findings:object[],truncated:boolean}}
 */
export function scanText(text, { file = '<text>', rules, config }) {
  const lines = String(text ?? '')
    .split(/\r?\n/)
    .map((line, index) => ({ text: line, file, line: index + 1 }))
  return scanLines(lines, rules, config)
}

/** Collapse findings that share an identity into one entry with locations. */
export function dedupeFindings(findings) {
  const byIdentity = new Map()
  for (const finding of findings) {
    const existing = byIdentity.get(finding.identity)
    if (existing === undefined) {
      byIdentity.set(finding.identity, {
        ...finding,
        locations: [{ file: finding.file, line: finding.line, preview: finding.preview }],
        count: 1,
      })
      continue
    }
    existing.count += 1
    if (existing.locations.length < 5) {
      existing.locations.push({ file: finding.file, line: finding.line, preview: finding.preview })
    }
  }
  return [...byIdentity.values()]
}

/**
 * Split deduped findings into still-blocked vs already-whitelisted.
 *
 * @param {object[]} findings - deduped findings.
 * @param {Set<string>} whitelistIds
 */
export function splitWhitelisted(findings, whitelistIds) {
  const blocked = []
  const whitelisted = []
  for (const finding of findings) {
    if (whitelistIds.has(finding.identity)) whitelisted.push(finding)
    else blocked.push(finding)
  }
  return { blocked, whitelisted }
}

/* ------------------------------------------------------------------ */
/* Git plumbing helpers                                               */
/* ------------------------------------------------------------------ */

/** Resolve the repository root containing `cwd`, or null when not a repo. */
export async function detectRepo(runGit, cwd) {
  if (typeof cwd !== 'string' || cwd.length === 0) return null
  try {
    const result = await runGit(['rev-parse', '--show-toplevel'], { cwd })
    if (!result?.ok) return null
    const root = result.stdout.trim()
    if (root.length === 0) return null
    return path.resolve(root)
  } catch {
    return null
  }
}

/** Resolve one revision to a commit sha, or null. */
export async function revParse(runGit, ref) {
  const result = await runGit(['rev-parse', '--verify', '--quiet', ref])
  if (!result?.ok) return null
  const sha = result.stdout.trim()
  return sha.length > 0 ? sha : null
}

/** List configured remote names. */
export async function listRemotes(runGit) {
  const result = await runGit(['remote'])
  if (!result?.ok) return []
  return result.stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line.length > 0)
}

/** Current branch name, or null when detached. */
export async function currentBranch(runGit) {
  const result = await runGit(['rev-parse', '--abbrev-ref', 'HEAD'])
  if (!result?.ok) return null
  const name = result.stdout.trim()
  return name.length > 0 && name !== 'HEAD' ? name : null
}

/** Remote owning the branch's upstream, if configured. */
async function upstreamRemote(runGit, ref) {
  const result = await runGit(['rev-parse', '--abbrev-ref', '--symbolic-full-name', `${ref}@{upstream}`])
  if (!result?.ok) return null
  const upstream = result.stdout.trim()
  const slash = upstream.indexOf('/')
  return slash > 0 ? upstream.slice(0, slash) : null
}

/** Commits reachable from `head` but not from the target remote's tracking refs. */
async function revListMissing(runGit, head, remote) {
  const args = ['rev-list', head, '--not']
  if (remote !== null) args.push(`--remotes=${remote}`)
  else args.push('--remotes')
  const result = await runGit(args)
  if (!result?.ok) return { ok: false, error: result?.stderr?.trim() || 'git rev-list failed' }
  const commits = result.stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => /^[0-9a-f]{7,40}$/i.test(line))
  return { ok: true, commits }
}

/** Read commit messages for a bounded list of commits (single git call). */
async function readCommitMessages(runGit, commits) {
  if (!Array.isArray(commits) || commits.length === 0) return []
  const result = await runGit(['log', '--no-walk', '--format=%x1e%B%x1f', ...commits])
  if (!result?.ok) return []
  return result.stdout
    .split('\u001e')
    .map(chunk => chunk.replace(/\u001f/g, '').trim())
    .filter(message => message.length > 0)
}

/* ------------------------------------------------------------------ */
/* Push planning                                                      */
/* ------------------------------------------------------------------ */

/** Parse one push refspec into `{src,dst,deleted}`. */
export function parseRefspec(refspec) {
  const stripped = String(refspec).replace(/^\+/, '')
  const colon = stripped.indexOf(':')
  if (colon < 0) return { src: stripped, dst: stripped, deleted: stripped.length === 0 }
  const src = stripped.slice(0, colon)
  const dst = stripped.slice(colon + 1)
  return { src, dst, deleted: src.length === 0 }
}

/** Resolve explicit remote / refspec positionals against the configured remotes. */
function resolveTargets(positionals, remotes) {
  if (positionals.length === 0) return { remote: null, refspec: null }
  if (positionals.length === 1) {
    const only = positionals[0]
    if (remotes.includes(only)) return { remote: only, refspec: null }
    return { remote: null, refspec: only }
  }
  return { remote: positionals[0], refspec: positionals[1] }
}

/**
 * Plan what a `git push` would upload without touching the network.
 *
 * @param {(args:string[], options?:object)=>Promise<object>} runGit
 * @param {{op:object,config:object}} options
 * @returns {Promise<object>} plan (`empty:true` when nothing is uploaded).
 */
export async function planPush(runGit, { op, config }) {
  const flags = op.flags ?? {}
  if (flags.delete && !flags.all && !flags.mirror) return { empty: true, reason: 'delete' }

  const remotes = await listRemotes(runGit)
  const positionals = Array.isArray(op.positional) ? op.positional : []
  const { remote, refspec } = resolveTargets(positionals, remotes)

  if (refspec !== null) {
    const parsed = parseRefspec(refspec)
    if (parsed.deleted) return { empty: true, reason: 'delete' }
  }

  if (flags.all || flags.mirror) {
    return planBroadPush(runGit, { config, remote, mirror: flags.mirror === true })
  }

  const srcName = refspec !== null ? parseRefspec(refspec).src : null
  const branch = srcName !== null && srcName.length > 0 ? srcName : await currentBranch(runGit)
  const headRef = branch !== null && branch.length > 0 ? branch : 'HEAD'
  let headSha = await revParse(runGit, `${headRef}^{commit}`)
  if (headSha === null) headSha = await revParse(runGit, 'HEAD^{commit}')
  if (headSha === null) return { empty: true, reason: 'no-head' }

  const targetRemote = remote ?? (await upstreamRemote(runGit, headRef)) ?? (remotes.length === 1 ? remotes[0] : null)
  const missing = await revListMissing(runGit, headSha, targetRemote)
  if (!missing.ok) return { empty: false, error: missing.error, reason: 'rev-list-failed' }
  if (missing.commits.length === 0) return { empty: true, reason: 'nothing-to-push' }

  const incomplete = missing.commits.length > config.maxCommits
  const notes = []
  let base
  if (incomplete) {
    base = EMPTY_TREE
    notes.push('commit-count-limit')
  } else {
    const oldest = missing.commits[missing.commits.length - 1]
    base = (await revParse(runGit, `${oldest}^`)) ?? EMPTY_TREE
  }

  return {
    empty: false,
    mode: 'push',
    broad: false,
    sync: op.kind === 'sync',
    headRef,
    headSha,
    base,
    commits: missing.commits.slice(0, config.maxCommits),
    commitCount: missing.commits.length,
    incomplete,
    notes,
    targetRemote,
  }
}

/** Plan a broad `--all` / `--mirror` push by walking every local branch. */
async function planBroadPush(runGit, { config, remote, mirror }) {
  const refsResult = await runGit(['for-each-ref', '--format=%(refname)', 'refs/heads'])
  if (!refsResult?.ok) return { empty: false, error: refsResult?.stderr?.trim() || 'git for-each-ref failed' }
  const branches = refsResult.stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line.startsWith('refs/heads/'))

  const plans = []
  let remaining = config.maxCommits
  let incomplete = false
  const notes = []
  for (const branchRef of branches) {
    const headSha = await revParse(runGit, `${branchRef}^{commit}`)
    if (headSha === null) continue
    const missing = await revListMissing(runGit, headSha, remote)
    if (!missing.ok || missing.commits.length === 0) continue
    const take = missing.commits.slice(0, remaining)
    if (take.length < missing.commits.length) {
      incomplete = true
      notes.push('commit-count-limit')
    }
    remaining -= take.length
    const oldest = take[take.length - 1]
    const base = (await revParse(runGit, `${oldest}^`)) ?? EMPTY_TREE
    plans.push({ headRef: branchRef, headSha, base, commits: take })
    if (remaining <= 0) {
      incomplete = true
      if (!notes.includes('branch-limit')) notes.push('branch-limit')
      break
    }
  }
  if (mirror) notes.push('mirror-ignores-tags')
  if (plans.length === 0) return { empty: true, reason: 'nothing-to-push' }
  return {
    empty: false,
    mode: 'push',
    broad: true,
    sync: false,
    branches: plans,
    commitCount: plans.reduce((total, plan) => total + plan.commits.length, 0),
    incomplete,
    notes,
    targetRemote: remote,
  }
}

/* ------------------------------------------------------------------ */
/* Commit scanning                                                    */
/* ------------------------------------------------------------------ */

/**
 * Scan staged content plus the messages the command will use.
 *
 * @param {(args:string[], options?:object)=>Promise<object>} runGit
 * @param {{op:object,rules:object[],config:object,readTextFile?:(file:string)=>Promise<string|null>}} options
 */
export async function scanCommit(runGit, { op, rules, config, readTextFile }) {
  const notes = []
  let incomplete = false
  const head = await revParse(runGit, 'HEAD^{commit}')
  const diffArgs =
    op.flags?.all === true && head !== null
      ? ['diff', 'HEAD', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0']
      : ['diff', '--cached', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0']

  const diff = await runGit(diffArgs, { maxBuffer: config.maxTotalBytes + 1024 * 1024 })
  if (!diff?.ok) {
    if (diff?.truncated) {
      incomplete = true
      notes.push('diff-too-large')
    } else {
      return { error: diff?.stderr?.trim() || diff?.error || 'git diff failed', findings: [], incomplete: true, notes }
    }
  }

  const added = parsePatch(diff?.stdout ?? '')
  const content = scanLines(added, rules, config)
  if (content.truncated) {
    incomplete = true
    notes.push('finding-limit')
  }

  const messages = Array.isArray(op.messages) ? [...op.messages] : []
  if (typeof op.messageFile === 'string' && op.messageFile.length > 0 && typeof readTextFile === 'function') {
    const filePath = path.resolve(op.cwd ?? process.cwd(), op.messageFile)
    try {
      const text = await readTextFile(filePath)
      if (typeof text === 'string') messages.push(text)
    } catch {
      notes.push('message-file-unreadable')
    }
  }

  const messageFindings = []
  for (const message of messages) {
    const result = scanText(message, { file: '<commit message>', rules, config: { ...config, maxFindings: Math.max(1, config.maxFindings - content.findings.length) } })
    messageFindings.push(...result.findings)
    if (result.truncated) {
      incomplete = true
      notes.push('finding-limit')
    }
  }

  return {
    findings: [...content.findings, ...messageFindings],
    incomplete,
    notes,
    filesScanned: new Set(added.map(entry => entry.file)).size,
    commitsScanned: 0,
  }
}

/* ------------------------------------------------------------------ */
/* Push scanning                                                      */
/* ------------------------------------------------------------------ */

/**
 * Scan the content a planned push would upload.
 *
 * @param {(args:string[], options?:object)=>Promise<object>} runGit
 * @param {{plan:object,rules:object[],config:object}} options
 */
export async function scanPush(runGit, { plan, rules, config }) {
  if (plan?.empty === true) return { findings: [], incomplete: false, notes: [], filesScanned: 0, commitsScanned: 0 }
  if (plan?.error !== undefined) return { error: plan.error, findings: [], incomplete: true, notes: [] }

  const notes = [...(plan.notes ?? [])]
  let incomplete = plan.incomplete === true
  const findings = []
  let filesScanned = 0

  const ranges = plan.broad === true ? plan.branches : [{ headSha: plan.headSha, base: plan.base, commits: plan.commits }]
  for (const range of ranges) {
    const diff = await runGit(
      ['diff', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0', range.base, range.headSha],
      { maxBuffer: config.maxTotalBytes + 1024 * 1024 },
    )
    if (!diff?.ok) {
      if (diff?.truncated) {
        incomplete = true
        notes.push('diff-too-large')
        continue
      }
      return { error: diff?.stderr?.trim() || diff?.error || 'git diff failed', findings: [], incomplete: true, notes }
    }
    const added = parsePatch(diff.stdout)
    filesScanned += new Set(added.map(entry => entry.file)).size
    const result = scanLines(added, rules, { ...config, maxFindings: Math.max(1, config.maxFindings - findings.length) })
    findings.push(...result.findings)
    if (result.truncated) {
      incomplete = true
      notes.push('finding-limit')
    }
  }

  const commits = []
  if (plan.broad === true) {
    for (const branch of plan.branches) commits.push(...branch.commits)
  } else if (Array.isArray(plan.commits)) {
    commits.push(...plan.commits)
  }
  const messages = await readCommitMessages(runGit, commits.slice(0, config.maxCommits))
  for (const message of messages) {
    const result = scanText(message, {
      file: '<commit message>',
      rules,
      config: { ...config, maxFindings: Math.max(1, config.maxFindings - findings.length) },
    })
    findings.push(...result.findings)
    if (result.truncated) {
      incomplete = true
      notes.push('finding-limit')
    }
  }

  return {
    findings,
    incomplete,
    notes,
    filesScanned,
    commitsScanned: commits.length,
    commitCount: plan.commitCount,
  }
}

/* ------------------------------------------------------------------ */
/* Full-repository scanning                                          */
/* ------------------------------------------------------------------ */

/**
 * Scan every tracked blob of `HEAD` (git-ignored files are untracked and thus
 * excluded by construction).
 *
 * @param {(args:string[], options?:object)=>Promise<object>} runGit
 * @param {{rules:object[],config:object}} options
 */
export async function scanFullRepo(runGit, { rules, config }) {
  const head = await revParse(runGit, 'HEAD^{commit}')
  if (head === null) return { findings: [], incomplete: false, notes: ['no-head'], filesScanned: 0, skipped: 0 }

  const tree = await runGit(['ls-tree', '-r', '-z', '--long', 'HEAD'], {
    maxBuffer: config.maxTotalBytes + 1024 * 1024,
  })
  if (!tree?.ok) {
    return {
      error: tree?.stderr?.trim() || tree?.error || 'git ls-tree failed',
      findings: [],
      incomplete: true,
      notes: [],
      filesScanned: 0,
      skipped: 0,
    }
  }

  const entries = parseLsTree(tree.stdout)
  const notes = []
  const findings = []
  let filesScanned = 0
  let skipped = 0
  let totalBytes = 0
  let incomplete = false

  for (const entry of entries) {
    if (filesScanned >= config.maxFiles) {
      incomplete = true
      notes.push('file-limit')
      break
    }
    if (entry.size > config.maxFileBytes) {
      skipped += 1
      continue
    }
    if (isIgnoredPath(entry.path, config.ignorePaths)) continue
    if (totalBytes + entry.size > config.maxTotalBytes) {
      incomplete = true
      notes.push('total-size-limit')
      break
    }
    const blob = await runGit(['cat-file', 'blob', entry.oid], { maxBuffer: config.maxFileBytes + 1024 * 1024 })
    if (!blob?.ok) {
      skipped += 1
      continue
    }
    totalBytes += entry.size
    filesScanned += 1
    if (looksBinary(blob.stdout)) continue
    const lines = blob.stdout.split(/\r?\n/).map((text, index) => ({ text, file: entry.path, line: index + 1 }))
    const result = scanLines(lines, rules, { ...config, maxFindings: Math.max(1, config.maxFindings - findings.length) })
    findings.push(...result.findings)
    if (result.truncated) {
      incomplete = true
      notes.push('finding-limit')
    }
  }

  if (skipped > 0) notes.push(`files-skipped:${skipped}`)
  return { findings, incomplete, notes: dedupeStrings(notes), filesScanned, skipped }
}

/** Parse `git ls-tree -r -z --long` output into blob entries. */
export function parseLsTree(stdout) {
  const entries = []
  if (typeof stdout !== 'string' || stdout.length === 0) return entries
  for (const record of stdout.split('\u0000')) {
    if (record.length === 0) continue
    const tab = record.indexOf('\t')
    if (tab < 0) continue
    const meta = record.slice(0, tab).split(' ')
    const file = record.slice(tab + 1)
    if (meta.length < 4) continue
    const [mode, type, oid, rawSize] = meta
    if (type !== 'blob') continue
    const size = Number(rawSize)
    if (!Number.isFinite(size)) continue
    entries.push({ mode, type, oid, size, path: file })
  }
  return entries
}

/** Heuristic binary detection used to skip blobs without scanning garbage. */
function looksBinary(text) {
  if (typeof text !== 'string') return true
  const sample = text.slice(0, 8192)
  return sample.includes('\u0000')
}

/** Deduplicate note strings while preserving order. */
function dedupeStrings(values) {
  return [...new Set(values)]
}
