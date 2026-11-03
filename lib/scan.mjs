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
        if (glob[index + 2] === '/') {
          // `**/` matches zero or more leading directories, including none.
          source += '(?:.*/)?'
          index += 2
        } else {
          source += '.*'
          index += 1
        }
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

/** Long lines are scanned in overlapping chunks so one huge line cannot stall the guard. */
const MAX_LINE_CHARS = 8192
const CHUNK_OVERLAP = 512

/**
 * Match one line, chunking very long lines to bound regex work per call.
 *
 * @param {object[]} rules
 * @param {string} line
 * @returns {object[]}
 */
function matchLineChunked(rules, line) {
  if (line.length <= MAX_LINE_CHARS) return matchLine(rules, line)
  const matches = []
  const seen = new Set()
  const step = MAX_LINE_CHARS - CHUNK_OVERLAP
  for (let start = 0; start < line.length; start += step) {
    const end = Math.min(line.length, start + MAX_LINE_CHARS)
    for (const match of matchLine(rules, line.slice(start, end))) {
      const key = `${match.ruleId}\u0000${match.value}`
      if (seen.has(key)) continue
      seen.add(key)
      matches.push({ ...match, index: start + match.index })
    }
    if (end >= line.length) break
  }
  return matches
}

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
    const matches = matchLineChunked(rules, entry.text)
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
    if (result?.ok) {
      const root = result.stdout.trim()
      if (root.length > 0) return path.resolve(root)
    }
    // Bare repositories have no worktree, but `git push` from them still uploads
    // whatever the refs point at; use the git directory as the scan root.
    const bare = await runGit(['rev-parse', '--is-bare-repository'], { cwd })
    if (bare?.ok && bare.stdout.trim() === 'true') {
      const gitDir = await runGit(['rev-parse', '--absolute-git-dir'], { cwd })
      if (gitDir?.ok && gitDir.stdout.trim().length > 0) return path.resolve(gitDir.stdout.trim())
    }
    return null
  } catch {
    return null
  }
}

/** Resolve one revision to a commit sha, or null. */
export async function revParse(runGit, ref) {
  const result = await revParseStrict(runGit, ref)
  return result.ok ? result.sha : null
}

/**
 * Resolve one revision while distinguishing "the ref does not exist" from
 * "git failed". The former is a legitimate empty state; the latter must block
 * (or ask) instead of being treated as "nothing to upload".
 *
 * @returns {{ok:true,sha:string}|{ok:false,missing?:boolean,error?:string}}
 */
export async function revParseStrict(runGit, ref) {
  if (typeof ref !== 'string' || ref.length === 0 || ref.startsWith('-')) {
    return { ok: false, error: 'invalid revision' }
  }
  const result = await runGit(['rev-parse', '--verify', ref])
  if (result?.ok) {
    const sha = String(result.stdout ?? '').trim()
    return sha.length > 0 ? { ok: true, sha } : { ok: false, error: 'git rev-parse returned no revision' }
  }
  if (result?.timedOut === true || result?.truncated === true || result?.error === 'NO_CWD') {
    return { ok: false, error: result.error ?? 'git rev-parse failed' }
  }
  const stderr = String(result?.stderr ?? '')
  if (/needed a single revision|unknown revision|bad revision|ambiguous argument|does not exist/i.test(stderr)) {
    return { ok: false, missing: true }
  }
  return { ok: false, error: stderr.trim() || result?.error || 'git rev-parse failed' }
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
  if (!Array.isArray(commits) || commits.length === 0) return { messages: [] }
  const result = await runGit(['log', '--no-walk', '--format=%x1e%B%x1f', ...commits])
  if (!result?.ok) {
    return { messages: [], error: result?.stderr?.trim() || result?.error || 'git log failed' }
  }
  const messages = result.stdout
    .split('\u001e')
    .map(chunk => chunk.replace(/\u001f/g, '').trim())
    .filter(message => message.length > 0)
  return { messages }
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

  const tagScan = await collectTagRefs(runGit, { op, config, remotes })
  if (tagScan.error !== undefined) {
    return { empty: false, error: tagScan.error, reason: 'tag-ref-list-failed' }
  }

  if (flags.all || flags.mirror) {
    const broad = await planBroadPush(runGit, { config, remote, mirror: flags.mirror === true })
    if (broad.error !== undefined) return broad
    if (broad.empty === true) {
      if (tagScan.names.length === 0) return broad
      return {
        empty: false,
        mode: 'push',
        broad: true,
        sync: false,
        branches: [],
        commitCount: 0,
        incomplete: tagScan.incomplete,
        notes: [...tagScan.notes],
        targetRemote: remote,
        tagRefs: tagScan.names,
      }
    }
    return {
      ...broad,
      incomplete: broad.incomplete === true || tagScan.incomplete === true,
      notes: [...(broad.notes ?? []), ...tagScan.notes],
      tagRefs: tagScan.names,
    }
  }

  const planRanges = []
  let remaining = config.maxCommits
  let incomplete = false
  const notes = [...tagScan.notes]
  const explicit = collectExplicitRefspecs(positionals, remotes)

  const addRange = async (srcName, targetRemote) => {
    const headRef = typeof srcName === 'string' && srcName.length > 0 ? srcName : null
    const resolveRef = headRef ?? (await currentBranch(runGit)) ?? 'HEAD'
    let resolved = await revParseStrict(runGit, `${resolveRef}^{commit}`)
    if (resolved.ok !== true && resolved.missing !== true) {
      return { error: resolved.error ?? 'git rev-parse failed' }
    }
    if (resolved.ok !== true) {
      resolved = await revParseStrict(runGit, 'HEAD^{commit}')
      if (resolved.ok !== true && resolved.missing !== true) return { error: resolved.error ?? 'git rev-parse failed' }
      if (resolved.ok !== true) return { missing: true }
    }
    const headSha = resolved.sha
    const remoteForRef = targetRemote ?? (await upstreamRemote(runGit, resolveRef)) ?? (remotes.length === 1 ? remotes[0] : null)
    const missing = await revListMissing(runGit, headSha, remoteForRef)
    if (missing.ok !== true) return { error: missing.error ?? 'git rev-list failed' }
    if (missing.commits.length === 0) return { empty: true, remoteForRef }

    const take = missing.commits.slice(0, remaining)
    let rangeIncomplete = false
    let base = EMPTY_TREE
    if (take.length < missing.commits.length) {
      rangeIncomplete = true
      notes.push('commit-count-limit')
    } else {
      const oldest = take[take.length - 1]
      base = (await revParse(runGit, `${oldest}^`)) ?? EMPTY_TREE
    }
    if (remoteForRef === null && !notes.includes('target-remote-unknown')) {
      rangeIncomplete = true
      notes.push('target-remote-unknown')
    }
    remaining -= take.length
    return {
      range: { headRef: resolveRef, headSha, base, commits: take, targetRemote: remoteForRef },
      incomplete: rangeIncomplete,
      remoteForRef,
      totalCommits: missing.commits.length,
    }
  }

  const refspecs = explicit.refspecs
  const sources = []
  if (refspecs.length === 0) {
    sources.push(null)
  } else {
    for (const value of refspecs) {
      const parsed = parseRefspec(value)
      if (parsed.deleted) continue
      if (parsed.src.includes('*')) {
        const pattern = parsed.src.startsWith('refs/') ? parsed.src : `refs/heads/${parsed.src}`
        const expanded = await runGit(['for-each-ref', '--format=%(refname)', pattern])
        if (!expanded?.ok) return { empty: false, error: expanded?.stderr?.trim() || 'git for-each-ref failed' }
        const matches = expanded.stdout
          .split(/\r?\n/)
          .map(line => line.trim())
          .filter(line => line.startsWith('refs/'))
        if (matches.length === 0) {
          notes.push('refspec-unmatched')
          continue
        }
        sources.push(...matches)
        continue
      }
      sources.push(parsed.src)
    }
  }

  for (const source of sources) {
    if (remaining <= 0) {
      incomplete = true
      notes.push('commit-count-limit')
      break
    }
    const added = await addRange(source, explicit.remote)
    if (added.error !== undefined) return { empty: false, error: added.error, reason: 'rev-list-failed' }
    if (added.missing === true) {
      if (sources.length === 1 && source === null) return { empty: true, reason: 'no-head' }
      notes.push('refspec-missing')
      continue
    }
    if (added.empty === true) {
      if (added.remoteForRef === null && !notes.includes('target-remote-unknown')) {
        incomplete = true
        notes.push('target-remote-unknown')
      }
      continue
    }
    incomplete = incomplete || added.incomplete === true
    planRanges.push(added.range)
  }

  if (planRanges.length === 0) {
    if (tagScan.names.length === 0) return { empty: true, reason: 'nothing-to-push' }
    return {
      empty: false,
      mode: 'push',
      broad: false,
      sync: op.kind === 'sync',
      headRef: null,
      headSha: null,
      base: EMPTY_TREE,
      commits: [],
      commitCount: 0,
      incomplete: incomplete || tagScan.incomplete === true,
      notes,
      targetRemote: explicit.remote,
      tagRefs: tagScan.names,
    }
  }

  const pushSync = op.kind === 'sync'
  if (planRanges.length === 1) {
    const only = planRanges[0]
    return {
      empty: false,
      mode: 'push',
      broad: false,
      sync: pushSync,
      headRef: only.headRef,
      headSha: only.headSha,
      base: only.base,
      commits: only.commits,
      commitCount: only.commits.length,
      incomplete: incomplete || tagScan.incomplete === true,
      notes,
      targetRemote: only.targetRemote ?? explicit.remote,
      tagRefs: tagScan.names,
    }
  }
  return {
    empty: false,
    mode: 'push',
    broad: true,
    sync: pushSync,
    branches: planRanges,
    commitCount: planRanges.reduce((total, range) => total + range.commits.length, 0),
    incomplete: incomplete || tagScan.incomplete === true,
    notes,
    targetRemote: planRanges[0].targetRemote ?? explicit.remote,
    tagRefs: tagScan.names,
  }
}

/** Split push positionals into an explicit remote plus its refspecs. */
function collectExplicitRefspecs(positionals, remotes) {
  if (!Array.isArray(positionals) || positionals.length === 0) return { remote: null, refspecs: [] }
  if (remotes.includes(positionals[0])) return { remote: positionals[0], refspecs: positionals.slice(1) }
  return { remote: null, refspecs: [...positionals] }
}

/**
 * List the tags a push would upload: all local tags for `--tags`/`--mirror`,
 * plus explicit tag refspecs. Their tag-object messages are scanned later.
 */
async function collectTagRefs(runGit, { op, config, remotes = [] }) {
  const flags = op.flags ?? {}
  const notes = []
  let incomplete = false
  const names = new Set()

  if (flags.tags === true || flags.mirror === true) {
    const result = await runGit(['for-each-ref', '--format=%(refname:short)', 'refs/tags'])
    if (!result?.ok) {
      return { names: [], incomplete: true, notes, error: result?.stderr?.trim() || 'git for-each-ref refs/tags failed' }
    }
    for (const name of result.stdout.split(/\r?\n/).map(line => line.trim()).filter(line => line.length > 0)) {
      if (names.size >= config.maxCommits) {
        incomplete = true
        notes.push('tag-limit')
        break
      }
      names.add(name)
    }
  }

  const positionals = Array.isArray(op.positional) ? op.positional : []
  for (const value of positionals) {
    const parsed = parseRefspec(value)
    const src = parsed.src
    if (src.length === 0) continue
    if (remotes.includes(src) || src === 'HEAD') continue
    if (src.startsWith('refs/tags/')) {
      names.add(src.slice('refs/tags/'.length))
      continue
    }
    if (src.startsWith('refs/')) continue
    if (names.size >= config.maxCommits) {
      incomplete = true
      notes.push('tag-limit')
      break
    }
    const resolved = await runGit(['rev-parse', '--symbolic-full-name', src])
    if (resolved?.ok && String(resolved.stdout).trim().startsWith('refs/tags/')) names.add(src)
  }

  return { names: [...names], incomplete, notes }
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
    // A failed rev-list must not be mistaken for "this branch has nothing new".
    if (missing.ok !== true) return { empty: false, error: missing.error ?? 'git rev-list failed' }
    if (missing.commits.length === 0) continue
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
 * Scan the content a `git commit` would record.
 *
 * Three content sources are combined:
 *   - the index (`git diff --cached`) for a plain commit;
 *   - the worktree (`git diff HEAD`, optionally limited to pathspecs) when the
 *     same command line also mutates the index (`git add ...; git commit`) or
 *     the commit itself targets paths (`git commit <path>`, `-i/--include`);
 *   - untracked, non-ignored files when a preceding `git add` could stage them.
 *
 * The extra sources over-approximate what the commit will contain on purpose:
 * a privacy guard may ask once too often, but must not miss a staged secret.
 *
 * @param {(args:string[], options?:object)=>Promise<object>} runGit
 * @param {{op:object,rules:object[],config:object,
 *          readTextFile?:(file:string)=>Promise<string|null>,
 *          readWorkingFile?:(file:string,maxBytes:number)=>Promise<Buffer|null>}} options
 */
export async function scanCommit(runGit, { op, rules, config, readTextFile, readWorkingFile }) {
  const notes = []
  let incomplete = false
  const head = await revParse(runGit, 'HEAD^{commit}')
  const mutation = op.mutation ?? {}
  // Any hint that the commit may record worktree content (pathspec, -a, -i,
  // an earlier git add in the same command, --pathspec-from-file) means we scan
  // the whole worktree diff. Narrowing to pathspecs is deliberately avoided:
  // a wrong/empty pathspec set would produce a silent empty diff and skip the
  // index entirely.
  const wantsWorktree =
    op.flags?.all === true ||
    op.flags?.worktreePaths === true ||
    mutation.indexMutated === true ||
    uniqueStrings(op.pathspecs).length > 0 ||
    (typeof op.pathspecFromFile === 'string' && op.pathspecFromFile.length > 0)

  const diffFlags = ['--no-color', '--no-ext-diff', '--no-textconv', '--unified=0']
  const diffArgs =
    wantsWorktree && head !== null ? ['diff', 'HEAD', ...diffFlags] : ['diff', '--cached', ...diffFlags]

  const diff = await runGit(diffArgs, { maxBuffer: config.maxTotalBytes + 1024 * 1024 })
  if (!diff?.ok) {
    if (diff?.truncated) {
      incomplete = true
      notes.push('diff-too-large')
    } else {
      return { error: diff?.stderr?.trim() || diff?.error || 'git diff failed', findings: [], incomplete: true, notes }
    }
  }

  const added = filterIgnoredPaths(parsePatch(diff?.stdout ?? ''), config)
  const content = scanLines(added, rules, config)
  if (content.truncated) {
    incomplete = true
    notes.push('finding-limit')
  }

  const findings = [...content.findings]
  let filesScanned = new Set(added.map(entry => entry.file)).size

  if (mutation.mayAddUntracked === true) {
    const untracked = await scanUntrackedFiles(runGit, {
      rules,
      config,
      mutation,
      cwd: op.cwd,
      readWorkingFile,
      remaining: Math.max(1, config.maxFindings - findings.length),
    })
    findings.push(...untracked.findings)
    filesScanned += untracked.filesScanned
    if (untracked.incomplete === true) incomplete = true
    notes.push(...untracked.notes)
  }

  const messages = Array.isArray(op.messages) ? [...op.messages] : []
  let messageUnresolved = false
  if (typeof op.messageFile === 'string' && op.messageFile.length > 0) {
    if (op.messageFile === '-') {
      // The message comes from stdin, which only git sees at execution time.
      messageUnresolved = true
      notes.push('message-from-stdin')
    } else if (typeof readTextFile === 'function') {
      const filePath = path.resolve(op.cwd ?? process.cwd(), op.messageFile)
      try {
        const text = await readTextFile(filePath)
        if (typeof text === 'string') messages.push(text)
      } catch {
        // Unreadable or oversized message files cannot be verified.
        messageUnresolved = true
        notes.push('message-file-unreadable')
      }
    }
  }
  if (messages.some(message => hasShellExpansion(message))) {
    messageUnresolved = true
    if (!notes.includes('message-dynamic')) notes.push('message-dynamic')
  }
  if (op.flags?.reuseMessage === true) notes.push('message-reused')
  if (messageUnresolved) incomplete = true

  const messageFindings = []
  for (const message of messages) {
    const result = scanText(message, {
      file: '<commit message>',
      rules,
      config: { ...config, maxFindings: Math.max(1, config.maxFindings - findings.length) },
    })
    messageFindings.push(...result.findings)
    if (result.truncated) {
      incomplete = true
      notes.push('finding-limit')
    }
  }

  return {
    findings: [...findings, ...messageFindings],
    incomplete,
    notes: dedupeStrings(notes),
    filesScanned,
    commitsScanned: 0,
  }
}

/** Drop added lines whose path the user configured to ignore. */
function filterIgnoredPaths(entries, config) {
  const ignorePaths = config?.ignorePaths
  if (!Array.isArray(ignorePaths) || ignorePaths.length === 0) return entries
  return entries.filter(entry => !isIgnoredPath(entry.file, ignorePaths))
}

/** De-duplicate an array of strings while keeping first-seen order. */
function uniqueStrings(value) {
  if (!Array.isArray(value)) return []
  return [...new Set(value.filter(item => typeof item === 'string' && item.length > 0))]
}

/**
 * Scan untracked files a preceding `git add` could stage.
 *
 * `git ls-files --others --exclude-standard` honours `.gitignore`; a forced add
 * (`git add -f`) falls back to the unfiltered listing. Files are read from the
 * worktree, capped by the same limits as the full-repository scan.
 */
async function scanUntrackedFiles(runGit, { rules, config, mutation, cwd, readWorkingFile, remaining }) {
  const notes = []
  const findings = []
  let filesScanned = 0
  let skipped = 0
  let totalBytes = 0
  let incomplete = false

  if (typeof readWorkingFile !== 'function') {
    return { findings, incomplete: true, notes: ['untracked-reader-missing'], filesScanned }
  }

  const listArgs = ['ls-files', '--others', '-z']
  if (mutation.scanIgnored !== true) listArgs.push('--exclude-standard')
  const list = await runGit(listArgs, { maxBuffer: config.maxTotalBytes + 1024 * 1024 })
  if (!list?.ok) {
    if (list?.truncated) return { findings, incomplete: true, notes: ['untracked-list-too-large'], filesScanned }
    return { findings, incomplete: true, notes: ['untracked-list-failed'], filesScanned }
  }

  let files = list.stdout
    .split('\u0000')
    .filter(file => file.length > 0)
    .map(file => file.replace(/\\/g, '/'))

  if (mutation.addScopeAll !== true) {
    const prefixes = uniqueStrings(mutation.addPaths).map(prefix =>
      prefix.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, ''),
    )
    if (prefixes.length > 0) {
      files = files.filter(file => prefixes.some(prefix => file === prefix || file.startsWith(`${prefix}/`)))
    }
  }
  // A forced add (`git add -f`) deliberately overrides .gitignore, so the
  // plugin's own ignorePaths must not silently drop those paths again.
  if (mutation.scanIgnored !== true) {
    files = files.filter(file => !isIgnoredPath(file, config.ignorePaths))
  }

  const base = typeof cwd === 'string' && cwd.length > 0 ? cwd : process.cwd()
  for (const file of files) {
    if (filesScanned + skipped >= config.maxFiles) {
      incomplete = true
      notes.push('file-limit')
      break
    }
    const buffer = await readWorkingFile(path.resolve(base, file), config.maxFileBytes).catch(() => null)
    if (buffer === null || buffer === undefined) {
      skipped += 1
      incomplete = true
      continue
    }
    if (totalBytes + buffer.length > config.maxTotalBytes) {
      incomplete = true
      notes.push('total-size-limit')
      break
    }
    totalBytes += buffer.length
    filesScanned += 1
    if (buffer.includes(0)) continue
    const lines = buffer
      .toString('utf8')
      .split(/\r?\n/)
      .map((text, index) => ({ text, file, line: index + 1 }))
    const result = scanLines(lines, rules, {
      ...config,
      maxFindings: Math.max(1, Math.min(remaining, config.maxFindings - findings.length)),
    })
    findings.push(...result.findings)
    if (result.truncated) {
      incomplete = true
      notes.push('finding-limit')
    }
  }

  if (skipped > 0) notes.push(`files-skipped:${skipped}`)
  return { findings, incomplete, notes: dedupeStrings(notes), filesScanned }
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
    // `git log -p` walks every commit in the uploaded range, not just the net
    // diff: a secret added in one commit and deleted in a later one is still
    // part of the pushed history and must be caught.
    const diff = await runGit(
      ['log', '-p', '--format=', '--no-color', '--no-ext-diff', '--no-textconv', '--unified=0', `${range.base}..${range.headSha}`],
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
    const added = filterIgnoredPaths(parsePatch(diff.stdout), config)
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
  const messageResult = await readCommitMessages(runGit, commits.slice(0, config.maxCommits))
  if (messageResult.error !== undefined) {
    return { error: messageResult.error, findings: [], incomplete: true, notes }
  }
  for (const message of messageResult.messages) {
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

  // Tag objects are uploaded too (e.g. `git push --tags`): scan their messages.
  if (Array.isArray(plan.tagRefs) && plan.tagRefs.length > 0) {
    for (const name of plan.tagRefs) {
      const result = await runGit(['for-each-ref', '--format=%(contents)', `refs/tags/${name}`])
      if (!result?.ok) {
        incomplete = true
        notes.push('tag-read-failed')
        continue
      }
      const text = result.stdout
      if (typeof text !== 'string' || text.trim().length === 0) continue
      const messageResult = scanText(text, {
        file: `<tag message: ${name}>`,
        rules,
        config: { ...config, maxFindings: Math.max(1, config.maxFindings - findings.length) },
      })
      findings.push(...messageResult.findings)
      if (messageResult.truncated) {
        incomplete = true
        notes.push('finding-limit')
      }
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
export async function scanFullRepo(runGit, { rules, config, readBlobs, cwd }) {
  const head = await revParse(runGit, 'HEAD^{commit}')
  if (head === null) return { findings: [], incomplete: false, notes: ['no-head'], filesScanned: 0, skipped: 0 }

  // --full-tree ignores the process cwd, so a scan started from a subdirectory
  // still covers the whole repository.
  const tree = await runGit(['ls-tree', '-r', '-z', '--full-tree', '--long', 'HEAD'], {
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

  // Select the blobs to read first so a single `git cat-file --batch` process
  // can stream all of them, instead of one process per file.
  const selected = []
  for (const entry of entries) {
    if (filesScanned + selected.length >= config.maxFiles) {
      incomplete = true
      notes.push('file-limit')
      break
    }
    if (isIgnoredPath(entry.path, config.ignorePaths)) continue
    if (entry.size > config.maxFileBytes) {
      // The file is skipped, so the scan is not a complete picture of the repo.
      skipped += 1
      incomplete = true
      continue
    }
    if (totalBytes + entry.size > config.maxTotalBytes) {
      incomplete = true
      notes.push('total-size-limit')
      break
    }
    totalBytes += entry.size
    selected.push(entry)
  }

  let blobs
  if (typeof readBlobs === 'function' && selected.length > 0) {
    try {
      blobs = await readBlobs({ cwd, oids: selected.map(entry => entry.oid) })
    } catch (error) {
      return {
        error: error instanceof Error ? error.message : 'git cat-file --batch failed',
        findings: [],
        incomplete: true,
        notes: ['batch-read-failed'],
        filesScanned: 0,
        skipped,
      }
    }
  }

  for (const entry of selected) {
    let buffer
    if (blobs instanceof Map) {
      buffer = blobs.get(entry.oid)
      if (buffer === undefined) {
        skipped += 1
        incomplete = true
        continue
      }
    } else {
      const blob = await runGit(['cat-file', 'blob', entry.oid], { maxBuffer: config.maxFileBytes + 1024 * 1024 })
      if (!blob?.ok) {
        skipped += 1
        incomplete = true
        continue
      }
      buffer = Buffer.from(blob.stdout ?? '', 'utf8')
    }
    filesScanned += 1
    if (looksBinaryBuffer(buffer)) continue
    const lines = buffer.toString('utf8').split(/\r?\n/).map((text, index) => ({ text, file: entry.path, line: index + 1 }))
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

/** Heuristic binary detection for a blob buffer. */
function looksBinaryBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) return true
  return buffer.subarray(0, 8192).includes(0)
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

/**
 * Whether a commit message contains shell expansions whose value is only known
 * when the shell runs the command (`$(...)`, `${VAR}`, `%VAR%`).
 */
function hasShellExpansion(text) {
  return /(?:\$\(|\$\{[A-Za-z_]|%[A-Za-z_][\w]*%)/.test(String(text ?? ''))
}
