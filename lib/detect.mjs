/**
 * Command detection for shell tool calls.
 *
 * Decides, without executing anything, whether a `pwsh` / `bash` /
 * `terminal_send` call commits or pushes git content (or runs `gh repo sync`),
 * and resolves the repository directory from `workdir`, in-command `cd`,
 * `git -C`, and simple shell `-c` wrappers.
 *
 * Pure module: no I/O, no child processes.
 *
 * @module dsh-push-privacy-guard/detect
 */

import os from 'node:os'
import path from 'node:path'

/** Tools whose command text is inspected. */
export const SHELL_TOOLS = new Set([
  'pwsh',
  'bash',
  'terminal_send',
  'bash_persistent',
  'pwsh_persistent',
])

/** Wrappers whose `-c` / `-Command` script is inspected recursively. */
const SHELL_WRAPPERS = new Set(['bash', 'sh', 'zsh', 'pwsh', 'powershell', 'cmd'])

/** Command position prefixes that only wrap the real command. */
const COMMAND_PREFIXES = new Set(['sudo', 'env', 'command', 'exec', 'time', 'nohup', 'start-process'])

/** Flags that consume a following value (so it is not a refspec/positional). */
const PUSH_VALUE_FLAGS = new Set(['-o', '--push-option', '--repo', '--receive-pack', '--exec'])
/** `git commit` long options that take a value (consumed so values never become pathspecs). */
const COMMIT_VALUE_FLAGS = new Set([
  '--author',
  '--date',
  '--template',
  '--cleanup',
  '--reuse-message',
  '--reedit-message',
  '--fixup',
  '--squash',
  '--trailer',
  '--pathspec-from-file',
])
/** `git commit` short letters that take an attached-or-following value. */
const COMMIT_VALUE_SHORT = new Set(['m', 'F', 'C', 'c', 't', 'S'])
/** `git commit` short options that take no value (only listed to document intent). */
const GH_GLOBAL_VALUE_FLAGS = new Set(['-R', '--repo', '--hostname'])

/** Maximum parser recursion for shell `-c` wrappers. */
const MAX_WRAPPER_DEPTH = 2

/**
 * Detect git commit / push operations in one tool call.
 *
 * @param {{tool?:string,args?:Record<string,unknown>,sessionCwd?:string,platform?:string}} input
 * @returns {Array<object>} operations with `kind` (`commit` | `push` | `sync`).
 */
export function detectOperations({ tool, args, sessionCwd, platform = process.platform }) {
  const toolName = String(tool ?? '').toLowerCase()
  if (!SHELL_TOOLS.has(toolName)) return []
  if (args === null || typeof args !== 'object') return []

  const text = pickCommandText(args)
  if (typeof text !== 'string' || text.trim().length === 0) return []
  if (!/\b(?:git|gh)(?:\.(?:exe|cmd|bat))?\b/i.test(text)) return []

  const base = resolveBaseCwd(args, sessionCwd, platform)
  const operations = []
  const state = { mutations: new Map() }
  walkCommandText(text, base.cwd, 0, operations, platform, state, base.unresolved)
  return operations
}

/** First string-valued command argument. */
function pickCommandText(args) {
  for (const key of ['command', 'text', 'cmd']) {
    const value = args[key]
    if (typeof value === 'string' && value.trim().length > 0) return value
  }
  return undefined
}

/** The directory the shell call starts in: explicit workdir, else session cwd. */
function resolveBaseCwd(args, sessionCwd, platform) {
  const fallback = typeof sessionCwd === 'string' && sessionCwd.length > 0 ? sessionCwd : process.cwd()
  const workdir = typeof args.workdir === 'string' && args.workdir.trim().length > 0 ? args.workdir.trim() : undefined
  if (workdir === undefined) return { cwd: path.resolve(fallback), unresolved: false }
  return {
    cwd: resolvePath(fallback, workdir, platform),
    unresolved: containsShellExpansion(workdir),
  }
}

/** Whether a path token depends on shell expansion we cannot evaluate. */
export function containsShellExpansion(value) {
  return /(?:\$[A-Za-z_{(]|%[A-Za-z_][\w]*%|`|\{\{)/.test(String(value ?? ''))
}

/** Resolve one path against a base directory. */
function resolvePath(base, value, platform) {
  const normalized = expandHome(stripOuterQuotes(value))
  if (platform === 'win32') {
    // path.win32 keeps drive letters and backslashes deterministic in tests.
    return path.win32.resolve(base, normalized)
  }
  return path.resolve(base, normalized)
}

/** Expand a leading `~` (the shell would do this before git sees the path). */
function expandHome(value) {
  if (value === '~') return os.homedir()
  if (value.startsWith('~/') || value.startsWith('~\\')) return path.join(os.homedir(), value.slice(2))
  return value
}

/** Remove one matching pair of surrounding quotes. */
function stripOuterQuotes(value) {
  const trimmed = value.trim()
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) return trimmed.slice(1, -1)
  if (trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'")) return trimmed.slice(1, -1)
  return trimmed
}

/**
 * Walk one command text: split into simple commands, update the tracked cwd for
 * `cd`, recurse into shell wrappers, and collect git/gh operations.
 */
function walkCommandText(text, baseCwd, depth, operations, platform, state, baseUnresolved = false) {
  let cwd = baseCwd
  let cwdUnresolved = baseUnresolved === true
  for (const tokens of splitSegments(text)) {
    if (tokens.length === 0) continue

    let envOverride = false
    let index = 0
    while (index < tokens.length) {
      const token = tokens[index]
      if (token === '&' || token === '.' || token === '(' || token === ')') {
        index += 1
        continue
      }
      if (/^\$?[A-Za-z_][\w]*=/.test(token)) {
        if (/^(?:GIT_DIR|GIT_WORK_TREE|GIT_INDEX_FILE|GIT_COMMON_DIR)=/i.test(token)) envOverride = true
        index += 1
        continue
      }
      const name = commandName(token)
      if (COMMAND_PREFIXES.has(name)) {
        index += 1
        continue
      }
      break
    }
    if (index >= tokens.length) continue

    const name = commandName(tokens[index])
    if (name === 'cd' || name === 'chdir' || name === 'set-location' || name === 'sl' || name === 'pushd') {
      const target = tokens[index + 1]
      if (typeof target === 'string' && target.length > 0 && !target.startsWith('-')) {
        if (containsShellExpansion(target)) {
          cwdUnresolved = true
          cwd = resolvePath(cwd, target, platform)
        } else {
          cwd = resolvePath(cwd, target, platform)
          if (path.isAbsolute(stripOuterQuotes(target))) cwdUnresolved = false
        }
      }
      continue
    }

    if (SHELL_WRAPPERS.has(name)) {
      if (depth < MAX_WRAPPER_DEPTH) {
        const script = findWrapperScript(tokens, index + 1)
        if (script !== undefined) walkCommandText(script, cwd, depth + 1, operations, platform, state, cwdUnresolved)
      }
      continue
    }

    if (name === 'git') {
      const operation = parseGit(tokens, index, cwd, platform)
      if (operation === null) continue
      operation.cwdUnresolved = operation.cwdUnresolved === true || cwdUnresolved || envOverride
      if (operation.kind === 'index-mutation') {
        recordIndexMutation(state, operation)
        continue
      }
      if (operation.kind === 'commit') {
        const mutation = state.mutations.get(operation.cwd)
        if (mutation !== undefined) operation.mutation = snapshotMutation(mutation)
      }
      operations.push(operation)
      continue
    }
    if (name === 'gh') {
      const operation = parseGh(tokens, index, cwd)
      if (operation !== null) {
        operation.cwdUnresolved = operation.cwdUnresolved === true || cwdUnresolved
        operations.push(operation)
      }
    }
  }
}

/** Basename of a command token, lowercased, without a Windows executable suffix. */
function commandName(token) {
  const stripped = stripOuterQuotes(token)
  const base = stripped.split(/[\\/]+/).pop() ?? stripped
  return base.toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '')
}

/** Script argument of a shell wrapper (`-c`, `-Command`, `/c`). */
function findWrapperScript(tokens, start) {
  for (let index = start; index < tokens.length; index += 1) {
    const token = tokens[index]
    const lower = token.toLowerCase()
    if (lower === '-c' || lower === '/c' || lower === '-command' || lower === '--command') {
      const rest = tokens.slice(index + 1)
      if (rest.length === 0) return undefined
      return rest.join(' ')
    }
  }
  return undefined
}

/** Parse `git ... <subcommand>` into an operation. */
function parseGit(tokens, gitIndex, baseCwd, platform) {
  let index = gitIndex + 1
  let repoDir
  let gitDirOverride = false

  while (index < tokens.length) {
    const token = tokens[index]
    if (token === '-C') {
      repoDir = tokens[index + 1]
      index += 2
      continue
    }
    if (token === '--git-dir' || token === '--work-tree') {
      // The scan would target a different directory than the tracked cwd.
      gitDirOverride = true
      index += 2
      continue
    }
    if (token.startsWith('--git-dir=') || token.startsWith('--work-tree=') || token.startsWith('--namespace=')) {
      if (!token.startsWith('--namespace=')) gitDirOverride = true
      index += 1
      continue
    }
    if (token === '-c') {
      index += 2
      continue
    }
    if (token.startsWith('-')) {
      index += 1
      continue
    }
    break
  }

  const subcommand = index < tokens.length ? tokens[index].toLowerCase() : ''
  const cwd =
    typeof repoDir === 'string' && repoDir.length > 0 ? resolvePath(baseCwd, repoDir, platform) : baseCwd
  const cwdUnresolved = gitDirOverride || (typeof repoDir === 'string' && containsShellExpansion(repoDir))
  const rest = tokens.slice(index + 1)

  if (subcommand === 'push') {
    const parsed = parsePushArgs(rest)
    if (parsed === null) return null
    return { kind: 'push', cwd, cwdUnresolved, ...parsed }
  }
  if (subcommand === 'commit') {
    const parsed = parseCommitArgs(rest)
    if (parsed === null) return null
    return { kind: 'commit', cwd, cwdUnresolved, ...parsed }
  }
  if (MUTATING_SUBCOMMANDS.has(subcommand)) {
    return { kind: 'index-mutation', cwd, cwdUnresolved, subcommand, args: rest }
  }
  return null
}

/** Subcommands that can change the index/worktree state a later commit commits. */
const MUTATING_SUBCOMMANDS = new Set([
  'add',
  'rm',
  'mv',
  'reset',
  'restore',
  'stash',
  'checkout',
  'switch',
  'apply',
  'am',
  'merge',
  'rebase',
  'cherry-pick',
  'pull',
])

/** Mutations that can put new content into the index a later commit records. */
const STAGING_SUBCOMMANDS = new Set(['add', 'rm', 'mv', 'stash', 'apply', 'am'])

/** Mutation accumulator for one repository directory during one command text. */
function mutationFor(state, cwd) {
  let record = state.mutations.get(cwd)
  if (record === undefined) {
    record = { indexMutated: false, mayAddUntracked: false, addPaths: new Set(), scanIgnored: false, addScopeAll: false }
    state.mutations.set(cwd, record)
  }
  return record
}

/** Fold one mutation subcommand into the per-repo accumulator. */
function recordIndexMutation(state, operation) {
  if (!STAGING_SUBCOMMANDS.has(operation.subcommand)) return
  const record = mutationFor(state, operation.cwd)
  record.indexMutated = true
  if (operation.subcommand !== 'add') return

  const parsed = parseAddArgs(operation.args)
  if (parsed.updateOnly && !parsed.explicitAll) return // `git add -u` only refreshes tracked files
  record.mayAddUntracked = true
  if (parsed.all) {
    record.addScopeAll = true
    record.addPaths.clear()
  } else {
    for (const target of parsed.paths) {
      if (target === '.' || target === '*' || target.endsWith('/*')) {
        record.addScopeAll = true
        record.addPaths.clear()
        break
      }
      record.addPaths.add(target)
    }
  }
  if (parsed.force) record.scanIgnored = true
}

/** Parse `git add` arguments into the facts the commit scanner needs. */
function parseAddArgs(args) {
  let all = false
  let updateOnly = false
  let force = false
  const paths = []
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index]
    if (token === '--') {
      paths.push(...args.slice(index + 1))
      break
    }
    if (token.startsWith('--')) {
      const [name, value] = splitLongFlag(token)
      if (name === '--all' || name === '--no-ignore-removal') all = true
      else if (name === '--update') updateOnly = true
      else if (name === '--force') force = true
      else if (value === undefined && (name === '--chmod' || name === '--pathspec-from-file')) index += 1
      continue
    }
    if (token.startsWith('-') && token.length > 1) {
      const cluster = token.slice(1)
      if (cluster.includes('A')) all = true
      if (cluster.includes('u')) updateOnly = true
      if (cluster.includes('f')) force = true
      continue
    }
    paths.push(token)
  }
  const allScope = all || paths.length === 0 || paths.some(target => target === '.' || target === '*')
  const explicitAll = all || paths.some(target => target === '.' || target === '*')
  return { all: allScope, explicitAll, updateOnly, force, paths }
}

/** Snapshot the mutable accumulator for attaching to a commit operation. */
function snapshotMutation(record) {
  return {
    indexMutated: record.indexMutated === true,
    mayAddUntracked: record.mayAddUntracked === true,
    addPaths: [...record.addPaths],
    addScopeAll: record.addScopeAll === true,
    scanIgnored: record.scanIgnored === true,
  }
}

/** Parse `git push` arguments (flags + positionals). */
function parsePushArgs(args) {
  const flags = { delete: false, all: false, mirror: false, force: false, tags: false, dryRun: false }
  const positional = []

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index]
    if (token === '--') {
      positional.push(...args.slice(index + 1))
      break
    }
    if (token.startsWith('--')) {
      const [name, value] = splitLongFlag(token)
      if (name === '--delete') flags.delete = true
      else if (name === '--all') flags.all = true
      else if (name === '--mirror') flags.mirror = true
      else if (name === '--force' || name === '--force-with-lease' || name === '--force-if-includes') flags.force = true
      else if (name === '--tags') flags.tags = true
      else if (name === '--dry-run') flags.dryRun = true
      else if (name === '--help') return null
      else if (PUSH_VALUE_FLAGS.has(name) && value === undefined) index += 1
      continue
    }
    if (token.startsWith('-') && token.length > 1) {
      if (token === '-h') return null
      const cluster = token.slice(1)
      if (cluster.includes('d')) flags.delete = true
      if (cluster.includes('f')) flags.force = true
      if (cluster.includes('n')) flags.dryRun = true
      if (PUSH_VALUE_FLAGS.has(token)) index += 1
      continue
    }
    positional.push(token)
  }

  return { flags, positional, remote: positional.length > 0 ? positional[0] : undefined }
}

/** Parse `git commit` arguments (flags + message sources + pathspecs). */
function parseCommitArgs(args) {
  const flags = { all: false, amend: false, reuseMessage: false, fixup: false, worktreePaths: false }
  const messages = []
  const pathspecs = []
  const includes = []
  let messageFile
  let pathspecFromFile

  const addPathspec = value => {
    if (typeof value !== 'string') return
    const trimmed = value.trim()
    if (trimmed.length > 0) pathspecs.push(trimmed)
  }
  const consumeNext = index => (index + 1 < args.length ? args[index + 1] : undefined)

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index]
    if (token === '--') {
      for (const rest of args.slice(index + 1)) addPathspec(rest)
      break
    }
    if (token.startsWith('--')) {
      const [name, value] = splitLongFlag(token)
      const takeValue = () => {
        if (value !== undefined) return value
        const next = consumeNext(index)
        if (next !== undefined) index += 1
        return next
      }
      if (name === '--all') flags.all = true
      else if (name === '--amend') flags.amend = true
      else if (name === '--help') return null
      else if (name === '--message') {
        const message = takeValue()
        if (message !== undefined) messages.push(message)
      } else if (name === '--file') {
        messageFile = takeValue()
      } else if (name === '--include' || name === '--only') {
        // Boolean switches that make positional pathspecs commit worktree content.
        flags.worktreePaths = true
      } else if (name === '--reuse-message' || name === '--reedit-message') {
        flags.reuseMessage = true
        takeValue()
      } else if (name === '--fixup' || name === '--squash') {
        flags.reuseMessage = true
        flags.fixup = true
        takeValue()
      } else if (name === '--trailer') {
        const trailer = takeValue()
        if (trailer !== undefined) messages.push(trailer)
      } else if (name === '--pathspec-from-file') {
        pathspecFromFile = takeValue()
        flags.worktreePaths = true
      } else if (COMMIT_VALUE_FLAGS.has(name)) {
        if (value === undefined) takeValue()
      }
      // Unknown long options are treated as boolean: never consume the next
      // token, so a real pathspec cannot be swallowed by an option value.
      continue
    }
    if (token.startsWith('-') && token.length > 1) {
      if (token === '-h') return null
      const cluster = token.slice(1)
      for (let position = 0; position < cluster.length; position += 1) {
        const letter = cluster[position]
        if (COMMIT_VALUE_SHORT.has(letter)) {
          const attached = cluster.slice(position + 1)
          const required = letter === 'm' || letter === 'F' || letter === 'C' || letter === 'c' || letter === 't'
          const value = attached.length > 0 ? attached : required ? consumeNext(index) : undefined
          if (attached.length === 0 && required && value !== undefined) index += 1
          if (letter === 'm' && value !== undefined) messages.push(value)
          else if (letter === 'F' && value !== undefined) messageFile = value
          else if (letter === 'C' || letter === 'c') flags.reuseMessage = true
          break
        }
        if (letter === 'S' || letter === 'u') {
          // Optional attached value only; never consume the next token.
          break
        }
        if (letter === 'a') flags.all = true
        if (letter === 'i' || letter === 'o') flags.worktreePaths = true
      }
      continue
    }
    addPathspec(token)
  }
  return { flags, messages, messageFile, pathspecs, includes, pathspecFromFile }
}

/** Split `--name=value` into its parts. */
function splitLongFlag(token) {
  const equals = token.indexOf('=')
  if (equals < 0) return [token, undefined]
  return [token.slice(0, equals), token.slice(equals + 1)]
}

/** Parse `gh ...` into a sync operation, if any. */
function parseGh(tokens, ghIndex, cwd) {
  const rest = []
  for (let index = ghIndex + 1; index < tokens.length; index += 1) {
    const token = tokens[index]
    if (token.startsWith('-')) {
      const [, value] = splitLongFlag(token)
      if (GH_GLOBAL_VALUE_FLAGS.has(token) && value === undefined) index += 1
      else if (token === '-R' || token === '--repo' || token === '--hostname') index += 1
      continue
    }
    rest.push(token)
  }
  if (rest[0] === 'repo' && rest[1] === 'sync') return { kind: 'sync', cwd }
  return null
}

/**
 * Split a command text into simple command token arrays.
 *
 * Respects single/double quotes, POSIX backslash escapes, PowerShell backtick
 * escapes, and does not split on redirection `&>` / `>&`.
 */
export function splitSegments(text) {
  const segments = []
  let tokens = []
  let current = ''
  let started = false
  let quote = null

  const pushToken = () => {
    if (!started) return
    tokens.push(current)
    current = ''
    started = false
  }
  const pushSegment = () => {
    pushToken()
    if (tokens.length > 0) segments.push(tokens)
    tokens = []
  }

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    const next = text[index + 1]

    if (quote !== null) {
      if (char === quote) {
        quote = null
        continue
      }
      if ((char === '\\' || char === '`') && next !== undefined) {
        current += next
        index += 1
        continue
      }
      current += char
      continue
    }

    if (char === '"' || char === "'") {
      quote = char
      started = true
      continue
    }
    if (char === '`' && next !== undefined) {
      current += next
      index += 1
      started = true
      continue
    }
    if (char === '\\' && next !== undefined && ' \t;|&'.includes(next)) {
      current += next
      index += 1
      started = true
      continue
    }
    if (char === '\n' || char === '\r' || char === ';') {
      pushSegment()
      continue
    }
    if (char === '&') {
      if (next === '&') {
        pushSegment()
        index += 1
        continue
      }
      const previous = index > 0 ? text[index - 1] : ''
      if (next === '>' || previous === '>') {
        current += char
        started = true
        continue
      }
      pushSegment()
      continue
    }
    if (char === '|') {
      pushSegment()
      if (next === '|') index += 1
      continue
    }
    if (char === '(' || char === ')') {
      pushToken()
      continue
    }
    if (char === ' ' || char === '\t') {
      pushToken()
      continue
    }
    current += char
    started = true
  }
  pushSegment()
  return segments
}
