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
const COMMIT_VALUE_FLAGS = new Set(['--author', '--date', '--template', '--cleanup'])
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

  const baseCwd = resolveBaseCwd(args, sessionCwd, platform)
  const operations = []
  walkCommandText(text, baseCwd, 0, operations, platform)
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
  if (workdir === undefined) return path.resolve(fallback)
  return resolvePath(fallback, workdir, platform)
}

/** Resolve one path against a base directory. */
function resolvePath(base, value, platform) {
  const normalized = stripOuterQuotes(value)
  if (platform === 'win32') {
    // path.win32 keeps drive letters and backslashes deterministic in tests.
    return path.win32.resolve(base, normalized)
  }
  return path.resolve(base, normalized)
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
function walkCommandText(text, baseCwd, depth, operations, platform) {
  let cwd = baseCwd
  for (const tokens of splitSegments(text)) {
    if (tokens.length === 0) continue

    let index = 0
    while (index < tokens.length) {
      const token = tokens[index]
      if (token === '&' || token === '.' || token === '(' || token === ')') {
        index += 1
        continue
      }
      if (/^\$?[A-Za-z_][\w]*=/.test(token)) {
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
        cwd = resolvePath(cwd, target, platform)
      }
      continue
    }

    if (SHELL_WRAPPERS.has(name)) {
      if (depth < MAX_WRAPPER_DEPTH) {
        const script = findWrapperScript(tokens, index + 1)
        if (script !== undefined) walkCommandText(script, cwd, depth + 1, operations, platform)
      }
      continue
    }

    if (name === 'git') {
      const operation = parseGit(tokens, index, cwd, platform)
      if (operation !== null) operations.push(operation)
      continue
    }
    if (name === 'gh') {
      const operation = parseGh(tokens, index, cwd)
      if (operation !== null) operations.push(operation)
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

  while (index < tokens.length) {
    const token = tokens[index]
    if (token === '-C') {
      repoDir = tokens[index + 1]
      index += 2
      continue
    }
    if (token === '--git-dir' || token === '--work-tree') {
      index += 2
      continue
    }
    if (token.startsWith('--git-dir=') || token.startsWith('--work-tree=') || token.startsWith('--namespace=')) {
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
  const rest = tokens.slice(index + 1)

  if (subcommand === 'push') {
    const parsed = parsePushArgs(rest)
    if (parsed === null) return null
    return { kind: 'push', cwd, ...parsed }
  }
  if (subcommand === 'commit') {
    const parsed = parseCommitArgs(rest)
    if (parsed === null) return null
    return { kind: 'commit', cwd, ...parsed }
  }
  return null
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
      const cluster = token.slice(1)
      if (cluster.includes('h')) return null
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

/** Parse `git commit` arguments (flags + message sources). */
function parseCommitArgs(args) {
  const flags = { all: false, amend: false }
  const messages = []
  let messageFile

  for (let index = 0; index < args.length; index += 1) {
    const token = args[index]
    if (token === '--') break
    if (token.startsWith('--')) {
      const [name, value] = splitLongFlag(token)
      if (name === '--all') flags.all = true
      else if (name === '--amend') flags.amend = true
      else if (name === '--help') return null
      else if (name === '--message') {
        if (value !== undefined) messages.push(value)
        else if (index + 1 < args.length) messages.push(args[++index])
      } else if (name === '--file') {
        if (value !== undefined) messageFile = value
        else if (index + 1 < args.length) messageFile = args[++index]
      } else if (COMMIT_VALUE_FLAGS.has(name) && value === undefined) {
        index += 1
      }
      continue
    }
    if (token.startsWith('-') && token.length > 1) {
      const cluster = token.slice(1)
      if (cluster.includes('h')) return null
      if (cluster.includes('a')) flags.all = true
      if (cluster.includes('m')) {
        if (index + 1 < args.length) messages.push(args[++index])
      }
      if (cluster.includes('F')) {
        if (index + 1 < args.length) messageFile = args[++index]
      }
      continue
    }
  }
  return { flags, messages, messageFile }
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
