/**
 * Read-only git runner used by the scanner.
 *
 * Every command is forced into a non-interactive, locale-stable, pager-free
 * shape. The scanner only ever calls read-only subcommands, so a check can
 * never mutate the user's repository (no index writes, no object writes, no
 * remote access).
 *
 * @module dsh-push-privacy-guard/git
 */

import { execFile, spawn } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

/** Arguments prepended to every git invocation. */
export const GIT_BASE_ARGS = ['--no-pager', '-c', 'color.ui=false', '-c', 'core.quotepath=false']

/** Environment variables that could redirect git at another repository. */
const REPO_REDIRECT_ENV = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_PREFIX',
  'GIT_COMMON_DIR',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
]

/** Environment inherited by git: stable locale, no prompts, no optional locks. */
export function gitEnvironment(base = process.env) {
  const env = { ...base }
  for (const name of REPO_REDIRECT_ENV) delete env[name]
  env.LC_ALL = 'C'
  env.LANG = 'C'
  env.GIT_PAGER = 'cat'
  env.GIT_TERMINAL_PROMPT = '0'
  env.GIT_OPTIONAL_LOCKS = '0'
  return env
}

/**
 * Create a bound runner: every call runs git in `cwd`.
 *
 * @param {{cwd?:string, timeoutMs?:number, maxBuffer?:number, env?:object, exec?:Function}} [options]
 * @returns {(args:string[], callOptions?:object) => Promise<object>}
 */
export function createGitRunner(options = {}) {
  const defaultCwd = options.cwd
  const defaultTimeoutMs = options.timeoutMs ?? 20000
  const defaultMaxBuffer = options.maxBuffer ?? 25 * 1024 * 1024
  const env = options.env ?? gitEnvironment()
  const execute = options.exec ?? execFileAsync

  return async function runGit(args, callOptions = {}) {
    const cwd = callOptions.cwd ?? defaultCwd
    if (typeof cwd !== 'string' || cwd.length === 0) {
      return { ok: false, code: null, stdout: '', stderr: 'no cwd for git', error: 'NO_CWD' }
    }
    try {
      const result = await execute('git', [...GIT_BASE_ARGS, ...args], {
        cwd,
        timeout: callOptions.timeoutMs ?? defaultTimeoutMs,
        maxBuffer: callOptions.maxBuffer ?? defaultMaxBuffer,
        windowsHide: true,
        encoding: 'utf8',
        env,
      })
      return { ok: true, code: 0, stdout: result.stdout ?? '', stderr: result.stderr ?? '' }
    } catch (error) {
      const stderr = typeof error?.stderr === 'string' ? error.stderr : ''
      const stdout = typeof error?.stdout === 'string' ? error.stdout : ''
      const truncated = error?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
      const timedOut = error?.killed === true || error?.signal === 'SIGTERM' || error?.code === 'ETIMEDOUT'
      return {
        ok: false,
        code: typeof error?.code === 'number' ? error.code : null,
        stdout,
        stderr,
        truncated,
        timedOut,
        error: error instanceof Error ? error.message : String(error),
      }
    }
  }
}

/**
 * Read many blobs through one `git cat-file --batch` process.
 *
 * Reading blobs one by one costs one process per file (minutes for a mid-sized
 * repository), so the full-repository scan streams all object ids through a
 * single child instead.
 *
 * @param {{cwd:string,oids:string[],timeoutMs?:number,maxBytes?:number,env?:object}} options
 * @returns {Promise<Map<string,Buffer>>}
 */
export function readBlobsBatch({ cwd, oids, timeoutMs = 20000, maxBytes = 64 * 1024 * 1024, env = gitEnvironment() }) {
  return new Promise((resolve, reject) => {
    if (!Array.isArray(oids) || oids.length === 0) {
      resolve(new Map())
      return
    }
    let child
    try {
      child = spawn('git', [...GIT_BASE_ARGS, 'cat-file', '--batch'], {
        cwd,
        windowsHide: true,
        env,
        stdio: ['pipe', 'pipe', 'pipe'],
      })
    } catch (error) {
      reject(error instanceof Error ? error : new Error(String(error)))
      return
    }

    const chunks = []
    let received = 0
    let stderr = ''
    let settled = false
    const timer = setTimeout(() => {
      child.kill()
      finish(new Error('git cat-file --batch timed out'))
    }, timeoutMs)
    if (typeof timer.unref === 'function') timer.unref()

    function finish(error, value) {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error !== undefined) reject(error)
      else resolve(value)
    }

    child.on('error', error => finish(error instanceof Error ? error : new Error(String(error))))
    child.stderr.setEncoding('utf8')
    child.stderr.on('data', text => {
      if (stderr.length < 8192) stderr += text
    })
    child.stdout.on('data', chunk => {
      received += chunk.length
      if (received > maxBytes) {
        child.kill()
        finish(new Error('git cat-file --batch output too large'))
        return
      }
      chunks.push(chunk)
    })
    child.on('close', code => {
      if (settled) return
      if (code !== 0) {
        finish(new Error(stderr.trim() || `git cat-file exited with ${code}`))
        return
      }
      try {
        finish(undefined, parseBatchOutput(Buffer.concat(chunks), oids))
      } catch (error) {
        finish(error instanceof Error ? error : new Error(String(error)))
      }
    })
    child.stdin.on('error', error => finish(error instanceof Error ? error : new Error(String(error))))
    child.stdin.end(oids.map(oid => `${oid}\n`).join(''))
  })
}

/** Parse `git cat-file --batch` output (headers, sizes, trailing newline). */
export function parseBatchOutput(buffer, requested) {
  const blobs = new Map()
  let offset = 0
  for (const oid of requested) {
    if (offset >= buffer.length) break
    const headerEnd = buffer.indexOf(0x0a, offset)
    if (headerEnd < 0) break
    const header = buffer.toString('utf8', offset, headerEnd)
    offset = headerEnd + 1
    const parts = header.split(' ')
    if (parts.length < 3) continue // "<input> missing" / "ambiguous"
    const size = Number(parts[2])
    if (!Number.isFinite(size) || size < 0) continue
    const content = buffer.subarray(offset, offset + size)
    offset += size + 1
    blobs.set(oid, Buffer.from(content))
  }
  return blobs
}
