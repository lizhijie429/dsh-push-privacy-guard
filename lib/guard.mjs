/**
 * The `tools/pre-execute` guard: detects commit/push commands, scans the
 * content that would enter git, and asks the user through the DSH approval seam
 * before anything unapproved is uploaded.
 *
 * The guard is intentionally fail-closed for anything it recognised as a
 * commit/push: a scan error blocks the command instead of leaking content.
 *
 * @module dsh-push-privacy-guard/guard
 */

import fs from 'node:fs/promises'
import { detectOperations } from './detect.mjs'
import { createGitRunner, readBlobsBatch } from './git.mjs'
import { buildDenyReason, buildFindingsApproval, buildFullScanQuestion } from './messages.mjs'
import { isInitialized, loadRepoState, markInitialized } from './repo-state.mjs'
import {
  dedupeFindings,
  detectRepo,
  planPush,
  scanCommit,
  scanFullRepo,
  scanPush,
  splitWhitelisted,
} from './scan.mjs'
import { addApproved, loadWhitelist } from './whitelist.mjs'
import {
  addProjectApproved,
  addSessionEntries,
  effectiveApprovedIds,
  rememberPending,
  sessionIdOf,
} from './scopes.mjs'

/** Commit message files larger than this are ignored (bounded read). */
const MAX_MESSAGE_FILE_BYTES = 512 * 1024

/** Tools whose shell keeps its own working directory the guard cannot observe. */
const PERSISTENT_SHELL_TOOLS = new Set(['terminal_send', 'bash_persistent', 'pwsh_persistent'])

/**
 * Build the guard.
 *
 * @param {{ctx:any,config:object,rules:object[],log?:(line:string)=>void,
 *          runGitFactory?:(options:object)=>Function,readTextFile?:(file:string)=>Promise<string>,
 *          now?:()=>Date}} deps
 * @returns {{handler:(exec:object,next:Function)=>Promise<any>}}
 */
export function createGuard({ ctx, config, rules, log = () => {}, runGitFactory, readTextFile, readWorkingFile, readBlobs, now }) {
  const createRunner = runGitFactory ?? (options => createGitRunner(options))
  const readFile = readTextFile ?? defaultReadTextFile
  const readWorkFile = readWorkingFile ?? defaultReadWorkingFile
  const readBlobBatch =
    readBlobs ?? (runGitFactory !== undefined ? undefined : options => readBlobsBatch({ ...options, timeoutMs: config.gitTimeoutMs }))
  const clock = now ?? (() => new Date())

  /**
   * `tools/pre-execute` listener.
   *
   * @param {object} exec - tool execution view (`name`, `arguments`, `agent`, `callId`, `signal`).
   * @param {Function} next - downstream waterfall continuation.
   */
  async function handler(exec, next) {
    if (config.enabled !== true) return next()

    let operations
    try {
      operations = detectOperations({
        tool: exec?.name,
        args: exec?.arguments,
        sessionCwd: resolveSessionCwd(ctx, exec?.agent?.session),
      })
    } catch (error) {
      log(`detect.error message=${guardMessage(error)}`)
      return next()
    }

    const selected = operations.filter(operation =>
      operation.kind === 'commit' ? config.interceptCommit : config.interceptPush,
    )
    if (selected.length === 0) return next()

    const toolName = String(exec?.name ?? '').toLowerCase()
    if (PERSISTENT_SHELL_TOOLS.has(toolName) && config.persistentShellCommits !== 'allow') {
      const action = selected[0].kind
      log(`deny op=${action} reason=persistent-shell tool=${toolName}`)
      return { kind: 'deny', reason: buildDenyReason({ action, outcome: 'persistent-shell' }) }
    }

    for (const operation of selected) {
      const denial = await checkOperation(operation, exec)
      if (denial !== undefined) return denial
    }
    return next()
  }

  /** Run one operation check; returns a deny decision or undefined to continue. */
  async function checkOperation(operation, exec) {
    const action = operation.kind
    try {
      if (exec?.agent === undefined) {
        log(`deny op=${action} reason=no-agent`)
        return { kind: 'deny', reason: buildDenyReason({ action, outcome: 'unavailable' }) }
      }

      const runner = createRunner({ cwd: operation.cwd, timeoutMs: config.gitTimeoutMs })
      const root = await detectRepo(runner, operation.cwd)
      if (root === null) {
        // `gh repo sync` talks to the GitHub API and does not need a local
        // repository; there is nothing local to scan in that case.
        if (operation.kind === 'sync') {
          log(`skip op=sync reason=no-local-repo cwd=${operation.cwd}`)
          return undefined
        }
        if (config.unresolvedRepo === 'allow') {
          log(`skip op=${action} reason=not-a-repo cwd=${operation.cwd}`)
          return undefined
        }
        const detail =
          operation.cwdUnresolved === true
            ? 'the working directory uses an unresolved shell variable or expansion'
            : `the working directory is not inside a git repository (${operation.cwd})`
        log(`deny op=${action} reason=repo-unresolved detail=${detail}`)
        return { kind: 'deny', reason: buildDenyReason({ action, outcome: 'repo-unresolved', detail }) }
      }

      const whitelist = loadWhitelist(config.whitelistFile)
      if (whitelist.warning !== undefined) log(`whitelist.warning ${whitelist.warning}`)
      const sessionId = sessionIdOf(exec.agent)
      const scoped = effectiveApprovedIds({ config, root, sessionId, globalDocument: whitelist })
      for (const warning of scoped.warnings) log(`project-whitelist.warning ${warning}`)
      const approvedIds = scoped.ids

      return action === 'commit'
        ? await checkCommit({ operation, exec, runner, root, approvedIds, sessionId })
        : await checkPush({ operation, exec, runner, root, approvedIds, sessionId })
    } catch (error) {
      const message = guardMessage(error)
      log(`check.error op=${action} message=${message}`)
      return { kind: 'deny', reason: buildDenyReason({ action, outcome: 'scan-failed', detail: message }) }
    }
  }

  /** Commit path: staged content + the message the command carries. */
  async function checkCommit({ operation, exec, runner, root, approvedIds, sessionId }) {
    const result = await scanCommit(runner, {
      op: operation,
      rules,
      config,
      readTextFile: readFile,
      readWorkingFile: readWorkFile,
    })
    if (result.error !== undefined) {
      log(`scan.error op=commit repo=${root} message=${guardMessage(result.error)}`)
      return {
        kind: 'deny',
        reason: buildDenyReason({ action: 'commit', outcome: 'scan-failed', detail: guardMessage(result.error) }),
      }
    }

    const deduped = dedupeFindings(result.findings)
    const { blocked, whitelisted } = splitWhitelisted(deduped, approvedIds)
    log(
      `scan op=commit repo=${root} findings=${blocked.length} whitelisted=${whitelisted.length} incomplete=${result.incomplete === true}`,
    )

    if (!needsApproval(blocked, result.incomplete, config)) return undefined
    if (blocked.length > 0) rememberPending(sessionId, blocked)

    const request = buildFindingsApproval({
      action: 'commit',
      repo: root,
      findings: blocked,
      whitelistedCount: whitelisted.length,
      incomplete: result.incomplete === true,
      whitelistOnApprove: config.whitelistOnApprove !== false,
      notes: result.notes,
      maxItems: config.maxApprovalItems,
    })
    const outcome = await requestApproval(exec, request)
    if (outcome !== 'allowed-once') {
      log(`deny op=commit repo=${root} answer=${outcome} findings=${blocked.length}`)
      return {
        kind: 'deny',
        reason: buildDenyReason({ action: 'commit', outcome: denyOutcome(outcome), count: blocked.length }),
      }
    }
    await rememberApproved({ blocked, root, sessionId })
    log(`allow op=commit repo=${root} approved=${blocked.length} scope=${config.approvalScope}`)
    return undefined
  }

  /** Push path: push plan, optional first-push full scan, approval, whitelist. */
  async function checkPush({ operation, exec, runner, root, approvedIds, sessionId }) {
    // A dry run uploads nothing; checking it would be pure friction.
    if (operation.flags?.dryRun === true) {
      log(`skip op=${operation.kind} repo=${root} reason=dry-run`)
      return undefined
    }
    const plan = await planPush(runner, { op: operation, config })
    if (plan.empty === true) {
      log(`skip op=${operation.kind} repo=${root} reason=${plan.reason ?? 'empty'}`)
      return undefined
    }
    if (plan.error !== undefined) {
      log(`scan.error op=push repo=${root} message=${guardMessage(plan.error)}`)
      return {
        kind: 'deny',
        reason: buildDenyReason({ action: operation.kind, outcome: 'scan-failed', detail: guardMessage(plan.error) }),
      }
    }

    let fullScan = false
    const repoState = loadRepoState(config.repoStateFile)
    if (repoState.warning !== undefined) log(`repo-state.warning ${repoState.warning}`)
    if (!isInitialized(repoState, root)) {
      const choice = await chooseFirstPushScan(exec, root)
      fullScan = choice.fullScan
      if (choice.answered === true) {
        try {
          await markInitialized(config.repoStateFile, {
            root,
            mode: fullScan ? 'full' : 'diff',
            now: clock().toISOString(),
          })
        } catch (error) {
          log(`repo-state.write-failed repo=${root} message=${guardMessage(error)}`)
        }
      }
    }

    const result = await scanPush(runner, { plan, rules, config })
    if (result.error !== undefined) {
      log(`scan.error op=push repo=${root} message=${guardMessage(result.error)}`)
      return {
        kind: 'deny',
        reason: buildDenyReason({ action: operation.kind, outcome: 'scan-failed', detail: guardMessage(result.error) }),
      }
    }

    let findings = result.findings
    let incomplete = result.incomplete === true
    const notes = [...(result.notes ?? [])]
    if (fullScan) {
      const full = await scanFullRepo(runner, {
        rules,
        config,
        cwd: root,
        readBlobs: readBlobBatch,
      })
      if (full.error !== undefined) {
        log(`scan.error op=full-scan repo=${root} message=${guardMessage(full.error)}`)
        return {
          kind: 'deny',
          reason: buildDenyReason({ action: operation.kind, outcome: 'scan-failed', detail: guardMessage(full.error) }),
        }
      }
      findings = [...findings, ...full.findings]
      incomplete = incomplete || full.incomplete === true
      notes.push(...(full.notes ?? []))
      log(`scan op=full-scan repo=${root} files=${full.filesScanned ?? 0} findings=${full.findings.length}`)
    }

    const deduped = dedupeFindings(findings)
    const { blocked, whitelisted } = splitWhitelisted(deduped, approvedIds)
    log(
      `scan op=push repo=${root} commits=${plan.commitCount ?? 0} findings=${blocked.length} whitelisted=${whitelisted.length} incomplete=${incomplete}`,
    )

    if (!needsApproval(blocked, incomplete, config)) return undefined
    if (blocked.length > 0) rememberPending(sessionId, blocked)

    const request = buildFindingsApproval({
      action: operation.kind,
      repo: root,
      findings: blocked,
      whitelistedCount: whitelisted.length,
      incomplete,
      whitelistOnApprove: config.whitelistOnApprove !== false,
      notes,
      maxItems: config.maxApprovalItems,
    })
    const outcome = await requestApproval(exec, request)
    if (outcome !== 'allowed-once') {
      log(`deny op=push repo=${root} answer=${outcome} findings=${blocked.length}`)
      return {
        kind: 'deny',
        reason: buildDenyReason({ action: operation.kind, outcome: denyOutcome(outcome), count: blocked.length }),
      }
    }
    await rememberApproved({ blocked, root, sessionId })
    log(`allow op=push repo=${root} approved=${blocked.length} scope=${config.approvalScope}`)
    return undefined
  }

  /**
   * First push in a repository: ask whether to scan the whole tracked tree.
   *
   * `answered` is false when the approval channel could not deliver a decision
   * (unavailable / error / cancelled); such a repository is not remembered, so
   * the next push asks again instead of silently degrading to diff-only mode.
   */
  async function chooseFirstPushScan(exec, root) {
    if (config.fullScanOnFirstPush === 'always') {
      log(`first-push repo=${root} full-scan=true mode=always`)
      return { fullScan: true, answered: true }
    }
    if (config.fullScanOnFirstPush === 'never') {
      log(`first-push repo=${root} full-scan=false mode=never`)
      return { fullScan: false, answered: true }
    }
    const outcome = await requestApproval(exec, buildFullScanQuestion(root))
    const fullScan = outcome === 'allowed-once'
    const answered = outcome === 'allowed-once' || outcome === 'rejected'
    log(`first-push repo=${root} full-scan=${fullScan} answer=${outcome} answered=${answered}`)
    return { fullScan, answered }
  }

  /** Ask the approval seam for one decision. */
  async function requestApproval(exec, request) {
    let approval
    try {
      approval = ctx.get?.('approval')
    } catch {
      approval = undefined
    }
    if (approval === undefined || typeof approval.request !== 'function') return 'unavailable'
    try {
      const outcome = await approval.request({
        agent: exec.agent,
        toolName: exec.name,
        callId: exec.callId,
        reason: request.reason,
        displayReason: request.displayReason,
        signal: exec.signal,
      })
      return typeof outcome === 'string' ? outcome : 'unavailable'
    } catch (error) {
      log(`approval.error message=${guardMessage(error)}`)
      return 'error'
    }
  }

  /** Remember approved findings in the configured scope; failures are logged, not fatal. */
  async function rememberApproved({ blocked, root, sessionId }) {
    if (config.whitelistOnApprove !== true || blocked.length === 0) return
    try {
      if (config.approvalScope === 'session') {
        const result = addSessionEntries(sessionId, blocked)
        log(`session-whitelist.add count=${result.added} total=${result.total}`)
        return
      }
      if (config.approvalScope === 'project') {
        const result = addProjectApproved(root, config, blocked)
        log(`project-whitelist.add count=${result.added} total=${result.total} file=${result.file}`)
        return
      }
      const result = await addApproved(config.whitelistFile, blocked)
      log(`whitelist.add count=${result.added} total=${result.total}`)
    } catch (error) {
      log(`whitelist.write-failed message=${guardMessage(error)}`)
    }
  }

  return { handler }
}

/** Approval required when anything is blocked, or when an incomplete scan must be confirmed. */
function needsApproval(blocked, incomplete, config) {
  return blocked.length > 0 || (incomplete === true && config.requireApprovalOnIncompleteScan === true)
}

/** Map an approval outcome to the denial vocabulary. */
function denyOutcome(outcome) {
  if (outcome === 'rejected') return 'rejected'
  if (outcome === 'cancelled') return 'cancelled'
  if (outcome === 'error') return 'scan-failed'
  return 'unavailable'
}

/** Current session working directory (mutable cwd first, header fallback). */
export function resolveSessionCwd(ctx, session) {
  if (session === undefined || session === null) return undefined
  try {
    const workingDirectory = ctx.get?.('workingDirectory')
    if (workingDirectory !== undefined && typeof workingDirectory.get === 'function') {
      const cwd = workingDirectory.get(session)
      if (typeof cwd === 'string' && cwd.length > 0) return cwd
    }
  } catch {
    /* fall back to the session header */
  }
  const cwd = session.header?.cwd
  return typeof cwd === 'string' && cwd.length > 0 ? cwd : undefined
}

/** Default bounded commit-message file reader (over-sized files fail the scan). */
async function defaultReadTextFile(file) {
  const stat = await fs.stat(file)
  if (stat.size > MAX_MESSAGE_FILE_BYTES) throw new Error('commit message file too large to verify')
  return fs.readFile(file, 'utf8')
}

/** Default bounded untracked-file reader (used by the add+commit path). */
async function defaultReadWorkingFile(file, maxBytes) {
  const stat = await fs.stat(file)
  if (Number.isFinite(maxBytes) && stat.size > maxBytes) return null
  if (!stat.isFile()) return null
  return fs.readFile(file)
}

/** One-line log-safe rendering of an error message. */
function guardMessage(error) {
  const message = error instanceof Error ? error.message : String(error ?? '')
  return message.replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ').slice(0, 300)
}
