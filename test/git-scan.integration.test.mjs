/**
 * Integration test against real git repositories.
 *
 * Run with: node test/git-scan.integration.test.mjs
 * (Needs permission to spawn git; sandboxed runs of the DSH shell may block it.)
 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { normalizeConfig } from '../lib/config.mjs'
import { compileRules } from '../lib/rules.mjs'
import { createGitRunner } from '../lib/git.mjs'
import { loadWhitelist } from '../lib/whitelist.mjs'
import { isInitialized, loadRepoState } from '../lib/repo-state.mjs'
import { createGuard } from '../lib/guard.mjs'
import {
  EMPTY_TREE,
  detectRepo,
  planPush,
  scanCommit,
  scanFullRepo,
  scanPush,
} from '../lib/scan.mjs'

const BASE = fs.mkdtempSync(path.join(import.meta.dirname, '.integration-'))
after(() => {
  try {
    fs.rmSync(BASE, { recursive: true, force: true })
  } catch {
    /* best effort */
  }
})
const SECRET = 'sk-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'.slice(0, 24)

function makeConfig(caseName) {
  const caseDir = path.join(BASE, caseName, 'state')
  fs.mkdirSync(caseDir, { recursive: true })
  return normalizeConfig(
    {
      whitelistFile: path.join(caseDir, 'whitelist.json'),
      repoStateFile: path.join(caseDir, 'repos.json'),
      logFile: path.join(caseDir, 'guard.log'),
    },
    path.join(BASE, caseName),
  )
}

async function gitOk(run, args) {
  const result = await run(args)
  assert.equal(result.ok, true, `git ${args.join(' ')} failed: ${result.stderr}`)
  return result
}

async function createRepository(name) {
  const repo = path.join(BASE, name, 'repo')
  fs.mkdirSync(repo, { recursive: true })
  const run = createGitRunner({ cwd: repo, timeoutMs: 20000 })
  await gitOk(run, ['init', '-q'])
  await gitOk(run, ['checkout', '-q', '-b', 'main'])
  await gitOk(run, ['config', 'user.email', 'tester@example-corp.cn'])
  await gitOk(run, ['config', 'user.name', 'Tester'])
  return { repo, run }
}

test('real git: staged scan, push plan, push scan, full scan and .gitignore', async () => {
  const { repo, run } = await createRepository('flows')
  const config = makeConfig('flows')
  const rules = compileRules(config)
  assert.equal(await detectRepo(run, repo), path.resolve(repo))

  fs.writeFileSync(path.join(repo, '.gitignore'), 'ignored.js\nnode_modules/\n', 'utf8')
  fs.mkdirSync(path.join(repo, 'src'), { recursive: true })
  fs.writeFileSync(path.join(repo, 'src', 'config.ts'), `const key = "${SECRET}"\n`, 'utf8')
  fs.writeFileSync(path.join(repo, 'ignored.js'), `const key = "${SECRET}"\n`, 'utf8')
  await gitOk(run, ['add', '.'])

  // Staged content scan (before the first commit, i.e. no HEAD yet).
  const commitMessage = 'feat: add config by tester@example-corp.cn'
  const staged = await scanCommit(run, {
    op: { kind: 'commit', cwd: repo, flags: { all: false }, messages: [commitMessage] },
    rules,
    config,
  })
  assert.equal(staged.error, undefined)
  assert.ok(staged.findings.some(finding => finding.ruleId === 'openai-key'))
  assert.ok(staged.findings.some(finding => finding.file === '<commit message>' && finding.ruleId === 'email'))

  await gitOk(run, ['commit', '-q', '-m', commitMessage])

  // Bare remote + push planning.
  const remotePath = path.join(BASE, 'flows', 'remote.git')
  const bare = createGitRunner({ cwd: path.join(BASE, 'flows') })
  await gitOk(bare, ['init', '--bare', '-q', 'remote.git'])
  await gitOk(run, ['remote', 'add', 'origin', remotePath])

  const plan = await planPush(run, { op: { kind: 'push', flags: {}, positional: ['origin', 'main'] }, config })
  assert.equal(plan.empty, false)
  assert.equal(plan.headSha.length, 40)
  assert.equal(plan.base, EMPTY_TREE) // root commit has no parent
  assert.equal(plan.commitCount, 1)

  const pushed = await scanPush(run, { plan, rules, config })
  assert.equal(pushed.error, undefined)
  assert.ok(pushed.findings.some(finding => finding.file === 'src/config.ts' && finding.ruleId === 'openai-key'))
  assert.ok(pushed.findings.some(finding => finding.file === '<commit message>' && finding.ruleId === 'email'))

  // Full-repo scan only sees tracked files; ignored.js is untracked and absent.
  const full = await scanFullRepo(run, { rules, config })
  assert.ok(full.findings.some(finding => finding.file === 'src/config.ts'))
  assert.ok(!full.findings.some(finding => finding.file === 'ignored.js'))
  assert.equal(full.incomplete, false)

  // `git commit -a` path uses `diff HEAD` and still sees tracked modifications.
  fs.appendFileSync(path.join(repo, 'src', 'config.ts'), '// phone 13812345678\n', 'utf8')
  const allScan = await scanCommit(run, {
    op: { kind: 'commit', cwd: repo, flags: { all: true }, messages: [] },
    rules,
    config,
  })
  assert.ok(allScan.findings.some(finding => finding.ruleId === 'cn-mobile'))
})

test('real git: guard asks for approval, denies a rejection and whitelists on approval', async () => {
  const { repo, run } = await createRepository('guard')
  const config = makeConfig('guard')
  const rules = compileRules(config)
  fs.writeFileSync(path.join(repo, 'secret.ts'), `const key = "${SECRET}"\n`, 'utf8')
  await gitOk(run, ['add', '.'])

  function makeCtx(outcome) {
    const requests = []
    return {
      requests,
      ctx: {
        get(name) {
          if (name === 'approval') {
            return {
              request: async request => {
                requests.push(request)
                return outcome
              },
            }
          }
          if (name === 'workingDirectory') return { get: () => repo }
          return undefined
        },
        on() {},
        effect() {},
        inject() {},
        logger: { warn() {} },
      },
    }
  }

  const exec = {
    name: 'pwsh',
    callId: 'call-1',
    agent: { session: {} },
    signal: new AbortController().signal,
    arguments: { command: 'git commit -m "add secret"' },
  }

  const rejectedCtx = makeCtx('rejected')
  const rejectedGuard = createGuard({
    ctx: rejectedCtx.ctx,
    config,
    rules,
    log: () => {},
    runGitFactory: options => createGitRunner(options),
  })
  const denied = await rejectedGuard.handler(exec, async () => ({ kind: 'allow' }))
  assert.equal(denied.kind, 'deny')
  assert.equal(rejectedCtx.requests.length, 1)
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 0)

  const approvedCtx = makeCtx('allowed-once')
  const approvedGuard = createGuard({
    ctx: approvedCtx.ctx,
    config,
    rules,
    log: () => {},
    runGitFactory: options => createGitRunner(options),
  })
  const allowed = await approvedGuard.handler(exec, async () => ({ kind: 'allow' }))
  assert.equal(allowed.kind, 'allow')
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 1)

  // A repeated approval of the now-whitelisted item asks nothing.
  const againCtx = makeCtx('rejected')
  const againGuard = createGuard({
    ctx: againCtx.ctx,
    config,
    rules,
    log: () => {},
    runGitFactory: options => createGitRunner(options),
  })
  const again = await againGuard.handler(exec, async () => ({ kind: 'allow' }))
  assert.equal(again.kind, 'allow')
  assert.equal(againCtx.requests.length, 0)
})

test('real git: first push records the repository and asks the full-scan question', async () => {
  const { repo, run } = await createRepository('firstpush')
  const config = makeConfig('firstpush')
  const rules = compileRules(config)
  fs.writeFileSync(path.join(repo, 'a.ts'), 'export const a = 1\n', 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'init'])
  const remotePath = path.join(BASE, 'firstpush', 'remote.git')
  const bare = createGitRunner({ cwd: path.join(BASE, 'firstpush') })
  await gitOk(bare, ['init', '--bare', '-q', 'remote.git'])
  await gitOk(run, ['remote', 'add', 'origin', remotePath])

  const requests = []
  const ctx = {
    get(name) {
      if (name === 'approval') {
        return {
          request: async request => {
            requests.push(request)
            return 'rejected'
          },
        }
      }
      if (name === 'workingDirectory') return { get: () => repo }
      return undefined
    },
    on() {},
    effect() {},
    inject() {},
    logger: { warn() {} },
  }
  const guard = createGuard({
    ctx,
    config,
    rules,
    log: () => {},
    runGitFactory: options => createGitRunner(options),
  })
  const exec = {
    name: 'pwsh',
    callId: 'call-1',
    agent: { session: {} },
    signal: new AbortController().signal,
    arguments: { command: 'git push origin main' },
  }
  const decision = await guard.handler(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'allow')
  assert.equal(requests.length, 1)
  assert.match(requests[0].displayReason.zh, /首次通过 DSH 推送/)
  assert.equal(isInitialized(loadRepoState(config.repoStateFile), repo), true)
})
