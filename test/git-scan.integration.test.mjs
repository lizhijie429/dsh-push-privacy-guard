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
import { createGitRunner, readBlobsBatch } from '../lib/git.mjs'
import { loadWhitelist } from '../lib/whitelist.mjs'
import { isInitialized, loadRepoState } from '../lib/repo-state.mjs'
import { createGuard } from '../lib/guard.mjs'
import { detectOperations } from '../lib/detect.mjs'
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

const readWorkingFile = async (file, maxBytes) => {
  const stat = fs.statSync(file)
  if (stat.size > maxBytes) return null
  return fs.readFileSync(file)
}

test('real git: an in-command git add is covered by worktree and untracked scanning', async () => {
  const { repo, run } = await createRepository('addcommit')
  const config = makeConfig('addcommit')
  const rules = compileRules(config)
  fs.writeFileSync(path.join(repo, 'tracked.ts'), 'export const a = 1\n', 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'init'])

  const secret = 'sk-' + 'G1h2J3k4L5m6N7o8P9q0R1s2'.slice(0, 24)
  fs.writeFileSync(path.join(repo, 'untracked-secret.ts'), `const key = "${secret}"\n`, 'utf8')
  const [op] = detectOperations({
    tool: 'pwsh',
    args: { command: 'git add .; git commit -m "add files"' },
    sessionCwd: repo,
  })
  assert.ok(op.mutation?.indexMutated)
  const result = await scanCommit(run, { op, rules, config, readWorkingFile })
  assert.ok(result.findings.some(finding => finding.file === 'untracked-secret.ts'))
  assert.equal(result.incomplete, false)

  // The real guard denies this command shape instead of letting git add+commit through.
  const ctx = {
    get(name) {
      if (name === 'approval') return { request: async () => 'rejected' }
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
  const decision = await guard.handler(
    {
      name: 'pwsh',
      callId: 'call-1',
      agent: { session: {} },
      signal: new AbortController().signal,
      arguments: { command: 'git add .; git commit -m "add files"' },
    },
    async () => ({ kind: 'allow' }),
  )
  assert.equal(decision.kind, 'deny')
})

test('real git: pathspec commits scan the worktree content', async () => {
  const { repo, run } = await createRepository('pathspec')
  const config = makeConfig('pathspec')
  const rules = compileRules(config)
  fs.writeFileSync(path.join(repo, 'a.ts'), 'export const a = 1\n', 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'init'])

  const secret = 'sk-' + 'H1i2J3k4L5m6N7o8P9q0R1s2'.slice(0, 24)
  fs.writeFileSync(path.join(repo, 'a.ts'), `export const a = "${secret}"\n`, 'utf8')
  const [op] = detectOperations({
    tool: 'pwsh',
    args: { command: 'git commit a.ts -m "update a"' },
    sessionCwd: repo,
  })
  assert.deepEqual(op.pathspecs, ['a.ts'])
  const result = await scanCommit(run, { op, rules, config })
  assert.ok(result.findings.some(finding => finding.file === 'a.ts' && finding.ruleId === 'openai-key'))
})

test('real git: ignorePaths excludes diff findings', async () => {
  const { repo, run } = await createRepository('ignorepaths')
  const config = { ...makeConfig('ignorepaths'), ignorePaths: ['**/fixtures/**'] }
  const rules = compileRules(config)
  fs.mkdirSync(path.join(repo, 'tests', 'fixtures'), { recursive: true })
  fs.writeFileSync(path.join(repo, 'tests', 'fixtures', 'data.ts'), 'export const data = 1\n', 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'init'])

  const secret = 'sk-' + 'I1j2K3l4M5n6O7p8Q9r0S1t2'.slice(0, 24)
  fs.writeFileSync(path.join(repo, 'tests', 'fixtures', 'data.ts'), `export const data = "${secret}"\n`, 'utf8')
  await gitOk(run, ['add', '.'])
  const result = await scanCommit(run, {
    op: { kind: 'commit', cwd: repo, flags: { all: false }, messages: [] },
    rules,
    config,
  })
  assert.equal(result.findings.filter(finding => finding.file.startsWith('tests/fixtures')).length, 0)
})

test('real git: annotated tag messages are scanned for --tags pushes', async () => {
  const { repo, run } = await createRepository('tagpush')
  const config = makeConfig('tagpush')
  const rules = compileRules(config)
  fs.writeFileSync(path.join(repo, 'a.ts'), 'export const a = 1\n', 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'init'])
  const secret = 'sk-' + 'L1m2N3o4P5q6R7s8T9u0V1w2'.slice(0, 24)
  await gitOk(run, ['tag', '-a', 'v1', '-m', `release note ${secret}`])
  await gitOk(run, ['remote', 'add', 'origin', repo])

  const [op] = detectOperations({
    tool: 'pwsh',
    args: { command: 'git push --tags origin' },
    sessionCwd: repo,
  })
  const plan = await planPush(run, { op, config })
  assert.ok(Array.isArray(plan.tagRefs) && plan.tagRefs.includes('v1'))
  const result = await scanPush(run, { plan, rules, config })
  assert.ok(result.findings.some(finding => finding.file === '<tag message: v1>' && finding.ruleId === 'openai-key'))
})

test('real git: readBlobsBatch streams all requested blobs in one process', async () => {
  const { repo, run } = await createRepository('batch')
  const secret = 'sk-' + 'M1n2O3p4Q5r6S7t8U9v0W1x2'.slice(0, 24)
  fs.writeFileSync(path.join(repo, 'a.ts'), `export const a = "${secret}"\n`, 'utf8')
  fs.writeFileSync(path.join(repo, 'b.ts'), 'export const b = 2\n', 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'init'])
  const oids = []
  for (const file of ['a.ts', 'b.ts']) {
    const result = await run(['rev-parse', `HEAD:${file}`])
    assert.equal(result.ok, true)
    oids.push(result.stdout.trim())
  }
  const blobs = await readBlobsBatch({ cwd: repo, oids })
  assert.equal(blobs.size, 2)
  assert.match(blobs.get(oids[0]).toString('utf8'), /sk-/)
  assert.match(blobs.get(oids[1]).toString('utf8'), /export const b/)
})

test('real git: secrets in intermediate commits are scanned even when later deleted', async () => {
  const { repo, run } = await createRepository('intermediate')
  const config = makeConfig('intermediate')
  const rules = compileRules(config)
  const secret = 'sk-' + 'O1p2Q3r4S5t6U7v8W9x0Y1z2'.slice(0, 24)
  fs.writeFileSync(path.join(repo, 'leak.ts'), `const key = "${secret}"\n`, 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'add leak'])
  await gitOk(run, ['rm', '-q', 'leak.ts'])
  await gitOk(run, ['commit', '-q', '-m', 'remove leak'])
  await gitOk(run, ['remote', 'add', 'origin', repo])

  const [op] = detectOperations({ tool: 'pwsh', args: { command: 'git push origin main' }, sessionCwd: repo })
  const plan = await planPush(run, { op, config })
  assert.equal(plan.commitCount, 2)
  const result = await scanPush(run, { plan, rules, config })
  assert.ok(result.findings.some(finding => finding.file === 'leak.ts' && finding.ruleId === 'openai-key'))
})

test('real git: every explicit refspec is planned and scanned', async () => {
  const { repo, run } = await createRepository('multiref')
  const config = makeConfig('multiref')
  const rules = compileRules(config)
  fs.writeFileSync(path.join(repo, 'a.ts'), 'export const a = 1\n', 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'init'])
  await gitOk(run, ['checkout', '-q', '-b', 'dev'])
  const secret = 'sk-' + 'P1q2R3s4T5u6V7w8X9y0Z1a2'.slice(0, 24)
  fs.writeFileSync(path.join(repo, 'dev-secret.ts'), `const key = "${secret}"\n`, 'utf8')
  await gitOk(run, ['add', '.'])
  await gitOk(run, ['commit', '-q', '-m', 'dev secret'])
  await gitOk(run, ['checkout', '-q', 'main'])
  await gitOk(run, ['remote', 'add', 'origin', repo])

  const [op] = detectOperations({ tool: 'pwsh', args: { command: 'git push origin main dev' }, sessionCwd: repo })
  const plan = await planPush(run, { op, config })
  assert.equal(plan.broad, true)
  assert.deepEqual(plan.branches.map(range => range.headRef).sort(), ['dev', 'main'])
  const result = await scanPush(run, { plan, rules, config })
  assert.ok(result.findings.some(finding => finding.file === 'dev-secret.ts' && finding.ruleId === 'openai-key'))
})

test('real git: detectRepo recognises a bare repository', async () => {
  const bare = path.join(BASE, 'bare.git')
  fs.mkdirSync(bare, { recursive: true })
  const run = createGitRunner({ cwd: bare, timeoutMs: 20000 })
  await gitOk(run, ['init', '-q', '--bare'])
  const root = await detectRepo(run, bare)
  assert.equal(typeof root, 'string')
  assert.ok(root.length > 0)
})

