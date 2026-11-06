import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { normalizeConfig } from '../lib/config.mjs'
import { createGuard } from '../lib/guard.mjs'
import { identityOf } from '../lib/rules.mjs'
import { compileRules } from '../lib/rules.mjs'
import { addApproved, loadWhitelist } from '../lib/whitelist.mjs'
import { isInitialized, loadRepoState } from '../lib/repo-state.mjs'

const ROOT = fs.mkdtempSync(path.join(import.meta.dirname, '.test-tmp-guard-'))
after(() => {
  try {
    fs.rmSync(ROOT, { recursive: true, force: true })
  } catch {
    /* best effort */
  }
})
const PLUGIN_DIR = path.join(ROOT, 'plugin')
const SECRET = 'sk-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'.slice(0, 24)
const HEAD = 'a'.repeat(40)
const PARENT = 'b'.repeat(40)

function makeConfig(overrides = {}) {
  const caseDir = fs.mkdtempSync(path.join(ROOT, 'case-'))
  return normalizeConfig(
    {
      whitelistFile: path.join(caseDir, 'state', 'whitelist.json'),
      repoStateFile: path.join(caseDir, 'state', 'repos.json'),
      logFile: path.join(caseDir, 'state', 'guard.log'),
      ...overrides,
    },
    path.join(caseDir, 'plugin'),
  )
}

const rules = compileRules(makeConfig())

function fakeGit(handlers) {
  const calls = []
  const run = async args => {
    calls.push(args)
    for (const { match, result } of handlers) {
      if (match(args)) return typeof result === 'function' ? result(args) : result
    }
    return { ok: false, code: 1, stdout: '', stderr: `unmocked: git ${args.join(' ')}` }
  }
  run.calls = calls
  return run
}
const ok = (stdout = '') => ({ ok: true, code: 0, stdout, stderr: '' })
const contains = (...parts) => args => parts.every(part => args.includes(part))

function patchFor(file, newLine, lines) {
  return [
    `diff --git a/${file} b/${file}`,
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -1,0 +${newLine},${lines.length} @@`,
    ...lines.map(line => `+${line}`),
    '',
  ].join('\n')
}

function commitRunner({ diff = '' } = {}) {
  return fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: ok('D:/repo\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${HEAD}\n`) },
    { match: args => args[0] === 'diff', result: ok(diff) },
  ])
}

function pushRunner({ diff = '', messages = '', lsTree = '', blobs = {}, revList = `${HEAD}\n` } = {}) {
  return fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: ok('D:/repo\n') },
    { match: args => args[0] === 'remote', result: ok('origin\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--abbrev-ref') && args.includes('HEAD'), result: ok('main\n') },
    { match: contains('--symbolic-full-name'), result: ok('origin/main\n') },
    {
      match: args => args[0] === 'rev-parse' && args.includes('--verify'),
      result: args => (args[args.length - 1].endsWith('^') ? ok(`${PARENT}\n`) : ok(`${HEAD}\n`)),
    },
    { match: args => args[0] === 'rev-list', result: ok(revList) },
    { match: args => args[0] === 'log' && args.includes('--no-walk'), result: ok(messages) },
    { match: args => args[0] === 'log', result: ok(diff) },
    { match: args => args[0] === 'diff', result: ok(diff) },
    { match: args => args[0] === 'ls-tree', result: ok(lsTree) },
    { match: args => args[0] === 'cat-file', result: args => ok(blobs[args[2]] ?? '') },
  ])
}

function makeCtx({ outcomes = ['allowed-once'], withApproval = true, sessionCwd = 'D:/repo' } = {}) {
  const requests = []
  const ctx = {
    get(name) {
      if (name === 'approval') {
        if (!withApproval) return undefined
        return {
          request: async request => {
            requests.push(request)
            return outcomes.length > 1 ? outcomes.shift() : outcomes[0]
          },
        }
      }
      if (name === 'workingDirectory') return { get: () => sessionCwd }
      return undefined
    },
    on() {
      return () => {}
    },
    effect() {},
    inject() {},
    logger: { warn() {} },
  }
  return { ctx, requests }
}

function makeGuard({ ctx, config, runner, readTextFile, readWorkingFile }) {
  const logLines = []
  const guard = createGuard({
    ctx,
    config,
    rules,
    log: line => logLines.push(line),
    runGitFactory: () => runner,
    readTextFile,
    readWorkingFile,
    now: () => new Date('2026-11-03T00:00:00.000Z'),
  })
  return { guard, logLines }
}

function execFor(command) {
  return {
    name: 'pwsh',
    callId: 'call-1',
    agent: { session: { id: 'guard-session', header: { cwd: 'D:/repo' } } },
    signal: new AbortController().signal,
    arguments: { command },
  }
}

test('ignores commands that are not git commit/push', async () => {
  const { ctx, requests } = makeCtx()
  const { guard } = makeGuard({ ctx, config: makeConfig(), runner: commitRunner() })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git status'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 0)
})

test('approved commit is allowed and the finding is whitelisted', async () => {
  const config = makeConfig()
  const { ctx, requests } = makeCtx({ outcomes: ['allowed-once'] })
  const { guard, logLines } = makeGuard({
    ctx,
    config,
    runner: commitRunner({ diff: patchFor('src/config.ts', 2, [`const key = "${SECRET}"`]) }),
  })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git commit -m "chore: config"'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 1)
  assert.equal(requests[0].toolName, 'pwsh')
  assert.equal(requests[0].callId, 'call-1')
  assert.match(requests[0].displayReason.zh, /隐私检查发现 1 处/)
  assert.ok(!requests[0].displayReason.zh.includes(SECRET))
  assert.ok(!requests[0].reason.includes(SECRET))

  const whitelist = loadWhitelist(config.whitelistFile)
  assert.equal(whitelist.entries.length, 1)
  assert.equal(whitelist.entries[0].id, identityOf('openai-key', SECRET))
  assert.ok(logLines.some(line => line.includes('allow op=commit')))
})

test('rejected commit is denied and nothing is whitelisted', async () => {
  const config = makeConfig()
  const { ctx } = makeCtx({ outcomes: ['rejected'] })
  const { guard } = makeGuard({
    ctx,
    config,
    runner: commitRunner({ diff: patchFor('a.ts', 1, [`token = "${SECRET}"`]) }),
  })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git commit -m "x"'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(nextCalled, 0)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /did not authorize/)
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 0)
})

test('already-whitelisted content does not trigger an approval', async () => {
  const config = makeConfig()
  await addApproved(config.whitelistFile, [
    { identity: identityOf('openai-key', SECRET), ruleId: 'openai-key', label: 'OpenAI API Key', masked: 'sk-a…34', file: 'a.ts' },
  ])
  const { ctx, requests } = makeCtx()
  const { guard } = makeGuard({
    ctx,
    config,
    runner: commitRunner({ diff: patchFor('a.ts', 1, [`const key = "${SECRET}"`]) }),
  })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git commit -m "x"'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 0)
})

test('first push asks once for a full scan and remembers the repository', async () => {
  const config = makeConfig()
  const { ctx, requests } = makeCtx({ outcomes: ['rejected'] })
  const { guard } = makeGuard({ ctx, config, runner: pushRunner({ diff: '' }) })
  let nextCalled = 0
  const exec = execFor('git push origin main')

  const first = await guard.handler(exec, async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(first.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 1)
  assert.match(requests[0].displayReason.zh, /首次通过 DSH 推送/)
  assert.equal(isInitialized(loadRepoState(config.repoStateFile), 'D:/repo'), true)

  const second = await guard.handler(exec, async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(second.kind, 'allow')
  assert.equal(requests.length, 1) // no repeating question
  assert.equal(nextCalled, 2)
})

test('push with unapproved content asks for findings approval after the first-push question', async () => {
  const config = makeConfig()
  const { ctx, requests } = makeCtx({ outcomes: ['rejected', 'allowed-once'] })
  const { guard } = makeGuard({
    ctx,
    config,
    runner: pushRunner({ diff: patchFor('src/config.ts', 2, [`const key = "${SECRET}"`]) }),
  })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git push origin main'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 2)
  assert.match(requests[0].displayReason.zh, /首次通过 DSH 推送/)
  assert.match(requests[1].displayReason.zh, /隐私检查发现 1 处/)
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 1)
})

test('push is denied when the user rejects the findings approval', async () => {
  const config = makeConfig()
  const { ctx } = makeCtx({ outcomes: ['rejected', 'rejected'] })
  const { guard } = makeGuard({
    ctx,
    config,
    runner: pushRunner({ diff: patchFor('a.ts', 1, [`token = "${SECRET}"`]) }),
  })
  const decision = await guard.handler(execFor('git push'), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /did not authorize/)
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 0)
})

test('missing approval channel denies recognised operations', async () => {
  const config = makeConfig()
  const { ctx } = makeCtx({ withApproval: false })
  const { guard } = makeGuard({ ctx, config, runner: commitRunner({ diff: patchFor('a.ts', 1, [`token = "${SECRET}"`]) }) })
  const decision = await guard.handler(execFor('git commit -m x'), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /no user approval channel/)
})

test('scan failures block the command instead of allowing it', async () => {
  const config = makeConfig()
  const { ctx } = makeCtx()
  const failing = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: ok('D:/repo\n') },
    { match: args => args[0] === 'remote', result: ok('origin\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--abbrev-ref'), result: ok('main\n') },
    { match: contains('--symbolic-full-name'), result: ok('origin/main\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${HEAD}\n`) },
    { match: args => args[0] === 'rev-list', result: ok(`${HEAD}\n`) },
    { match: args => args[0] === 'diff', result: { ok: false, code: 1, stdout: '', stderr: 'boom' } },
  ])
  const { guard } = makeGuard({ ctx, config, runner: failing })
  const decision = await guard.handler(execFor('git push origin main'), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /could not complete/)
})

test('disabled guard passes everything through', async () => {
  const config = makeConfig({ enabled: false })
  const { ctx, requests } = makeCtx()
  const { guard } = makeGuard({ ctx, config, runner: commitRunner() })
  let nextCalled = 0
  await guard.handler(execFor('git commit -m x'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 0)
})

test('agentless calls are denied for recognised operations', async () => {
  const config = makeConfig()
  const { ctx } = makeCtx()
  const { guard } = makeGuard({ ctx, config, runner: commitRunner() })
  const exec = execFor('git commit -m x')
  delete exec.agent
  const decision = await guard.handler(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /no user approval channel/)
})

test('always-full-scan mode scans tracked files even when the diff is clean', async () => {
  const config = makeConfig({ fullScanOnFirstPush: 'always' })
  const lsTree = `100644 blob ${'1'.repeat(40)} 30\tsrc/old.ts\u0000`
  const { ctx, requests } = makeCtx({ outcomes: ['allowed-once'] })
  const { guard } = makeGuard({
    ctx,
    config,
    runner: pushRunner({
      diff: '',
      lsTree,
      blobs: { ['1'.repeat(40)]: `const key = "${SECRET}"\n` },
    }),
  })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git push origin main'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 1)
  assert.match(requests[0].displayReason.zh, /隐私检查发现 1 处/)
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 1)
})

test('nothing-to-push passes without asking anything', async () => {
  const config = makeConfig()
  const { ctx, requests } = makeCtx()
  const { guard } = makeGuard({ ctx, config, runner: pushRunner({ revList: '' }) })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git push origin main'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 0)
})

test('dry-run pushes are not scanned or approved', async () => {
  const config = makeConfig()
  const { ctx, requests } = makeCtx({ outcomes: ['rejected'] })
  const { guard, logLines } = makeGuard({ ctx, config, runner: commitRunner() })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git push --dry-run origin main'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.equal(requests.length, 0)
  assert.ok(logLines.some(line => line.includes('reason=dry-run')))
})

test('commit after an in-command git add is still scanned and denied', async () => {
  const config = makeConfig()
  const { ctx, requests } = makeCtx({ outcomes: ['rejected'] })
  const secret = 'sk-' + 'E5f6G7h8I9j0K1l2M3n4O5p6'.slice(0, 24)
  const run = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: ok('D:/repo\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${HEAD}\n`) },
    { match: args => args[0] === 'diff', result: ok('') },
    { match: args => args[0] === 'ls-files', result: ok('new.ts\u0000') },
  ])
  const { guard } = makeGuard({
    ctx,
    config,
    runner: run,
    readWorkingFile: async () => Buffer.from(`const key = "${secret}"\n`),
  })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git add .; git commit -m "x"'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(nextCalled, 0)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /did not authorize/)
  assert.equal(requests.length, 1)
})

test('recognised commit/push in an unresolved repository is denied by default', async () => {
  const config = makeConfig()
  const { ctx } = makeCtx()
  const notRepo = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: { ok: false, code: 128, stdout: '', stderr: 'not a repo' } },
  ])
  const { guard, logLines } = makeGuard({ ctx, config, runner: notRepo })
  let nextCalled = 0
  const decision = await guard.handler(execFor('cd $repo; git commit -m x'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(nextCalled, 0)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /repository could not be located/)
  assert.match(decision.reason, /unresolved/)
  assert.ok(logLines.some(line => line.includes('reason=repo-unresolved')))
})

test('unresolvedRepo=allow restores the old pass-through behaviour', async () => {
  const config = makeConfig({ unresolvedRepo: 'allow' })
  const { ctx } = makeCtx()
  const notRepo = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: { ok: false, code: 128, stdout: '', stderr: 'not a repo' } },
  ])
  const { guard } = makeGuard({ ctx, config, runner: notRepo })
  let nextCalled = 0
  const decision = await guard.handler(execFor('git commit -m x'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
})

test('a literal non-repository cwd is denied by default too', async () => {
  const config = makeConfig()
  const { ctx } = makeCtx()
  const notRepo = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: { ok: false, code: 128, stdout: '', stderr: 'not a repo' } },
  ])
  const { guard } = makeGuard({ ctx, config, runner: notRepo })
  const decision = await guard.handler(execFor('git push origin main'), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /repository could not be located/)
})

test('commit options with values do not disable the staged-index scan', async () => {
  const config = makeConfig()
  const secret = 'sk-' + 'K1l2M3n4O5p6Q7r8S9t0U1v2'.slice(0, 24)
  for (const command of [
    'git commit -C HEAD',
    'git commit -c HEAD',
    'git commit --fixup HEAD',
    'git commit -m "msg" --trailer "Co-authored-by: 13812345678 <ops@' + 'corp.local>"',
    'git commit --only -m "msg"',
  ]) {
    const { ctx, requests } = makeCtx({ outcomes: ['rejected'] })
    const { guard } = makeGuard({
      ctx,
      config,
      runner: commitRunner({ diff: patchFor('a.ts', 1, [`const key = "${secret}"`]) }),
    })
    const decision = await guard.handler(execFor(command), async () => ({ kind: 'allow' }))
    assert.equal(decision.kind, 'deny', `expected deny for: ${command}`)
    assert.equal(requests.length >= 1, true, `expected approval ask for: ${command}`)
  }
})

test('commits sent to a persistent terminal are denied by default', async () => {  const config = makeConfig()
  const { ctx, requests } = makeCtx()
  const { guard, logLines } = makeGuard({ ctx, config, runner: commitRunner() })
  const exec = { ...execFor('git commit -m x'), name: 'terminal_send', arguments: { text: 'git commit -m x' } }
  const decision = await guard.handler(exec, async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /persistent terminal/)
  assert.equal(requests.length, 0)
  assert.ok(logLines.some(line => line.includes('reason=persistent-shell')))
})

test('persistentShellCommits=allow keeps the previous best-effort scanning', async () => {
  const config = makeConfig({ persistentShellCommits: 'allow' })
  const { ctx } = makeCtx()
  const { guard } = makeGuard({ ctx, config, runner: commitRunner({ diff: patchFor('a.ts', 1, ['clean line']) }) })
  const exec = { ...execFor('git commit -m x'), name: 'terminal_send', arguments: { text: 'git commit -m x' } }
  let nextCalled = 0
  const decision = await guard.handler(exec, async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
})

test('a first push without an approval channel is not remembered as initialised', async () => {
  const config = makeConfig()
  const { ctx, requests } = makeCtx({ outcomes: ['unavailable'] })
  const { guard } = makeGuard({ ctx, config, runner: pushRunner() })
  const exec = execFor('git push origin main')
  const first = await guard.handler(exec, async () => ({ kind: 'allow' }))
  assert.equal(first.kind, 'allow')
  assert.equal(isInitialized(loadRepoState(config.repoStateFile), 'D:/repo'), false)
  const second = await guard.handler(exec, async () => ({ kind: 'allow' }))
  assert.equal(second.kind, 'allow')
  assert.equal(requests.length, 2)
})

test('gh repo sync outside a repository is allowed (it needs no local checkout)', async () => {
  const config = makeConfig()
  const { ctx } = makeCtx()
  const notRepo = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: { ok: false, code: 128, stdout: '', stderr: 'not a repo' } },
  ])
  const { guard, logLines } = makeGuard({ ctx, config, runner: notRepo })
  let nextCalled = 0
  const decision = await guard.handler(execFor('gh repo sync owner/fork'), async () => {
    nextCalled += 1
    return { kind: 'allow' }
  })
  assert.equal(decision.kind, 'allow')
  assert.equal(nextCalled, 1)
  assert.ok(logLines.some(line => line.includes('reason=no-local-repo')))
})

test('approvalScope=project writes the repository whitelist and reuses it', async () => {
  const root = fs.mkdtempSync(path.join(ROOT, 'project-repo-'))
  const secret = 'sk-' + 'Q1w2E3r4T5y6U7i8O9p0A1s2'.slice(0, 24)
  const config = makeConfig({ approvalScope: 'project' })
  const { ctx, requests } = makeCtx({ outcomes: ['allowed-once'] })
  const runner = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: ok(`${root}\n`) },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${HEAD}\n`) },
    { match: args => args[0] === 'diff', result: ok(patchFor('a.ts', 1, [`const key = "${secret}"`])) },
  ])
  const { guard } = makeGuard({ ctx, config, runner })
  const first = await guard.handler(execFor('git commit -m x'), async () => ({ kind: 'allow' }))
  assert.equal(first.kind, 'allow')
  const projectFile = path.join(root, '.dsh', 'privacy-guard-whitelist.json')
  assert.equal(fs.existsSync(projectFile), true)
  const document = JSON.parse(fs.readFileSync(projectFile, 'utf8'))
  assert.equal(document.entries.length, 1)
  assert.equal(document.entries[0].source, 'project')

  const second = await guard.handler(execFor('git commit -m x'), async () => ({ kind: 'allow' }))
  assert.equal(second.kind, 'allow')
  assert.equal(requests.length, 1)
})

test('approvalScope=session remembers only inside the session', async () => {
  const config = makeConfig({ approvalScope: 'session' })
  const secret = 'sk-' + 'R1e2W3q4A5s6D7f8G9h0J1k2'.slice(0, 24)
  const { ctx, requests } = makeCtx({ outcomes: ['allowed-once'] })
  const { guard } = makeGuard({ ctx, config, runner: commitRunner({ diff: patchFor('a.ts', 1, [`const key = "${secret}"`]) }) })
  const first = await guard.handler(execFor('git commit -m x'), async () => ({ kind: 'allow' }))
  assert.equal(first.kind, 'allow')
  const second = await guard.handler(execFor('git commit -m x'), async () => ({ kind: 'allow' }))
  assert.equal(second.kind, 'allow')
  assert.equal(requests.length, 1)
  // Nothing was written to the global whitelist.
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 0)
})

test('a project revoke entry overrides a globally approved identity', async () => {
  const root = fs.mkdtempSync(path.join(ROOT, 'project-deny-'))
  const secret = 'sk-' + 'S1d2F3g4H5j6K7l8Z9x0C1v2'.slice(0, 24)
  const config = makeConfig()
  const identity = identityOf('openai-key', secret)
  await addApproved(config.whitelistFile, [
    { identity, ruleId: 'openai-key', label: 'OpenAI API Key', masked: 'sk-S…12', file: 'a.ts' },
  ])
  fs.mkdirSync(path.join(root, '.dsh'), { recursive: true })
  fs.writeFileSync(
    path.join(root, '.dsh', 'privacy-guard-whitelist.json'),
    JSON.stringify({
      version: 1,
      entries: [{ id: identity, rule: 'openai-key', label: 'OpenAI API Key', masked: 'sk-S…12', allowed: false }],
    }),
  )
  const runner = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: ok(`${root}\n`) },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${HEAD}\n`) },
    { match: args => args[0] === 'diff', result: ok(patchFor('a.ts', 1, [`const key = "${secret}"`])) },
  ])
  const { ctx } = makeCtx({ outcomes: ['rejected'] })
  const { guard } = makeGuard({ ctx, config, runner })
  const decision = await guard.handler(execFor('git commit -m x'), async () => ({ kind: 'allow' }))
  assert.equal(decision.kind, 'deny')
})

test('the approval prompt names the approval scope and project file', async () => {
  const root = fs.mkdtempSync(path.join(ROOT, 'scope-prompt-'))
  const secret = 'sk-' + 'H1j2K3l4M5n6O7p8Q9r0S1t2'.slice(0, 24)
  const config = makeConfig({ approvalScope: 'project' })
  const { ctx, requests } = makeCtx({ outcomes: ['rejected'] })
  const runner = fakeGit([
    { match: contains('rev-parse', '--show-toplevel'), result: ok(`${root}\n`) },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${HEAD}\n`) },
    { match: args => args[0] === 'diff', result: ok(patchFor('a.ts', 1, [`const key = "${secret}"`])) },
  ])
  const { guard } = makeGuard({ ctx, config, runner })
  await guard.handler(execFor('git commit -m x'), async () => ({ kind: 'allow' }))
  const request = requests[0]
  assert.match(request.displayReason.zh, /项目级白名单/)
  assert.match(request.displayReason.en, /project whitelist/)
  assert.match(request.displayReason.en, /privacy-guard-whitelist\.json/)
})

test('session approvals fail closed when the host exposes no session id', async () => {
  const config = makeConfig({ approvalScope: 'session' })
  const secret = 'sk-' + 'T1u2V3w4X5y6Z7a8B9c0D1e2'.slice(0, 24)
  const { ctx, requests } = makeCtx({ outcomes: ['allowed-once'] })
  const { guard } = makeGuard({ ctx, config, runner: commitRunner({ diff: patchFor('a.ts', 1, [`const key = "${secret}"`]) }) })
  const noSession = { ...execFor('git commit -m x'), agent: { session: { header: { cwd: 'D:/repo' } } } }
  assert.equal((await guard.handler(noSession, async () => ({ kind: 'allow' }))).kind, 'allow')
  assert.equal((await guard.handler(noSession, async () => ({ kind: 'allow' }))).kind, 'allow')
  assert.equal(requests.length, 2)
})