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
      result: args => (args[3].endsWith('^') ? ok(`${PARENT}\n`) : ok(`${HEAD}\n`)),
    },
    { match: args => args[0] === 'rev-list', result: ok(revList) },
    { match: args => args[0] === 'diff', result: ok(diff) },
    { match: args => args[0] === 'log', result: ok(messages) },
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

function makeGuard({ ctx, config, runner, readTextFile }) {
  const logLines = []
  const guard = createGuard({
    ctx,
    config,
    rules,
    log: line => logLines.push(line),
    runGitFactory: () => runner,
    readTextFile,
    now: () => new Date('2026-11-03T00:00:00.000Z'),
  })
  return { guard, logLines }
}

function execFor(command) {
  return {
    name: 'pwsh',
    callId: 'call-1',
    agent: { session: { header: { cwd: 'D:/repo' } } },
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
