import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { normalizeConfig } from '../lib/config.mjs'
import { executePrivacyCommand } from '../lib/commands.mjs'
import { clearWhitelist, loadWhitelist } from '../lib/whitelist.mjs'
import { loadRepoState, markInitialized } from '../lib/repo-state.mjs'
import { rememberPending, sessionEntries } from '../lib/scopes.mjs'

const ROOT = fs.mkdtempSync(path.join(import.meta.dirname, '.test-tmp-commands-'))
after(() => {
  try {
    fs.rmSync(ROOT, { recursive: true, force: true })
  } catch {
    /* best effort */
  }
})

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

test('help and unknown subcommands render usage', async () => {
  const config = makeConfig()
  const help = await executePrivacyCommand('help', { config })
  assert.equal(help.kind, 'success')
  assert.match(help.text, /推送隐私检查命令/)
  const unknown = await executePrivacyCommand('bogus', { config })
  assert.equal(unknown.kind, 'success')
  assert.match(unknown.text, /推送隐私检查命令/)
})

test('list shows entries and empty state', async () => {
  const config = makeConfig()
  const empty = await executePrivacyCommand('list', { config })
  assert.match(empty.text, /白名单为空/)

  fs.mkdirSync(path.dirname(config.whitelistFile), { recursive: true })
  fs.writeFileSync(
    config.whitelistFile,
    JSON.stringify({
      version: 1,
      entries: [
        { id: 'a1b2c3d4e5f60718', rule: 'openai-key', label: 'OpenAI API Key', masked: 'sk-a…34', firstFile: 'a.ts', addedAt: '2026-11-03', source: 'approval' },
      ],
    }),
    'utf8',
  )
  const list = await executePrivacyCommand('list', { config })
  assert.match(list.text, /白名单：1 条/)
  assert.match(list.text, /a1b2c3d4e5f60718/)
})

test('remove validates input and removes a unique prefix', async () => {
  const config = makeConfig()
  const missingArg = await executePrivacyCommand('remove', { config })
  assert.equal(missingArg.kind, 'error')
  const noMatch = await executePrivacyCommand('remove zzz', { config })
  assert.equal(noMatch.kind, 'error')

  fs.mkdirSync(path.dirname(config.whitelistFile), { recursive: true })
  fs.writeFileSync(
    config.whitelistFile,
    JSON.stringify({ version: 1, entries: [{ id: 'a1b2c3d4e5f60718', rule: 'openai-key', label: 'OpenAI API Key', masked: 'sk-a…34' }] }),
    'utf8',
  )
  const removed = await executePrivacyCommand('remove a1b2', { config })
  assert.equal(removed.kind, 'success')
  assert.match(removed.text, /已删除/)
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 0)
})

test('clear requires the confirm word', async () => {
  const config = makeConfig()
  const refused = await executePrivacyCommand('clear', { config })
  assert.equal(refused.kind, 'error')
  assert.match(refused.text, /confirm/)
  await clearWhitelist(config.whitelistFile)
  const cleared = await executePrivacyCommand('clear confirm', { config })
  assert.equal(cleared.kind, 'success')
  assert.match(cleared.text, /已清空白名单/)
})

test('repos and reset manage repository initialization records', async () => {
  const config = makeConfig()
  const empty = await executePrivacyCommand('repos', { config })
  assert.match(empty.text, /暂无已初始化仓库/)

  await markInitialized(config.repoStateFile, { root: 'D:/repo-a', mode: 'full' })
  const repos = await executePrivacyCommand('repos', { config })
  assert.match(repos.text, /D:[\\/]repo-a/)

  const missingQuery = await executePrivacyCommand('reset', { config })
  assert.equal(missingQuery.kind, 'error')
  const reset = await executePrivacyCommand('reset repo-a', { config })
  assert.equal(reset.kind, 'success')
  assert.match(reset.text, /已清除 1 个仓库/)
  assert.deepEqual(loadRepoState(config.repoStateFile).repos, {})
})

test('status reports configuration and counts', async () => {
  const config = makeConfig()
  const repoRoot = path.resolve('D:/repo')
  const fakeRunner = async args => {
    if (args.includes('--show-toplevel')) return { ok: true, code: 0, stdout: `${repoRoot}\n`, stderr: '' }
    return { ok: false, code: 1, stdout: '', stderr: 'unmocked' }
  }
  const status = await executePrivacyCommand('status', {
    config,
    cwd: repoRoot,
    createRunner: () => fakeRunner,
  })
  assert.equal(status.kind, 'success')
  assert.match(status.text, /已启用/)
  assert.ok(status.text.includes(`当前仓库：${repoRoot}`))
  assert.match(status.text, /首次推送将询问全仓扫描/)
})

test('scan renders an injected scan result without writing the whitelist', async () => {
  const config = makeConfig()
  const scan = await executePrivacyCommand('scan', {
    config,
    cwd: 'D:/repo',
    scanRepository: async () => ({
      root: 'D:/repo',
      result: {
        findings: [
          {
            ruleId: 'openai-key',
            label: 'OpenAI API Key',
            severity: 'high',
            masked: 'sk-a…34',
            preview: 'sk-a…34',
            identity: 'a1b2c3d4e5f60718',
            file: 'src/config.ts',
            line: 2,
            locations: [{ file: 'src/config.ts', line: 2, preview: 'sk-a…34' }],
            count: 1,
          },
        ],
        incomplete: false,
        notes: [],
        filesScanned: 3,
      },
    }),
  })
  assert.equal(scan.kind, 'success')
  assert.match(scan.text, /扫描仓库：D:\/repo/)
  assert.match(scan.text, /发现：1 处/)
  assert.match(scan.text, /已扫描文件：3 个/)
  assert.equal(loadWhitelist(config.whitelistFile).entries.length, 0)
})

test('scan reports a helpful error outside a git repository', async () => {
  const config = makeConfig()
  const fakeRunner = async () => ({ ok: false, code: 128, stdout: '', stderr: 'not a repository' })
  const result = await executePrivacyCommand('scan', {
    config,
    cwd: 'D:/not-a-repo',
    createRunner: () => fakeRunner,
  })
  assert.equal(result.kind, 'error')
  assert.match(result.text, /不在 git 仓库内/)
})

test('pending, session allow and project allow scopes work through commands', async () => {
  const config = makeConfig()
  const identity = 'a1b2c3d4e5f60718'
  rememberPending('cmd-session', [
    { identity, ruleId: 'openai-key', label: 'OpenAI API Key', masked: 'sk-a…34', file: 'src/config.ts' },
  ])

  const pending = await executePrivacyCommand('pending', { config, cwd: 'D:/repo', sessionId: 'cmd-session' })
  assert.equal(pending.kind, 'success')
  assert.match(pending.text, /a1b2c3d4e5f60718/)

  const allowSession = await executePrivacyCommand('allow last session', {
    config,
    cwd: 'D:/repo',
    sessionId: 'cmd-session',
  })
  assert.equal(allowSession.kind, 'success')
  assert.equal(sessionEntries('cmd-session')[0].id, identity)

  const list = await executePrivacyCommand('list', { config, cwd: 'D:/repo', sessionId: 'cmd-session' })
  assert.match(list.text, /会话白名单：1 条/)

  const repo = fs.mkdtempSync(path.join(ROOT, 'project-command-'))
  const fakeRunner = async args => {
    if (args.join(' ').includes('--show-toplevel')) return { ok: true, stdout: `${repo}\n`, stderr: '' }
    return { ok: false, stdout: '', stderr: '' }
  }
  rememberPending('cmd-project', [
    { identity: 'bbbbbbbbbbbbbbbb', ruleId: 'email', label: '邮箱地址', masked: 'z***@x.cn', file: 'b.ts' },
  ])
  const allowProject = await executePrivacyCommand('project allow last', {
    config,
    cwd: repo,
    sessionId: 'cmd-project',
    createRunner: () => fakeRunner,
  })
  assert.equal(allowProject.kind, 'success')
  const projectFile = path.join(repo, '.dsh', 'privacy-guard-whitelist.json')
  assert.equal(fs.existsSync(projectFile), true)
  assert.equal(JSON.parse(fs.readFileSync(projectFile, 'utf8')).entries[0].id, 'bbbbbbbbbbbbbbbb')

  const revoke = await executePrivacyCommand('session revoke a1b2', { config, cwd: 'D:/repo', sessionId: 'cmd-session' })
  assert.equal(revoke.kind, 'success')
  assert.equal(sessionEntries('cmd-session').length, 0)
})
