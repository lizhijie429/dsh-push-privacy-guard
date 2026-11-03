import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildDenyReason,
  buildFindingsApproval,
  buildFullScanQuestion,
  describeNotes,
  renderHelp,
  renderRepos,
  renderScanReport,
  renderStatus,
  renderWhitelist,
} from '../lib/messages.mjs'

const SECRET = 'sk-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'.slice(0, 24)

function dedupedFinding(overrides = {}) {
  return {
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
    ...overrides,
  }
}

test('findings approval includes masked previews, counts and whitelist hint', () => {
  const approval = buildFindingsApproval({
    action: 'push',
    repo: 'D:/repo',
    findings: [dedupedFinding(), dedupedFinding({ identity: 'b', ruleId: 'email', label: '邮箱地址', masked: 'z***@x.cn', preview: 'z***@x.cn', locations: [{ file: 'a.ts', line: 4, preview: 'z***@x.cn' }] })],
    maxItems: 1,
  })
  assert.match(approval.reason, /2 unapproved sensitive item/)
  assert.match(approval.reason, /D:\/repo/)
  assert.match(approval.displayReason.zh, /隐私检查发现 2 处/)
  assert.match(approval.displayReason.zh, /sk-a…34/)
  assert.match(approval.displayReason.zh, /另有 1 处未列出/)
  assert.ok(!approval.displayReason.en.includes(SECRET))
  assert.ok(!approval.displayReason.zh.includes(SECRET))
  assert.match(approval.displayReason.en, /Approve: continue this time/)
})

test('approval mentions incomplete scans and already-whitelisted items', () => {
  const approval = buildFindingsApproval({
    action: 'commit',
    repo: 'D:/repo',
    findings: [dedupedFinding()],
    whitelistedCount: 3,
    incomplete: true,
    notes: ['diff-too-large'],
  })
  assert.match(approval.displayReason.zh, /扫描不完整/)
  assert.match(approval.displayReason.zh, /已跳过 3 处/)
  assert.match(approval.reason, /scan was incomplete/)
})

test('full scan question explains both choices', () => {
  const question = buildFullScanQuestion('D:/repo')
  assert.match(question.reason, /first push/)
  assert.match(question.displayReason.zh, /批准 = 先全仓库扫描/)
  assert.match(question.displayReason.en, /Reject = check only this push/)
})

test('deny reasons are actionable and never contain matched values', () => {
  const rejected = buildDenyReason({ action: 'push', outcome: 'rejected', count: 2 })
  assert.match(rejected, /git push/)
  assert.match(rejected, /2 unapproved/)
  const unavailable = buildDenyReason({ action: 'commit', outcome: 'unavailable' })
  assert.match(unavailable, /no user approval channel/)
  const failed = buildDenyReason({ action: 'push', outcome: 'scan-failed', detail: 'fatal:\nbad repo' })
  assert.match(failed, /could not complete/)
  assert.ok(!failed.includes('\n'))
  const unresolved = buildDenyReason({
    action: 'commit',
    outcome: 'repo-unresolved',
    detail: 'cwd uses an unresolved shell variable',
  })
  assert.match(unresolved, /repository could not be located/)
  assert.match(unresolved, /unresolved shell variable/)
  assert.match(unresolved, /unresolvedRepo=allow/)
  const persistent = buildDenyReason({ action: 'push', outcome: 'persistent-shell' })
  assert.match(persistent, /persistent terminal/)
  assert.match(persistent, /persistentShellCommits=allow/)
})

test('describeNotes maps known and unknown notes', () => {
  assert.match(describeNotes(['diff-too-large', 'files-skipped:2'], 'zh'), /差异超过扫描大小上限/)
  assert.match(describeNotes(['files-skipped:2'], 'zh'), /2 个/)
  assert.equal(describeNotes([], 'zh'), '')
  assert.equal(describeNotes(['custom-note'], 'en'), 'custom-note')
})

test('command report rendering uses masked data only', () => {
  const whitelist = {
    entries: [
      { id: 'a1b2c3d4e5f60718', rule: 'openai-key', label: 'OpenAI API Key', masked: 'sk-a…34', firstFile: 'a.ts', addedAt: '2026-11-03' },
    ],
  }
  const list = renderWhitelist(whitelist)
  assert.match(list, /白名单：1 条/)
  assert.match(list, /a1b2c3d4e5f60718/)
  assert.ok(!list.includes(SECRET))
  assert.match(renderWhitelist({ entries: [] }), /白名单为空/)

  const repos = renderRepos({ repos: { a: { root: 'D:/a', mode: 'full', initializedAt: 'x' } } })
  assert.match(repos, /D:\/a/)
  assert.match(renderRepos({ repos: {} }), /暂无已初始化仓库/)

  const status = renderStatus({
    config: {
      enabled: true,
      interceptCommit: true,
      interceptPush: true,
      fullScanOnFirstPush: 'ask',
      whitelistOnApprove: true,
      requireApprovalOnIncompleteScan: true,
      whitelistFile: 'C:/plugin/state/whitelist.json',
    },
    whitelist: { entries: [] },
    repoState: { repos: {} },
    rulesCount: 16,
    currentRepo: 'D:/repo',
    initialized: false,
  })
  assert.match(status, /已启用/)
  assert.match(status, /首次推送将询问全仓扫描/)

  const scan = renderScanReport({
    root: 'D:/repo',
    result: { findings: [dedupedFinding()], incomplete: true, notes: ['file-limit'], filesScanned: 12 },
  })
  assert.match(scan, /发现：1 处/)
  assert.match(scan, /扫描不完整/)
  assert.match(scan, /已扫描文件：12 个/)
  assert.match(renderHelp(), /\/privacy-guard remove/)
})

test('an incomplete scan with no findings gets its own approval wording', () => {
  const approval = buildFindingsApproval({
    action: 'push',
    repo: 'D:/repo',
    findings: [],
    incomplete: true,
    notes: ['diff-too-large'],
  })
  assert.match(approval.reason, /scan .* was incomplete/)
  assert.doesNotMatch(approval.reason, /0 unapproved/)
  assert.match(approval.displayReason.zh, /未能完整扫描/)
  assert.match(approval.displayReason.zh, /差异超过扫描大小上限/)
  assert.doesNotMatch(approval.displayReason.zh, /0 处/)
  assert.match(approval.displayReason.en, /could not complete/)
  assert.match(approval.displayReason.en, /Approve: continue/)
})
