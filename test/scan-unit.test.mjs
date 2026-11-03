import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { compileRules } from '../lib/rules.mjs'
import { normalizeConfig } from '../lib/config.mjs'
import {
  dedupeFindings,
  detectRepo,
  EMPTY_TREE,
  globToRegExp,
  isIgnoredPath,
  parseLsTree,
  parsePatch,
  parseRefspec,
  planPush,
  scanCommit,
  scanFullRepo,
  scanPush,
  scanText,
  splitWhitelisted,
} from '../lib/scan.mjs'

const config = normalizeConfig({}, 'C:/plugin')
const rules = compileRules(config)
const SECRET = 'sk-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'.slice(0, 24)
const SHA_A = 'a'.repeat(40)
const SHA_B = 'b'.repeat(40)
const SHA_C = 'c'.repeat(40)

function fakeGit(handlers) {
  const calls = []
  const run = async (args) => {
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

function diffFor(file, newLine, addedLines) {
  const body = addedLines.map(line => `+${line}`).join('\n')
  return [
    `diff --git a/${file} b/${file}`,
    'index 1111111..2222222 100644',
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -1,0 +${newLine},${addedLines.length} @@`,
    body,
    '',
  ].join('\n')
}

test('glob helper matches gitignore-style patterns', () => {
  assert.equal(isIgnoredPath('node_modules/a/b.js', ['**/node_modules/**']), true)
  assert.equal(isIgnoredPath('src/a.ts', ['**/node_modules/**']), false)
  assert.equal(isIgnoredPath('docs/x.min.js', ['**/*.min.js']), true)
  assert.equal(globToRegExp('src/**/*.ts').test('src/a/b/c.ts'), true)
  // `**/dist/**` must not leak into similarly-named directories.
  assert.equal(isIgnoredPath('prebuild/x.js', ['**/build/**']), false)
  assert.equal(isIgnoredPath('mydist/x.js', ['**/dist/**']), false)
  assert.equal(isIgnoredPath('src/build/x.js', ['**/build/**']), true)
  assert.equal(isIgnoredPath('root.ts', ['**/*.ts']), true)
})

test('parsePatch reports file, line and added text', () => {
  const added = parsePatch(diffFor('src/config.ts', 3, ['const a = 1', 'const b = 2']))
  assert.deepEqual(added, [
    { file: 'src/config.ts', line: 3, text: 'const a = 1' },
    { file: 'src/config.ts', line: 4, text: 'const b = 2' },
  ])
})

test('parsePatch handles new files, deletions and quoted paths', () => {
  const newFile = ['diff --git a/a.txt b/a.txt', 'new file mode 100644', '--- /dev/null', '+++ b/a.txt', '@@ -0,0 +1 @@', '+hello', ''].join('\n')
  assert.deepEqual(parsePatch(newFile), [{ file: 'a.txt', line: 1, text: 'hello' }])

  const deleted = ['diff --git a/old.txt b/old.txt', 'deleted file mode 100644', '--- a/old.txt', '+++ /dev/null', '@@ -1 +0,0 @@', '-old', ''].join('\n')
  assert.deepEqual(parsePatch(deleted), [])

  const quoted = ['diff --git "a/dir with space/a.txt" "b/dir with space/a.txt"', '--- "a/dir with space/a.txt"', '+++ "b/dir with space/a.txt"', '@@ -0,0 +1 @@', '+x', ''].join('\n')
  assert.deepEqual(parsePatch(quoted), [{ file: 'dir with space/a.txt', line: 1, text: 'x' }])
})

test('scanText attaches rule, identity and masking to each finding', () => {
  const { findings } = scanText(`const key = "${SECRET}"`, { file: 'a.ts', rules, config })
  assert.equal(findings.length, 1)
  assert.equal(findings[0].ruleId, 'openai-key')
  assert.equal(findings[0].file, 'a.ts')
  assert.equal(findings[0].line, 1)
  assert.match(findings[0].identity, /^[0-9a-f]{16}$/)
  assert.ok(!findings[0].masked.includes(SECRET))
})

test('dedupe collapses repeated identities and records locations', () => {
  const one = scanText(`a=${SECRET}`, { file: 'a.ts', rules, config }).findings
  const two = scanText(`b=${SECRET}`, { file: 'b.ts', rules, config }).findings
  const deduped = dedupeFindings([...one, ...two])
  assert.equal(deduped.length, 1)
  assert.equal(deduped[0].count, 2)
  assert.deepEqual(deduped[0].locations.map(location => location.file), ['a.ts', 'b.ts'])
})

test('splitWhitelisted separates approved identities', () => {
  const findings = dedupeFindings(scanText(`a=${SECRET}`, { file: 'a.ts', rules, config }).findings)
  const id = findings[0].identity
  assert.equal(splitWhitelisted(findings, new Set([id])).blocked.length, 0)
  assert.equal(splitWhitelisted(findings, new Set()).blocked.length, 1)
})

test('parseRefspec handles force, delete and simple refspecs', () => {
  assert.deepEqual(parseRefspec('+dev:dev'), { src: 'dev', dst: 'dev', deleted: false })
  assert.deepEqual(parseRefspec(':old'), { src: '', dst: 'old', deleted: true })
  assert.deepEqual(parseRefspec('main'), { src: 'main', dst: 'main', deleted: false })
})

test('detectRepo resolves the repository root and tolerates failures', async () => {
  const repo = fakeGit([{ match: contains('rev-parse', '--show-toplevel'), result: ok('D:/repo\n') }])
  assert.equal(await detectRepo(repo, 'D:/repo/sub'), path.resolve('D:/repo'))
  const none = fakeGit([{ match: contains('rev-parse'), result: { ok: false, stderr: 'not a repo' } }])
  assert.equal(await detectRepo(none, 'D:/tmp'), null)
})

test('planPush computes base and commits to upload', async () => {
  const run = fakeGit([
    { match: contains('remote'), result: ok('origin\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--abbrev-ref') && args.includes('HEAD'), result: ok('dev\n') },
    { match: contains('--symbolic-full-name'), result: ok('origin/dev\n') },
    {
      match: args => args[0] === 'rev-parse' && args.includes('--verify'),
      result: args => (args[args.length - 1].endsWith('^') ? ok(`${SHA_C}\n`) : ok(`${SHA_A}\n`)),
    },
    { match: contains('rev-list'), result: ok(`${SHA_A}\n${SHA_B}\n`) },
  ])
  const plan = await planPush(run, { op: { kind: 'push', flags: {}, positional: [] }, config })
  assert.equal(plan.empty, false)
  assert.equal(plan.base, SHA_C)
  assert.equal(plan.headSha, SHA_A)
  assert.deepEqual(plan.commits, [SHA_A, SHA_B])
  assert.equal(plan.targetRemote, 'origin')
  assert.equal(plan.incomplete, false)
})

test('planPush marks a large commit set incomplete and falls back to the empty tree', async () => {
  const run = fakeGit([
    { match: contains('remote'), result: ok('origin\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('HEAD'), result: ok('dev\n') },
    { match: contains('--symbolic-full-name'), result: ok('origin/dev\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${SHA_A}\n`) },
    { match: contains('rev-list'), result: ok([SHA_A, SHA_B, SHA_C].join('\n') + '\n') },
  ])
  const small = { ...config, maxCommits: 2 }
  const plan = await planPush(run, { op: { kind: 'push', flags: {}, positional: [] }, config: small })
  assert.equal(plan.incomplete, true)
  assert.equal(plan.base, EMPTY_TREE)
  assert.equal(plan.commits.length, 2)
  assert.ok(plan.notes.includes('commit-count-limit'))
})

test('planPush allows deletes and nothing-to-push pushes', async () => {
  const deleteRun = fakeGit([])
  assert.equal((await planPush(deleteRun, { op: { kind: 'push', flags: { delete: true }, positional: [] }, config })).empty, true)
  assert.equal((await planPush(deleteRun, { op: { kind: 'push', flags: {}, positional: ['origin', ':old'] }, config })).empty, true)

  const noCommits = fakeGit([
    { match: contains('remote'), result: ok('origin\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('HEAD'), result: ok('dev\n') },
    { match: contains('--symbolic-full-name'), result: ok('origin/dev\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${SHA_A}\n`) },
    { match: contains('rev-list'), result: ok('') },
  ])
  const plan = await planPush(noCommits, { op: { kind: 'push', flags: {}, positional: [] }, config })
  assert.equal(plan.empty, true)
  assert.equal(plan.reason, 'nothing-to-push')
})

test('scanPush finds secrets in the planned diff and commit messages', async () => {
  const run = fakeGit([
    { match: args => args[0] === 'log' && args.includes('--no-walk'), result: ok(`\u001efeat: add phone 13812345678\u001f`) },
    { match: args => args[0] === 'log', result: ok(diffFor('src/config.ts', 2, [`const key = "${SECRET}"`])) },
  ])
  const plan = { empty: false, broad: false, headSha: SHA_A, base: SHA_B, commits: [SHA_A], commitCount: 1, incomplete: false, notes: [] }
  const result = await scanPush(run, { plan, rules, config })
  const ids = result.findings.map(finding => finding.ruleId)
  assert.ok(ids.includes('openai-key'))
  assert.ok(ids.includes('cn-mobile'))
  assert.equal(result.filesScanned, 1)
  assert.equal(result.commitsScanned, 1)
})

test('scanCommit scans staged content and -m / -F messages', async () => {
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: ok(diffFor('a.ts', 1, [`token = "${SECRET}"`])) },
  ])
  const op = { kind: 'commit', cwd: 'D:/repo', flags: { all: false }, messages: ['fix phone 13812345678'], messageFile: 'msg.txt' }
  const result = await scanCommit(run, {
    op,
    rules,
    config,
    readTextFile: async () => 'message body with 11010519491231002X',
  })
  const ids = result.findings.map(finding => finding.ruleId)
  assert.ok(ids.includes('openai-key'))
  assert.ok(ids.includes('cn-mobile'))
  assert.ok(ids.includes('cn-id-card'))
  assert.equal(result.incomplete, false)
})

test('scanCommit uses diff HEAD when -a is set and tolerates a missing message file', async () => {
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: args => {
      assert.ok(args.includes('HEAD'))
      return ok('')
    } },
  ])
  const result = await scanCommit(run, {
    op: { kind: 'commit', cwd: 'D:/repo', flags: { all: true }, messages: [], messageFile: 'missing.txt' },
    rules,
    config,
    readTextFile: async () => {
      throw new Error('missing')
    },
  })
  assert.equal(result.findings.length, 0)
  assert.ok(result.notes.includes('message-file-unreadable'))
})

test('scanFullRepo only scans tracked, non-ignored blobs and reports limits', async () => {
  const records = [
    { oid: '1'.repeat(40), size: 40, path: 'src/config.ts' },
    { oid: '2'.repeat(40), size: 10, path: 'node_modules/pkg/index.js' },
    { oid: '3'.repeat(40), size: 10, path: 'bin/data.bin' },
    { oid: '4'.repeat(40), size: 2 * 1024 * 1024, path: 'big.zip' },
  ]
  const lsTree = records.map(record => `100644 blob ${record.oid} ${record.size}\t${record.path}`).join('\u0000') + '\u0000'
  const contents = {
    ['1'.repeat(40)]: `const key = "${SECRET}"\n`,
    ['2'.repeat(40)]: `const key = "${SECRET}"\n`,
    ['3'.repeat(40)]: 'binary\u0000data',
  }
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'ls-tree', result: ok(lsTree) },
    { match: args => args[0] === 'cat-file', result: args => ok(contents[args[2]] ?? '') },
  ])
  const result = await scanFullRepo(run, { rules, config })
  assert.equal(result.filesScanned, 2) // config.ts + binary (read but not matched); ignored & oversized skipped
  assert.equal(result.findings.length, 1)
  assert.equal(result.findings[0].file, 'src/config.ts')
  // A size-skipped file means the full scan is incomplete and needs approval.
  assert.equal(result.incomplete, true)
  assert.ok(result.notes.includes('files-skipped:1'))
})

test('scanFullRepo reads every blob through one batch call when supported', async () => {
  const records = [
    { oid: '1'.repeat(40), size: 40, path: 'src/config.ts' },
    { oid: '2'.repeat(40), size: 40, path: 'src/other.ts' },
  ]
  const lsTree = records.map(record => `100644 blob ${record.oid} ${record.size}\t${record.path}`).join('\u0000') + '\u0000'
  const batchCalls = []
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'ls-tree', result: ok(lsTree) },
    { match: args => args[0] === 'cat-file', result: ok('') },
  ])
  const result = await scanFullRepo(run, {
    rules,
    config,
    cwd: 'D:/repo',
    readBlobs: async ({ oids }) => {
      batchCalls.push(oids)
      return new Map([
        ['1'.repeat(40), Buffer.from(`const key = "${SECRET}"\n`)],
        ['2'.repeat(40), Buffer.from('clean\n')],
      ])
    },
  })
  assert.deepEqual(batchCalls, [[records[0].oid, records[1].oid]])
  assert.equal(result.findings.length, 1)
  assert.equal(result.findings[0].file, 'src/config.ts')
  assert.equal(result.incomplete, false)
})

test('scanFullRepo marks truncation when the file limit is hit', async () => {
  const records = [
    { oid: '1'.repeat(40), size: 1, path: 'a.ts' },
    { oid: '2'.repeat(40), size: 1, path: 'b.ts' },
  ]
  const lsTree = records.map(record => `100644 blob ${record.oid} ${record.size}\t${record.path}`).join('\u0000') + '\u0000'
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'ls-tree', result: ok(lsTree) },
    { match: args => args[0] === 'cat-file', result: ok('x') },
  ])
  const result = await scanFullRepo(run, { rules, config: { ...config, maxFiles: 1 } })
  assert.equal(result.incomplete, true)
  assert.ok(result.notes.includes('file-limit'))
})

test('parseLsTree ignores non-blob entries and malformed records', () => {
  const stdout = [
    `100644 blob ${'1'.repeat(40)} 12\tsrc/a.ts`,
    `160000 commit ${'2'.repeat(40)} -\tlibs/sub`,
    'garbage',
    `100644 blob ${'3'.repeat(40)} 4\tb.ts`,
  ].join('\u0000') + '\u0000'
  const entries = parseLsTree(stdout)
  assert.deepEqual(entries.map(entry => entry.path), ['src/a.ts', 'b.ts'])
})

test('scanCommit covers worktree diff and untracked files after an in-command git add', async () => {
  const trackedSecret = 'sk-' + 'A1b2C3d4E5f6G7h8I9j0K1l2'.slice(0, 24)
  const untrackedSecret = 'sk-' + 'Z9y8X7w6V5u4T3s2R1q0P9o8'.slice(0, 24)
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: ok(diffFor('src/tracked.ts', 1, [`const key = "${trackedSecret}"`])) },
    { match: args => args[0] === 'ls-files', result: ok('new.ts\u0000') },
  ])
  const result = await scanCommit(run, {
    op: {
      kind: 'commit',
      cwd: 'D:/repo',
      flags: { all: false },
      messages: [],
      mutation: { indexMutated: true, mayAddUntracked: true, addScopeAll: true, scanIgnored: false, addPaths: [] },
    },
    rules,
    config,
    readWorkingFile: async () => Buffer.from(`const key = "${untrackedSecret}"\n`),
  })
  const files = result.findings.map(finding => finding.file)
  assert.ok(files.includes('src/tracked.ts'))
  assert.ok(files.includes('new.ts'))
  const diffCall = run.calls.find(args => args[0] === 'diff')
  assert.ok(diffCall.includes('HEAD'))
})

test('pathspec commits scan the worktree diff limited to the pathspec', async () => {
  const secret = 'sk-' + 'B2c3D4e5F6g7H8i9J0k1L2m3'.slice(0, 24)
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: ok(diffFor('a.ts', 1, [`const key = "${secret}"`])) },
  ])
  const result = await scanCommit(run, {
    op: { kind: 'commit', cwd: 'D:/repo', flags: { all: false }, messages: [], pathspecs: ['a.ts'], includes: [] },
    rules,
    config,
  })
  assert.equal(result.findings.length, 1)
  const diffCall = run.calls.find(args => args[0] === 'diff')
  assert.ok(diffCall.includes('HEAD'))
  // Pathspec narrowing is deliberately not used: scan the whole worktree diff.
  assert.ok(!diffCall.includes('--'))
})

test('untracked scanning honours the add path prefix and ignorePaths', async () => {
  const secret = 'sk-' + 'C3d4E5f6G7h8I9j0K1l2M3n4'.slice(0, 24)
  const seen = []
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: ok('') },
    { match: args => args[0] === 'ls-files', result: ok('src/new.ts\u0000other.ts\u0000src/skip.min.js\u0000') },
  ])
  const result = await scanCommit(run, {
    op: {
      kind: 'commit',
      cwd: 'D:/repo',
      flags: { all: false },
      messages: [],
      mutation: { indexMutated: true, mayAddUntracked: true, addScopeAll: false, scanIgnored: false, addPaths: ['src'] },
    },
    rules,
    config,
    readWorkingFile: async file => {
      seen.push(file)
      return Buffer.from(`const key = "${secret}"\n`)
    },
  })
  const expected = path.resolve('D:/repo', 'src/new.ts').replace(/\\/g, '/')
  assert.deepEqual(seen.map(file => file.replace(/\\/g, '/')), [expected])
  assert.ok(result.findings.some(finding => finding.file === 'src/new.ts'))
  assert.ok(!result.findings.some(finding => finding.file === 'other.ts'))
})

test('unreadable or oversized untracked files mark the scan incomplete', async () => {
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: ok('') },
    { match: args => args[0] === 'ls-files', result: ok('big.bin\u0000') },
  ])
  const result = await scanCommit(run, {
    op: {
      kind: 'commit',
      cwd: 'D:/repo',
      flags: { all: false },
      messages: [],
      mutation: { indexMutated: true, mayAddUntracked: true, addScopeAll: true, scanIgnored: false, addPaths: [] },
    },
    rules,
    config,
    readWorkingFile: async () => null,
  })
  assert.equal(result.incomplete, true)
  assert.ok(result.notes.includes('files-skipped:1'))
})

test('ignorePaths filters diff findings', async () => {
  const secret = 'sk-' + 'D4e5F6g7H8i9J0k1L2m3N4o5'.slice(0, 24)
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: ok(diffFor('tests/fixtures/data.ts', 1, [`const key = "${secret}"`])) },
  ])
  const custom = { ...config, ignorePaths: [...config.ignorePaths, '**/fixtures/**'] }
  const result = await scanCommit(run, { op: { kind: 'commit', cwd: 'D:/repo', flags: { all: false }, messages: [] }, rules, config: custom })
  assert.equal(result.findings.length, 0)
})

test('scanText scans very long lines in overlapping chunks', () => {
  const secret = 'sk-' + 'J1k2L3m4N5o6P7q8R9s0T1u2'.slice(0, 24)
  const result = scanText(`${'a'.repeat(20000)} ${secret}`, { file: 'long.ts', rules, config })
  assert.ok(result.findings.some(finding => finding.ruleId === 'openai-key'))
})

test('scanPush scans tag object messages listed in the plan', async () => {
  const secret = 'sk-' + 'K1l2M3n4O5p6Q7r8S9t0U1v2'.slice(0, 24)
  const run = fakeGit([
    { match: args => args[0] === 'log', result: ok('') },
    { match: args => args[0] === 'for-each-ref', result: ok(`release note ${secret}\n`) },
  ])
  const result = await scanPush(run, {
    plan: {
      empty: false,
      mode: 'push',
      broad: false,
      commits: [],
      base: EMPTY_TREE,
      headSha: SHA_A,
      notes: [],
      tagRefs: ['v1'],
    },
    rules,
    config,
  })
  assert.ok(result.findings.some(finding => finding.file === '<tag message: v1>' && finding.ruleId === 'openai-key'))
})

test('planPush lists local tags for --tags pushes', async () => {
  const run = fakeGit([
    { match: contains('remote'), result: ok('origin\n') },
    { match: args => args[0] === 'for-each-ref', result: ok('v1\nv2\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--abbrev-ref'), result: ok('main\n') },
    { match: contains('--symbolic-full-name'), result: ok('origin/main\n') },
    { match: args => args[0] === 'rev-parse' && args.includes('--verify'), result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'rev-list', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: ok('') },
    { match: args => args[0] === 'log', result: ok('') },
  ])
  const op = { kind: 'push', flags: { tags: true }, positional: ['origin'], cwd: 'D:/repo' }
  const plan = await planPush(run, { op, config })
  assert.deepEqual([...plan.tagRefs].sort(), ['v1', 'v2'])
})

test('scanPush walks every commit in the range, not just the net diff', async () => {
  const run = fakeGit([
    { match: args => args[0] === 'log' && args.includes('--no-walk'), result: ok('') },
    { match: args => args[0] === 'log', result: ok(diffFor('leak.txt', 1, [`const key = "${SECRET}"`])) },
  ])
  const plan = { empty: false, broad: false, headSha: SHA_A, base: SHA_B, commits: [SHA_A, SHA_B], commitCount: 2, incomplete: false, notes: [] }
  const result = await scanPush(run, { plan, rules, config })
  assert.ok(result.findings.some(finding => finding.file === 'leak.txt'))
  const logCall = run.calls.find(args => args[0] === 'log' && args.includes('-p'))
  assert.ok(logCall.includes(`${SHA_B}..${SHA_A}`))
})

test('planPush plans every explicit refspec instead of only the first', async () => {
  const run = fakeGit([
    { match: contains('remote'), result: ok('origin\n') },
    {
      match: args => args[0] === 'rev-parse' && args.includes('--verify'),
      result: args => (args[args.length - 1].endsWith('^') ? ok(`${SHA_B}\n`) : ok(`${SHA_A}\n`)),
    },
    { match: args => args[0] === 'rev-list', result: ok(`${SHA_A}\n`) },
  ])
  const op = { kind: 'push', flags: {}, positional: ['origin', 'main', 'dev'], cwd: 'D:/repo' }
  const plan = await planPush(run, { op, config })
  assert.equal(plan.empty, false)
  assert.equal(plan.broad, true)
  assert.deepEqual(plan.branches.map(range => range.headRef), ['main', 'dev'])
})

test('planPush expands wildcard refspecs', async () => {
  const run = fakeGit([
    { match: contains('remote'), result: ok('origin\n') },
    { match: args => args[0] === 'for-each-ref', result: ok('refs/heads/main\nrefs/heads/dev\n') },
    {
      match: args => args[0] === 'rev-parse' && args.includes('--verify'),
      result: args => (args[args.length - 1].endsWith('^') ? ok(`${SHA_B}\n`) : ok(`${SHA_A}\n`)),
    },
    { match: args => args[0] === 'rev-list', result: ok(`${SHA_A}\n`) },
  ])
  const op = { kind: 'push', flags: {}, positional: ['origin', 'refs/heads/*:refs/heads/*'], cwd: 'D:/repo' }
  const plan = await planPush(run, { op, config })
  assert.equal(plan.broad, true)
  assert.deepEqual(plan.branches.map(range => range.headRef), ['refs/heads/main', 'refs/heads/dev'])
})

test('planPush fails closed when git queries fail', async () => {
  const failed = fakeGit([
    { match: contains('remote'), result: ok('origin\n') },
    { match: args => args[0] === 'rev-parse', result: { ok: false, stderr: 'fatal: unable to read tree' } },
  ])
  const plan = await planPush(failed, { op: { kind: 'push', flags: {}, positional: [] }, config })
  assert.equal(plan.empty, false)
  assert.ok(typeof plan.error === 'string')

  const missing = fakeGit([
    { match: contains('remote'), result: ok('origin\n') },
    { match: args => args[0] === 'rev-parse', result: { ok: false, stderr: 'fatal: Needed a single revision' } },
  ])
  const noHead = await planPush(missing, { op: { kind: 'push', flags: {}, positional: [] }, config })
  assert.equal(noHead.empty, true)
  assert.equal(noHead.reason, 'no-head')
})

test('scanPush fails closed when commit messages cannot be read', async () => {
  const run = fakeGit([
    { match: args => args[0] === 'log' && args.includes('--no-walk'), result: { ok: false, stderr: 'fatal: bad object' } },
    { match: args => args[0] === 'log', result: ok('') },
  ])
  const plan = { empty: false, broad: false, headSha: SHA_A, base: SHA_B, commits: [SHA_A], commitCount: 1, incomplete: false, notes: [] }
  const result = await scanPush(run, { plan, rules, config })
  assert.ok(typeof result.error === 'string')
})

test('commit messages from stdin, shell expansion or unreadable files are incomplete', async () => {
  const base = { kind: 'commit', cwd: 'D:/repo', flags: { all: false }, pathspecs: [], includes: [] }

  const fromStdin = await scanCommit(fakeGit([{ match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) }, { match: args => args[0] === 'diff', result: ok('') }]), {
    op: { ...base, messages: [], messageFile: '-' },
    rules,
    config,
  })
  assert.equal(fromStdin.incomplete, true)
  assert.ok(fromStdin.notes.includes('message-from-stdin'))

  const dynamic = await scanCommit(fakeGit([{ match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) }, { match: args => args[0] === 'diff', result: ok('') }]), {
    op: { ...base, messages: ['fix $(cat secret.txt)'] },
    rules,
    config,
  })
  assert.equal(dynamic.incomplete, true)
  assert.ok(dynamic.notes.includes('message-dynamic'))

  const unreadable = await scanCommit(fakeGit([{ match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) }, { match: args => args[0] === 'diff', result: ok('') }]), {
    op: { ...base, messages: [], messageFile: 'msg.txt' },
    rules,
    config,
    readTextFile: async () => {
      throw new Error('too large')
    },
  })
  assert.equal(unreadable.incomplete, true)
  assert.ok(unreadable.notes.includes('message-file-unreadable'))
})

test('forced git add paths are not dropped by ignorePaths', async () => {
  const secret = 'sk-' + 'N1o2P3q4R5s6T7u8V9w0X1y2'.slice(0, 24)
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'diff', result: ok('') },
    { match: args => args[0] === 'ls-files', result: ok('dist/secret.js\u0000') },
  ])
  const custom = { ...config, ignorePaths: [...config.ignorePaths, '**/dist/**'] }
  const result = await scanCommit(run, {
    op: {
      kind: 'commit',
      cwd: 'D:/repo',
      flags: { all: false },
      messages: [],
      mutation: { indexMutated: true, mayAddUntracked: true, addScopeAll: true, scanIgnored: true, addPaths: [] },
    },
    rules,
    config: custom,
    readWorkingFile: async () => Buffer.from(`const key = "${secret}"\n`),
  })
  assert.ok(result.findings.some(finding => finding.file === 'dist/secret.js'))
  const listCall = run.calls.find(args => args[0] === 'ls-files')
  assert.ok(!listCall.includes('--exclude-standard'))
})

test('scanFullRepo lists the whole tree regardless of cwd', async () => {
  const run = fakeGit([
    { match: args => args[0] === 'rev-parse', result: ok(`${SHA_A}\n`) },
    { match: args => args[0] === 'ls-tree', result: ok('') },
  ])
  await scanFullRepo(run, { rules, config, cwd: 'D:/repo/src' })
  const treeCall = run.calls.find(args => args[0] === 'ls-tree')
  assert.ok(treeCall.includes('--full-tree'))
})
