import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import {
  addApproved,
  clearWhitelist,
  entryForFinding,
  loadWhitelist,
  removeByPrefix,
  whitelistIds,
} from '../lib/whitelist.mjs'
import {
  isInitialized,
  listRepos,
  loadRepoState,
  markInitialized,
  repoKey,
  resetRepos,
} from '../lib/repo-state.mjs'

const ROOT = fs.mkdtempSync(path.join(import.meta.dirname, '.test-tmp-'))
after(() => {
  try {
    fs.rmSync(ROOT, { recursive: true, force: true })
  } catch {
    /* best effort */
  }
})
const file = name => path.join(ROOT, name)

function finding(identity, overrides = {}) {
  return {
    identity,
    ruleId: 'openai-key',
    label: 'OpenAI API Key',
    masked: 'sk-a…34',
    file: 'src/config.ts',
    line: 2,
    ...overrides,
  }
}

test('missing and corrupt whitelist files are tolerated', () => {
  assert.deepEqual(loadWhitelist(file('missing.json')).entries, [])
  fs.writeFileSync(file('corrupt.json'), '{not json', 'utf8')
  const corrupt = loadWhitelist(file('corrupt.json'))
  assert.deepEqual(corrupt.entries, [])
  assert.match(corrupt.warning, /unreadable/)
})

test('approved findings are stored masked, deduped and reloadable', async () => {
  const target = file('whitelist.json')
  const first = await addApproved(target, [finding('a1b2c3d4e5f60718')])
  assert.equal(first.added, 1)
  const second = await addApproved(target, [finding('a1b2c3d4e5f60718')])
  assert.equal(second.added, 0)

  const document = loadWhitelist(target)
  assert.equal(document.entries.length, 1)
  assert.equal(document.entries[0].id, 'a1b2c3d4e5f60718')
  assert.equal(document.entries[0].masked, 'sk-a…34')
  assert.equal(document.entries[0].source, 'approval')
  const raw = fs.readFileSync(target, 'utf8')
  assert.ok(!raw.includes('sk-REAL-SECRET'))
  assert.deepEqual([...whitelistIds(document)], ['a1b2c3d4e5f60718'])
})

test('entryForFinding never copies the raw value', () => {
  const entry = entryForFinding(finding('deadbeefdeadbeef', { value: 'sk-REAL-SECRET', preview: 'sk-R…ET' }))
  assert.ok(!JSON.stringify(entry).includes('sk-REAL-SECRET'))
  assert.equal(entry.firstFile, 'src/config.ts')
})

test('removeByPrefix removes a unique entry and rejects empty/ambiguous/missing prefixes', async () => {
  const target = file('remove.json')
  fs.writeFileSync(
    target,
    JSON.stringify({
      version: 1,
      entries: [
        { id: 'abc1deadbeef0001', rule: 'openai-key', label: 'OpenAI', masked: 'sk-a…34', firstFile: 'a.ts', addedAt: '', source: 'approval' },
        { id: 'abc2deadbeef0002', rule: 'email', label: 'Email', masked: 'z***@x.cn', firstFile: 'b.ts', addedAt: '', source: 'approval' },
      ],
    }),
    'utf8',
  )
  assert.equal((await removeByPrefix(target, '')).error, 'empty-prefix')
  assert.equal((await removeByPrefix(target, 'zzz')).error, 'no-match')
  assert.equal((await removeByPrefix(target, 'abc')).error, 'ambiguous')
  const removed = await removeByPrefix(target, 'ABC2')
  assert.equal(removed.removed.length, 1)
  assert.deepEqual(loadWhitelist(target).entries.map(entry => entry.id), ['abc1deadbeef0001'])
})

test('clearWhitelist empties the document and leaves no temp files', async () => {
  const target = file('clear.json')
  await addApproved(target, [finding('a1b2c3d4e5f60718'), finding('0011223344556677', { ruleId: 'email' })])
  const result = await clearWhitelist(target)
  assert.equal(result.removed, 2)
  assert.equal(loadWhitelist(target).entries.length, 0)
  const leftovers = fs.readdirSync(ROOT).filter(name => name.includes('.tmp-'))
  assert.deepEqual(leftovers, [])
})

test('repository state records, lists and resets', async () => {
  const target = file('repos.json')
  assert.deepEqual(loadRepoState(target).repos, {})
  assert.equal(isInitialized(loadRepoState(target), 'D:/repo-a'), false)

  await markInitialized(target, { root: 'D:/repo-a', mode: 'full', now: '2026-11-03T00:00:00.000Z' })
  await markInitialized(target, { root: 'D:/repo-b', mode: 'diff' })
  const state = loadRepoState(target)
  assert.equal(isInitialized(state, 'D:/repo-a'), true)
  assert.equal(state.repos[repoKey('D:/repo-a')].mode, 'full')
  assert.equal(listRepos(state).length, 2)

  const resetOne = await resetRepos(target, 'repo-a')
  assert.equal(resetOne.removed, 1)
  assert.equal(isInitialized(loadRepoState(target), 'D:/repo-a'), false)

  const resetAll = await resetRepos(target, 'all')
  assert.equal(resetAll.removed, 1)
  assert.deepEqual(loadRepoState(target).repos, {})
  assert.equal((await resetRepos(target, '')).error, 'empty-query')
})

test('repoKey is stable for spelling variants', () => {
  assert.equal(repoKey('D:/Work/Repo'), repoKey('D:\\Work\\Repo'))
})
