import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { normalizeConfig } from '../lib/config.mjs'
import { entryForFinding, loadWhitelist } from '../lib/whitelist.mjs'
import {
  addProjectApproved,
  addSessionEntries,
  clearSession,
  effectiveApprovedIds,
  loadProjectWhitelist,
  pendingFor,
  pendingMatch,
  projectWhitelistPath,
  rememberPending,
  removeSessionByPrefix,
  sessionEntries,
  sessionIds,
} from '../lib/scopes.mjs'

const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'privacy-scopes-'))
const config = normalizeConfig({}, path.join(DIR, 'plugin'))
const finding = (identity, extra = {}) => ({
  identity,
  ruleId: 'openai-key',
  label: 'OpenAI API Key',
  masked: 'sk-a…34',
  file: 'src/config.ts',
  ...extra,
})

test('project whitelist path is relative to the repository root', () => {
  assert.equal(projectWhitelistPath(DIR, config), path.join(DIR, '.dsh/privacy-guard-whitelist.json'))
  const absolute = path.join(DIR, 'custom.json')
  assert.equal(projectWhitelistPath(DIR, { ...config, projectWhitelistFile: absolute }), absolute)
})

test('project allow entries combine with the global whitelist', () => {
  const whitelistFile = path.join(DIR, 'global.json')
  fs.writeFileSync(whitelistFile, JSON.stringify({ version: 1, entries: [entryForFinding(finding('aaaaaaaaaaaaaaaa'))] }))
  const root = path.join(DIR, 'repo-allow')
  fs.mkdirSync(root, { recursive: true })
  addProjectApproved(root, config, [finding('bbbbbbbbbbbbbbbb')])

  const result = effectiveApprovedIds({
    config,
    root,
    sessionId: 'session-allow',
    globalDocument: loadWhitelist(whitelistFile),
  })
  assert.equal(result.ids.has('aaaaaaaaaaaaaaaa'), true)
  assert.equal(result.ids.has('bbbbbbbbbbbbbbbb'), true)
  assert.equal(result.projectAllow, 1)
})

test('project deny overrides global and session allows', () => {
  const whitelistFile = path.join(DIR, 'global-deny.json')
  fs.writeFileSync(whitelistFile, JSON.stringify({ version: 1, entries: [entryForFinding(finding('cccccccccccccccc'))] }))
  const root = path.join(DIR, 'repo-deny')
  fs.mkdirSync(path.join(root, '.dsh'), { recursive: true })
  fs.writeFileSync(
    path.join(root, '.dsh/privacy-guard-whitelist.json'),
    JSON.stringify({
      version: 1,
      entries: [{ ...entryForFinding(finding('cccccccccccccccc')), allowed: false }],
    }),
  )
  addSessionEntries('session-deny', [finding('cccccccccccccccc')])
  const result = effectiveApprovedIds({
    config,
    root,
    sessionId: 'session-deny',
    globalDocument: loadWhitelist(whitelistFile),
  })
  assert.equal(result.ids.has('cccccccccccccccc'), false)
  assert.equal(result.projectDeny, 1)
})

test('session and pending entries are scoped per session', () => {
  const sessionId = 's1'
  addSessionEntries(sessionId, [finding('dddddddddddddddd'), finding('eeeeeeeeeeeeeeee')])
  assert.deepEqual([...sessionIds(sessionId)].sort(), ['dddddddddddddddd', 'eeeeeeeeeeeeeeee'])
  assert.equal(sessionEntries(sessionId).length, 2)
  assert.equal(sessionIds('other').size, 0)

  rememberPending(sessionId, [finding('ffffffffffffffff')])
  assert.equal(pendingFor(sessionId).length, 1)
  assert.equal(pendingMatch(sessionId, 'last').findings[0].identity, 'ffffffffffffffff')
  assert.equal(pendingMatch(sessionId, 'ffff').findings[0].identity, 'ffffffffffffffff')
  assert.equal(pendingMatch(sessionId, 'nope').error, 'no-match')

  const removed = removeSessionByPrefix(sessionId, 'dddd')
  assert.equal(removed.removed[0].id, 'dddddddddddddddd')
  assert.equal(clearSession(sessionId).removed, 1)
  assert.equal(sessionIds(sessionId).size, 0)
})

test('loadProjectWhitelist separates allow and deny entries', () => {
  const root = path.join(DIR, 'repo-split')
  fs.mkdirSync(path.join(root, '.dsh'), { recursive: true })
  fs.writeFileSync(
    path.join(root, '.dsh/privacy-guard-whitelist.json'),
    JSON.stringify({
      version: 1,
      entries: [
        { ...entryForFinding(finding('1111111111111111')), allowed: true },
        { ...entryForFinding(finding('2222222222222222')), allowed: false },
      ],
    }),
  )
  const project = loadProjectWhitelist(root, config)
  assert.equal(project.allowed.length, 1)
  assert.equal(project.denied.length, 1)
})