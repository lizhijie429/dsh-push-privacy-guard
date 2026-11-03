import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { detectOperations } from '../lib/detect.mjs'

const SESSION_CWD = 'D:/work'
const detect = (command, args = {}) =>
  detectOperations({ tool: 'pwsh', args: { command, ...args }, sessionCwd: SESSION_CWD })
const kinds = command => detect(command).map(op => op.kind)

test('detects a plain git push', () => {
  const [op] = detect('git push')
  assert.equal(op.kind, 'push')
  assert.equal(op.cwd, path.resolve(SESSION_CWD))
  assert.deepEqual(op.positional, [])
  assert.deepEqual(op.flags, { delete: false, all: false, mirror: false, force: false, tags: false })
})

test('detects push inside compound commands and keeps only one operation', () => {
  const ops = detect('git add . && git push origin main')
  assert.equal(ops.length, 1)
  assert.equal(ops[0].kind, 'push')
  assert.deepEqual(ops[0].positional, ['origin', 'main'])
})

test('resolves the repository directory from git -C and quoted paths', () => {
  assert.equal(detect('git -C backups push')[0].cwd, path.resolve(SESSION_CWD, 'backups'))
  assert.equal(detect('git -C "my repo" push')[0].cwd, path.resolve(SESSION_CWD, 'my repo'))
  assert.equal(detect('git -C D:/other/repo push')[0].cwd, path.resolve('D:/other/repo'))
})

test('resolves the working directory from workdir and command-level cd', () => {
  assert.equal(detect('git push', { workdir: 'repo' })[0].cwd, path.resolve(SESSION_CWD, 'repo'))
  assert.equal(detect('cd sub; git push')[0].cwd, path.resolve(SESSION_CWD, 'sub'))
  assert.equal(detect('Set-Location sub; git push')[0].cwd, path.resolve(SESSION_CWD, 'sub'))
})

test('parses push flags and refspecs verbatim for later resolution', () => {
  const force = detect('git push --force origin +dev:dev')[0]
  assert.equal(force.flags.force, true)
  assert.deepEqual(force.positional, ['origin', '+dev:dev'])
  assert.equal(detect('git push --delete origin old')[0].flags.delete, true)
  assert.equal(detect('git push --all')[0].flags.all, true)
  assert.equal(detect('git push --mirror')[0].flags.mirror, true)
  assert.equal(detect('git push --tags origin')[0].flags.tags, true)
})

test('detects commit and its message sources', () => {
  const plain = detect('git commit -m "feat: add feature"')[0]
  assert.equal(plain.kind, 'commit')
  assert.deepEqual(plain.messages, ['feat: add feature'])
  assert.equal(plain.flags.all, false)

  const all = detect('git commit -am "msg"')[0]
  assert.equal(all.flags.all, true)
  assert.deepEqual(all.messages, ['msg'])

  const explicit = detect('git commit --all --message=hello')[0]
  assert.equal(explicit.flags.all, true)
  assert.deepEqual(explicit.messages, ['hello'])

  const fromFile = detect('git commit -F msg.txt')[0]
  assert.equal(fromFile.messageFile, 'msg.txt')

  const amend = detect('git commit --amend --no-edit')[0]
  assert.equal(amend.flags.amend, true)
  assert.deepEqual(amend.messages, [])

  const editor = detect('git commit')[0]
  assert.equal(editor.flags.all, false)
  assert.deepEqual(editor.messages, [])
})

test('detects gh repo sync but not unrelated gh subcommands', () => {
  assert.deepEqual(kinds('gh repo sync'), ['sync'])
  assert.deepEqual(kinds('gh pr create --fill'), [])
  assert.deepEqual(kinds('gh repo view'), [])
})

test('does not treat lookalike text as a git operation', () => {
  assert.deepEqual(kinds('git status'), [])
  assert.deepEqual(kinds('git log --grep=push'), [])
  assert.deepEqual(kinds('git push --help'), [])
  assert.deepEqual(kinds('echo "git push"'), [])
  assert.deepEqual(kinds('git --version'), [])
})

test('recurses into shell -c / -Command wrappers', () => {
  assert.deepEqual(kinds('bash -c "git push origin main"'), ['push'])
  assert.deepEqual(kinds('pwsh -Command "git commit -m test"'), ['commit'])
})

test('detects multiple operations in one command line', () => {
  assert.deepEqual(kinds('git commit -m "x" && git push origin main'), ['commit', 'push'])
})

test('accepts git.exe / gh.exe spellings and non-pwsh shell tools', () => {
  assert.deepEqual(kinds('git.exe push'), ['push'])
  const bashOps = detectOperations({
    tool: 'bash',
    args: { command: 'git push origin main' },
    sessionCwd: SESSION_CWD,
  })
  assert.equal(bashOps[0].kind, 'push')
})

test('ignores non-shell tools and empty commands', () => {
  assert.deepEqual(detectOperations({ tool: 'write', args: { file_path: 'a' }, sessionCwd: SESSION_CWD }), [])
  assert.deepEqual(detect(''), [])
  assert.deepEqual(detect('   '), [])
})

test('terminal_send text is inspected as a command line', () => {
  const ops = detectOperations({
    tool: 'terminal_send',
    args: { text: 'git push origin dev' },
    sessionCwd: SESSION_CWD,
  })
  assert.equal(ops[0].kind, 'push')
})
