import { test } from 'node:test'
import assert from 'node:assert/strict'
import os from 'node:os'
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
  assert.deepEqual(op.flags, { delete: false, all: false, mirror: false, force: false, tags: false, dryRun: false })
})

test('detects dry-run pushes', () => {
  assert.equal(detect('git push --dry-run origin main')[0].flags.dryRun, true)
  assert.equal(detect('git push -n origin main')[0].flags.dryRun, true)
})

test('detects push inside compound commands and keeps only one operation', () => {
  const ops = detect('git add . && git push origin main')
  assert.equal(ops.length, 1)
  assert.equal(ops[0].kind, 'push')
  assert.deepEqual(ops[0].positional, ['origin', 'main'])
})

test('resolves the repository directory from git -C and quoted paths', () => {
  const absoluteRepo = process.platform === 'win32' ? 'D:/other/repo' : '/other/repo'
  assert.equal(detect('git -C backups push')[0].cwd, path.resolve(SESSION_CWD, 'backups'))
  assert.equal(detect('git -C "my repo" push')[0].cwd, path.resolve(SESSION_CWD, 'my repo'))
  assert.equal(detect(`git -C ${absoluteRepo} push`)[0].cwd, path.resolve(absoluteRepo))
  if (process.platform === 'win32') {
    const windowsPath = 'C:\\Users\\tester path\\.dsh\\plugins\\guard'
    assert.equal(detect(`git -C "${windowsPath}" push`)[0].cwd, path.win32.normalize(windowsPath))
  }
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

test('marks commits that follow an index mutation in the same command', () => {
  const all = detect('git add .; git commit -m "x"')[0]
  assert.equal(all.mutation.indexMutated, true)
  assert.equal(all.mutation.mayAddUntracked, true)
  assert.equal(all.mutation.addScopeAll, true)

  const scoped = detect('git add src/a.ts; git commit -m x')[0]
  assert.equal(scoped.mutation.indexMutated, true)
  assert.equal(scoped.mutation.addScopeAll, false)
  assert.deepEqual(scoped.mutation.addPaths, ['src/a.ts'])

  const update = detect('git add -u; git commit -m x')[0]
  assert.equal(update.mutation.indexMutated, true)
  assert.equal(update.mutation.mayAddUntracked, false)

  assert.equal(detect('git status; git commit -m x')[0].mutation, undefined)
  assert.equal(detect('git commit -m x; git add .')[0].mutation, undefined)

  const otherRepo = detect('git -C repo add .; git -C repo commit -m x')[0]
  assert.equal(otherRepo.mutation.indexMutated, true)
})

test('parses commit pathspecs and -i/--include paths', () => {
  const pathspec = detect('git commit a.ts b.ts -m x')[0]
  assert.deepEqual(pathspec.pathspecs, ['a.ts', 'b.ts'])
  assert.deepEqual(pathspec.includes, [])

  const afterDash = detect('git commit -- a.ts')[0]
  assert.deepEqual(afterDash.pathspecs, ['a.ts'])

  const includeShort = detect('git commit -i a.ts -m x')[0]
  assert.deepEqual(includeShort.pathspecs, ['a.ts'])
  assert.equal(includeShort.flags.worktreePaths, true)
  assert.deepEqual(includeShort.messages, ['x'])

  const includeLong = detect('git commit --include a.ts --message x')[0]
  assert.deepEqual(includeLong.pathspecs, ['a.ts'])
  assert.equal(includeLong.flags.worktreePaths, true)
  assert.deepEqual(includeLong.messages, ['x'])
})

test('option values are never mistaken for pathspecs', () => {
  const reuse = detect('git commit -C HEAD')[0]
  assert.deepEqual(reuse.pathspecs, [])
  assert.equal(reuse.flags.reuseMessage, true)

  const reedit = detect('git commit -c HEAD')[0]
  assert.deepEqual(reedit.pathspecs, [])
  assert.equal(reedit.flags.reuseMessage, true)

  const fixup = detect('git commit --fixup HEAD')[0]
  assert.deepEqual(fixup.pathspecs, [])
  assert.equal(fixup.flags.fixup, true)

  const trailer = detect(
    'git commit -m "msg" --trailer "Co-authored-by: 13812345678 <ops@' + 'corp.local>"',
  )[0]
  assert.deepEqual(trailer.pathspecs, [])
  assert.ok(trailer.messages.some(message => message.includes('13812345678')))

  const fromFile = detect('git commit -m msg --pathspec-from-file paths.txt')[0]
  assert.deepEqual(fromFile.pathspecs, [])
  assert.equal(fromFile.pathspecFromFile, 'paths.txt')
  assert.equal(fromFile.flags.worktreePaths, true)

  const attachedMessage = detect('git commit -m"fix the bug"')[0]
  assert.deepEqual(attachedMessage.messages, ['fix the bug'])

  const only = detect('git commit --only -m "msg" file.ts')[0]
  assert.deepEqual(only.messages, ['msg'])
  assert.deepEqual(only.pathspecs, ['file.ts'])

  const booleanLong = detect('git commit --no-gpg-sign --quiet file.ts')[0]
  assert.deepEqual(booleanLong.pathspecs, ['file.ts'])
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

test('marks operations whose repository directory depends on shell expansion', () => {
  const variable = detect('$repo="x"; cd $repo; git commit -m x')[0]
  assert.equal(variable.cwdUnresolved, true)

  const literal = detect('cd sub; git commit -m x')[0]
  assert.equal(literal.cwdUnresolved, false)

  const gitC = detect('git -C $repo push')[0]
  assert.equal(gitC.cwdUnresolved, true)

  const workdir = detectOperations({
    tool: 'pwsh',
    args: { command: 'git push', workdir: '$DIR' },
    sessionCwd: SESSION_CWD,
  })[0]
  assert.equal(workdir.cwdUnresolved, true)

  const absolute = process.platform === 'win32' ? 'D:/abs' : '/abs'
  const afterAbsolute = detect(`cd $repo; cd ${absolute}; git commit -m x`)[0]
  assert.equal(afterAbsolute.cwdUnresolved, false)
})

test('marks GIT_DIR/environment overrides and expands a literal ~', () => {
  assert.equal(detect('GIT_DIR=D:/other/.git git push')[0].cwdUnresolved, true)
  assert.equal(detect('GIT_WORK_TREE=D:/other git commit -m x')[0].cwdUnresolved, true)
  assert.equal(detect('git --git-dir=D:/other/.git push')[0].cwdUnresolved, true)
  assert.equal(detect('git --work-tree D:/other push')[0].cwdUnresolved, true)

  const expanded = detect('cd ~/repo; git push')[0]
  assert.equal(expanded.cwd, path.resolve(path.join(os.homedir(), 'repo')))
})
