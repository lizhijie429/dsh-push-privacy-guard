import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_RULES,
  compileRules,
  identityOf,
  isPlaceholder,
  maskValue,
  matchLine,
} from '../lib/rules.mjs'

const rules = compileRules({ disableRules: [], extraRules: [] })
const ids = line => matchLine(rules, line).map(finding => finding.ruleId)
const findRule = id => DEFAULT_RULES.find(rule => rule.id === id)

const openai = 'sk-' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4'.slice(0, 24)
const github = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'.slice(0, 36)
const aws = 'AKIA' + 'ABCDEFGHIJKLMNOP'.slice(0, 16)
const slack = 'xoxb-' + '1234567890-abcdefghijklmnop'
const google = 'AIza' + 'A'.repeat(35)
const jwt = 'eyJ' + 'hbGciOiJIUzI1NiJ9' + '.' + 'eyJzdWIiOiIxMjM0NTY3ODkwIn0' + '.' + 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
const bearer = 'Bearer ' + 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4'
const mysql = 'mysql://app:' + 'p4ssw0rd' + '@db.internal:3306/app'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----'

test('detects every default high-confidence rule', () => {
  assert.ok(ids(openai).includes('openai-key'))
  assert.ok(ids(github).includes('github-token'))
  assert.ok(ids(aws).includes('aws-access-key'))
  assert.ok(ids(slack).includes('slack-token'))
  assert.ok(ids(google).includes('google-api-key'))
  assert.ok(ids(jwt).includes('jwt'))
  assert.ok(ids(bearer).includes('bearer-token'))
  assert.ok(ids(mysql).includes('connection-string'))
  assert.ok(ids(privateKey).includes('private-key-block'))
  assert.ok(ids('const password = "correct horse battery"').includes('assigned-secret'))
})

test('detects local paths, emails and phone numbers', () => {
  assert.ok(ids('open C:\\Users\\zhangsan\\secret.txt').includes('local-abs-path-win'))
  assert.ok(ids('copy /home/zhangsan/.ssh/id_rsa .').includes('local-home-path-posix'))
  assert.ok(ids('mail zhangsan@example-corp.cn now').includes('email'))
  assert.ok(ids('phone 13812345678').includes('cn-mobile'))
  assert.ok(ids('cat ' + '~/' + '.ssh/id_rsa').includes('ssh-home-path'))
  assert.ok(ids('open ' + '\\\\\\\\' + 'fileserver\\share\\private\\x.txt').includes('local-abs-path-unc'))
})

test('detects additional token families and Chinese secret labels', () => {
  const fineGrained = 'github_pat_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6'.slice(0, 30)
  assert.ok(ids(fineGrained).includes('github-fine-grained-token'))
  const gitlab = 'glpat-' + 'a1B2c3D4e5F6g7H8i9J0'.slice(0, 20)
  assert.ok(ids(gitlab).includes('gitlab-token'))
  assert.ok(ids('ASIA' + 'ABCDEFGHIJKLMNOP').includes('aws-access-key'))
  assert.ok(ids('-----BEGIN PGP ' + 'PRIVATE KEY BLOCK-----').includes('private-key-block'))
  assert.ok(ids('密' + '码：Abc123456').includes('assigned-secret-zh'))
  const npm = 'npm_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'.slice(0, 36)
  assert.ok(ids(npm).includes('npm-token'))
})

test('does not flag placeholder secrets or documentation examples', () => {
  assert.deepEqual(ids('const token = "${GITHUB_TOKEN}"'), [])
  assert.deepEqual(ids('api_key = "your_api_key_here"'), [])
  assert.deepEqual(ids('password = "changeme"'), [])
  assert.deepEqual(ids('secret: {{ secrets.MY_SECRET }}'), [])
  assert.deepEqual(ids('token: process.env.API_TOKEN'), [])
  assert.deepEqual(ids('mail git@github.com'), [])
  assert.deepEqual(ids('host user@example.com'), [])
  assert.deepEqual(ids('password: null'), [])
})

test('invalid id-card numbers are ignored, valid ones are reported', () => {
  // 11010519491231002X is the canonical valid sample.
  assert.ok(ids('id 11010519491231002X').includes('cn-id-card'))
  assert.ok(!ids('id 110105194912310021').includes('cn-id-card'))
})

test('masked values never contain the complete secret', () => {
  const secretRule = findRule('openai-key')
  const masked = maskValue(secretRule, openai)
  assert.ok(masked.includes('…'))
  assert.ok(!masked.includes(openai))
  assert.ok(masked.startsWith('sk-a'))

  const emailRule = findRule('email')
  assert.equal(maskValue(emailRule, 'zhangsan@example-corp.cn'), 'z***@example-corp.cn')
  const phoneRule = findRule('cn-mobile')
  assert.equal(maskValue(phoneRule, '13812345678'), '138****5678')
  const pathRule = findRule('local-abs-path-win')
  const maskedPath = maskValue(pathRule, 'C:\\Users\\zhangsan\\secret.txt')
  assert.ok(!maskedPath.includes('zhangsan'))

  const projectPath = maskValue(pathRule, 'D:' + '\\WorkSpace\\secret-project\\config\\app.yml')
  assert.ok(!projectPath.includes('secret-project'))
  assert.ok(!projectPath.includes('WorkSpace'))
  assert.ok(projectPath.endsWith('app.yml'))
})

test('identity is stable, prefix-length bounded, and value-sensitive', () => {
  const a = identityOf('openai-key', openai)
  const b = identityOf('openai-key', openai)
  const c = identityOf('openai-key', openai.slice(0, -1) + 'x')
  assert.equal(a, b)
  assert.notEqual(a, c)
  assert.match(a, /^[0-9a-f]{16}$/)
  assert.notEqual(identityOf('github-token', openai), a)
})

test('compileRules honours disableRules and custom rules', () => {
  const custom = compileRules({
    disableRules: ['email'],
    extraRules: [{ id: 'tenant-id', label: 'Tenant id', pattern: 'TENANT_[A-Z0-9]{8}', severity: 'medium', mask: 'secret' }],
  })
  assert.ok(!custom.some(rule => rule.id === 'email'))
  assert.deepEqual(matchLine(custom, 'TENANT_ABCD1234').map(f => f.ruleId), ['tenant-id'])
  assert.deepEqual(matchLine(custom, 'zhangsan@example-corp.cn'), [])
})

test('matchLine reports the matched value and index once per rule', () => {
  const matches = matchLine(rules, `a ${openai} b ${openai}`)
  const openaiMatches = matches.filter(match => match.ruleId === 'openai-key')
  // Overlapping equal secrets on one line are collapsed by value.
  assert.equal(openaiMatches.length, 1)
  assert.equal(openaiMatches[0].value, openai)
  assert.equal(openaiMatches[0].index, 2)
})

test('isPlaceholder accepts template and env references', () => {
  assert.equal(isPlaceholder(findRule('assigned-secret'), '${TOKEN}'), true)
  assert.equal(isPlaceholder(findRule('assigned-secret'), 'actual-value-123'), false)
})

test('long lines cannot trigger catastrophic regex backtracking', () => {
  const started = process.hrtime.bigint()
  const assigned = matchLine(rules, 'password=' + 'x'.repeat(200000))
  const atHeavy = matchLine(rules, 'a@'.repeat(40000))
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6
  assert.ok(elapsedMs < 2000, `matchLine took ${elapsedMs.toFixed(0)}ms on long lines`)
  assert.equal(assigned.length, 0)
  assert.equal(atHeavy.length, 0)
})

test('email rule still matches realistic addresses after bounding', () => {
  assert.deepEqual(ids('mail zhangsan@example-corp.cn'), ['email'])
  assert.deepEqual(ids('mail git@github.com'), [])
})
