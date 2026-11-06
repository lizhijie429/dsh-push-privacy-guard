/**
 * Cordis `Config` schema for the plugin.
 *
 * The DSH loader validates profile `config:` against this schema before
 * `apply()` runs, and the settings subsystem derives its form from the schema
 * metadata. Fields marked `.volatile()` become live references: the loader
 * commits a change without remounting the plugin and emits
 * `loader/volatile-update`, which the plugin handles by re-normalizing config.
 *
 * Schemastery is vendored under `vendor/schemastery` because an externally
 * mounted plugin cannot resolve the host's `@deepseek-ai/*` packages.
 *
 * @module dsh-push-privacy-guard/schema
 */

import Schema from '../vendor/schemastery/index.mjs'

const positiveInt = (fallback, description) =>
  Schema.natural().min(1).default(fallback).description(description)

/** Config schema shown by the DSH settings form and enforced by the loader. */
export const Config = Schema.object({
  enabled: Schema.boolean().default(true).description('总开关 / master switch').volatile(),
  interceptCommit: Schema.boolean()
    .default(true)
    .description('检查 git commit / check git commit')
    .volatile(),
  interceptPush: Schema.boolean()
    .default(true)
    .description('检查 git push 与 gh repo sync / check git push and gh repo sync')
    .volatile(),
  fullScanOnFirstPush: Schema.union(['ask', 'always', 'never'])
    .default('ask')
    .description('首次推送是否先做全仓扫描 / first-push full scan mode')
    .volatile(),
  unresolvedRepo: Schema.union(['deny', 'allow'])
    .default('deny')
    .description('仓库无法定位时的策略 / policy when the repository cannot be located')
    .volatile(),
  persistentShellCommits: Schema.union(['deny', 'allow'])
    .default('deny')
    .description('持久终端内 commit/push 的策略 / policy for persistent-terminal commits')
    .volatile(),
  approvalScope: Schema.union(['global', 'project', 'session'])
    .default('global')
    .description('授权后记住的范围（项目级覆盖全局级）/ where approvals are remembered')
    .volatile(),
  projectWhitelistFile: Schema.string()
    .default('.dsh/privacy-guard-whitelist.json')
    .description('项目级白名单文件（相对仓库根目录）/ project whitelist file relative to the repo root')
    .volatile(),
  whitelistOnApprove: Schema.boolean()
    .default(true)
    .description('授权后自动写白名单 / add approved items to the whitelist')
    .volatile(),
  requireApprovalOnIncompleteScan: Schema.boolean()
    .default(true)
    .description('扫描不完整时要求授权 / require approval when the scan is incomplete')
    .volatile(),
  disableRules: Schema.array(Schema.string())
    .default([])
    .description('关闭的内置规则 id / disabled built-in rule ids'),
  extraRules: Schema.array(
    Schema.object({
      id: Schema.string().required().description('规则 id / rule id'),
      label: Schema.string().description('展示名称 / display label'),
      pattern: Schema.string().required().description('正则表达式 / regular expression'),
      flags: Schema.string().default('').description('正则 flags'),
      severity: Schema.union(['high', 'medium']).default('high').description('级别 / severity'),
      mask: Schema.union(['secret', 'full', 'path', 'email', 'phone', 'id'])
        .default('secret')
        .description('掩码方式 / masking strategy'),
      capture: Schema.natural().min(0).default(0).description('捕获组序号 / capture group'),
      precheck: Schema.string().default('').description('廉价字面量预检 / cheap literal precheck'),
    }),
  )
    .default([])
    .description('自定义规则 / custom rules'),
  ignorePaths: Schema.array(Schema.string())
    .default([])
    .description('追加忽略的 glob / additional ignored globs'),
  whitelistFile: Schema.string().default('').description('白名单文件路径 / whitelist file path').volatile(),
  repoStateFile: Schema.string().default('').description('仓库状态文件路径 / repo-state file path').volatile(),
  logFile: Schema.string().default('').description('日志文件路径 / log file path').volatile(),
  maxTotalBytes: positiveInt(20 * 1024 * 1024, '单次扫描总字节上限 / total byte cap').volatile(),
  maxFileBytes: positiveInt(1024 * 1024, '单文件字节上限 / per-file byte cap').volatile(),
  maxFiles: positiveInt(5000, '文件数上限 / file count cap').volatile(),
  maxCommits: positiveInt(100, '提交/ref 数上限 / commit and ref cap').volatile(),
  maxFindings: positiveInt(200, '命条数上限 / finding cap').volatile(),
  maxApprovalItems: positiveInt(20, '审批列表最多展示条数 / approval list size').volatile(),
  gitTimeoutMs: positiveInt(20000, '单条 git 命令超时 / git timeout in ms').volatile(),
})

export default Config
