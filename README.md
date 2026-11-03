# dsh-push-privacy-guard

DSH（DeepSeek Harness）Host 插件：在 Agent 执行 `git commit`、`git push`（以及 `gh repo sync`）**之前**检查将要进入 git 的内容，发现本地绝对路径、用户信息、API Key、私钥、连接串等敏感信息时，通过 DSH 原生审批面板请求用户一次性授权；拒绝则阻止命令，批准则放行并把本次授权的信息写入**可管理的白名单**，之后同样的信息不再重复询问。

> 定位：**内容泄露护栏**，不是安全边界。它只覆盖 DSH 工具层（`pwsh` / `bash` / `terminal_send` 及 PTC 内部 bash 调用），不覆盖人工终端推送、脚本内部自行发起的推送，也不能发现规则库之外的泄露形式。

## 能力

- **提交前检查**：扫描 `git commit` 的暂存区新增内容（`git commit -a` 时按 `git diff HEAD` 覆盖全部已跟踪改动）与 `-m` / `-F` 提交信息。
- **推送前检查**：只读计算本次 `git push` 真正要上传的提交范围（支持 `git -C`、remote/refspec、`--force`、`--all`、`--mirror`、`--delete`、`gh repo sync`），扫描新增行 + 待推送提交信息。
- **dry-run 放行**：`git push --dry-run` / `git push -n` 不上传任何内容，直接放行、不打扰。
- **首次仓库全仓扫描**：某个仓库第一次通过 DSH 推送时询问一次「是否先全仓库扫描」；全仓扫描只覆盖 `HEAD` 里 **git 已跟踪的文件**，`.gitignore` 忽略的内容天然不参与。之后该仓库只检查本次提交/推送内容。
- **用户授权**：命中未白名单项时调用 `ctx.approval.request()`，在 Web UI 审批面板展示脱敏后的命中清单；批准 = 本次放行 + 入白名单，拒绝/取消 = 阻止命令。
- **白名单管理**：`/privacy-guard` 斜杠命令（用户专属，不产生模型消息），底层 `state/whitelist.json` 可手改、即时生效。
- **失败关闭**：一旦识别为 commit/push，扫描失败/超时/无法获得授权都会**阻止**命令，而不是放行。
- 零运行时依赖（仅 `node:*` 内置模块），可按绝对路径挂载，也可作为 bundle 安装。

## 工作原理

```text
工具调用（pwsh / bash / terminal_send / PTC 内部 bash）
  └─ tools/pre-execute（本插件，异步，prepend）
       ├─ lib/detect.mjs   解析命令：git commit / git push / gh repo sync；workdir、cd、git -C
       ├─ lib/scan.mjs     只读 git：暂存区 / 推送范围 / 全仓 tracked 文件 / 提交信息
       ├─ lib/rules.mjs    规则匹配、占位符过滤、掩码、稳定指纹
       ├─ lib/whitelist.mjs 白名单（只存掩码，不存明文）
       ├─ lib/repo-state.mjs 每仓库是否已问过全仓扫描
       └─ ctx.approval.request() → 用户允许 / 拒绝
  └─ 放行 → 工具执行；拒绝 → 返回 {kind:'deny', reason}

/privacy-guard …（ctx.inject(['commands']) 可选注册，仅用户可见）
```

所有 git 调用都是只读子命令（`rev-parse` / `rev-list` / `diff` / `log` / `ls-tree` / `cat-file` / `remote`），**不会修改仓库、index 或远端**。

## 内置规则（V1）

| 规则 | 说明 | 级别 |
| --- | --- | --- |
| `private-key-block` | `-----BEGIN … PRIVATE KEY-----` | 高 |
| `aws-access-key` | `AKIA` + 16 位 | 高 |
| `github-token` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` | 高 |
| `openai-key` | `sk-` / `sk-proj-` 长串 | 高 |
| `slack-token` | `xox[baprs]-…` | 高 |
| `google-api-key` | `AIza` + 35 位 | 高 |
| `jwt` | 三段 JWT | 高 |
| `bearer-token` | `Bearer <token>` | 高 |
| `assigned-secret` | `password/secret/token/api_key/... = 值` | 高 |
| `connection-string` | mongodb/mysql/postgres/redis/amqp/jdbc URI | 高 |
| `local-abs-path-win` | Windows 绝对路径（`C:\Users\…`） | 中 |
| `local-home-path-posix` | `/Users/…`、`/home/…` | 中 |
| `email` | 邮箱（过滤 example / noreply / `git@github.com` 等占位） | 中 |
| `cn-mobile` | 中国大陆手机号 | 中 |
| `cn-id-card` | 18 位身份证（校验位通过才报） | 高 |
| `internal-url` | 内网 IP / `.local`、`.internal`、`.corp` 地址 | 中 |

过滤：`${…}`、`{{…}}`、`<…>`、`your_*`、`changeme`、`process.env.*`、`os.environ[...]`、示例域名等占位值不报；`ignorePaths` 默认忽略锁文件、`*.min.js`、`*.map`、`node_modules`、`dist`、`build` 等。

## 白名单

`state/whitelist.json`：

```json
{
  "version": 1,
  "entries": [
    {
      "id": "a1b2c3d4e5f60718",
      "rule": "openai-key",
      "label": "OpenAI API Key",
      "masked": "sk-a…34",
      "firstFile": "src/config.ts",
      "addedAt": "2026-11-03T02:00:00.000Z",
      "source": "approval"
    }
  ]
}
```

- 身份 = `sha256(规则 id + 命中值)` 截断 16 位：同一个敏感值跨文件、跨仓库只需授权一次。
- **只存掩码**，不落明文；手改后下一次检查立即生效；文件损坏时按空白名单处理并写日志。
- 仓库初始化状态在 `state/repos.json`。

## `/privacy-guard` 命令

| 命令 | 行为 |
| --- | --- |
| `/privacy-guard list` | 列出白名单条目（id / 规则 / 掩码 / 首次文件 / 时间） |
| `/privacy-guard remove <id前缀>` | 删除单条（前缀需唯一） |
| `/privacy-guard clear confirm` | 清空白名单（必须带 `confirm`） |
| `/privacy-guard status` | 开关、文件路径、规则数、白名单数、已初始化仓库数、当前仓库状态 |
| `/privacy-guard repos` | 列出已初始化仓库 |
| `/privacy-guard reset <路径子串\|all>` | 清除仓库初始化记录，下次推送重新询问全仓扫描 |
| `/privacy-guard scan` | 立即扫描当前会话仓库（全仓 tracked + 暂存区）并报告，不推送、不写白名单 |
| `/privacy-guard help` | 帮助 |

命令在 Web UI 的命令面板执行，**不会变成模型消息**，模型无法借此修改白名单或自我授权。

## 配置（profile `cordis.patch.yml` 的 `config:`）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `interceptCommit` | `true` | 检查 `git commit` |
| `interceptPush` | `true` | 检查 `git push` / `gh repo sync` |
| `fullScanOnFirstPush` | `ask` | `ask` / `always` / `never` |
| `whitelistOnApprove` | `true` | 授权后自动写白名单 |
| `requireApprovalOnIncompleteScan` | `true` | 扫描不完整（超时/超限）时是否要求授权 |
| `disableRules` | `[]` | 关闭的内置规则 id |
| `extraRules` | `[]` | 自定义规则 `{id,label,pattern,flags,severity,mask,capture}` |
| `ignorePaths` | 锁文件/构建产物 | 追加到默认忽略 glob |
| `whitelistFile` | `state/whitelist.json` | 相对插件目录或绝对路径 |
| `repoStateFile` | `state/repos.json` | 同上 |
| `logFile` | `state/push-privacy-guard.log` | 同上；挂载时 >5MB 轮转一次 |
| `maxTotalBytes` | 20 MiB | 单次差异/扫描总字节上限 |
| `maxFileBytes` | 1 MiB | 全仓单文件上限（超限跳过并记日志） |
| `maxFiles` | 5000 | 全仓文件数上限 |
| `maxCommits` | 100 | 多分支/镜像逐提交扫描与提交信息上限 |
| `maxFindings` | 200 | 单次扫描命中上限 |
| `maxApprovalItems` | 20 | 审批文案最多列举条数 |
| `gitTimeoutMs` | 20000 | 单条 git 命令超时 |

非法值回退默认并写 `config.warning` 日志，不会静默失效。

## 安装

### 桌面端（desktop profile）

在 `%USERPROFILE%\.dsh\profiles\desktop\cordis.patch.yml` 末尾追加（把 `<用户>` 换成实际 Windows 用户名）：

```yaml
- insert:
    - id: push-privacy-guard
      name: 'C:\Users\<用户>\.dsh\plugins\dsh-push-privacy-guard\index.mjs'
      config:
        fullScanOnFirstPush: ask
        whitelistOnApprove: true
```

desktop profile 的 `patchReload` 为 `live`，保存后热加载；`state/push-privacy-guard.log` 出现 `plugin.mounted` 即生效。代码改动后需重启 DeepSeek Harness（Node ESM 模块缓存）。

### 其他 profile（bundle 方式）

```powershell
dsh plugin --profile web add "file:$env:USERPROFILE\.dsh\plugins\dsh-push-privacy-guard"
```

`package.json` 的 `dsh.bundle.patch` 会加载 `cordis.patch.yml` 默认配置。

## 验证

```powershell
cd "$env:USERPROFILE\.dsh\plugins\dsh-push-privacy-guard"
npm test
Get-Content state\push-privacy-guard.log -Tail 20
```

CI：`.github/workflows/test.yml` 在 `ubuntu-latest` / `windows-latest`（Node 22）上执行 `npm test`（含真实 git 集成用例）。

端到端（需要会话审批策略为 `ask`，即有审批面板可点）：

1. 在临时仓库 `git add` 一个包含 `sk-<长串>` 的文件，执行 `git commit` → UI 弹审批；批准 → 提交成功且 `state/whitelist.json` 增加条目；再次提交同类内容不再询问。
2. 换一个新的假密钥 → 拒绝 → 命令被阻止。
3. 首次 `git push` → 弹「是否全仓扫描」；拒绝后只检查本次推送，`state/repos.json` 记录该仓库。

> 若会话审批策略为 `never`（关闭审批），本插件一律**拒绝**命中项——这是 fail-closed 设计，不是故障。需要弹窗授权时把策略切回 `ask`。

## 已知限制

- **不覆盖 DSH 之外的操作**：人工终端推送、脚本内部自行执行 `git push`、其他机器上的推送都不经过本插件。
- **只检查将要进入 git 的内容**：未暂存/未跟踪文件不会被提交或推送，因此不检查；`git push` 只按本地 git 数据估算上传范围（不联网）。
- **仅识别命令文本**：`bash -c` / `pwsh -Command` 会递归解析一层；变量拼接、别名、`node deploy.mjs` 之类间接执行无法识别。
- **`terminal_send` 的真实 cwd 不可知**：按会话 cwd + 命令内 `cd` 推断，可能与持久终端实际目录不一致。
- **force push / mirror**：只对比远端跟踪 ref 与本地分支；tag 对象、被强制覆盖的历史不单独扫描。
- **首次全仓扫描只看 `HEAD` 的已跟踪文件**：历史提交中被删除的敏感信息不会被重新发现；大文件（> `maxFileBytes`）跳过，扫描因此可能不完整（默认要求授权）。
- **规则库不是万能**：高熵字符串、自定义内部格式、二进制内容可能漏报；规则可配置但与任何正则方案一样存在误报/漏报。
- **多进程并发写白名单**只在单进程内串行；同时运行多个 DSH 进程时可能相互覆盖。
- **不清理仓库**：插件只负责阻止/放行，不会自动删除已提交的敏感信息或改写历史。

## License

MIT，见 [LICENSE](LICENSE)。
