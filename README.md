# dsh-push-privacy-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DSH](https://img.shields.io/badge/DSH-%E2%89%A50.2.2--rc.1-6f42c1)](https://github.com/deepseek-ai/deepseek-harness)
[![Plugin Market](https://img.shields.io/badge/DSH%20Plugin%20Market-index-brightgreen)](market/index.json)

简体中文 | [English](README.en.md)

## 插件介绍

DSH（DeepSeek Harness）Host 插件：在 Agent 执行 `git commit`、`git push`（以及 `gh repo sync`）**之前**，检查即将进入 git 的内容；发现本地绝对路径、用户信息、API Key、私钥、连接串等敏感信息时，通过 DSH 原生审批请求用户一次性授权。拒绝则阻止命令，批准则放行并把本次授权写入**可管理的白名单**。

> 定位：**内容泄露护栏**，不是安全边界。它只覆盖 DSH 工具层（`pwsh` / `bash` 一次性命令、PTC 内部 bash 调用）；持久终端（`terminal_send`）的 commit/push 默认直接拒绝；不覆盖人工终端、脚本内部自行发起的推送，也不能发现规则库之外的泄露形式。

核心能力：

- **提交前检查**：扫描暂存区、`commit -a` / pathspec / `git add` 组合、未跟踪文件，以及 `-m` / `-F` / `--trailer` 提交信息。
- **推送前检查**：只读计算真正上传范围（`git -C`、多/通配 refspec、`--force`、`--all`、`--mirror`、`--delete`、`gh repo sync`），逐个提交扫描，并检查待推送提交信息与 tag 消息。
- **首次全仓扫描**：仓库第一次通过 DSH 推送时询问是否先扫描整个 `HEAD` 的已跟踪文件（`.gitignore` 天然排除）。
- **三级白名单**：全局 `state/whitelist.json`、仓库内项目白名单 `.dsh/privacy-guard-whitelist.json`（项目级优先，可用 `allowed:false` 撤销）、仅当前会话的内存白名单。白名单只存掩码与 identity 哈希，不存明文。
- **四种管理通道**：DSH 审批面板、`/privacy-guard` 斜杠命令、对话内 `privacy_guard` 工具、Web/桌面客户端图形化设置页。
- **失败关闭**：识别为 commit/push 后，扫描失败、超时、git 查询失败或无法获得授权都会阻止命令；无法定位仓库默认拒绝。
- **原生 DSH 配置**：导出 Cordis `Config`（Schemastery），开关/模式/上限/路径为 `.volatile()`，在设置页修改后热生效；零运行时依赖（仅 `node:*`，Schemastery 按 MIT 内嵌在 `vendor/`）。

工作原理：

```text
工具调用（pwsh / bash / terminal_send / PTC 内部 bash）
  └─ tools/pre-execute（本插件，异步，prepend）
       ├─ lib/detect.mjs     解析命令：git commit / git push / gh repo sync；workdir、cd、git -C
       ├─ lib/scan.mjs       只读 git：暂存区 / 推送范围 / 全仓 tracked 文件 / 提交信息
       ├─ lib/rules.mjs      规则匹配、占位符过滤、掩码、稳定 identity
       ├─ lib/scopes.mjs     全局 / 项目 / 会话白名单与项目路径安全校验
       ├─ lib/whitelist.mjs  全局白名单（只存掩码）
       └─ ctx.approval.request() → 用户允许 / 拒绝
  └─ 放行 → 工具执行；拒绝 → 返回 {kind:'deny', reason}
```

所有 git 调用均为只读子命令（`rev-parse` / `rev-list` / `diff` / `log` / `for-each-ref` / `ls-tree` / `cat-file` / `remote`），不修改仓库、index 或远端；全仓扫描通过一次 `git cat-file --batch` 流式读取。

内置规则（V1）：

| 规则 | 说明 | 级别 |
| --- | --- | --- |
| `private-key-block` | `-----BEGIN … PRIVATE KEY-----` / PGP 私钥块 | 高 |
| `aws-access-key` | `AKIA` / `ASIA` + 16 位 | 高 |
| `github-token` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` | 高 |
| `github-fine-grained-token` | `github_pat_…` | 高 |
| `gitlab-token` | `glpat-` / `gldt-` / `glrt-` | 高 |
| `npm-token` | `npm_…` | 高 |
| `openai-key` | `sk-` / `sk-proj-` 长串 | 高 |
| `slack-token` | `xox[baprs]-…` | 高 |
| `google-api-key` | `AIza` + 35 位 | 高 |
| `jwt` | 三段 JWT | 高 |
| `bearer-token` | `Bearer <token>` | 高 |
| `assigned-secret` | `password/secret/token/api_key/... = 值` | 高 |
| `assigned-secret-zh` | 中文 `密码/密钥/令牌/凭证` 标签 | 高 |
| `connection-string` | mongodb/mysql/postgres/redis/amqp/jdbc URI | 高 |
| `local-abs-path-win` | Windows 绝对路径（`C:\Users\…`） | 中 |
| `local-abs-path-unc` | UNC 共享路径（双反斜杠开头） | 中 |
| `local-home-path-posix` | `/Users/…`、`/home/…` | 中 |
| `ssh-home-path` | `~/.ssh/<文件>`、`$HOME/.ssh/<文件>`、`%USERPROFILE%\.ssh\<文件>` | 中 |
| `email` | 邮箱（过滤 example / noreply / `git@github.com` 等占位） | 中 |
| `cn-mobile` | 中国大陆手机号 | 中 |
| `cn-id-card` | 18 位身份证（校验位通过才报） | 高 |
| `internal-url` | 内网 IP / `.local`、`.internal`、`.corp` 地址 | 中 |

占位符（`${…}`、`{{…}}`、`<…>`、`your_*`、`changeme`、`process.env.*`、示例域名等）不报告；`ignorePaths` 默认忽略 lock 文件、`*.min.js`、`*.map`、`node_modules`、`dist`、`build` 等。

## 安装方式

### 插件市场（推荐）

DSH **插件 → 实验性插件 → 更多 → 启用「自定义插件市场」**，然后在 **插件 → 发现 → 索引源** 添加：

```text
https://raw.githubusercontent.com/lizhijie429/dsh-push-privacy-guard/main/market/index.json
```

搜索 “Push Privacy Guard” 安装。索引使用 DSH 市场格式 1，并已通过 `@deepseek-ai/dsh-plugin-market-index` 校验。

### Git 源

```powershell
dsh plugin --profile desktop add https://github.com/lizhijie429/dsh-push-privacy-guard
```

`web` 等其他 profile 同理替换 `--profile`。安装后重启 DSH 使 Host 代码和客户端 bundle 生效。

### 绝对路径（本地开发/离线）

在 profile 的 `cordis.patch.yml` 追加（替换 `<user>`）：

```yaml
- insert:
    - id: push-privacy-guard
      name: 'C:\Users\<user>\.dsh\plugins\dsh-push-privacy-guard\index.mjs'
      config:
        fullScanOnFirstPush: ask
        whitelistOnApprove: true
```

桌面客户端的 profile 为 `desktop`，patch 文件在 `%USERPROFILE%\.dsh\profiles\desktop\cordis.patch.yml`；`patchReload: live` 会在保存后热加载配置，但代码变更仍需重启 DSH。

### 验证安装

```powershell
cd "$env:USERPROFILE\.dsh\plugins\dsh-push-privacy-guard"
npm test
Get-Content state\push-privacy-guard.log -Tail 20
```

日志出现 `plugin.mounted`、`settings-web.registered` 说明 Host 已加载；图形化设置页需在重启后从「设置 → 隐私检查」进入。CI 在 `ubuntu-latest` / `windows-latest`（Node 22）上执行 `npm test`，包含真实 git 集成用例。

## 拦截与审批场景

插件在以下场景向 DSH 审批面板发起“批准/拒绝”，或直接阻止命令：

| 场景 | 行为 |
| --- | --- |
| `git commit` | 扫描暂存区；同名命令先 `git add`、commit 带 pathspec / `-i` / `--include`、`commit -a` 时补扫工作区与未跟踪文件；同时扫描 `-m` / `-F` / `--trailer` 消息。 |
| `git push` | 计算实际上传提交/对象范围，按提交扫描 diff、提交信息与 tag 对象消息；支持 remote、通配 refspec、`--force`、`--all`、`--mirror`、`--delete`。 |
| `gh repo sync` | 若本地有仓库则按 push 范围扫描；无本地仓库时放行（无可扫描内容）。 |
| 首次推送 | 仓库首次通过 DSH 推送时询问一次“是否先全仓扫描”；批准则额外扫描 `HEAD` 的全部已跟踪文件。 |
| `git push --dry-run` / `-n` | 不上传内容，直接放行。 |
| 扫描不完整 | 动态提交信息（`-F -`、命令替换）、超大文件、超限等无法完整扫描时，按配置要求审批（默认要求）。 |
| 无法定位仓库 | `cd $repo`、`GIT_DIR`、非仓库目录等：默认拒绝，可改用 `git -C` / `workdir` 或设 `unresolvedRepo: allow`。 |
| 持久终端 | `terminal_send` 无法获知真实 cwd：commit/push 默认拒绝，可设 `persistentShellCommits: allow` 或改用一次性 pwsh/bash + workdir。 |
| 无审批通道 | 会话策略为 `never` 或审批不可用时 fail-closed：命中即拒绝。 |

一次典型授权：命中未白名单项 → 审批面板列出规则/掩码/文件/identity → 批准则本次放行并按 `approvalScope` 写入全局/项目/会话白名单；拒绝/取消则阻止命令。端到端验证（需审批策略 `ask`）：

1. 临时仓库 `git add` 包含假 `sk-…` 的文件 → `git commit` 弹审批；批准后提交成功，`whitelist.json` 增加条目；再次提交同类内容不再询问。
2. 换一个新假密钥 → 拒绝 → 命令被阻止。
3. 首次 `git push` → 弹「是否全仓扫描」；拒绝后只检查本次推送，`state/repos.json` 记录该仓库。

## 配置参考

配置通过 `cordis.patch.yml` 的 `config:` 块或 DSH 插件设置表单修改；schema 由 `lib/schema.mjs` 校验，非法枚举/类型在加载时失败，不会静默回退。

### 三级白名单

| 作用域 | 存储位置 | 生效范围 |
| --- | --- | --- |
| `global` | `state/whitelist.json` | 当前用户所有仓库 |
| `project` | 仓库内 `.dsh/privacy-guard-whitelist.json`（`projectWhitelistFile` 可改） | 仅该仓库；**项目级优先**：项目条目 `allowed:false` 撤销全局/会话授权 |
| `session` | 进程内存（按 session id） | 仅当前会话；DSH 重启/插件重载后失效 |

有效白名单 = 全局 ∪ 项目允许 ∪ 会话允许 − 项目撤销。项目文件必须位于仓库根内，符号链接或 `..` 越界会被忽略并记录警告；项目文件只含哈希/掩码，可提交共享，不想共享就把 `.dsh/` 加入 `.gitignore`。

项目白名单示例：

```json
{
  "version": 1,
  "entries": [
    { "id": "a1b2c3d4e5f60718", "rule": "email", "label": "邮箱地址", "masked": "z***@x.cn", "source": "project", "allowed": true },
    { "id": "0123456789abcdef", "rule": "openai-key", "label": "OpenAI API Key", "masked": "sk-a…34", "allowed": false }
  ]
}
```

身份 = `sha256(规则 id + 命中值)` 截断 16 位；同一敏感值跨文件/仓库只需授权一次。白名单文件可手改，下一次检查立即生效；损坏文件按空白名单处理并写日志。仓库初始化状态在 `state/repos.json`。

### 配置字段

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `interceptCommit` | `true` | 检查 `git commit` |
| `interceptPush` | `true` | 检查 `git push` / `gh repo sync` |
| `fullScanOnFirstPush` | `ask` | `ask` / `always` / `never` |
| `unresolvedRepo` | `deny` | 无法定位仓库时：`deny` / `allow` |
| `persistentShellCommits` | `deny` | 持久终端 commit/push：`deny` / `allow` |
| `whitelistOnApprove` | `true` | 审批通过后自动写入白名单 |
| `requireApprovalOnIncompleteScan` | `true` | 扫描不完整时要求审批 |
| `approvalScope` | `global` | 审批后写入范围：`global` / `project` / `session` |
| `projectWhitelistFile` | `.dsh/privacy-guard-whitelist.json` | 项目白名单文件（相对仓库根） |
| `projectWhitelistEnabled` | `true` | 是否启用项目级白名单 |
| `trustProjectWhitelist` | `true` | 是否信任仓库自带的放行条目；关闭后只应用项目撤销 |
| `disableRules` | `[]` | 禁用的内置规则 id |
| `extraRules` | `[]` | 自定义规则 `{id,label,pattern,flags,severity,mask,capture}` |
| `ignorePaths` | lock 文件/构建产物 | 追加忽略 glob |
| `whitelistFile` | `state/whitelist.json` | 相对插件目录或绝对路径 |
| `repoStateFile` | `state/repos.json` | 仓库初始化状态 |
| `logFile` | `state/push-privacy-guard.log` | 日志；挂载时 >5MB 轮转一次 |
| `maxTotalBytes` | 20 MiB | 单次扫描/ diff 总字节上限 |
| `maxFileBytes` | 1 MiB | 全仓/未跟踪单文件上限；跳过会标记不完整（默认需审批） |
| `maxFiles` | 5000 | 全仓扫描文件数上限 |
| `maxCommits` | 100 | 多分支/mirror 推送提交与提交信息上限 |
| `maxFindings` | 200 | 单次扫描命中上限 |
| `maxApprovalItems` | 20 | 审批面板最多展示条数 |
| `gitTimeoutMs` | 20000 | 单条 git 命令超时（毫秒） |

### 管理命令与工具

`/privacy-guard`（Web UI 命令面板，用户专属，不会变成模型消息）：

```text
/privacy-guard list
/privacy-guard pending
/privacy-guard allow <id前缀|last> [global|project|session]
/privacy-guard revoke <id前缀> [global|project|session]
/privacy-guard session [list|allow <id|last>|revoke <id>|clear]
/privacy-guard project [list|allow <id|last>|revoke <id>|clear]
/privacy-guard remove <id前缀>
/privacy-guard clear confirm
/privacy-guard status
/privacy-guard repos
/privacy-guard reset <路径子串|all>
/privacy-guard scan
/privacy-guard help
```

对话内 `privacy_guard` 工具（模型调用）：`pending` / `list` / `status` / `allow` / `revoke`，参数 `scope: session|project|global`、`target: <id前缀|last>`。`allow/revoke` 只接受最近 `pending` 中的条目，且每次写操作都会再次弹 DSH 审批；审批不可用/被拒时失败关闭，模型无法静默自我授权。

## 通知通道（审批与管理入口）

插件通过以下通道与用户交互，均只展示掩码/哈希：

1. **DSH 审批面板**（主通道）：guard 与 `privacy_guard` 工具调用 `ctx.approval.request()`；面板显示规则、掩码、文件、identity（工具审批）或命中清单（guard 审批），批准/拒绝/取消决定命令是否放行。会话策略 `never` 时一律失败关闭。
2. **`/privacy-guard` 命令**：用户专属，适合快速查看 `pending`、放行/撤销、清空、扫描与仓库初始化管理；命令不产生模型消息。
3. **`privacy_guard` 工具**：在对话中让助手完成放行/撤销；写操作强制二次审批，适合“把最近这条放行到本项目”的自然语言流程。
4. **图形化设置页**：DSH 客户端（Web GUI / 桌面客户端）**设置 → 隐私检查**。页面提供服务状态、可热更新的插件配置、最近拦截一键放行、全局/项目白名单增删清空；项目页输入仓库路径后管理项目文件。桌面客户端通过 `dsh-app://app` 协议把请求转发到本地 Host，无需另开浏览器。Web GUI 也可直接访问 `http://<GUI 地址>/privacy-guard/settings`。
5. **手动编辑文件**：`state/whitelist.json`、项目白名单文件可手工维护（只支持掩码/identity），修改后立即生效；项目路径必须位于仓库根内。

图形化设置页的 API（`/privacy-guard/api`）要求每进程随机 token 和同源 Origin，仅当 Host `webServer` 绑定回环地址时注册；页面不返回明文。页面上的配置保存经 DSH `configEditor` 写入 profile，`volatile` 字段热生效；会话级放行因页面无会话上下文，仍在命令/对话中完成。

## 已知限制

- **不覆盖 DSH 之外的操作**：人工终端推送、脚本内部 `git push`、其他机器上的推送不会经过插件。
- **只检查即将进入 git 的内容**：未暂存/未跟踪且不会被提交的内容不扫描；push 范围仅基于本地 git 数据估算，不访问网络。
- **命令文本解析有限**：只解析一层 `bash -c` / `pwsh -Command`；变量拼接、别名、`node deploy.mjs` 等间接执行无法识别。
- **持久终端默认拒绝**：无法获知 `terminal_send` 真实 cwd；需要时设 `persistentShellCommits: allow`（自担风险）或使用一次性工具 + `workdir`。
- **仓库定位失败默认拒绝**：`cd $repo`、`GIT_DIR`、非仓库目录等；用 `git -C <绝对路径>` / `workdir`，或设 `unresolvedRepo: allow`。
- **force push / mirror**：已覆盖多/通配 refspec 与 tag 对象；被强制覆盖的远端旧历史、`--mirror` 删除的远端 ref 不重扫。
- **首次全仓扫描只看 `HEAD` 已跟踪文件**：历史提交中已删除的敏感信息不会重新发现；超过 `maxFileBytes` 的文件跳过并标记不完整（默认要求审批）。
- **`git commit -C/-c/--fixup` 复用的旧提交信息**在 commit 阶段不重扫（push 通常兜底；`interceptPush:false` 时属残余风险）。
- **规则库不是万能**：高熵字符串、自定义内部格式、二进制内容可能漏报；规则可配置，但任何正则方案都存在误报/漏报。
- **白名单文件是信任边界**：能写全局/项目白名单文件或直接调用审批服务的主体（Full access 模型、其他插件、把 state 指到 workspace 的配置）可以预置条目实现“自我授权”；请把 state 放在用户目录并限制写权限。项目白名单默认信任仓库自带的 `allowed:true` 条目，可用 `trustProjectWhitelist:false` 忽略。
- **会话级放行仅内存**：DSH 重启/插件重载后失效；宿主无法提供稳定 session id 时会话操作失败关闭，不会退回共享桶。
- **多进程并发写白名单**：全局/项目白名单只在单进程内串行；同时运行多个 DSH 进程可能相互覆盖。
- **不清理仓库**：插件只负责阻止/放行，不会删除已提交的敏感信息或改写历史。
- **图形化设置页**：仅在 Host `webServer` 绑定回环地址时注册；非回环绑定会跳过（避免 LAN 暴露）。桌面客户端依赖 `dsh-app://app` 转发；若客户端 bundle 未加载，重启 DSH 或使用命令/对话。
- **i18n 与测试**：命令/工具回复目前为中文硬编码，未接入 DSH locale；CI 只覆盖 Node 单元/集成测试，未在真实 DSH 进程内自动化验证审批 UI；vendored Schemastery 为 3.18.5，宿主为 3.19.0。

## License

MIT，见 [LICENSE](LICENSE)。

`vendor/schemastery` 与 `vendor/cosmokit` 内嵌自 DeepSeek Harness 运行时的 `@deepseek-ai/schemastery` / `@deepseek-ai/cosmokit`（MIT，许可证随目录保留），用于让按绝对路径挂载的外部插件也能声明 DSH 原生 `Config` schema。