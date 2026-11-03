# dsh-push-privacy-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DSH](https://img.shields.io/badge/DSH-%E2%89%A50.2.1--rc.5-6f42c1)](https://github.com/deepseek-ai/deepseek-harness)
[![Plugin Market](https://img.shields.io/badge/DSH%20Plugin%20Market-index-brightgreen)](market/index.json)

DSH（DeepSeek Harness）Host 插件：在 Agent 执行 `git commit`、`git push`（以及 `gh repo sync`）**之前**检查将要进入 git 的内容，发现本地绝对路径、用户信息、API Key、私钥、连接串等敏感信息时，通过 DSH 原生审批面板请求用户一次性授权；拒绝则阻止命令，批准则放行并把本次授权的信息写入**可管理的白名单**，之后同样的信息不再重复询问。

> 定位：**内容泄露护栏**，不是安全边界。它只覆盖 DSH 工具层（`pwsh` / `bash` 一次性命令，以及 PTC 内部 bash 调用）；持久终端（`terminal_send`）的 commit/push 默认直接拒绝；不覆盖人工终端推送、脚本内部自行发起的推送，也不能发现规则库之外的泄露形式。

## 能力

- **提交前检查**：扫描 `git commit` 将记录的暂存区内容；同一命令里先 `git add`、commit 带 pathspec / `-i` / `--include`、`commit -a` 时按 `git diff HEAD` 覆盖工作区改动并补扫未跟踪文件；同时检查 `-m` / `-F` / `--trailer` 提交信息。`-F -`、命令替换等无法预读的信息按“扫描不完整”处理并请求授权。
- **推送前检查**：只读计算本次 `git push` 真正要上传的范围（支持 `git -C`、多个/通配 refspec、remote、`--force`、`--all`、`--mirror`、`--delete`、`gh repo sync`），按提交逐个扫描（`git log -p`，含“先加后删”的中间提交）+ 待推送提交信息 + tag 对象消息。
- **dry-run 放行**：`git push --dry-run` / `git push -n` 不上传任何内容，直接放行、不打扰。
- **首次仓库全仓扫描**：某个仓库第一次通过 DSH 推送时询问一次「是否先全仓库扫描」；全仓扫描用 `--full-tree` 覆盖整个 `HEAD` 的 **git 已跟踪文件**，`.gitignore` 忽略的内容天然不参与。之后该仓库只检查本次提交/推送内容。
- **用户授权**：命中未白名单项时调用 `ctx.approval.request()`，在 Web UI 审批面板展示脱敏后的命中清单；批准 = 本次放行 + 入白名单，拒绝/取消 = 阻止命令。
- **白名单管理**：`/privacy-guard` 斜杠命令（用户专属，不产生模型消息），底层 `state/whitelist.json` 可手改、即时生效。
- **失败关闭**：一旦识别为 commit/push，扫描失败/超时/git 查询失败/无法获得授权都会**阻止**命令，而不是放行；`git commit`/`git push` 无法定位仓库时默认拒绝（`unresolvedRepo`）。
- **原生配置 schema**：`index.mjs` 导出 Cordis `Config`（Schemastery），加载时由 DSH 校验；开关、模式、上限与路径字段标记为 `.volatile()`，可在 DSH 设置页直接修改并**热生效**（loader 提交后插件原地刷新配置，不重启）。
- 零运行时依赖（仅 `node:*` 内置模块；Schemastery 按 MIT 许可内嵌在 `vendor/`），可按绝对路径挂载，也可作为 bundle 安装。

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

所有 git 调用都是只读子命令（`rev-parse` / `rev-list` / `diff` / `log` / `for-each-ref` / `ls-tree` / `cat-file` / `remote`），**不会修改仓库、index 或远端**；全仓扫描通过一次 `git cat-file --batch` 流式读取所有 blob。

## 内置规则（V1）

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
| `assigned-secret-zh` | `密码/密钥/令牌/凭证：值` | 高 |
| `connection-string` | mongodb/mysql/postgres/redis/amqp/jdbc URI | 高 |
| `local-abs-path-win` | Windows 绝对路径（`C:\Users\…`） | 中 |
| `local-abs-path-unc` | UNC 共享路径（双反斜杠开头的网络共享路径） | 中 |
| `local-home-path-posix` | `/Users/…`、`/home/…` | 中 |
| `ssh-home-path` | `~/.ssh/<文件>`、`$HOME/.ssh/<文件>`、`%USERPROFILE%\.ssh\<文件>` | 中 |
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

命令在 Web UI 的命令面板执行，**不会变成模型消息**，模型无法借此修改白名单或自我授权（但能直接写 `state/whitelist.json` 的主体是信任边界，见“已知限制”）。

## 配置（profile `cordis.patch.yml` 的 `config:`）

配置由 `lib/schema.mjs` 导出的 Cordis `Config`（Schemastery）校验：非法枚举/类型会在加载时报错，不再静默回退。带 `.volatile()` 的字段会出现在 DSH 设置页表单中（设置页只投影 `volatile` 字段）；编辑后 loader 直接提交新值并触发 `loader/volatile-update`，插件原地刷新配置，**无需重启**。数组/对象类字段（`disableRules`、`extraRules`、`ignorePaths`）仍通过 `cordis.patch.yml` 修改，由 profile 重载生效。

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `interceptCommit` | `true` | 检查 `git commit` |
| `interceptPush` | `true` | 检查 `git push` / `gh repo sync` |
| `fullScanOnFirstPush` | `ask` | `ask` / `always` / `never` |
| `unresolvedRepo` | `deny` | 识别出 commit/push 但仓库定位失败（变量路径、非仓库、`GIT_DIR` 覆盖等）时：`deny` / `allow` |
| `persistentShellCommits` | `deny` | `terminal_send` 等持久终端的 commit/push（无法获知其真实 cwd）：`deny` / `allow` |
| `whitelistOnApprove` | `true` | 授权后自动写白名单 |
| `requireApprovalOnIncompleteScan` | `true` | 扫描不完整（超时/超限/大文件跳过/动态提交信息）时是否要求授权 |
| `disableRules` | `[]` | 关闭的内置规则 id |
| `extraRules` | `[]` | 自定义规则 `{id,label,pattern,flags,severity,mask,capture}` |
| `ignorePaths` | 锁文件/构建产物 | 追加到默认忽略 glob |
| `whitelistFile` | `state/whitelist.json` | 相对插件目录或绝对路径 |
| `repoStateFile` | `state/repos.json` | 同上 |
| `logFile` | `state/push-privacy-guard.log` | 同上；挂载时 >5MB 轮转一次 |
| `maxTotalBytes` | 20 MiB | 单次差异/扫描总字节上限 |
| `maxFileBytes` | 1 MiB | 全仓/未跟踪单文件上限；超限跳过会把扫描标记为不完整（默认要求授权） |
| `maxFiles` | 5000 | 全仓文件数上限 |
| `maxCommits` | 100 | 多分支/镜像逐提交扫描与提交信息上限 |
| `maxFindings` | 200 | 单次扫描命中上限 |
| `maxApprovalItems` | 20 | 审批文案最多列举条数 |
| `gitTimeoutMs` | 20000 | 单条 git 命令超时 |

非法值回退默认并写 `config.warning` 日志，不会静默失效。

## 社区收录 / 插件市场

可通过 DSH「插件 → 发现」添加本插件自带的**市场索引**（格式 1，由 `@deepseek-ai/dsh-plugin-market-index` 的 `parseMarketIndex` 校验）：

```text
https://raw.githubusercontent.com/lizhijie429/dsh-push-privacy-guard/main/market/index.json
```

步骤：先启用实验性的 **自定义插件市场**（插件 → 实验性插件 → 更多 → 自定义插件市场），再在 插件 → 发现 → 索引源 中粘贴上面的 URL，搜索 “Push Privacy Guard” 安装即可。

也可以直接用 Git 源安装（无需 npm 发布）：

```powershell
dsh plugin --profile desktop add https://github.com/lizhijie429/dsh-push-privacy-guard
```

已提交的社区收录：

- [Open Plugin Market（社区插件索引）](https://github.com/polang233/dsh-plugin-index) 收录申请（pinned Git commit `b752f61`，v0.2.1）。
- [awesome-dsh-plugin](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin) 精选列表 PR（`data/plugins/lizhijie429__dsh-push-privacy-guard.yml`）。

> npm 包尚未发布（需要维护者 npm token）；当前以固定 Git commit 作为市场安装源。索引条目只声明安装参数，实际安装内容以仓库 `package.json` 与 `cordis.patch.yml` 为准。

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
- **持久终端默认拒绝**：`terminal_send` 等持久终端的真实 cwd 无法获知，commit/push 默认直接拒绝；需要时把 `persistentShellCommits` 设为 `allow`（风险自担），或改用一次性的 `pwsh`/`bash` + `workdir`。
- **仓库定位失败默认拒绝**：`cd $repo`、`GIT_DIR=…`、非仓库目录等无法定位仓库时默认拒绝；可用 `git -C <绝对路径>` / `workdir`，或把 `unresolvedRepo` 设为 `allow`。
- **force push / mirror**：已覆盖多个/通配 refspec 与 tag 对象；但被强制覆盖的**远端旧历史**、`--mirror` 删除的远端 ref 不重扫。
- **首次全仓扫描只看 `HEAD` 的已跟踪文件**：历史提交中被删除的敏感信息不会被重新发现；大文件（> `maxFileBytes`）跳过时标记不完整（默认要求授权）。
- **`git commit -C/-c/--fixup` 复用的旧提交信息**在 commit 阶段不重扫（push 阶段通常兜底；`interceptPush:false` 时属残余风险）。
- **规则库不是万能**：高熵字符串、自定义内部格式、二进制内容可能漏报；规则可配置但与任何正则方案一样存在误报/漏报。
- **白名单文件即信任边界**：能写 `state/whitelist.json` 的主体（Full access 会话中的模型、其他插件、把 state 指到 workspace 的配置）可以预置白名单实现“自我授权”；请把 state 放在用户目录并限制写权限。
- **多进程并发写白名单**只在单进程内串行；同时运行多个 DSH 进程时可能相互覆盖。
- **不清理仓库**：插件只负责阻止/放行，不会自动删除已提交的敏感信息或改写历史。

## License

MIT，见 [LICENSE](LICENSE)。

`vendor/schemastery` 与 `vendor/cosmokit` 内嵌自 DeepSeek Harness 运行时的 `@deepseek-ai/schemastery` / `@deepseek-ai/cosmokit`（MIT，许可证随目录保留），用于让按绝对路径挂载的外部插件也能声明 DSH 原生 `Config` schema。
