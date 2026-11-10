# dsh-push-privacy-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DSH](https://img.shields.io/badge/DSH-%E2%89%A50.2.2--rc.1-6f42c1)](https://github.com/deepseek-ai/deepseek-harness)
[![Plugin Market](https://img.shields.io/badge/DSH%20Plugin%20Market-index-brightgreen)](market/index.json)

[简体中文](README.md) | English

## Introduction

A DSH (DeepSeek Harness) Host plugin that checks what is about to enter git **before** an Agent runs `git commit`, `git push` (or `gh repo sync`). When it finds local absolute paths, user information, API keys, private keys or connection strings, it asks for one-time user approval through the native DSH approval UI. A rejection blocks the command; an approval lets it through and records the decision in a **manageable whitelist**.

> Positioning: a **content-leak guard**, not a security boundary. It only covers the DSH tool layer (`pwsh` / `bash` one-shot commands and PTC-internal bash calls); commits/pushes sent to a persistent terminal (`terminal_send`) are denied by default; manual terminal pushes, pushes initiated inside scripts, and leak patterns outside the rule set are not covered.

Core capabilities:

- **Pre-commit check**: scans the index, `commit -a` / pathspec / `git add` combinations and untracked files, plus `-m` / `-F` / `--trailer` commit messages.
- **Pre-push check**: computes, read-only, what a push would upload (`git -C`, multiple/wildcard refspecs, `--force`, `--all`, `--mirror`, `--delete`, `gh repo sync`), scans commit by commit and also checks pushed messages and tag messages.
- **First-push full scan**: asks once whether to scan all tracked files in `HEAD`; content ignored by `.gitignore` is naturally excluded.
- **Three whitelist scopes**: global `state/whitelist.json`, repository project whitelist `.dsh/privacy-guard-whitelist.json` (project overrides global; `allowed:false` revokes), and in-memory session-only approvals. The whitelist stores masked values and identity hashes only, never plaintext.
- **Four management surfaces**: DSH approval panel, `/privacy-guard` slash command, conversation-facing `privacy_guard` tool, and the graphical Settings page in the Web/desktop client.
- **Fail closed**: once a commit/push is recognised, scan errors, timeouts, failed git queries and unavailable approval all block the command; an unlocatable repository is denied by default.
- **Native DSH configuration**: exports a Cordis `Config` (Schemastery); switches, modes, limits and paths are `.volatile()` and apply live from the settings page. Zero runtime dependencies (Node `node:*` built-ins only; Schemastery is vendored under the MIT license).

How it works:

```text
tool call (pwsh / bash / terminal_send / PTC-internal bash)
  └─ tools/pre-execute (this plugin, async, prepend)
       ├─ lib/detect.mjs     parse the command: git commit / git push / gh repo sync; workdir, cd, git -C
       ├─ lib/scan.mjs       read-only git: index / push range / tracked files / commit messages
       ├─ lib/rules.mjs      rule matching, placeholder filtering, masking, stable identity
       ├─ lib/scopes.mjs     global/project/session whitelists and project-path safety
       ├─ lib/whitelist.mjs  global whitelist (masked values only)
       └─ ctx.approval.request() → user allows / rejects
  └─ allow → run the tool; deny → return {kind:'deny', reason}
```

Every git invocation is a read-only subcommand (`rev-parse` / `rev-list` / `diff` / `log` / `for-each-ref` / `ls-tree` / `cat-file` / `remote`); it never modifies the repository, index or remote. The full scan streams all blobs through one `git cat-file --batch` process.

Built-in rules (V1):

| Rule | Description | Severity |
| --- | --- | --- |
| `private-key-block` | `-----BEGIN … PRIVATE KEY-----` / PGP private key block | high |
| `aws-access-key` | `AKIA` / `ASIA` + 16 chars | high |
| `github-token` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` | high |
| `github-fine-grained-token` | `github_pat_…` | high |
| `gitlab-token` | `glpat-` / `gldt-` / `glrt-` | high |
| `npm-token` | `npm_…` | high |
| `openai-key` | `sk-` / `sk-proj-` long strings | high |
| `slack-token` | `xox[baprs]-…` | high |
| `google-api-key` | `AIza` + 35 chars | high |
| `jwt` | three-part JWT | high |
| `bearer-token` | `Bearer <token>` | high |
| `assigned-secret` | `password/secret/token/api_key/... = value` | high |
| `assigned-secret-zh` | Chinese `密码/密钥/令牌/凭证` labels | high |
| `connection-string` | mongodb/mysql/postgres/redis/amqp/jdbc URI | high |
| `local-abs-path-win` | Windows absolute path (`C:\Users\…`) | medium |
| `local-abs-path-unc` | UNC share path (leading double backslashes) | medium |
| `local-home-path-posix` | `/Users/…`, `/home/…` | medium |
| `ssh-home-path` | `~/.ssh/<file>`, `$HOME/.ssh/<file>`, `%USERPROFILE%\.ssh\<file>` | medium |
| `email` | email addresses (example / noreply / `git@github.com` placeholders filtered) | medium |
| `cn-mobile` | mainland-China mobile numbers | medium |
| `cn-id-card` | 18-digit Chinese ID card (checksum must pass) | high |
| `internal-url` | intranet IPs / `.local`, `.internal`, `.corp` addresses | medium |

Placeholders (`${…}`, `{{…}}`, `<…>`, `your_*`, `changeme`, `process.env.*`, example domains, …) are not reported. `ignorePaths` ignores lock files, `*.min.js`, `*.map`, `node_modules`, `dist`, `build` etc. by default.

## Installation

### Plugin market (recommended)

In DSH **Plugins → Experimental plugins → More → enable Custom Plugin Market**, then **Plugins → Discover → Index sources** and add:

```text
https://raw.githubusercontent.com/lizhijie429/dsh-push-privacy-guard/main/market/index.json
```

Search for “Push Privacy Guard” and install. The index uses DSH market format 1 and has been validated with `@deepseek-ai/dsh-plugin-market-index`.

### Git source

```powershell
dsh plugin --profile desktop add https://github.com/lizhijie429/dsh-push-privacy-guard
```

Use the same command with another `--profile` for other profiles. Restart DSH after installation so Host code and the client bundle load.

### Absolute path (local development/offline)

Append to the profile's `cordis.patch.yml` (replace `<user>`):

```yaml
- insert:
    - id: push-privacy-guard
      name: 'C:\Users\<user>\.dsh\plugins\dsh-push-privacy-guard\index.mjs'
      config:
        fullScanOnFirstPush: ask
        whitelistOnApprove: true
```

The desktop client profile is `desktop`; its patch file is `%USERPROFILE%\.dsh\profiles\desktop\cordis.patch.yml`. `patchReload: live` reloads configuration on save, but code changes still require a DSH restart.

### Verify the installation

```powershell
cd "$env:USERPROFILE\.dsh\plugins\dsh-push-privacy-guard"
npm test
Get-Content state\push-privacy-guard.log -Tail 20
```

`plugin.mounted` and `settings-web.registered` in the log mean the Host loaded; the graphical page appears after a restart under **Settings → Privacy Guard**. CI runs `npm test` on `ubuntu-latest` / `windows-latest` (Node 22), including real-git integration cases.

## Blocking & approval scenarios

The plugin asks the DSH approval panel for a decision, or blocks the command, in these situations:

| Scenario | Behaviour |
| --- | --- |
| `git commit` | Scans the index; when the same command first runs `git add`, the commit has a pathspec / `-i` / `--include`, or `commit -a` is used, it also scans working-tree changes and untracked files; messages from `-m` / `-F` / `--trailer` are checked too. |
| `git push` | Computes the actual range of commits/objects, scans per-commit diffs, messages and tag-object messages; supports remotes, multiple/wildcard refspecs, `--force`, `--all`, `--mirror`, `--delete`. |
| `gh repo sync` | Scans like a push when a local repository exists; without a local repository there is nothing to scan, so it passes. |
| First push | Asks once whether to scan the whole repository first; approving adds a `--full-tree` scan of all tracked files in `HEAD`. |
| `--dry-run` / `-n` | Uploads nothing, so it passes without friction. |
| Incomplete scan | Dynamic commit messages (`-F -`, command substitution), skipped large files or exceeded limits mark the scan incomplete; approval is required by default. |
| Unresolvable repository | `cd $repo`, `GIT_DIR`, a non-repository directory: denied by default; use `git -C` / `workdir`, or set `unresolvedRepo: allow`. |
| Persistent terminal | `terminal_send` has no observable cwd: commits/pushes are denied by default; use one-shot pwsh/bash with `workdir`, or set `persistentShellCommits: allow`. |
| No approval channel | With policy `never` or an unavailable approval channel the guard fails closed: matches block the command. |

Typical approval: unapproved findings → the approval panel lists rule/masked/file/identity → approve allows this command and records the findings in the whitelist named by `approvalScope`; reject/cancel blocks the command. End-to-end (requires approval policy `ask`):

1. In a temporary repository, `git add` a file containing a fake `sk-…`, then `git commit` → approval appears; approving commits and adds an entry to `whitelist.json`; committing the same content again does not ask.
2. Use a different fake key → reject → the command is blocked.
3. The first `git push` asks about the full scan; rejecting means only this push is checked and `state/repos.json` records the repository.

## Configuration reference

Configuration is edited in the profile's `cordis.patch.yml` `config:` block or the DSH plugin settings form. The schema in `lib/schema.mjs` validates enums/types at load time; invalid values fail instead of silently falling back.

### Whitelist scopes

| Scope | Storage | Applies to |
| --- | --- | --- |
| `global` | `state/whitelist.json` | every repository of the current user |
| `project` | `.dsh/privacy-guard-whitelist.json` (configurable via `projectWhitelistFile`) | this repository only; **project overrides global**: `allowed:false` revokes global/session approvals |
| `session` | process memory, keyed by session id | the current session only; cleared when DSH restarts or the plugin reloads |

Effective whitelist = global ∪ project allow ∪ session allow − project revoke. The project file must live inside the repository root; symlinks and `..` escapes are ignored with a warning. It contains hashes and masked previews only, so it can be committed and shared; add `.dsh/` to `.gitignore` to keep it local.

Example project whitelist:

```json
{
  "version": 1,
  "entries": [
    { "id": "a1b2c3d4e5f60718", "rule": "email", "label": "Email", "masked": "z***@x.cn", "source": "project", "allowed": true },
    { "id": "0123456789abcdef", "rule": "openai-key", "label": "OpenAI API Key", "masked": "sk-a…34", "allowed": false }
  ]
}
```

Identity = `sha256(rule id + matched value)` truncated to 16 hex chars: the same sensitive value only needs one approval across files and repositories. Whitelist files can be edited by hand and apply on the next check; a corrupt file is treated as empty and logged. Repository initialisation state lives in `state/repos.json`.

### Configuration fields

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Master switch |
| `interceptCommit` | `true` | Check `git commit` |
| `interceptPush` | `true` | Check `git push` / `gh repo sync` |
| `fullScanOnFirstPush` | `ask` | `ask` / `always` / `never` |
| `unresolvedRepo` | `deny` | Policy when a commit/push is recognised but the repo cannot be located: `deny` / `allow` |
| `persistentShellCommits` | `deny` | Commits/pushes in a persistent terminal: `deny` / `allow` |
| `whitelistOnApprove` | `true` | Add approved findings to the whitelist automatically |
| `requireApprovalOnIncompleteScan` | `true` | Require approval for incomplete scans |
| `approvalScope` | `global` | Where approvals are remembered: `global` / `project` / `session` |
| `projectWhitelistFile` | `.dsh/privacy-guard-whitelist.json` | Project whitelist file (repo-relative) |
| `projectWhitelistEnabled` | `true` | Enable project-scoped whitelists |
| `trustProjectWhitelist` | `true` | Trust repository-authored allow entries; when false only project revokes apply |
| `disableRules` | `[]` | Built-in rule ids to disable |
| `extraRules` | `[]` | Custom rules `{id,label,pattern,flags,severity,mask,capture}` |
| `ignorePaths` | lock files/build output | Additional ignore globs |
| `whitelistFile` | `state/whitelist.json` | Relative to the plugin directory, or absolute |
| `repoStateFile` | `state/repos.json` | Repository initialisation state |
| `logFile` | `state/push-privacy-guard.log` | Log file; rotated once at mount when >5 MB |
| `maxTotalBytes` | 20 MiB | Total byte cap per scan/diff |
| `maxFileBytes` | 1 MiB | Per-file cap for full/untracked scans; skipped files mark the scan incomplete (approval required by default) |
| `maxFiles` | 5000 | File-count cap for full scans |
| `maxCommits` | 100 | Commit/message cap for multi-branch/mirror pushes |
| `maxFindings` | 200 | Findings cap per scan |
| `maxApprovalItems` | 20 | Maximum findings shown in the approval panel |
| `gitTimeoutMs` | 20000 | Timeout for one git command (ms) |

### Management commands and tool

`/privacy-guard` (Web UI command palette, user-only, never becomes a model message):

```text
/privacy-guard list
/privacy-guard pending
/privacy-guard allow <id-prefix|last> [global|project|session]
/privacy-guard revoke <id-prefix> [global|project|session]
/privacy-guard session [list|allow <id|last>|revoke <id>|clear]
/privacy-guard project [list|allow <id|last>|revoke <id>|clear]
/privacy-guard remove <id-prefix>
/privacy-guard clear confirm
/privacy-guard status
/privacy-guard repos
/privacy-guard reset <path-substring|all>
/privacy-guard scan
/privacy-guard help
```

The conversation-facing `privacy_guard` tool supports `pending` / `list` / `status` / `allow` / `revoke`, with `scope: session|project|global` and `target: <id-prefix|last>`. `allow/revoke` only accept findings from the most recent `pending` set, and every write triggers a fresh DSH approval; when approval is unavailable or rejected the tool fails closed, so a model cannot silently widen its own permissions.

## Notification channels (approval & management surfaces)

The plugin talks to the user through these surfaces; all of them show masked values/hashes only:

1. **DSH approval panel** (primary): guard and the `privacy_guard` tool call `ctx.approval.request()`. The panel shows rule/masked/file/identity (or the guard's finding list); approve/reject/cancel decides whether the command runs. Policy `never` always fails closed.
2. **`/privacy-guard` command**: user-only surface for inspecting `pending`, allowing/revoking, clearing, scanning and repository resets; it never becomes a model message.
3. **`privacy_guard` tool**: lets the assistant perform allow/revoke from the conversation; writes require a second approval, which suits requests such as “allow the latest finding for this project”.
4. **Graphical Settings page**: DSH client (Web GUI or desktop client) **Settings → Privacy Guard**. It shows runtime status, live-editable plugin configuration, recent blocked findings with one-click allow-to-global/project, and global/project whitelist tables (remove/clear). The project tab takes a repository path and manages its project file. The desktop client forwards requests to the local Host through the `dsh-app://app` protocol, so no separate browser is needed. In the Web GUI you can also open `http://<GUI host>/privacy-guard/settings`.
5. **Manual file editing**: `state/whitelist.json` and project whitelist files may be edited by hand (masked/identity entries only) and apply immediately; project paths must stay inside the repository root.

The graphical settings page and API first pass the host's `connection.admit()` authentication (Host/Origin fence + signed browser/API cookie): unauthenticated requests get 401 and never receive the page or its operation token; once authenticated, a per-process token is still required before changing whitelists or configuration. Routes are registered only when the Host `webServer` binds loopback; the page never returns plaintext. Configuration saves go through the DSH `configEditor` into the profile and apply live for `volatile` fields. Session-scoped allow decisions still belong to a conversation because the settings page has no session context.

## Known limitations

- **Operations outside DSH are not covered**: manual terminal pushes, `git push` inside scripts, and pushes from other machines bypass the plugin.
- **Only content about to enter git is checked**: unstaged/untracked files that will not be committed are not scanned; the push range is estimated from local git data without network access.
- **Command parsing is shallow**: only one level of `bash -c` / `pwsh -Command` is parsed; variable concatenation, aliases, and indirect execution such as `node deploy.mjs` are not recognised.
- **Persistent terminals are denied by default**: the real cwd of `terminal_send` is not observable; set `persistentShellCommits: allow` if needed (at your own risk) or use one-shot tools with `workdir`.
- **Unresolvable repositories are denied by default**: `cd $repo`, `GIT_DIR`, non-repository directories; use `git -C <absolute path>` / `workdir`, or set `unresolvedRepo: allow`.
- **force push / mirror**: multiple and wildcard refspecs plus tag objects are covered; remote history overwritten by a force push and remote refs deleted by `--mirror` are not re-scanned.
- **The first full scan only sees tracked files in `HEAD`**: secrets deleted from older commits are not rediscovered; files above `maxFileBytes` are skipped and mark the scan incomplete (approval required by default).
- **Messages reused by `git commit -C/-c/--fixup`** are not re-scanned at commit time (the push scan usually covers them; with `interceptPush:false` this is residual risk).
- **The rule set is not omniscient**: high-entropy strings, custom internal formats and binary content may be missed; rules are configurable, and any regex approach can produce false positives and false negatives.
- **The whitelist files are the trust boundary**: any principal that can write the global/project whitelist or call the approval service directly (a full-access model, another plugin, a configuration that points state at the workspace) can pre-seed entries and “self-authorise”. Keep state in the user directory and restrict write permissions. Project allow entries authored by the repository are trusted by default; set `trustProjectWhitelist:false` to ignore them.
- **Session decisions are in-memory only**: they are lost when DSH restarts or the plugin reloads; when the host exposes no stable session id, session operations fail closed instead of sharing a bucket.
- **Concurrent multi-process writes** are only serialised inside one process; running several DSH processes at once can overwrite each other's whitelist changes.
- **The plugin does not clean repositories**: it only blocks/allows; it never deletes already-committed sensitive data or rewrites history.
- **Graphical settings page**: registered only when Host `webServer` binds loopback (non-loopback binds are skipped to avoid LAN exposure). The page and API first require host `connection.admit()` authentication; unauthenticated requests get 401 and never receive the operation token. The desktop client relies on `dsh-app://app` forwarding; if the client bundle is not loaded, restart DSH or use commands/conversation.
- **i18n and tests**: command/tool replies are currently hard-coded Chinese and do not use the DSH locale; CI covers Node unit/integration tests but not automated approval-UI validation inside a real DSH process. Vendored Schemastery is 3.18.5 while the host is 3.19.0.

## License

MIT, see [LICENSE](LICENSE).

`vendor/schemastery` and `vendor/cosmokit` are embedded from the DeepSeek Harness runtime's `@deepseek-ai/schemastery` / `@deepseek-ai/cosmokit` (MIT, license files kept alongside) so an externally mounted plugin (absolute path) can still declare a native DSH `Config` schema.