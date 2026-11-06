# dsh-push-privacy-guard

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DSH](https://img.shields.io/badge/DSH-%E2%89%A50.2.1--rc.5-6f42c1)](https://github.com/deepseek-ai/deepseek-harness)
[![Plugin Market](https://img.shields.io/badge/DSH%20Plugin%20Market-index-brightgreen)](market/index.json)

[简体中文](README.md) | English

A DSH (DeepSeek Harness) Host plugin that checks what is about to enter git **before** an Agent runs `git commit`, `git push` (or `gh repo sync`). When it finds local absolute paths, user information, API keys, private keys or connection strings, it requests a one-time user approval through the native DSH approval UI. A rejection blocks the command; an approval lets it through and records the approved items in a **manageable whitelist**, so the same value is not asked about again.

> Positioning: a **content-leak guard**, not a security boundary. It only covers the DSH tool layer (`pwsh` / `bash` one-shot commands and PTC-internal bash calls). Commits/pushes sent to a persistent terminal (`terminal_send`) are denied by default; manual terminal pushes, pushes initiated inside scripts, and leak patterns outside the rule set are not covered.

## Features

- **Pre-commit check**: scans the index content `git commit` would record. When the same command first runs `git add`, the commit has a pathspec / `-i` / `--include`, or `commit -a` is used, it scans `git diff HEAD` and also covers untracked files; `-m` / `-F` / `--trailer` commit messages are scanned too. Content that cannot be read ahead of time (`-F -`, command substitution) is treated as an incomplete scan and requires approval.
- **Pre-push check**: computes, read-only, what a `git push` would really upload (supports `git -C`, multiple and wildcard refspecs, remotes, `--force`, `--all`, `--mirror`, `--delete`, `gh repo sync`). It scans commit by commit (`git log -p`, including commits that added and later deleted a secret), plus messages of the pushed commits and tag-object messages.
- **Dry-run pass-through**: `git push --dry-run` / `git push -n` upload nothing, so they are allowed without friction.
- **First-push full scan**: the first push from a repository asks once whether to scan the whole tracked tree. The full scan uses `--full-tree`, covering all **git-tracked files in `HEAD`**; anything ignored by `.gitignore` is naturally excluded. Afterwards only the current commit/push content is checked.
- **User approval**: when unapproved items are found, calls `ctx.approval.request()` and shows a masked list in the Web UI approval panel. Approve = allow this command + add to the whitelist; reject/cancel = block the command.
- **Whitelist management (global / project / session)**: approvals can be remembered globally in `state/whitelist.json`, per repository in `.dsh/privacy-guard-whitelist.json` (project entries override global; `allowed: false` revokes a global approval for that repository), or only for the current session (in-memory, cleared by a restart). Both the `/privacy-guard` slash command and the conversation-facing `privacy_guard` tool can manage them; write operations require user approval.
- **Fail closed**: once a commit/push is recognised, scan errors, timeouts, failed git queries and unavailable approval all **block** the command instead of allowing it. When the repository cannot be located for a `git commit`/`git push`, the default is to deny (`unresolvedRepo`).
- **Native config schema**: `index.mjs` exports a Cordis `Config` (Schemastery) validated by DSH at load time. Switches, modes, limits and path fields are marked `.volatile()`, so they can be edited in the DSH settings page and take effect **live** (the loader commits the new values and the plugin refreshes its config in place, without a restart).
- Zero runtime dependencies (Node `node:*` built-ins only; Schemastery is vendored under `vendor/` with its MIT license). It can be mounted by absolute path or installed as a bundle.

## How it works

```text
tool call (pwsh / bash / terminal_send / PTC-internal bash)
  └─ tools/pre-execute (this plugin, async, prepend)
       ├─ lib/detect.mjs     parse the command: git commit / git push / gh repo sync; workdir, cd, git -C
       ├─ lib/scan.mjs       read-only git: index / push range / tracked files / commit messages
       ├─ lib/rules.mjs      rule matching, placeholder filtering, masking, stable identity
       ├─ lib/whitelist.mjs  whitelist (masked values only, never plaintext)
       ├─ lib/repo-state.mjs whether a repository has been asked about the full scan
       └─ ctx.approval.request() → user allows / rejects
  └─ allow → run the tool; deny → return {kind:'deny', reason}

/privacy-guard … (ctx.inject(['commands']) optional, user-only)
```

Every git invocation is a read-only subcommand (`rev-parse` / `rev-list` / `diff` / `log` / `for-each-ref` / `ls-tree` / `cat-file` / `remote`); it **never modifies the repository, the index or a remote**. The full scan streams all blobs through a single `git cat-file --batch` process.

## Built-in rules (V1)

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
| `assigned-secret-zh` | Chinese labels such as `密码` / `密钥` / `令牌` / `凭证` followed by a value | high |
| `connection-string` | mongodb/mysql/postgres/redis/amqp/jdbc URI | high |
| `local-abs-path-win` | Windows absolute path (`C:\Users\…`) | medium |
| `local-abs-path-unc` | UNC share path (leading double backslashes) | medium |
| `local-home-path-posix` | `/Users/…`, `/home/…` | medium |
| `ssh-home-path` | `~/.ssh/<file>`, `$HOME/.ssh/<file>`, `%USERPROFILE%\.ssh\<file>` | medium |
| `email` | email addresses (example / noreply / `git@github.com` placeholders filtered) | medium |
| `cn-mobile` | mainland-China mobile numbers | medium |
| `cn-id-card` | 18-digit Chinese ID card (only reported when the checksum passes) | high |
| `internal-url` | intranet IPs / `.local`, `.internal`, `.corp` addresses | medium |

Filtering: placeholders such as `${…}`, `{{…}}`, `<…>`, `your_*`, `changeme`, `process.env.*`, `os.environ[...]` and example domains are not reported. `ignorePaths` ignores lock files, `*.min.js`, `*.map`, `node_modules`, `dist`, `build` and similar by default.

## Whitelist

`state/whitelist.json`:

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

- Identity = `sha256(rule id + matched value)` truncated to 16 hex chars: the same sensitive value only needs one approval across files and repositories.
- **Masked values only**, never plaintext. Hand edits take effect on the next check; a corrupt file is treated as an empty whitelist and logged.
- Repository initialisation state lives in `state/repos.json`.

### Scopes and precedence

| Scope | Storage | Applies to |
| --- | --- | --- |
| `global` | `state/whitelist.json` | every repository of the current user |
| `project` | `.dsh/privacy-guard-whitelist.json` in the repository (`projectWhitelistFile` changes the path) | this repository only; **project overrides global**: an entry with `allowed: false` revokes a global/session approval here |
| `session` | process memory, keyed by session id | the current session only; cleared when DSH restarts or the plugin reloads |

Every scan computes the effective whitelist as “global ∪ project allow ∪ session allow − project revoke”. The project file can be committed and shared with the team (it contains hashes and masked previews only); add `.dsh/` to `.gitignore` if you do not want to share it.

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

## `/privacy-guard` commands

| Command | Behaviour |
| --- | --- |
| `/privacy-guard list` | List the global / project / session whitelists |
| `/privacy-guard pending` | Show the findings of the most recent blocked command (id / rule / masked / file) |
| `/privacy-guard allow <id-prefix\|last> [global\|project\|session]` | Allow a finding in the given scope (default `approvalScope`) |
| `/privacy-guard revoke <id-prefix> [global\|project\|session]` | Revoke an allow decision in that scope |
| `/privacy-guard session [list\|allow <id\|last>\|revoke <id>\|clear]` | Session-scoped decisions |
| `/privacy-guard project [list\|allow <id\|last>\|revoke <id>]` | Project-scoped decisions (priority over global) |
| `/privacy-guard remove <id-prefix>` | Remove one global entry (unique prefix) |
| `/privacy-guard clear confirm` | Clear the global whitelist (requires `confirm`) |
| `/privacy-guard status` | Switches, file paths, rule count, whitelist count, initialised repo count, current repo state |
| `/privacy-guard repos` | List initialised repositories |
| `/privacy-guard reset <path-substring\|all>` | Clear a repository initialisation record; the next push asks about the full scan again |
| `/privacy-guard scan` | Immediately scan the current session repository (tracked full tree + index) and report; no push, no whitelist writes |
| `/privacy-guard help` | Help |

Commands run from the Web UI command palette and **never become model messages**, so the model cannot use them to edit the whitelist or self-authorise. (Anything that can write the whitelist files directly is the trust boundary — see “Known limitations”.)

## Conversation-based allow (`privacy_guard` tool)

Besides the slash commands, the plugin registers a model-facing `privacy_guard` tool so allow decisions can be made from the conversation:

- `action: "pending"` — list the findings of the most recent blocked command (id hash, rule, masked preview, file; never plaintext);
- `action: "list"` / `"status"` — inspect the three whitelists and the effective switches;
- `action: "allow"` / `"revoke"` with `scope: "session" | "project" | "global"` and `target: "<id-prefix|last>"` — change an allow decision.

**Every `allow`/`revoke` triggers a fresh DSH approval request** and only writes after the user approves. With the `never` policy or an unavailable approval channel the tool fails closed and changes nothing, so a model cannot silently widen its own permissions. Session entries live only in memory, project entries are written to the repository's `.dsh/privacy-guard-whitelist.json`, and global entries go to `state/whitelist.json`.

## Configuration (the `config:` block of `cordis.patch.yml`)

Configuration is validated by the Cordis `Config` (Schemastery) exported from `lib/schema.mjs`: invalid enums/types fail at load time instead of silently falling back. Fields marked `.volatile()` appear in the DSH settings form (the settings page projects only `volatile` fields); after an edit the loader commits the new values and emits `loader/volatile-update`, and the plugin refreshes its config in place — **no restart needed**. Array/object fields (`disableRules`, `extraRules`, `ignorePaths`) are still edited in `cordis.patch.yml` and take effect when the profile reloads.

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Master switch |
| `interceptCommit` | `true` | Check `git commit` |
| `interceptPush` | `true` | Check `git push` / `gh repo sync` |
| `fullScanOnFirstPush` | `ask` | `ask` / `always` / `never` |
| `unresolvedRepo` | `deny` | Policy when a commit/push is recognised but the repository cannot be located (variable path, not a repo, `GIT_DIR` override, …): `deny` / `allow` |
| `persistentShellCommits` | `deny` | Commits/pushes in a persistent terminal (`terminal_send`, real cwd unknown): `deny` / `allow` |
| `approvalScope` | `global` | Scope an approval is remembered in: `global` / `project` / `session` |
| `projectWhitelistFile` | `.dsh/privacy-guard-whitelist.json` | Project whitelist file (relative to the repository root, or absolute) |
| `whitelistOnApprove` | `true` | Add approved items to the whitelist automatically |
| `requireApprovalOnIncompleteScan` | `true` | Require approval when the scan is incomplete (timeout / limits / skipped large files / dynamic commit messages) |
| `disableRules` | `[]` | Built-in rule ids to disable |
| `extraRules` | `[]` | Custom rules `{id,label,pattern,flags,severity,mask,capture}` |
| `ignorePaths` | lock files / build output | Extra ignore globs appended to the defaults |
| `whitelistFile` | `state/whitelist.json` | Relative to the plugin directory, or absolute |
| `repoStateFile` | `state/repos.json` | Same as above |
| `logFile` | `state/push-privacy-guard.log` | Same as above; rotated once at mount when >5 MB |
| `maxTotalBytes` | 20 MiB | Total byte cap per diff / scan |
| `maxFileBytes` | 1 MiB | Per-file cap for the full scan / untracked files; a skipped file marks the scan incomplete (approval required by default) |
| `maxFiles` | 5000 | File-count cap for the full scan |
| `maxCommits` | 100 | Commit/ref and commit-message cap for multi-branch / mirror pushes |
| `maxFindings` | 200 | Findings cap per scan |
| `maxApprovalItems` | 20 | Maximum items listed in the approval prompt |
| `gitTimeoutMs` | 20000 | Timeout for a single git command |

Invalid values fall back to the default and write a `config.warning` log line; nothing fails silently.

## Community listing / plugin market

You can add this plugin's own **market index** through DSH “Plugins → Discover”. The index uses format 1 and is validated by `parseMarketIndex` from `@deepseek-ai/dsh-plugin-market-index`:

```text
https://raw.githubusercontent.com/lizhijie429/dsh-push-privacy-guard/main/market/index.json
```

Steps: first enable the experimental **Custom Plugin Market** (Plugins → Experimental plugins → More → Custom Plugin Market), then open Plugins → Discover → Index sources and paste the URL above, then search for “Push Privacy Guard” and install.

You can also install directly from the Git source (no npm release required):

```powershell
dsh plugin --profile desktop add https://github.com/lizhijie429/dsh-push-privacy-guard
```

Community listings submitted:

- [Open Plugin Market (community plugin index) listing request #216](https://github.com/polang233/dsh-plugin-index/issues/216) (pinned Git commit `756cc68`, v0.2.1).
- [awesome-dsh-plugin curated list PR #11727](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin/pull/11727) (`data/plugins/lizhijie429__dsh-push-privacy-guard.yml`).
- [GitHub Release v0.2.1](https://github.com/lizhijie429/dsh-push-privacy-guard/releases/tag/v0.2.1) (changelog and install instructions).

> The npm package is not published yet (it needs the maintainer's npm token); the market entry currently pins a Git commit. An index entry declares install parameters only; what is actually installed is determined by the repository's `package.json` and `cordis.patch.yml`.

## Installation

### Desktop (desktop profile)

Append the following to `%USERPROFILE%\.dsh\profiles\desktop\cordis.patch.yml` (replace `<user>` with the actual Windows user name):

```yaml
- insert:
    - id: push-privacy-guard
      name: 'C:\Users\<user>\.dsh\plugins\dsh-push-privacy-guard\index.mjs'
      config:
        fullScanOnFirstPush: ask
        whitelistOnApprove: true
```

The desktop profile's `patchReload` is `live`, so saving hot-reloads the config; once `plugin.mounted` appears in `state/push-privacy-guard.log`, the plugin is active. Code changes require restarting DeepSeek Harness (Node ESM module cache).

### Other profiles (bundle)

```powershell
dsh plugin --profile web add "file:$env:USERPROFILE\.dsh\plugins\dsh-push-privacy-guard"
```

`dsh.bundle.patch` in `package.json` loads the default `cordis.patch.yml`.

## Verification

```powershell
cd "$env:USERPROFILE\.dsh\plugins\dsh-push-privacy-guard"
npm test
Get-Content state\push-privacy-guard.log -Tail 20
```

CI: `.github/workflows/test.yml` runs `npm test` on `ubuntu-latest` / `windows-latest` (Node 22), including real-git integration cases.

End-to-end (requires the session approval policy to be `ask`, i.e. an approval panel is available):

1. In a temporary repository, `git add` a file containing `sk-<long string>` and run `git commit` → the UI asks for approval; approving commits successfully and adds an entry to `state/whitelist.json`; committing the same content again no longer asks.
2. Use a different fake key → reject → the command is blocked.
3. On the first `git push`, the “scan the whole repository?” question appears; rejecting it means only this push is checked and `state/repos.json` records the repository.

> When the session approval policy is `never` (approvals disabled), this plugin always **denies** matched items — that is the fail-closed design, not a bug. Switch the policy back to `ask` to get an approval prompt.

## Known limitations

- **Operations outside DSH are not covered**: manual terminal pushes, `git push` executed inside a script, and pushes from other machines bypass the plugin.
- **Only content about to enter git is checked**: unstaged/untracked files are not committed or pushed and therefore not scanned; `git push` estimates the upload range from local git data only (no network access).
- **Command text only**: `bash -c` / `pwsh -Command` are parsed one level deep; variable concatenation, aliases and indirect execution such as `node deploy.mjs` are not recognised.
- **Persistent terminals are denied by default**: the real cwd of `terminal_send` and similar sessions cannot be observed, so commits/pushes there are denied by default. Set `persistentShellCommits: allow` if needed (at your own risk), or use one-shot `pwsh`/`bash` with an explicit `workdir`.
- **Unresolvable repositories are denied by default**: `cd $repo`, `GIT_DIR=…`, a non-repository directory and similar cases are denied; use `git -C <absolute path>` / `workdir`, or set `unresolvedRepo: allow`.
- **force push / mirror**: multiple and wildcard refspecs plus tag objects are covered; **remote history overwritten by a force push** and remote refs deleted by `--mirror` are not re-scanned.
- **The first full scan only sees tracked files in `HEAD`**: secrets deleted from older commits are not rediscovered; files larger than `maxFileBytes` are skipped and mark the scan incomplete (approval required by default).
- **Messages reused by `git commit -C/-c/--fixup`** are not re-scanned at commit time (the push scan usually covers them; with `interceptPush: false` this is a residual risk).
- **The rule set is not omniscient**: high-entropy strings, custom internal formats and binary content may be missed; rules are configurable and, like any regex approach, can produce both false positives and false negatives.
- **The whitelist files are the trust boundary**: any principal that can write `state/whitelist.json` or a project whitelist file, or call the approval service directly (a model in a full-access session, another plugin, a configuration that points state at the workspace), can pre-seed entries and “self-authorise”. Keep the global state in the user directory and restrict write permissions. The `privacy_guard` tool itself requires user approval for every write, but approvals still follow the session policy.
- **A project whitelist file may be committed**: it contains hashes and masked previews only, so it is safe to share; add `.dsh/` to `.gitignore` if you do not want the team to see the allow list.
- **Session decisions are in-memory only**: they are lost when DSH restarts or the plugin reloads; use project or global scope for durable decisions.
- **Concurrent whitelist writes across processes** are only serialised within one process; running several DSH processes at once can overwrite each other.
- **The plugin does not clean repositories**: it only blocks/allows; it never deletes already-committed sensitive data or rewrites history.

## License

MIT, see [LICENSE](LICENSE).

`vendor/schemastery` and `vendor/cosmokit` are embedded from the DeepSeek Harness runtime's `@deepseek-ai/schemastery` / `@deepseek-ai/cosmokit` (MIT, their license files are kept alongside) so that an externally mounted plugin (absolute path) can still declare a native DSH `Config` schema.
