/**
 * dsh-push-privacy-guard — a DSH Host plugin that privacy-checks `git commit`
 * and `git push` (plus `gh repo sync`) before anything leaves the machine.
 *
 * Extension points:
 *   - `tools/pre-execute` (async waterfall): detects the operation, scans the
 *     content that would enter git, and either continues or returns a denial;
 *   - `ctx.approval.request()`: shows a one-time approval in the Harness UI;
 *   - `ctx.commands.register()` (optional): `/privacy-guard` management, which
 *     is user-only and never becomes a model message.
 *
 * Design notes:
 *   - zero runtime dependencies (node built-ins only), mountable by absolute
 *     path or as a bundle;
 *   - fail-closed for recognised commit/push commands: a scan error blocks the
 *     command rather than risking an upload;
 *   - the raw matched value never reaches the model, the approval reason, the
 *     whitelist file, or the log.
 *
 * @module dsh-push-privacy-guard
 */

import { fileURLToPath } from 'node:url'
import { executePrivacyCommand } from './lib/commands.mjs'
import { normalizeConfig } from './lib/config.mjs'
import { createGitRunner } from './lib/git.mjs'
import { createGuard, resolveSessionCwd } from './lib/guard.mjs'
import { createLog } from './lib/log.mjs'
import { compileRules } from './lib/rules.mjs'
import { sessionIdOf } from './lib/scopes.mjs'
import { registerPrivacyTool } from './lib/tool.mjs'

/** Cordis plugin name. */
export const name = 'push-privacy-guard'

/** Loader-enforced config schema; the DSH settings form derives its fields from it. */
export { Config } from './lib/schema.mjs'

/** The tool registry is required; `commands` is used opportunistically. */
export const inject = ['tools']

const PLUGIN_DIR = fileURLToPath(new URL('.', import.meta.url))

/**
 * Mount the guard and its management command.
 *
 * @param {any} ctx - Cordis context of the profile/host plugin tree.
 * @param {unknown} rawConfig - the `config:` block of the loader entry.
 */
export function apply(ctx, rawConfig) {
  let log = () => {}
  try {
    const config = normalizeConfig(rawConfig, PLUGIN_DIR)
    log = createLog(config.logFile)
    const warn = message => {
      log(`config.warning ${message}`)
      try {
        ctx.logger?.warn?.(`[push-privacy-guard] ${message}`)
      } catch {
        /* host logger is optional */
      }
    }
    for (const message of config.warnings) warn(message)

    const rules = compileRules(config)
    const guard = createGuard({ ctx, config, rules, log })

    // The loader commits `.volatile()` config changes into the running entry
    // without remounting; refresh the normalized snapshot in place so the
    // running guard and commands see the new switches immediately.
    const reloadVolatileConfig = () => {
      try {
        const next = normalizeConfig(rawConfig, PLUGIN_DIR)
        for (const message of next.warnings) warn(message)
        Object.assign(config, next)
        log(
          `config.volatile-update enabled=${config.enabled} commit=${config.interceptCommit} push=${config.interceptPush} fullScan=${config.fullScanOnFirstPush}`,
        )
      } catch (error) {
        log(`config.volatile-update-failed ${safeMessage(error)}`)
      }
    }
    if (typeof ctx.on === 'function') {
      const registerVolatileConfig = () => {
        const off = ctx.on('loader/volatile-update', reloadVolatileConfig)
        return () => {
          try {
            off?.()
          } catch {
            /* disposal is best effort */
          }
        }
      }
      if (typeof ctx.effect === 'function') {
        ctx.effect(registerVolatileConfig, 'push-privacy-guard: volatile config')
      } else {
        registerVolatileConfig()
      }
    }

    const registerGuard = () => {
      const off = ctx.on('tools/pre-execute', guard.handler, { prepend: true })
      log('pre-execute.registered')
      return () => {
        try {
          off?.()
        } catch {
          /* disposal is best effort */
        }
      }
    }
    if (typeof ctx.effect === 'function') {
      ctx.effect(registerGuard, 'push-privacy-guard: pre-execute')
    } else {
      const off = registerGuard()
      if (typeof ctx.on === 'function') ctx.on('dispose', off)
    }

    registerCommands(ctx, config, log)

    const registerTool = () => {
      try {
        return registerPrivacyTool(ctx, { config, log })
      } catch (error) {
        log(`tool.register-failed ${safeMessage(error)}`)
        return () => {}
      }
    }
    if (typeof ctx.effect === 'function') {
      ctx.effect(registerTool, 'push-privacy-guard: privacy_guard tool')
    } else {
      registerTool()
    }

    if (typeof ctx.effect === 'function') {
      ctx.effect(() => () => log('plugin.disposed'), 'push-privacy-guard: lifecycle')
    }

    log(`plugin.mounted pid=${process.pid} rules=${rules.length}`)
  } catch (error) {
    log(`plugin.error ${safeMessage(error)}`)
    try {
      // Surface a mount failure instead of silently disabling the guard.
      ctx.logger?.warn?.(`push-privacy-guard disabled after mount error: ${safeMessage(error)}`)
    } catch {
      /* host logger is optional */
    }
  }
}

/** Register `/privacy-guard` when the profile composes the command runtime. */
function registerCommands(ctx, config, log) {
  if (typeof ctx.inject !== 'function') return
  try {
    ctx.inject(['commands'], commandCtx => {
      try {
        commandCtx.commands.register({
          name: 'privacy-guard',
          description: 'Inspect or manage the commit/push privacy whitelist',
          input: {
            hint: '[list|remove <id>|clear confirm|status|repos|reset <path|all>|scan|help]',
          },
          handler: ({ agent, rawInput }) =>
            executePrivacyCommand(rawInput, {
              config,
              cwd: resolveSessionCwd(ctx, agent?.session),
              sessionId: sessionIdOf(agent),
              createRunner: options => createGitRunner({ cwd: options?.cwd, timeoutMs: config.gitTimeoutMs }),
            }),
        })
        log('commands.registered name=privacy-guard')
      } catch (error) {
        log(`commands.register-failed ${safeMessage(error)}`)
      }
    })
  } catch (error) {
    log(`commands.inject-failed ${safeMessage(error)}`)
  }
}

/** One-line log-safe rendering. */
function safeMessage(error) {
  const message = error instanceof Error ? error.message : String(error ?? '')
  return message.replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ').slice(0, 300)
}
