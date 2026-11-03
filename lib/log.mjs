/**
 * Minimal append-only host log with one-time size rotation at mount.
 *
 * @module dsh-push-privacy-guard/log
 */

import { appendFileSync, mkdirSync, renameSync, statSync } from 'node:fs'
import path from 'node:path'

/** Rotate the log once it passes this size (checked only when opened). */
export const LOG_MAX_BYTES = 5 * 1024 * 1024

/**
 * Create a logger that never throws.
 *
 * @param {string} file - absolute log path.
 * @returns {(line:string)=>{}} log function.
 */
export function createLog(file) {
  try {
    if (statSync(file).size > LOG_MAX_BYTES) renameSync(file, `${file}.1`)
  } catch {
    /* no log yet, or rotation failed: keep appending */
  }
  return line => {
    try {
      mkdirSync(path.dirname(file), { recursive: true })
      appendFileSync(file, `${new Date().toISOString()} ${redactLine(line)}\n`, 'utf8')
    } catch {
      /* swallow logging failures */
    }
  }
}

/** Strip control characters and bound line length. */
export function redactLine(line) {
  return String(line ?? '')
    .replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ')
    .slice(0, 400)
}
