/**
 * Small JSON persistence helpers: tolerant reads, atomic writes, and
 * per-file write serialization so concurrent approvals cannot interleave.
 *
 * @module dsh-push-privacy-guard/store
 */

import { randomBytes } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

/** Read a JSON file. Missing files are `{data:null}`; broken files carry a warning. */
export function readJson(file) {
  let text
  try {
    text = fs.readFileSync(file, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return { data: null }
    return { data: null, warning: error instanceof Error ? error.message : String(error) }
  }
  if (text.trim().length === 0) return { data: null, warning: 'empty file' }
  try {
    return { data: JSON.parse(text) }
  } catch (error) {
    return { data: null, warning: error instanceof Error ? error.message : String(error) }
  }
}

/** Write JSON atomically (same-directory temp file + rename). */
export function writeJsonAtomic(file, data) {
  const directory = path.dirname(file)
  fs.mkdirSync(directory, { recursive: true })
  const temporary = path.join(
    directory,
    `.${path.basename(file)}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`,
  )
  fs.writeFileSync(temporary, `${JSON.stringify(data, null, 2)}\n`, 'utf8')
  try {
    fs.renameSync(temporary, file)
  } catch (error) {
    try {
      fs.unlinkSync(temporary)
    } catch {
      /* best effort */
    }
    throw error
  }
}

/** Per-file promise chains: same-file writes run one after another. */
const chains = new Map()

/**
 * Serialize a read-modify-write task for one file path.
 *
 * @param {string} file
 * @param {() => Promise<any>} task
 * @returns {Promise<any>}
 */
export function serialize(file, task) {
  const previous = chains.get(file) ?? Promise.resolve()
  const run = previous.then(task, task)
  const tail = run.catch(() => {})
  chains.set(file, tail)
  tail.finally(() => {
    if (chains.get(file) === tail) chains.delete(file)
  })
  return run
}
