/**
 * Community vulnerability store (server-side only).
 *
 * The vulnerability data lives ONLY in a plain text file — locally
 * (COMMUNITY_VULN_DB_LOCAL_PATH) and/or on GitHub (COMMUNITY_VULN_DB_REMOTE_URL).
 * It is parsed and validated in memory; nothing is copied into a database
 * table. Edit the file, click Reload/Sync (or just run a scan after saving —
 * the local file is re-read automatically when it changes).
 */
import fs from 'fs/promises'
import path from 'path'
import type { CommunityVulnerability } from '@/types'
import { getCommunityDbConfig } from './config'
import { MESSAGES } from './constants'
import { DatabaseFormatError, ValidationIssue, parseDatabaseText, validateDatabase } from './validator'

type Db = any

const MAX_FILE_BYTES = 5 * 1024 * 1024
const REMOTE_TIMEOUT_MS = 10_000
const REMOTE_HOST = 'raw.githubusercontent.com'

export interface LoadSummary {
  source: 'local' | 'remote'
  source_url: string
  status: 'success' | 'partial' | 'failed'
  message: string
  total_records: number
  loaded_records: number
  skipped_records: number
  invalid_records: number
  duplicate_records: number
  issues: ValidationIssue[]
  error?: string
  fell_back_to_local?: boolean
}

interface Snapshot { records: CommunityVulnerability[]; summary: LoadSummary }

interface StoreState {
  localCache: { key: string; snapshot: Snapshot } | null
  remoteCache: { url: string; snapshot: Snapshot } | null
  lastLocal: LoadSummary | null
  lastRemote: LoadSummary | null
}

// Shared across all API routes (see the note in lib/supabase/local-db.ts).
const globalStore = globalThis as typeof globalThis & { __sentrixVulnStore?: StoreState }
const state: StoreState = (globalStore.__sentrixVulnStore ??= { localCache: null, remoteCache: null, lastLocal: null, lastRemote: null })

/** Test helper: forget everything held in memory. */
export function resetVulnStore() {
  state.localCache = state.remoteCache = null
  state.lastLocal = state.lastRemote = null
}

// ─── Reading the files ───────────────────────────────────────────────────────

export function resolveLocalPath(configured: string): string {
  const root = process.cwd()
  const resolved = path.resolve(root, configured)
  if (!resolved.startsWith(root + path.sep)) {
    throw new DatabaseFormatError('Local vulnerability database path must be inside the project directory.')
  }
  if (path.extname(resolved).toLowerCase() !== '.txt') {
    throw new DatabaseFormatError('Local vulnerability database must be a .txt file.')
  }
  return resolved
}

async function readLocalText(configured: string): Promise<{ text: string; key: string }> {
  const file = resolveLocalPath(configured)
  try {
    const stat = await fs.stat(file)
    if (stat.size > MAX_FILE_BYTES) throw new DatabaseFormatError('Vulnerability database file is too large (limit 5 MB).')
    return { text: await fs.readFile(file, 'utf8'), key: `${file}:${stat.mtimeMs}:${stat.size}` }
  } catch (e) {
    if (e instanceof DatabaseFormatError) throw e
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new DatabaseFormatError(MESSAGES.localMissing, `File not found: ${configured}`)
    }
    throw new DatabaseFormatError('Unable to read the local vulnerability database file.', (e as Error).message)
  }
}

export function validateRemoteUrl(url: string): URL {
  let u: URL
  try { u = new URL(url) } catch { throw new DatabaseFormatError(MESSAGES.remoteUnavailable, 'Remote URL is missing or invalid') }
  if (u.protocol !== 'https:' || u.hostname !== REMOTE_HOST) {
    throw new DatabaseFormatError(MESSAGES.remoteUnavailable, `Remote URL must be an https://${REMOTE_HOST}/... link`)
  }
  return u
}

export async function fetchRemoteText(url: string): Promise<string> {
  const u = validateRemoteUrl(url)
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REMOTE_TIMEOUT_MS)
  try {
    const res = await fetch(u.toString(), {
      signal: controller.signal,
      redirect: 'error',
      headers: { Accept: 'text/plain' },
      cache: 'no-store',
    })
    if (!res.ok) throw new DatabaseFormatError(MESSAGES.remoteUnavailable, `Remote server responded with HTTP ${res.status}`)
    if (Number(res.headers.get('content-length') ?? 0) > MAX_FILE_BYTES) throw new DatabaseFormatError('Remote vulnerability database is too large (limit 5 MB).')
    const text = await res.text()
    if (text.length > MAX_FILE_BYTES) throw new DatabaseFormatError('Remote vulnerability database is too large (limit 5 MB).')
    return text
  } catch (e) {
    if (e instanceof DatabaseFormatError) throw e
    const aborted = (e as Error).name === 'AbortError'
    throw new DatabaseFormatError(MESSAGES.remoteUnavailable, aborted ? 'Request timed out' : (e as Error).message)
  } finally {
    clearTimeout(timer)
  }
}

// ─── Parsing ─────────────────────────────────────────────────────────────────

function emptySummary(source: 'local' | 'remote', sourceUrl: string): LoadSummary {
  return {
    source, source_url: sourceUrl, status: 'failed', message: '', total_records: 0, loaded_records: 0,
    skipped_records: 0, invalid_records: 0, duplicate_records: 0, issues: [],
  }
}

/** Parse + validate file text. Throws DatabaseFormatError if the file is empty. */
export function loadFromText(text: string, source: 'local' | 'remote', sourceUrl: string): Snapshot {
  const summary = emptySummary(source, sourceUrl)
  const raw = parseDatabaseText(text)
  const { valid, issues, duplicates } = validateDatabase(raw)
  summary.total_records = raw.length
  summary.loaded_records = valid.length
  summary.issues = issues
  summary.duplicate_records = duplicates
  summary.invalid_records = issues.length - duplicates
  summary.skipped_records = issues.length

  if (valid.length === 0) {
    summary.status = 'failed'
    summary.message = MESSAGES.invalidFormat
    summary.error = 'No record passed validation'
  } else if (issues.length > 0) {
    summary.status = 'partial'
    summary.message = MESSAGES.partial
  } else {
    summary.status = 'success'
    summary.message = source === 'remote' ? MESSAGES.remoteSuccess : MESSAGES.localSuccess
  }
  return { records: valid.map(r => ({ ...r, vuln_id: r.id })), summary }
}

function failure(source: 'local' | 'remote', sourceUrl: string, e: unknown): LoadSummary {
  const s = emptySummary(source, sourceUrl)
  if (e instanceof DatabaseFormatError) { s.message = e.userMessage; s.error = e.message }
  else { s.message = source === 'remote' ? MESSAGES.remoteUnavailable : MESSAGES.invalidFormat; s.error = (e as Error).message }
  return s
}

async function loadLocal(force: boolean): Promise<Snapshot> {
  const cfg = getCommunityDbConfig()
  try {
    const { text, key } = await readLocalText(cfg.localPath)
    if (!force && state.localCache?.key === key) return state.localCache.snapshot
    const snapshot = loadFromText(text, 'local', cfg.localPath)
    state.localCache = snapshot.summary.status === 'failed' ? null : { key, snapshot }
    state.lastLocal = snapshot.summary
    return snapshot
  } catch (e) {
    state.localCache = null
    state.lastLocal = failure('local', cfg.localPath, e)
    throw e
  }
}

// ─── Audit log ───────────────────────────────────────────────────────────────

async function audit(db: Db, userId: string | null, action: string, details: Record<string, unknown>) {
  try { await db.from('audit_logs').insert({ user_id: userId, action, details }) }
  catch (e) { console.error('[SentriX] audit log failed', e) }
}

function auditDetails(s: LoadSummary) {
  return {
    source: s.source, source_url: s.source_url, status: s.status, message: s.message,
    total: s.total_records, loaded: s.loaded_records, skipped: s.skipped_records,
    error: s.status === 'failed' ? s.error : undefined,
  }
}

// ─── Public actions ──────────────────────────────────────────────────────────

/** Re-read the local text file now (admin button). */
export async function reloadLocal(db: Db, userId: string | null): Promise<LoadSummary> {
  const cfg = getCommunityDbConfig()
  await audit(db, userId, 'vuln_db_local_import_started', { source_url: cfg.localPath })
  let summary: LoadSummary
  try { summary = (await loadLocal(true)).summary } catch (e) { summary = failure('local', cfg.localPath, e) }
  await audit(db, userId, `vuln_db_local_import_${summary.status === 'failed' ? 'failed' : 'completed'}`, auditDetails(summary))
  return summary
}

/** Download the GitHub text file (admin button). On failure the local file keeps being used. */
export async function syncRemote(db: Db, userId: string | null): Promise<LoadSummary> {
  const cfg = getCommunityDbConfig()
  await audit(db, userId, 'vuln_db_github_sync_started', { source_url: cfg.remoteUrl })
  let summary: LoadSummary
  try {
    const snapshot = loadFromText(await fetchRemoteText(cfg.remoteUrl), 'remote', cfg.remoteUrl)
    summary = snapshot.summary
    if (summary.status !== 'failed') state.remoteCache = { url: cfg.remoteUrl, snapshot }
  } catch (e) {
    summary = failure('remote', cfg.remoteUrl, e)
  }
  state.lastRemote = summary
  await audit(db, userId, `vuln_db_github_sync_${summary.status === 'failed' ? 'failed' : 'completed'}`, auditDetails(summary))
  if (summary.status === 'failed') {
    summary = { ...summary, message: MESSAGES.remoteUnavailable }
    try { await loadLocal(false); summary.fell_back_to_local = true } catch { /* local also unavailable */ }
  }
  return summary
}

// ─── Reading records ─────────────────────────────────────────────────────────

function merge(base: CommunityVulnerability[], extra: CommunityVulnerability[]): CommunityVulnerability[] {
  const byId = new Map(base.map(r => [r.id, r]))
  for (const r of extra) {
    const prev = byId.get(r.id)
    if (!prev || Date.parse(r.last_updated) > Date.parse(prev.last_updated)) byId.set(r.id, r) // newer wins
  }
  return Array.from(byId.values())
}

/**
 * The records currently in effect, according to COMMUNITY_VULN_DB_SYNC_MODE.
 * `fetchRemoteIfMissing` lets a scan pull the GitHub file once if it has not been synced yet.
 */
export async function getCommunityRecords(
  db: Db, userId: string | null, opts: { fetchRemoteIfMissing?: boolean } = {},
): Promise<CommunityVulnerability[]> {
  const cfg = getCommunityDbConfig()
  if (!cfg.enabled) return []

  let local: CommunityVulnerability[] = []
  const loadLocalSafe = async () => {
    try { local = (await loadLocal(false)).records } catch (e) { console.error('[SentriX] local vulnerability file:', (e as Error).message) }
  }

  const needRemote = cfg.syncMode !== 'local' && cfg.remoteUrl !== ''
  if (needRemote && opts.fetchRemoteIfMissing && state.remoteCache?.url !== cfg.remoteUrl) await syncRemote(db, userId)
  const remote = needRemote && state.remoteCache?.url === cfg.remoteUrl ? state.remoteCache.snapshot.records : []

  if (cfg.syncMode === 'remote' && remote.length > 0) return remote
  await loadLocalSafe()
  return cfg.syncMode === 'both' ? merge(local, remote) : local
}

/** Config + what was last loaded, for the status page. Reads the local file (cheap, cached). */
export async function getLoadInfo() {
  try { await loadLocal(false) } catch { /* reflected in state.lastLocal */ }
  return { local: state.lastLocal, remote: state.lastRemote }
}
