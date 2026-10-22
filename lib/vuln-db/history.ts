/**
 * Import/sync history, derived from the audit log (no separate table).
 */
import type { VulnDbRun } from '@/types'

type Db = any

const RESULT_ACTIONS = [
  'vuln_db_local_import_completed', 'vuln_db_local_import_failed',
  'vuln_db_github_sync_completed', 'vuln_db_github_sync_failed',
]

export async function getRunHistory(db: Db, limit = 50): Promise<VulnDbRun[]> {
  const { data } = await db.from('audit_logs').select('*').in('action', RESULT_ACTIONS).order('created_at', { ascending: false }).limit(limit)
  return (data ?? []).map((row: { created_at: string; action: string; details: Record<string, any> }) => ({
    at: row.created_at,
    source: row.action.startsWith('vuln_db_github') ? 'remote' : 'local',
    status: row.details?.status ?? (row.action.endsWith('_failed') ? 'failed' : 'success'),
    total_records: row.details?.total ?? 0,
    loaded_records: row.details?.loaded ?? 0,
    skipped_records: row.details?.skipped ?? 0,
    message: row.details?.message ?? '',
  }))
}

export async function lastRunFromAudit(db: Db): Promise<{ last: VulnDbRun | null; lastSuccessAt: string | null }> {
  const runs = await getRunHistory(db, 50)
  return { last: runs[0] ?? null, lastSuccessAt: runs.find(r => r.status !== 'failed')?.at ?? null }
}
