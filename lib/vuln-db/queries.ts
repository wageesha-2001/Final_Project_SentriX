/**
 * Helpers shared by the scanner, API routes, and report generator.
 * (Vulnerability records themselves come from the text file — see store.ts.
 * Only per-scan match results are saved, in device_vulnerability_matches.)
 */
import type { CommunityVulnerability, EnrichedMatch } from '@/types'
import { COMMUNITY_CHECK_SLUG } from './constants'
import { getCommunityDbConfig } from './config'

type Db = any

/** Mapping runs only if the env flag is on AND the admin-controlled check is enabled. */
export async function isCommunityMappingEnabled(db: Db): Promise<boolean> {
  if (!getCommunityDbConfig().enabled) return false
  const { data } = await db.from('vulnerability_checks').select('enabled').eq('slug', COMMUNITY_CHECK_SLUG).single()
  // No row yet (migration not run) → default to enabled.
  return data ? data.enabled !== false : true
}

/** The part of a record that is copied into a match so old scans and reports stay readable. */
export function snapshotOf(v: CommunityVulnerability): EnrichedMatch['vulnerability'] {
  return {
    vuln_id: v.vuln_id, title: v.title, description: v.description, vendor: v.vendor,
    category: v.category, severity: v.severity, cvss_score: v.cvss_score, risk_score: v.risk_score,
    recommendation: v.recommendation, remediation_steps: v.remediation_steps,
    source_type: v.source_type, reference_url: v.reference_url, confidence_note: v.confidence_note,
  }
}

const SEVERITY_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 }

/** Saved matches for the given devices, most severe first. */
export async function getEnrichedMatches(db: Db, deviceIds: string[]): Promise<EnrichedMatch[]> {
  if (deviceIds.length === 0) return []
  const { data: rows } = await db.from('device_vulnerability_matches').select('*').in('device_id', deviceIds)
  const enriched: EnrichedMatch[] = []
  for (const row of rows ?? []) {
    const { vulnerability_snapshot, ...match } = row
    if (!vulnerability_snapshot) continue
    enriched.push({ ...match, vulnerability: vulnerability_snapshot })
  }
  return enriched.sort((a, b) =>
    (SEVERITY_RANK[a.vulnerability.severity] ?? 5) - (SEVERITY_RANK[b.vulnerability.severity] ?? 5) ||
    b.risk_score_added - a.risk_score_added)
}
