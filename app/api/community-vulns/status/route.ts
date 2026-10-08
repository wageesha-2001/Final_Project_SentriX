import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { getCommunityDbConfig } from '@/lib/vuln-db/config'
import { COMMUNITY_CHECK_SLUG } from '@/lib/vuln-db/constants'
import { getCommunityRecords, getLoadInfo } from '@/lib/vuln-db/store'
import { lastRunFromAudit } from '@/lib/vuln-db/history'

/** Configuration + last load summary for the Community Vulnerability Database page. */
export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError

  const supabase = createServerSupabase()
  const cfg = getCommunityDbConfig()
  const records = await getCommunityRecords(supabase, user!.sub)
  const info = await getLoadInfo()

  const [{ data: matches }, { data: check }, lastRun] = await Promise.all([
    supabase.from('device_vulnerability_matches').select('id'),
    supabase.from('vulnerability_checks').select('id, enabled').eq('slug', COMMUNITY_CHECK_SLUG).single(),
    lastRunFromAudit(supabase),
  ])

  return NextResponse.json({
    data: {
      enabled: cfg.enabled,
      sync_mode: cfg.syncMode,
      local_path: cfg.localPath,
      remote_url: cfg.remoteUrl,
      total_records: records.length,
      total_matches: (matches ?? []).length,
      last_load: info.local,
      last_remote_load: info.remote,
      last_sync: lastRun.last,
      last_successful_sync_at: lastRun.lastSuccessAt,
      check: check ? { id: check.id, enabled: check.enabled } : null,
      is_admin: user!.role === 'admin',
    },
  })
}
