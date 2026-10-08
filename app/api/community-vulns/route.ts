import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { SEVERITIES } from '@/lib/vuln-db/constants'
import { getCommunityRecords } from '@/lib/vuln-db/store'
import type { CommunityVulnerability } from '@/types'

const PAGE_SIZE_MAX = 100

/** Search / filter the stored community vulnerability records (read-only, any signed-in user). */
export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError

  const sp = new URL(req.url).searchParams
  const q = (sp.get('q') ?? '').trim().toLowerCase()
  const vendor = sp.get('vendor') ?? ''
  const category = sp.get('category') ?? ''
  const severity = sp.get('severity') ?? ''
  const sourceType = sp.get('source_type') ?? ''
  const page = Math.max(parseInt(sp.get('page') ?? '0') || 0, 0)
  const limit = Math.min(Math.max(parseInt(sp.get('limit') ?? '25') || 25, 1), PAGE_SIZE_MAX)

  const supabase = createServerSupabase()
  const all = await getCommunityRecords(supabase, user!.sub)

  const filtered = all.filter(v =>
    (!vendor || v.vendor === vendor) &&
    (!category || v.category === category) &&
    (!severity || v.severity === severity) &&
    (!sourceType || v.source_type === sourceType) &&
    (!q || [v.vuln_id, v.title, v.description, v.vendor, v.category, ...(v.affected_models ?? [])]
      .some(f => String(f).toLowerCase().includes(q))))
    .sort((a, b) =>
      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.vuln_id.localeCompare(b.vuln_id))

  const distinct = (pick: (v: CommunityVulnerability) => string) => Array.from(new Set(all.map(pick))).sort()
  return NextResponse.json({
    data: {
      records: filtered.slice(page * limit, (page + 1) * limit),
      total: filtered.length,
      page,
      limit,
      filters: {
        vendors: distinct(v => v.vendor),
        categories: distinct(v => v.category),
        severities: SEVERITIES,
        source_types: distinct(v => v.source_type),
      },
    },
  })
}
