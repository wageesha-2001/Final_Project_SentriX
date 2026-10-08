import { NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { getAuthUser } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { getCommunityDbConfig } from '@/lib/vuln-db/config'
import { reloadLocal, syncRemote } from '@/lib/vuln-db/store'
import { getRunHistory } from '@/lib/vuln-db/history'

const bodySchema = z.object({ source: z.enum(['local', 'remote']) })

/** Sync history — admin only. */
export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  if (user.role !== 'admin') return NextResponse.json({ error: 'Forbidden — admin only' }, { status: 403 })

  const supabase = createServerSupabase()
  return NextResponse.json({ data: await getRunHistory(supabase) })
}

/** Reload the local text file or sync the GitHub raw file — admin only. */
export async function POST(req: NextRequest) {
  const user = await getAuthUser(req)
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  if (user.role !== 'admin') return NextResponse.json({ error: 'Forbidden — admin only' }, { status: 403 })

  const parsed = bodySchema.safeParse(await req.json().catch(() => null))
  if (!parsed.success) return NextResponse.json({ error: 'source must be "local" or "remote"' }, { status: 400 })

  if (!getCommunityDbConfig().enabled) {
    return NextResponse.json({ error: 'The Community Vulnerability Database is disabled (COMMUNITY_VULN_DB_ENABLED=false).' }, { status: 409 })
  }

  const supabase = createServerSupabase()
  try {
    const summary = parsed.data.source === 'local'
      ? await reloadLocal(supabase, user.sub)
      : await syncRemote(supabase, user.sub)
    const { error: _omit, ...publicSummary } = summary // internal detail stays in the audit log
    return NextResponse.json({ data: publicSummary }, { status: summary.status === 'failed' && !summary.fell_back_to_local ? 422 : 200 })
  } catch (e) {
    console.error('Vulnerability sync error:', e)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
