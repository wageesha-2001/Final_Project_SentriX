import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { getDeviceInventory, getVisibleCompletedScans, withSecuritySummary } from '@/lib/devices/inventory'

/**
 * GET /api/devices            — device inventory: each device once, from its latest completed scan
 * GET /api/devices?scan=<id>  — every device found by one scan
 */
export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  const scanId = req.nextUrl.searchParams.get('scan')

  try {
    if (scanId) {
      const { data: scan } = await supabase.from('scans').select('*').eq('id', scanId).single()
      if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
      if (user!.role !== 'admin' && scan.user_id !== user!.sub) {
        return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
      }
      const { data, error } = await supabase.from('devices').select('*').eq('scan_id', scanId)
        .order('risk_score', { ascending: false })
      if (error) throw error
      const simulated = scan.scan_mode === 'simulated'
      return NextResponse.json({ data: (await withSecuritySummary(supabase, data || [])).map(d => ({ ...d, simulated })) })
    }

    const scans = await getVisibleCompletedScans(supabase, user!)
    return NextResponse.json({ data: await getDeviceInventory(supabase, scans) })
  } catch (error) {
    console.error('Devices fetch error:', error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
