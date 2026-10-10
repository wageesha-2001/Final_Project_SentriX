import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { generateReportHtml } from '@/lib/scanner/report-generator'
import { getEnrichedMatches } from '@/lib/vuln-db/queries'

export async function POST(req: NextRequest, { params }: { params: { scanId: string } }) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  const { data: scan } = await supabase.from('scans').select('*').eq('id', params.scanId).single()
  if (!scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  if (user!.role !== 'admin' && scan.user_id !== user!.sub) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  if (scan.status !== 'completed') {
    return NextResponse.json({ error: 'Reports can only be generated for completed scans.' }, { status: 400 })
  }
  const { data: devices } = await supabase.from('devices').select('*').eq('scan_id', params.scanId)
  const allMatches = await getEnrichedMatches(supabase, (devices || []).map((d: Record<string, unknown>) => d.id as string))
  const devicesWithVulns = await Promise.all(
    (devices || []).map(async (device: Record<string, unknown>) => {
      const { data: vulns } = await supabase.from('vulnerabilities').select('*').eq('device_id', device.id)
      return {
        ...device,
        vulnerabilities: vulns || [],
        community_matches: allMatches.filter(m => m.device_id === device.id),
      }
    })
  )
  const reportHtml = generateReportHtml(scan, devicesWithVulns)
  await supabase.from('reports').delete().eq('scan_id', params.scanId)
  const { data: report } = await supabase
    .from('reports')
    .insert({ scan_id: params.scanId, report_title: `Security Report - ${scan.scan_name}`, report_html: reportHtml })
    .select()
    .single()
  await supabase.from('audit_logs').insert({
    user_id: user!.sub,
    action: 'report_generated',
    details: { scan_id: params.scanId, scan_name: scan.scan_name },
  })
  return NextResponse.json({ data: report }, { status: 201 })
}
