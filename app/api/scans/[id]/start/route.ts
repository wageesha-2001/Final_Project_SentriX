import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { runMockScan } from '@/lib/scanner/mock-scanner'
import { rateLimit } from '@/lib/utils/rate-limiter'

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  if (!rateLimit(`scan-start:${user!.sub}`, 10, 60_000)) {
    return NextResponse.json({ error: 'Too many requests. Please wait before starting another scan.' }, { status: 429 })
  }
  const supabase = createServerSupabase()
  const { data: scan, error } = await supabase.from('scans').select('*').eq('id', params.id).single()
  if (error || !scan) return NextResponse.json({ error: 'Scan not found' }, { status: 404 })
  if (user!.role !== 'admin' && scan.user_id !== user!.sub) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  if (scan.status === 'running') {
    return NextResponse.json({ error: 'Scan is already running' }, { status: 400 })
  }
  // A scan runs once; re-running a finished scan would duplicate its devices. Start a new scan instead.
  if (scan.status !== 'pending') {
    return NextResponse.json({ error: `Scan is already ${scan.status}. Start a new scan instead.` }, { status: 400 })
  }

  // Atomically claim the scan: only proceed if this request is the one that
  // actually flipped the status, so concurrent start requests for the same
  // scan can't both launch a runMockScan pass.
  const { data: claimed } = await supabase
    .from('scans')
    .update({ status: 'running', progress: 0, started_at: new Date().toISOString(), completed_at: null })
    .eq('id', params.id)
    .eq('status', 'pending')
    .select()
  if (!claimed || claimed.length === 0) {
    return NextResponse.json({ error: 'Scan is already running' }, { status: 400 })
  }

  const { data: settings } = await supabase.from('settings').select('*').eq('user_id', user!.sub).single()
  const safeScanMode = settings?.safe_scan_mode ?? true
  runMockScan(params.id, scan.network_range, safeScanMode).catch(console.error)
  await supabase.from('audit_logs').insert({
    user_id: user!.sub,
    action: 'scan_started',
    details: { scan_id: params.id, scan_name: scan.scan_name, network_range: scan.network_range, safe_scan_mode: safeScanMode },
  })
  return NextResponse.json({ message: 'Scan started', data: { scan_id: params.id } })
}
