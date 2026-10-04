import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'

export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()
  const isAdmin = user!.role === 'admin'

  let scanQuery = supabase.from('scans').select('*').order('started_at', { ascending: false })
  if (!isAdmin) scanQuery = scanQuery.eq('user_id', user!.sub)
  const { data: scans } = await scanQuery

  const completedScans = (scans || []).filter((s: Record<string, unknown>) => s.status === 'completed')
  const totalDevices = completedScans.reduce((sum: number, s: Record<string, unknown>) => sum + ((s.total_devices as number) || 0), 0)
  const vulnerableDevices = completedScans.reduce((sum: number, s: Record<string, unknown>) => sum + ((s.vulnerable_devices as number) || 0), 0)
  const criticalDevices = completedScans.reduce((sum: number, s: Record<string, unknown>) => sum + ((s.critical_devices as number) || 0), 0)
  const secureDevices = totalDevices - vulnerableDevices

  const riskDistribution = [
    { name: 'Secure', value: 0, color: '#00ff9d' },
    { name: 'Low', value: 0, color: '#60a5fa' },
    { name: 'Medium', value: 0, color: '#ffcc00' },
    { name: 'High', value: 0, color: '#fb923c' },
    { name: 'Critical', value: 0, color: '#ff3b5c' },
  ]

  const scanIds = (scans || []).map((s: Record<string, unknown>) => s.id)
  let devices: { risk_level: string }[] = []
  if (isAdmin || scanIds.length > 0) {
    const deviceQuery = isAdmin
      ? supabase.from('devices').select('risk_level')
      : supabase.from('devices').select('risk_level').in('scan_id', scanIds)
    const { data } = await deviceQuery
    devices = data || []
  }
  if (devices.length > 0) {
    devices.forEach(d => {
      const idx = riskDistribution.findIndex(r => r.name.toLowerCase() === d.risk_level)
      if (idx >= 0) riskDistribution[idx].value++
    })
  }

  return NextResponse.json({
    data: {
      total_devices: totalDevices,
      secure_devices: secureDevices,
      vulnerable_devices: vulnerableDevices,
      critical_devices: criticalDevices,
      total_scans: (scans || []).length,
      latest_scan: (scans || [])[0] || null,
      recent_scans: (scans || []).slice(0, 5),
      risk_distribution: riskDistribution,
    },
  })
}
