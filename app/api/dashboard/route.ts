import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'
import { createServerSupabase } from '@/lib/supabase/server'
import { getDeviceInventory, getVisibleCompletedScans } from '@/lib/devices/inventory'

export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  const supabase = createServerSupabase()

  let scanQuery = supabase.from('scans').select('*').order('started_at', { ascending: false })
  if (user!.role !== 'admin') scanQuery = scanQuery.eq('user_id', user!.sub)
  const { data: scans } = await scanQuery

  // Counts come from the device inventory (each physical device once, latest
  // completed scan), so re-scanning a network never inflates the numbers.
  const inventory = await getDeviceInventory(supabase, await getVisibleCompletedScans(supabase, user!))
  const count = (pred: (d: (typeof inventory)[number]) => boolean) => inventory.filter(pred).length

  const riskDistribution = [
    { name: 'Secure', value: count(d => d.risk_level === 'secure'), color: '#00ff9d' },
    { name: 'Low', value: count(d => d.risk_level === 'low'), color: '#60a5fa' },
    { name: 'Medium', value: count(d => d.risk_level === 'medium'), color: '#ffcc00' },
    { name: 'High', value: count(d => d.risk_level === 'high'), color: '#fb923c' },
    { name: 'Critical', value: count(d => d.risk_level === 'critical'), color: '#ff3b5c' },
  ]

  return NextResponse.json({
    data: {
      total_devices: inventory.length,
      camera_devices: count(d => d.device_type === 'camera'),
      nvr_devices: count(d => d.device_type === 'nvr' || d.device_type === 'dvr'),
      secure_devices: count(d => d.security_status === 'secure'),
      potential_devices: count(d => d.security_status === 'potential'),
      vulnerable_devices: count(d => d.security_status === 'vulnerable'),
      critical_devices: count(d => d.risk_level === 'critical'),
      total_scans: (scans || []).length,
      latest_scan: (scans || [])[0] || null,
      recent_scans: (scans || []).slice(0, 5),
      risk_distribution: riskDistribution,
    },
  })
}
