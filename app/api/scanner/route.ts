import { NextRequest, NextResponse } from 'next/server'
import { getAuthUser, requireAuth } from '@/lib/auth/middleware'

/** Which discovery engine scans use, so the UI can describe it accurately. */
export async function GET(req: NextRequest) {
  const user = await getAuthUser(req)
  const authError = requireAuth(user)
  if (authError) return authError
  return NextResponse.json({ data: { mode: process.env.SENTRIX_REAL_SCAN === '1' ? 'real' : 'simulated' } })
}
