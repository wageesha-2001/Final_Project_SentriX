import { NextRequest, NextResponse } from 'next/server'
import { verifyToken } from '@/lib/auth/jwt'

// Logout must work even with an invalid/expired token (it just clears the
// cookie), so it stays public alongside login.
const publicPaths = ['/login', '/api/auth/login', '/api/auth/logout']

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl
  const isApi = pathname.startsWith('/api/')
  const isPublic = publicPaths.some(p => pathname.startsWith(p))

  if (isPublic) return NextResponse.next()

  const token = req.cookies.get('sentrix_token')?.value
  if (!token) {
    if (isApi) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    return NextResponse.redirect(new URL('/login', req.url))
  }
  try {
    await verifyToken(token)
    return NextResponse.next()
  } catch {
    if (isApi) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const response = NextResponse.redirect(new URL('/login', req.url))
    response.cookies.delete('sentrix_token')
    return response
  }
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|public/).*)'],
}
