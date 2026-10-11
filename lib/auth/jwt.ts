import { SignJWT, jwtVerify } from 'jose'
import { JWTPayload, UserRole } from '@/types'

const jwtSecret = process.env.JWT_SECRET
if (!jwtSecret) {
  throw new Error('JWT_SECRET environment variable must be set')
}
if (jwtSecret.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters long')
}
const secret = new TextEncoder().encode(jwtSecret)

export async function signToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): Promise<string> {
  // A unique token id lets a single session be revoked on logout.
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime('24h')
    .sign(secret)
}

export async function verifyToken(token: string): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, secret)
  return payload as unknown as JWTPayload
}

export async function getTokenFromCookies(cookieHeader: string | null): Promise<JWTPayload | null> {
  if (!cookieHeader) return null
  const cookies = Object.fromEntries(
    cookieHeader.split(';').map(c => {
      const [key, ...val] = c.trim().split('=')
      return [key, val.join('=')]
    })
  )
  const token = cookies['sentrix_token']
  if (!token) return null
  try {
    return await verifyToken(token)
  } catch {
    return null
  }
}
