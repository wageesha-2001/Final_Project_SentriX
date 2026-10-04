// Sliding-window in-memory rate limiter.
// Not suitable for multi-process deployments — swap for Redis in production.

interface Window { timestamps: number[] }
const store = new Map<string, Window>()

export function rateLimit(key: string, maxRequests: number, windowMs: number): boolean {
  const now = Date.now()
  const entry = store.get(key) ?? { timestamps: [] }
  entry.timestamps = entry.timestamps.filter(t => now - t < windowMs)
  if (entry.timestamps.length >= maxRequests) {
    store.set(key, entry)
    return false // blocked
  }
  entry.timestamps.push(now)
  store.set(key, entry)
  return true // allowed
}

export function getRateLimitHeaders(key: string, maxRequests: number, windowMs: number) {
  const now = Date.now()
  const entry = store.get(key)
  const used = entry ? entry.timestamps.filter(t => now - t < windowMs).length : 0
  return {
    'X-RateLimit-Limit': String(maxRequests),
    'X-RateLimit-Remaining': String(Math.max(0, maxRequests - used)),
  }
}
