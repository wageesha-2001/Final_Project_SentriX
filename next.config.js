/** @type {import('next').NextConfig} */
// A static header, not per-request-nonced: most pages here are prerendered
// once at build time (see the "○ (Static)" rows in `next build` output), so
// their <script> tags can't carry a per-request nonce — a nonce-only CSP
// would reject every script on those pages and the app would never hydrate.
// 'unsafe-inline' stays for that reason.
//
// 'unsafe-eval' is only added in development: webpack's dev-mode Hot Module
// Replacement wraps modules in eval(), so without it `next dev` is blocked
// entirely by CSP (silent blank page, no server-side error). Production
// doesn't need eval, so it's excluded from the real security posture.
const isProd = process.env.NODE_ENV === 'production'

const securityHeaders = [
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      `script-src 'self' 'unsafe-inline'${isProd ? '' : " 'unsafe-eval'"}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob: https://res.cloudinary.com",
      "font-src 'self'",
      `connect-src 'self'${isProd ? '' : ' ws:'}`,
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
    ].join('; '),
  },
]

const nextConfig = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'res.cloudinary.com' },
    ],
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ]
  },
}
module.exports = nextConfig
