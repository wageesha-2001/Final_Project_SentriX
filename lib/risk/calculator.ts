import {
  Vulnerability, RiskLevel, MatchConfidence, SecurityStatus,
  KnownVulnerabilityStatus, AuthenticationStatus, OverallSecurityStatus,
} from '@/types'

export interface VulnDefinition {
  title: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  score: number
  recommendation: string
  checkKey: string
}

export const VULNERABILITY_DEFINITIONS: VulnDefinition[] = [
  {
    checkKey: 'default_credentials',
    title: 'Default Credentials Detected',
    description: 'The device is using factory default username and password combinations, making it trivially accessible to attackers.',
    severity: 'critical',
    score: 35,
    recommendation: 'Change all default credentials immediately and use strong unique passwords.',
  },
  {
    checkKey: 'weak_auth',
    title: 'Weak Authentication Mechanism',
    description: 'The device uses weak or basic authentication without proper brute-force protection or account lockout policies.',
    severity: 'high',
    score: 25,
    recommendation: 'Enforce strong password policies and disable weak authentication methods.',
  },
  {
    checkKey: 'open_ports',
    title: 'Open Risky Ports Detected',
    description: 'Exposed high-risk ports (Telnet, FTP, RTSP, HTTP, UPnP) are accessible on the network.',
    severity: 'high',
    score: 20,
    recommendation: 'Close unused ports and restrict access using firewall rules.',
  },
  {
    checkKey: 'http_only',
    title: 'HTTP-Only Web Interface',
    description: 'The device web interface is accessible over unencrypted HTTP, exposing credentials and session tokens to network sniffing.',
    severity: 'medium',
    score: 15,
    recommendation: 'Enable HTTPS and redirect all HTTP traffic securely.',
  },
  {
    checkKey: 'rtsp_exposed',
    title: 'Exposed RTSP Stream Without Authentication',
    description: 'The RTSP video stream (port 554) is accessible without authentication, allowing anyone on the network to view live footage.',
    severity: 'high',
    score: 25,
    recommendation: 'Require authentication for RTSP streams and restrict access.',
  },
  {
    checkKey: 'outdated_firmware',
    title: 'Outdated Firmware Version',
    description: 'The device is running outdated firmware with known security vulnerabilities that have been patched in newer versions.',
    severity: 'high',
    score: 20,
    recommendation: 'Update firmware to the latest stable secure release.',
  },
  {
    checkKey: 'insecure_web',
    title: 'Insecure Web Interface Configuration',
    description: 'The device web interface has security misconfigurations including exposed management ports or outdated web server software.',
    severity: 'medium',
    score: 15,
    recommendation: 'Disable unnecessary features and secure the admin interface.',
  },
  {
    checkKey: 'missing_headers',
    title: 'Missing Security Headers',
    description: 'The device web interface is missing critical HTTP security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options).',
    severity: 'medium',
    score: 10,
    recommendation: 'Implement proper HTTP security headers.',
  },
  {
    checkKey: 'telnet_open',
    title: 'Telnet Service Exposed',
    description: 'Telnet (port 23) is open and transmits all data including credentials in plaintext over the network.',
    severity: 'high',
    score: 25,
    recommendation: 'Disable Telnet and use secure protocols such as SSH.',
  },
  {
    checkKey: 'onvif_anonymous',
    title: 'ONVIF Anonymous Access Enabled',
    description: 'The ONVIF service allows unauthenticated access, permitting anyone to control camera settings and retrieve video streams.',
    severity: 'high',
    score: 20,
    recommendation: 'Require authentication for ONVIF services.',
  },
  {
    checkKey: 'internet_exposure',
    title: 'Device Publicly Exposed to Internet',
    description: 'This CCTV device appears to be directly reachable from the public internet, dramatically increasing attack surface.',
    severity: 'critical',
    score: 30,
    recommendation: 'Restrict public exposure and use VPN-based remote access.',
  },
  {
    checkKey: 'cve_mapping',
    title: 'Known CVE Vulnerabilities Detected',
    description: 'The detected firmware version or service matches entries in the known CVE database.',
    severity: 'high',
    score: 20,
    recommendation: 'Patch vulnerable systems immediately.',
  },
  {
    checkKey: 'session_cookies',
    title: 'Insecure Session Cookie Configuration',
    description: 'Web session cookies are missing Secure, HttpOnly, and/or SameSite attributes, exposing sessions to hijacking.',
    severity: 'medium',
    score: 10,
    recommendation: 'Configure secure cookie settings.',
  },
]

export function calculateRiskScore(vulnerabilities: Pick<Vulnerability, 'score'>[]): number {
  const total = vulnerabilities.reduce((sum, v) => sum + v.score, 0)
  return Math.min(total, 100)
}

/**
 * Device risk including community vulnerability matches. `risk_score_added`
 * is already scaled by match confidence (High 100%, Medium 75%, Low 50%).
 */
export function calculateRiskScoreWithMatches(
  vulnerabilities: Pick<Vulnerability, 'score'>[],
  matches: { risk_score_added: number }[],
): number {
  const total =
    vulnerabilities.reduce((sum, v) => sum + v.score, 0) +
    matches.reduce((sum, m) => sum + m.risk_score_added, 0)
  return Math.min(total, 100)
}

/** Community-database category covered by each built-in check. */
export const CHECK_CATEGORY: Record<string, string> = {
  default_credentials: 'Default Credentials',
  weak_auth: 'Weak Authentication',
  open_ports: 'Open Risky Ports',
  http_only: 'HTTP-Only Interface',
  rtsp_exposed: 'RTSP Exposure',
  outdated_firmware: 'Outdated Firmware',
  insecure_web: 'Web Interface Security',
  missing_headers: 'Missing Security Headers',
  telnet_open: 'Telnet Enabled',
  onvif_anonymous: 'ONVIF Anonymous Access',
  internet_exposure: 'Internet Exposure',
  session_cookies: 'Session Cookie Weakness',
}

/**
 * A built-in check and a community record can describe the same weakness
 * (e.g. the RTSP check and an "RTSP Exposure" record). The weakness is scored
 * once, at the larger of the two: the match only adds what exceeds the check.
 * Matches stay in the results (with the reason) so the record is still shown.
 */
export function discountOverlappingMatches<M extends { category: string; risk_score_added: number; matched_reason: string }>(
  checks: Pick<VulnDefinition, 'checkKey' | 'title' | 'score'>[],
  matches: M[],
): M[] {
  const byCategory = new Map<string, { title: string; score: number }>()
  for (const c of checks) {
    const cat = CHECK_CATEGORY[c.checkKey]
    if (cat && (byCategory.get(cat)?.score ?? -1) < c.score) byCategory.set(cat, { title: c.title, score: c.score })
  }
  return matches.map(m => {
    const check = byCategory.get(m.category)
    if (!check) return m
    const extra = Math.max(0, m.risk_score_added - check.score)
    return {
      ...m,
      risk_score_added: extra,
      matched_reason: `${m.matched_reason} Risk already counted by the built-in "${check.title}" check${extra > 0 ? `; adds only the extra ${extra}` : ''}.`,
    }
  })
}

/**
 * Security status of a discovered device:
 *   vulnerable — confirmed check findings, or a High/Medium community match
 *   potential  — only low-confidence "Potential Match" results to review
 *   secure     — nothing found
 */
export function getSecurityStatus(
  findingsCount: number,
  matches: { match_confidence: MatchConfidence }[],
): SecurityStatus {
  if (findingsCount > 0 || matches.some(m => m.match_confidence !== 'Low')) return 'vulnerable'
  if (matches.length > 0) return 'potential'
  return 'secure'
}

export function calculateTrustScore(riskScore: number): number {
  return 100 - Math.min(Math.max(riskScore, 0), 100)
}

// ─── Confirmed-finding risk & separated classification ───────────────────────

/** Risk contribution of a confirmed default-credential finding. */
export const CREDENTIAL_FINDING = {
  title: 'Default Credentials Confirmed',
  description: 'An authorized verification confirmed the device accepts factory-default credentials.',
  severity: 'critical' as const,
  score: 35,
  recommendation: 'Change the default credentials immediately and set a strong, unique password.',
}

/**
 * Device risk from CONFIRMED findings only. Confirmed vulnerabilities.txt
 * matches (risk_score_added already confidence-scaled) plus a confirmed
 * default-credential finding. Unverified/informational items contribute 0.
 * The same credential weakness is not double-counted. Capped at 100.
 */
export function calculateDeviceRisk(
  confirmedMatches: { risk_score_added: number }[],
  credentialConfirmed: boolean,
): number {
  const fromMatches = confirmedMatches.reduce((sum, m) => sum + m.risk_score_added, 0)
  const fromCreds = credentialConfirmed ? CREDENTIAL_FINDING.score : 0
  return Math.min(fromMatches + fromCreds, 100)
}

/**
 * Overall per-device status from the two independent assessments.
 *   VULNERABLE    — a confirmed file match OR confirmed default credentials.
 *   NOT_VERIFIED  — no confirmed finding, but an essential check could not be
 *                   completed (unverified firmware match, auth error, or an
 *                   auth test required by policy that did not run).
 *   HEALTHY       — no confirmed finding and all essential checks completed.
 */
export function getOverallSecurityStatus(args: {
  knownStatus: KnownVulnerabilityStatus
  authStatus: AuthenticationStatus
  essentialChecksComplete: boolean
}): OverallSecurityStatus {
  const { knownStatus, authStatus, essentialChecksComplete } = args
  if (knownStatus === 'MATCHED' || authStatus === 'CONFIRMED_DEFAULT_CREDENTIALS') return 'VULNERABLE'
  if (knownStatus === 'UNVERIFIED' || authStatus === 'AUTHENTICATION_ERROR' || !essentialChecksComplete) {
    return 'NOT_VERIFIED'
  }
  return 'HEALTHY'
}

/** Legacy tri-state used by the existing device/dashboard UI. */
export function overallToSecurityStatus(overall: OverallSecurityStatus): SecurityStatus {
  return overall === 'VULNERABLE' ? 'vulnerable' : overall === 'NOT_VERIFIED' ? 'potential' : 'secure'
}

export function getRiskLevel(score: number): RiskLevel {
  if (score === 0) return 'secure'
  if (score <= 20) return 'low'
  if (score <= 45) return 'medium'
  if (score <= 70) return 'high'
  return 'critical'
}

export function getOverallScanRisk(devices: { risk_score: number }[]): RiskLevel {
  if (devices.length === 0) return 'secure'
  const maxScore = Math.max(...devices.map(d => d.risk_score))
  return getRiskLevel(maxScore)
}
