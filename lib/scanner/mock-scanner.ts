import { createServerSupabase } from '@/lib/supabase/server'
import { calculateRiskScoreWithMatches, getRiskLevel, getSecurityStatus, VULNERABILITY_DEFINITIONS, getOverallScanRisk, discountOverlappingMatches } from '@/lib/risk/calculator'
import { matchDevice, MatchResult } from '@/lib/vuln-db/matcher'
import { isCommunityMappingEnabled, snapshotOf } from '@/lib/vuln-db/queries'
import { getCommunityRecords } from '@/lib/vuln-db/store'
import { Device, Vulnerability, RiskLevel, CommunityVulnerability } from '@/types'
import { classifyHost, DiscoveredHost, ipToInt, simulatedHostIp } from './cctv-discovery'
import { discoverHosts, deriveChecksFromEvidence } from './network-discovery'

interface MockDeviceTemplate {
  /** Host number on the simulated site's /24 (e.g. 64 -> x.x.x.64) */
  host: number
  vendor: string
  model: string
  firmware_version: string
  device_type: 'camera' | 'nvr' | 'dvr' | 'router' | 'unknown'
  open_ports: { port: number; service: string; protocol: string }[]
  protocols: string[]
  mac_prefix: string
  vulnerability_checks: string[]
}

const MOCK_DEVICE_TEMPLATES: MockDeviceTemplate[] = [
  {
    vendor: 'Hikvision',
    host: 64,
    model: 'DS-2CD2043G0-I',
    firmware_version: 'V5.5.800',
    device_type: 'camera',
    open_ports: [
      { port: 80, service: 'HTTP', protocol: 'tcp' },
      { port: 554, service: 'RTSP', protocol: 'tcp' },
      { port: 8000, service: 'SDK', protocol: 'tcp' },
    ],
    protocols: ['HTTP', 'RTSP', 'ONVIF', 'Hikvision-SDK'],
    mac_prefix: 'E8:B7:48',
    vulnerability_checks: ['http_only', 'rtsp_exposed', 'outdated_firmware', 'missing_headers', 'onvif_anonymous'],
  },
  {
    vendor: 'Dahua',
    host: 65,
    model: 'IPC-HFW1230S',
    firmware_version: 'V2.420.0000.1.R',
    device_type: 'camera',
    open_ports: [
      { port: 80, service: 'HTTP', protocol: 'tcp' },
      { port: 554, service: 'RTSP', protocol: 'tcp' },
      { port: 37777, service: 'Dahua-SDK', protocol: 'tcp' },
    ],
    protocols: ['HTTP', 'RTSP', 'ONVIF', 'Dahua-SDK'],
    mac_prefix: 'BC:32:5F',
    vulnerability_checks: ['default_credentials', 'rtsp_exposed', 'http_only', 'session_cookies'],
  },
  {
    vendor: 'Axis',
    host: 66,
    model: 'M3045-V',
    firmware_version: '9.80.1',
    device_type: 'camera',
    open_ports: [
      { port: 443, service: 'HTTPS', protocol: 'tcp' },
      { port: 554, service: 'RTSP', protocol: 'tcp' },
    ],
    protocols: ['HTTPS', 'RTSP', 'ONVIF', 'VAPIX'],
    mac_prefix: 'AC:CC:8E',
    vulnerability_checks: ['missing_headers', 'rtsp_exposed', 'cve_mapping'],
  },
  {
    vendor: 'Uniview',
    host: 67,
    model: 'IPC3615-ADFKN-I0',
    firmware_version: 'IPC_G6112C_V3.1',
    device_type: 'camera',
    open_ports: [
      { port: 80, service: 'HTTP', protocol: 'tcp' },
      { port: 23, service: 'Telnet', protocol: 'tcp' },
      { port: 554, service: 'RTSP', protocol: 'tcp' },
    ],
    protocols: ['HTTP', 'Telnet', 'RTSP', 'ONVIF'],
    mac_prefix: 'C4:B3:01',
    vulnerability_checks: ['telnet_open', 'http_only', 'weak_auth', 'rtsp_exposed', 'open_ports'],
  },
  {
    vendor: 'Generic',
    host: 10,
    model: 'NVR-8CH-4K',
    firmware_version: 'V1.0.0',
    device_type: 'nvr',
    open_ports: [
      { port: 80, service: 'HTTP', protocol: 'tcp' },
      { port: 554, service: 'RTSP', protocol: 'tcp' },
      { port: 8080, service: 'HTTP-ALT', protocol: 'tcp' },
    ],
    protocols: ['HTTP', 'RTSP', 'ONVIF'],
    mac_prefix: '00:1A:2B',
    vulnerability_checks: ['insecure_web', 'default_credentials', 'http_only', 'missing_headers', 'internet_exposure'],
  },
  {
    vendor: 'Hikvision',
    host: 11,
    model: 'DS-7608NI-K2',
    firmware_version: 'V4.30.000',
    device_type: 'nvr',
    open_ports: [
      { port: 80, service: 'HTTP', protocol: 'tcp' },
      { port: 554, service: 'RTSP', protocol: 'tcp' },
      { port: 8000, service: 'SDK', protocol: 'tcp' },
    ],
    protocols: ['HTTP', 'RTSP', 'Hikvision-SDK'],
    mac_prefix: 'E8:B7:48',
    vulnerability_checks: ['http_only', 'rtsp_exposed', 'outdated_firmware', 'missing_headers'],
  },
  {
    vendor: 'Dahua',
    host: 12,
    model: 'NVR4108HS-4KS2',
    firmware_version: 'V4.001.0000000.0',
    device_type: 'nvr',
    open_ports: [
      { port: 80, service: 'HTTP', protocol: 'tcp' },
      { port: 554, service: 'RTSP', protocol: 'tcp' },
      { port: 37777, service: 'Dahua-SDK', protocol: 'tcp' },
    ],
    protocols: ['HTTP', 'RTSP', 'Dahua-SDK'],
    mac_prefix: 'BC:32:5F',
    vulnerability_checks: ['http_only', 'rtsp_exposed', 'session_cookies'],
  },
  // Hardened devices: HTTPS-only management, current firmware, no failed checks
  {
    vendor: 'Bosch',
    host: 68,
    model: 'FLEXIDOME IP 5000i',
    firmware_version: '8.71.0066',
    device_type: 'camera',
    open_ports: [
      { port: 443, service: 'HTTPS', protocol: 'tcp' },
    ],
    protocols: ['HTTPS'],
    mac_prefix: '00:07:5F',
    vulnerability_checks: [],
  },
  {
    vendor: 'Hanwha',
    host: 69,
    model: 'XNV-8080R',
    firmware_version: '2.21.02',
    device_type: 'camera',
    open_ports: [
      { port: 443, service: 'HTTPS', protocol: 'tcp' },
    ],
    protocols: ['HTTPS'],
    mac_prefix: '00:09:18',
    vulnerability_checks: [],
  },
]

// Deterministic: the same device (vendor/model at the same IP) always reports the same MAC
function generateMacAddress(prefix: string, seed: string): string {
  let h = 2166136261
  for (let i = 0; i < seed.length; i++) h = Math.imul(h ^ seed.charCodeAt(i), 16777619) >>> 0
  const hex = (n: number) => n.toString(16).padStart(2, '0').toUpperCase()
  return `${prefix}:${hex((h >>> 16) & 0xff)}:${hex((h >>> 8) & 0xff)}:${hex(h & 0xff)}`
}

// Other hosts on the simulated site. Discovery sees them, but they are not
// CCTV equipment, so they are skipped: never stored and never audited.
const NON_CCTV_HOSTS: (DiscoveredHost & { host: number })[] = [
  { host: 1, vendor: 'TP-Link', model: 'Archer C6 Router', protocols: ['HTTP', 'DNS'],
    open_ports: [{ port: 53, service: 'DNS', protocol: 'udp' }, { port: 80, service: 'HTTP', protocol: 'tcp' }] },
  { host: 25, vendor: 'Dell', model: 'OptiPlex Workstation', protocols: ['SMB', 'RDP'],
    open_ports: [{ port: 445, service: 'SMB', protocol: 'tcp' }, { port: 3389, service: 'RDP', protocol: 'tcp' }] },
  { host: 40, vendor: 'HP', model: 'LaserJet Printer', protocols: ['HTTP', 'IPP'],
    open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }, { port: 631, service: 'IPP', protocol: 'tcp' }, { port: 9100, service: 'JetDirect', protocol: 'tcp' }] },
  { host: 50, vendor: 'Synology', model: 'DS220+ NAS', protocols: ['HTTP', 'HTTPS', 'SMB'],
    open_ports: [{ port: 445, service: 'SMB', protocol: 'tcp' }, { port: 5000, service: 'HTTP', protocol: 'tcp' }, { port: 5001, service: 'HTTPS', protocol: 'tcp' }] },
  { host: 100, vendor: 'Samsung', model: 'Smart TV', protocols: ['HTTP'],
    open_ports: [{ port: 8001, service: 'HTTP', protocol: 'tcp' }, { port: 8002, service: 'HTTPS', protocol: 'tcp' }] },
]

/** Which discovery engine scans use: live probing, or the built-in demo hosts above. */
export function getScannerMode(): 'real' | 'simulated' {
  return process.env.SENTRIX_REAL_SCAN === '1' ? 'real' : 'simulated'
}

async function getEnabledCheckSlugs(supabase: ReturnType<typeof createServerSupabase>): Promise<Set<string>> {
  const { data } = await supabase
    .from('vulnerability_checks')
    .select('slug, enabled')

  if (!data || data.length === 0) {
    // Fallback only when the checks table itself is empty (not when an admin disabled every check)
    return new Set(VULNERABILITY_DEFINITIONS.map(v => v.checkKey))
  }
  return new Set(data.filter((r: { enabled: boolean }) => r.enabled).map((r: { slug: string }) => r.slug))
}

export async function runMockScan(scanId: string, networkRange: string, safeScanMode: boolean) {
  const supabase = createServerSupabase()

  await supabase.from('scans').update({ status: 'running', progress: 0 }).eq('id', scanId)

  // Fetch globally enabled checks from the database
  const enabledSlugs = await getEnabledCheckSlugs(supabase)

  // Community Vulnerability Mapping (defensive lookup against stored records only)
  const { data: scanRow } = await supabase.from('scans').select('user_id, scan_name').eq('id', scanId).single()
  const userId: string | null = scanRow?.user_id ?? null
  let communityRecords: CommunityVulnerability[] = []
  let communityEnabled = false
  try {
    communityEnabled = await isCommunityMappingEnabled(supabase)
    if (communityEnabled) {
      communityRecords = await getCommunityRecords(supabase, userId, { fetchRemoteIfMissing: true })
      await supabase.from('audit_logs').insert({
        user_id: userId, action: 'community_vuln_matching_started',
        details: { scan_id: scanId, records_available: communityRecords.length },
      })
    }
  } catch (e) {
    console.error('[SentriX] community vulnerability loading failed', e)
    communityEnabled = false
  }
  const recordById = new Map(communityRecords.map(r => [r.id, r]))
  let totalCommunityMatches = 0
  let devicesWithMatches = 0

  // Discovery produces the list of CCTV devices to analyse. Two sources:
  //  - REAL (SENTRIX_REAL_SCAN=1): non-destructive probing of the live network.
  //  - SIMULATION (default): a fixed set of demo hosts, deterministic for the POC.
  // Both feed the SAME weighted classifier and the SAME downstream analysis.
  const realScan = getScannerMode() === 'real'
  const isStoppedNow = async () =>
    (await supabase.from('scans').select('status').eq('id', scanId).single()).data?.status === 'stopped'
  const filterChecks = (checks: string[]) => {
    const enabled = checks.filter(c => enabledSlugs.has(c))
    return safeScanMode ? enabled.filter(c => c !== 'default_credentials') : enabled
  }

  const allDevices: (Omit<Device, 'id'> & { vulnerabilityChecks: string[] })[] = []
  let hostsDiscovered = 0
  let cctvIdentified = 0
  let classificationBreakdown: Record<string, unknown>[] = []

  if (realScan) {
    // ── REAL network discovery (authorized networks only) ──────────────────
    const hosts = await discoverHosts(networkRange, {
      shouldStop: isStoppedNow,
      onProgress: async (done, total) => {
        // Probes already in flight when the scan is stopped still report back;
        // the progress of a stopped scan must stay where it was stopped.
        await supabase.from('scans').update({ progress: Math.floor((done / total) * 70) })
          .eq('id', scanId).eq('status', 'running')
      },
    })
    if (await isStoppedNow()) {
      await supabase.from('scans').update({ total_devices: 0 }).eq('id', scanId)
      return { success: false, devices: 0 }
    }
    const classified = hosts.map(h => ({ host: h, verdict: classifyHost(h) }))
    const cctv = classified.filter(c => c.verdict.cctv)
    hostsDiscovered = classified.length
    cctvIdentified = cctv.length
    classificationBreakdown = classified.map(c => ({
      ip: c.host.ip_address, classification: c.verdict.classification, confidence: c.verdict.confidence,
      score: c.verdict.score, vendor: c.verdict.vendor || c.host.vendor, cctv: c.verdict.cctv, evidence: c.verdict.evidence,
    }))
    for (const c of cctv) {
      allDevices.push({
        scan_id: scanId,
        ip_address: c.host.ip_address,
        mac_address: c.host.mac_address || '',
        vendor: c.verdict.vendor || c.host.vendor || 'Unknown',
        model: c.host.model || 'Unknown',
        firmware_version: c.host.firmware_version || 'Unknown',
        device_type: c.host.device_type,
        open_ports: c.host.open_ports,
        protocols: c.host.protocols,
        risk_score: 0,
        risk_level: 'secure' as RiskLevel,
        status: 'active',
        created_at: new Date().toISOString(),
        vulnerabilityChecks: filterChecks(deriveChecksFromEvidence(c.host)),
      })
    }
    await supabase.from('scans').update({ total_devices: cctvIdentified }).eq('id', scanId)
  } else {
    // ── SIMULATION (deterministic demo hosts) ──────────────────────────────
    const liveHosts = [
      ...MOCK_DEVICE_TEMPLATES.map(t => ({ host: t, ip: simulatedHostIp(networkRange, t.host) })),
      ...NON_CCTV_HOSTS.map(h => ({ host: h, ip: simulatedHostIp(networkRange, h.host) })),
    ]
      .filter(h => h.ip !== null)
      .map(h => ({ host: h.host, ip: h.ip as string, verdict: classifyHost(h.host) }))

    const cctvHosts = liveHosts
      .filter(h => h.verdict.cctv)
      .map(h => ({ template: h.host as MockDeviceTemplate, ip: h.ip }))
      .sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip))

    hostsDiscovered = liveHosts.length
    cctvIdentified = cctvHosts.length
    classificationBreakdown = liveHosts
      .sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip))
      .map(h => ({
        ip: h.ip, classification: h.verdict.classification, confidence: h.verdict.confidence,
        score: h.verdict.score, vendor: h.verdict.vendor || h.host.vendor, cctv: h.verdict.cctv, evidence: h.verdict.evidence,
      }))

    // Live counter for the progress page
    await supabase.from('scans').update({ total_devices: cctvHosts.length }).eq('id', scanId)

    for (let i = 0; i < cctvHosts.length; i++) {
      const { template, ip: ipAddress } = cctvHosts[i]
      const progress = Math.floor(((i + 1) / cctvHosts.length) * 70)

      // Check if scan was stopped before continuing
      if (await isStoppedNow()) {
        // Nothing has been analysed or saved yet
        await supabase.from('scans').update({ total_devices: 0 }).eq('id', scanId)
        return { success: false, devices: 0 }
      }

      await supabase.from('scans').update({ progress }).eq('id', scanId).eq('status', 'running')
      await new Promise(r => setTimeout(r, 1000))

      allDevices.push({
        scan_id: scanId,
        ip_address: ipAddress,
        mac_address: generateMacAddress(template.mac_prefix, `${template.vendor}|${template.model}|${ipAddress}`),
        vendor: template.vendor,
        model: template.model,
        firmware_version: template.firmware_version,
        device_type: template.device_type,
        open_ports: template.open_ports,
        protocols: template.protocols,
        risk_score: 0,
        risk_level: 'secure' as RiskLevel,
        status: 'active',
        created_at: new Date().toISOString(),
        vulnerabilityChecks: filterChecks(template.vulnerability_checks),
      })
    }
  }

  // Per-host evidence breakdown — stored for auditing and shown when
  // SENTRIX_SCAN_DEBUG=1, so you can see WHY each host was or was not CCTV.
  if (process.env.SENTRIX_SCAN_DEBUG === '1') {
    console.log(`[SentriX] ${realScan ? 'REAL' : 'SIMULATED'} CCTV discovery for ${networkRange}:`)
    for (const b of classificationBreakdown) {
      const ev = Array.isArray(b.evidence) ? (b.evidence as string[]).join('; ') : ''
      console.log(`  ${String(b.ip).padEnd(15)} ${b.cctv ? '✓' : '·'} ${b.classification} (${b.confidence}, ${b.score}) ${b.vendor} — ${ev || 'no CCTV evidence'}`)
    }
  }

  await supabase.from('audit_logs').insert({
    user_id: userId, action: 'cctv_discovery_completed',
    details: {
      scan_id: scanId, network_range: networkRange, mode: realScan ? 'real' : 'simulated',
      hosts_discovered: hostsDiscovered,
      cctv_devices_identified: cctvIdentified,
      non_cctv_hosts_skipped: hostsDiscovered - cctvIdentified,
      classification_breakdown: classificationBreakdown,
    },
  })

  await supabase.from('scans').update({ progress: 75 }).eq('id', scanId).eq('status', 'running')

  let totalVulnerable = 0
  let totalCritical = 0
  const deviceRiskScores: number[] = []
  const isStopped = async () =>
    (await supabase.from('scans').select('status').eq('id', scanId).single()).data?.status === 'stopped'
  // A stopped scan keeps the devices analysed so far, with totals that match them
  const savePartialTotals = () => supabase.from('scans').update({
    total_devices: deviceRiskScores.length,
    vulnerable_devices: totalVulnerable,
    critical_devices: totalCritical,
    overall_risk: getOverallScanRisk(deviceRiskScores.map(s => ({ risk_score: s }))),
  }).eq('id', scanId)

  for (const deviceData of allDevices) {
    if (await isStopped()) {
      await savePartialTotals()
      return { success: false, devices: deviceRiskScores.length }
    }
    const { vulnerabilityChecks, ...deviceInsert } = deviceData

    const vulnDefs = VULNERABILITY_DEFINITIONS.filter(v => vulnerabilityChecks.includes(v.checkKey))
    const matches: MatchResult[] = communityEnabled
      ? discountOverlappingMatches(vulnDefs, matchDevice(deviceInsert, communityRecords))
      : []
    const riskScore = calculateRiskScoreWithMatches(vulnDefs, matches)
    const riskLevel = getRiskLevel(riskScore)

    const { data: insertedDevice } = await supabase
      .from('devices')
      .insert({ ...deviceInsert, risk_score: riskScore, risk_level: riskLevel })
      .select()
      .single()

    if (insertedDevice && vulnDefs.length > 0) {
      const vulnerabilities: Omit<Vulnerability, 'id'>[] = vulnDefs.map(v => ({
        device_id: insertedDevice.id,
        title: v.title,
        description: v.description,
        severity: v.severity,
        score: v.score,
        recommendation: v.recommendation,
        created_at: new Date().toISOString(),
      }))
      await supabase.from('vulnerabilities').insert(vulnerabilities)
    }

    if (insertedDevice && matches.length > 0) {
      const { error: matchError } = await supabase.from('device_vulnerability_matches').insert(matches.map(m => ({
        device_id: insertedDevice.id,
        scan_id: scanId,
        vulnerability_id: m.vulnerability_id,
        vulnerability_snapshot: snapshotOf(recordById.get(m.vulnerability_id)!),
        match_type: m.match_type,
        match_confidence: m.match_confidence,
        matched_fields: m.matched_fields,
        matched_reason: m.matched_reason,
        risk_score_added: m.risk_score_added,
        created_at: new Date().toISOString(),
      })))
      if (matchError) {
        console.error('[SentriX] could not save community vulnerability matches (run database/migrate_community_vulnerabilities.sql?):', matchError.message)
      }
      totalCommunityMatches += matches.length
      devicesWithMatches++
    }

    if (insertedDevice && getSecurityStatus(vulnDefs.length, matches) === 'vulnerable') totalVulnerable++
    if (insertedDevice && riskLevel === 'critical') totalCritical++

    deviceRiskScores.push(riskScore)
    await supabase.from('scans').update({ vulnerable_devices: totalVulnerable, critical_devices: totalCritical }).eq('id', scanId)
  }

  if (communityEnabled) {
    await supabase.from('audit_logs').insert({
      user_id: userId, action: 'community_vuln_matching_completed',
      details: { scan_id: scanId, devices_matched: devicesWithMatches, total_matches: totalCommunityMatches },
    })
  }

  await supabase.from('scans').update({ progress: 90 }).eq('id', scanId).eq('status', 'running')
  await new Promise(r => setTimeout(r, 1000))

  // Stopped while finalising: keep what was analysed, with matching totals
  if (await isStopped()) {
    await savePartialTotals()
    return { success: false, devices: deviceRiskScores.length }
  }

  const overallRisk = getOverallScanRisk(deviceRiskScores.map(s => ({ risk_score: s })))

  await supabase.from('scans').update({
    status: 'completed',
    progress: 100,
    total_devices: allDevices.length,
    vulnerable_devices: totalVulnerable,
    critical_devices: totalCritical,
    overall_risk: overallRisk,
    completed_at: new Date().toISOString(),
  }).eq('id', scanId).neq('status', 'stopped')

  await supabase.from('audit_logs').insert({
    user_id: userId, action: 'scan_completed',
    details: {
      scan_id: scanId, scan_name: scanRow?.scan_name, network_range: networkRange,
      cctv_devices: allDevices.length, vulnerable_devices: totalVulnerable,
      critical_devices: totalCritical, overall_risk: overallRisk,
    },
  })

  return { success: true, devices: allDevices.length }
}
