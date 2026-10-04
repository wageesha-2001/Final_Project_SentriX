import { createServerSupabase } from '@/lib/supabase/server'
import { calculateRiskScore, getRiskLevel, VULNERABILITY_DEFINITIONS, getOverallScanRisk } from '@/lib/risk/calculator'
import { Device, Vulnerability, RiskLevel } from '@/types'

interface MockDeviceTemplate {
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
]

function generateMacAddress(prefix: string): string {
  const hex = () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase()
  return `${prefix}:${hex()}:${hex()}:${hex()}`
}

function generateIpInRange(baseIp: string, index: number): string {
  const parts = baseIp.split('.')
  const lastOctet = (parseInt(parts[3]) + index + 20) % 254 + 1
  return `${parts[0]}.${parts[1]}.${parts[2]}.${lastOctet}`
}

async function getEnabledCheckSlugs(supabase: ReturnType<typeof createServerSupabase>): Promise<Set<string>> {
  const { data } = await supabase
    .from('vulnerability_checks')
    .select('slug')
    .eq('enabled', true)

  if (!data || data.length === 0) {
    // Fallback: all checks enabled
    return new Set(VULNERABILITY_DEFINITIONS.map(v => v.checkKey))
  }
  return new Set(data.map((r: { slug: string }) => r.slug))
}

export async function runMockScan(scanId: string, networkRange: string, safeScanMode: boolean) {
  const supabase = createServerSupabase()

  await supabase.from('scans').update({ status: 'running', progress: 0 }).eq('id', scanId)

  // Fetch globally enabled checks from the database
  const enabledSlugs = await getEnabledCheckSlugs(supabase)

  const baseIp = networkRange.split('/')[0].split('.').slice(0, 3).join('.') + '.1'
  const numDevices = Math.floor(Math.random() * 3) + 3
  const selectedTemplates = MOCK_DEVICE_TEMPLATES.slice(0, numDevices)

  const allDevices: (Omit<Device, 'id'> & { vulnerabilityChecks: string[] })[] = []

  for (let i = 0; i < selectedTemplates.length; i++) {
    const template = selectedTemplates[i]
    const progress = Math.floor(((i + 1) / selectedTemplates.length) * 70)

    // Check if scan was stopped before continuing
    const { data: scanCheck } = await supabase.from('scans').select('status').eq('id', scanId).single()
    if (scanCheck?.status === 'stopped') return { success: false, devices: 0 }

    await supabase.from('scans').update({ progress }).eq('id', scanId)
    await new Promise(r => setTimeout(r, 1500))

    // Filter by: 1) enabled in DB, 2) safe scan mode (no credential checks)
    let vulnerabilityChecks = template.vulnerability_checks.filter(c => enabledSlugs.has(c))
    if (safeScanMode) {
      vulnerabilityChecks = vulnerabilityChecks.filter(c => c !== 'default_credentials')
    }

    allDevices.push({
      scan_id: scanId,
      ip_address: generateIpInRange(baseIp, i * 10 + 10),
      mac_address: generateMacAddress(template.mac_prefix),
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
      vulnerabilityChecks,
    })
  }

  await supabase.from('scans').update({ progress: 75 }).eq('id', scanId)

  let totalVulnerable = 0
  let totalCritical = 0
  const deviceRiskScores: number[] = []

  for (const deviceData of allDevices) {
    const { vulnerabilityChecks, ...deviceInsert } = deviceData

    const vulnDefs = VULNERABILITY_DEFINITIONS.filter(v => vulnerabilityChecks.includes(v.checkKey))
    const riskScore = calculateRiskScore(vulnDefs)
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
      totalVulnerable++
      if (riskLevel === 'critical') totalCritical++
    }

    deviceRiskScores.push(riskScore)
  }

  await supabase.from('scans').update({ progress: 90 }).eq('id', scanId)
  await new Promise(r => setTimeout(r, 1000))

  // Abort if the scan was stopped while we were running
  const { data: currentScan } = await supabase.from('scans').select('status').eq('id', scanId).single()
  if (currentScan?.status === 'stopped') {
    return { success: false, devices: 0 }
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
  }).eq('id', scanId)

  return { success: true, devices: allDevices.length }
}
