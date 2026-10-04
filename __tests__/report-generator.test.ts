import { generateReportHtml } from '@/lib/scanner/report-generator'
import { Scan, Device, Vulnerability } from '@/types'

const mockScan: Scan = {
  id: 'scan-1',
  user_id: 'user-1',
  scan_name: 'Test <b>Scan</b>',
  network_range: '192.168.1.0/24',
  status: 'completed',
  total_devices: 1,
  vulnerable_devices: 1,
  critical_devices: 0,
  overall_risk: 'high',
  started_at: '2024-01-15T10:00:00.000Z',
  completed_at: '2024-01-15T10:05:00.000Z',
}

const mockDevice: Device & { vulnerabilities: Vulnerability[] } = {
  id: 'device-1',
  scan_id: 'scan-1',
  ip_address: '192.168.1.100',
  mac_address: 'AA:BB:CC:DD:EE:FF',
  vendor: 'Hikvision',
  model: 'DS-2CD2043G0-I',
  firmware_version: 'V5.5.800',
  device_type: 'camera',
  open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }],
  protocols: ['HTTP'],
  risk_score: 50,
  risk_level: 'high',
  status: 'active',
  created_at: '2024-01-15T10:01:00.000Z',
  vulnerabilities: [
    {
      id: 'vuln-1',
      device_id: 'device-1',
      title: 'HTTP-Only Web Interface',
      description: 'Using plain HTTP',
      severity: 'medium',
      score: 15,
      recommendation: 'Enable HTTPS',
      created_at: '2024-01-15T10:01:00.000Z',
    },
  ],
}

describe('generateReportHtml', () => {
  let html: string

  beforeAll(() => {
    html = generateReportHtml(mockScan, [mockDevice])
  })

  it('returns valid HTML with doctype', () => {
    expect(html).toMatch(/^<!DOCTYPE html>/i)
  })

  it('escapes < and > in the scan name (XSS prevention)', () => {
    // "Test <b>Scan</b>" should be escaped
    expect(html).not.toContain('<b>Scan</b>')
    expect(html).toContain('&lt;b&gt;Scan&lt;/b&gt;')
  })

  it('includes device IP address', () => {
    expect(html).toContain('192.168.1.100')
  })

  it('includes vulnerability title', () => {
    expect(html).toContain('HTTP-Only Web Interface')
  })

  it('includes network range', () => {
    expect(html).toContain('192.168.1.0/24')
  })

  it('does not contain raw script tags from device data', () => {
    const xssDevice = {
      ...mockDevice,
      vendor: '<script>alert("xss")</script>',
      vulnerabilities: [],
    }
    const xssHtml = generateReportHtml(mockScan, [xssDevice])
    expect(xssHtml).not.toContain('<script>alert("xss")</script>')
    expect(xssHtml).toContain('&lt;script&gt;')
  })
})
