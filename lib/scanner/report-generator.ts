import { Scan, Device, Vulnerability, RiskLevel } from '@/types'
import { formatDate } from '@/lib/utils'

function esc(str: unknown): string {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

interface DeviceWithVulns extends Device {
  vulnerabilities: Vulnerability[]
}

function getRiskBadgeHtml(risk: RiskLevel): string {
  const colors: Record<string, string> = {
    secure: '#00ff9d', low: '#60a5fa', medium: '#ffcc00', high: '#fb923c', critical: '#ff3b5c',
  }
  const color = colors[risk] || '#718096'
  return `<span style="background:${color}20;color:${color};border:1px solid ${color}40;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:bold;text-transform:uppercase">${risk}</span>`
}

export function generateReportHtml(scan: Scan, devices: DeviceWithVulns[]): string {
  const secureDevices = devices.filter(d => d.risk_level === 'secure').length
  const vulnerableDevices = devices.filter(d => d.risk_level !== 'secure').length
  const allVulns = devices.flatMap(d => d.vulnerabilities)
  const criticalVulns = allVulns.filter(v => v.severity === 'critical').length
  const highVulns = allVulns.filter(v => v.severity === 'high').length

  const devicesHtml = devices.map(device => {
    const vulnsHtml = device.vulnerabilities.length > 0
      ? device.vulnerabilities.map(v => `
        <tr>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d">${esc(v.title)}</td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d">${getRiskBadgeHtml(v.severity as RiskLevel)}</td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d;font-size:13px;color:#718096">${esc(v.recommendation)}</td>
        </tr>`).join('')
      : '<tr><td colspan="3" style="padding:8px;color:#00ff9d;text-align:center">No vulnerabilities detected</td></tr>'

    return `
      <div style="background:#111827;border:1px solid #1e2d3d;border-radius:8px;padding:20px;margin-bottom:20px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px">
          <div>
            <h3 style="margin:0;color:#e2e8f0;font-size:16px">${esc(device.vendor)} ${esc(device.model)}</h3>
            <p style="margin:4px 0 0;color:#718096;font-size:13px">${esc(device.ip_address)} | ${esc(device.mac_address)}</p>
          </div>
          <div style="text-align:right">
            ${getRiskBadgeHtml(device.risk_level)}
            <p style="margin:4px 0 0;color:#718096;font-size:12px">Risk Score: ${esc(device.risk_score)}/100</p>
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:14px;color:#e2e8f0">
          <thead>
            <tr style="background:#0f1629">
              <th style="padding:8px;text-align:left;color:#00d4ff">Vulnerability</th>
              <th style="padding:8px;text-align:left;color:#00d4ff">Severity</th>
              <th style="padding:8px;text-align:left;color:#00d4ff">Recommendation</th>
            </tr>
          </thead>
          <tbody>${vulnsHtml}</tbody>
        </table>
        <div style="margin-top:12px;font-size:12px;color:#718096">
          Open Ports: ${device.open_ports.map((p: { port: number; service: string }) => `${esc(p.port)}/${esc(p.service)}`).join(', ')} |
          Device Type: ${esc(device.device_type.toUpperCase())} |
          Firmware: ${esc(device.firmware_version)}
        </div>
      </div>`
  }).join('')

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SentriX Security Report - ${esc(scan.scan_name)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0a0e1a; color: #e2e8f0; margin: 0; padding: 20px; }
  .header { background: linear-gradient(135deg, #0f1629, #111827); border: 1px solid #1e2d3d; border-radius: 12px; padding: 30px; margin-bottom: 24px; }
  .logo { font-size: 28px; font-weight: 900; color: #00d4ff; letter-spacing: 4px; }
  .subtitle { color: #718096; font-size: 13px; margin-top: 4px; }
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .stat-card { background: #111827; border: 1px solid #1e2d3d; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-value { font-size: 28px; font-weight: bold; }
  .stat-label { color: #718096; font-size: 12px; margin-top: 4px; }
  .section { margin-bottom: 24px; }
  .section-title { font-size: 18px; font-weight: bold; color: #00d4ff; border-bottom: 1px solid #1e2d3d; padding-bottom: 8px; margin-bottom: 16px; }
  .summary-box { background: #111827; border: 1px solid #1e2d3d; border-radius: 8px; padding: 20px; }
  @media print { body { background: white; color: black; } }
</style>
</head>
<body>
<div class="header">
  <div class="logo">SENTRIX</div>
  <div class="subtitle">Intelligent Security Auditing Framework for IP CCTV Networks</div>
  <div style="margin-top:20px;display:flex;gap:40px;flex-wrap:wrap">
    <div><span style="color:#718096;font-size:12px">REPORT TITLE</span><br><strong>${esc(scan.scan_name)}</strong></div>
    <div><span style="color:#718096;font-size:12px">SCAN DATE</span><br><strong>${formatDate(scan.started_at)}</strong></div>
    <div><span style="color:#718096;font-size:12px">NETWORK RANGE</span><br><strong>${esc(scan.network_range)}</strong></div>
    <div><span style="color:#718096;font-size:12px">OVERALL RISK</span><br>${getRiskBadgeHtml(scan.overall_risk)}</div>
  </div>
</div>

<div class="stat-grid">
  <div class="stat-card"><div class="stat-value" style="color:#00d4ff">${devices.length}</div><div class="stat-label">Total Devices</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#00ff9d">${secureDevices}</div><div class="stat-label">Secure Devices</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#ffcc00">${vulnerableDevices}</div><div class="stat-label">Vulnerable Devices</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#ff3b5c">${scan.critical_devices}</div><div class="stat-label">Critical Risk</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#ff3b5c">${criticalVulns}</div><div class="stat-label">Critical Vulns</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#fb923c">${highVulns}</div><div class="stat-label">High Vulns</div></div>
</div>

<div class="section">
  <div class="section-title">EXECUTIVE SUMMARY</div>
  <div class="summary-box">
    <p>This security audit was conducted on the network range <strong>${esc(scan.network_range)}</strong> on ${formatDate(scan.started_at)}. The scan discovered <strong>${devices.length} active IP CCTV devices</strong>, of which <strong>${vulnerableDevices} devices (${Math.round(vulnerableDevices/Math.max(devices.length,1)*100)}%)</strong> were found to have security vulnerabilities.</p>
    <p>The overall network security posture is rated as <strong>${esc(scan.overall_risk.toUpperCase())}</strong>. ${criticalVulns > 0 ? `There are <strong style="color:#ff3b5c">${criticalVulns} critical vulnerabilities</strong> that require immediate attention.` : 'No critical vulnerabilities were detected.'}</p>
    <p><strong>Key Findings:</strong></p>
    <ul>
      ${allVulns.filter(v=>v.severity==='critical').map(v=>`<li style="color:#ff3b5c">CRITICAL: ${esc(v.title)}</li>`).join('')}
      ${allVulns.filter(v=>v.severity==='high').map(v=>`<li style="color:#fb923c">HIGH: ${esc(v.title)}</li>`).join('')}
    </ul>
  </div>
</div>

<div class="section">
  <div class="section-title">DEVICE ANALYSIS</div>
  ${devicesHtml}
</div>

<div class="section">
  <div class="section-title">RECOMMENDED ACTIONS</div>
  <div class="summary-box">
    <ol>
      <li style="margin-bottom:8px"><strong>Immediately change all default credentials</strong> — Default username/password combinations are the #1 attack vector for IP cameras.</li>
      <li style="margin-bottom:8px"><strong>Disable Telnet</strong> — Remove all Telnet access and enforce SSH for management.</li>
      <li style="margin-bottom:8px"><strong>Enable HTTPS</strong> — All web interfaces should use TLS encryption.</li>
      <li style="margin-bottom:8px"><strong>Secure RTSP streams</strong> — Require authentication for all RTSP video streams.</li>
      <li style="margin-bottom:8px"><strong>Update firmware</strong> — Apply latest manufacturer firmware updates to patch known vulnerabilities.</li>
      <li style="margin-bottom:8px"><strong>Network segmentation</strong> — Place all CCTV devices on a dedicated VLAN isolated from the corporate network.</li>
      <li style="margin-bottom:8px"><strong>Regular audits</strong> — Schedule quarterly security audits using SentriX to track remediation progress.</li>
    </ol>
  </div>
</div>

<div style="text-align:center;color:#4a5568;font-size:12px;margin-top:40px;border-top:1px solid #1e2d3d;padding-top:20px">
  Generated by SentriX Security Auditing Framework | ${formatDate(new Date().toISOString())} | FOR AUTHORIZED USE ONLY
</div>
</body>
</html>`
}
