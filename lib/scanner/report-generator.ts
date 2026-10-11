import { Scan, Device, Vulnerability, RiskLevel, EnrichedMatch } from '@/types'
import { formatDate } from '@/lib/utils'
import { getSecurityStatus } from '@/lib/risk/calculator'
import { REPORT_NOTE, SEVERITIES, confidenceLabel } from '@/lib/vuln-db/constants'

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
  community_matches?: EnrichedMatch[]
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ff3b5c', High: '#fb923c', Medium: '#ffcc00', Low: '#60a5fa', Informational: '#a78bfa',
}

function severityBadge(severity: string): string {
  const color = SEVERITY_COLORS[severity] || '#718096'
  return `<span style="background:${color}20;color:${color};border:1px solid ${color}40;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:bold;text-transform:uppercase">${esc(severity)}</span>`
}

function safeHref(url: string): string | null {
  return /^https?:\/\//i.test(url) ? url : null
}

function communitySectionHtml(devices: DeviceWithVulns[]): string {
  const withMatches = devices.filter(d => (d.community_matches?.length ?? 0) > 0)
  const all = devices.flatMap(d => d.community_matches ?? [])
  const dist = SEVERITIES.map(sev => ({ sev, count: all.filter(m => m.vulnerability.severity === sev).length }))
  const recommendations = Array.from(new Set(all.map(m => m.vulnerability.recommendation)))

  const summary = all.length === 0
    ? '<p style="color:#00ff9d">No community vulnerability records were matched to the devices in this scan.</p>'
    : `<p><strong>${all.length}</strong> community vulnerability match${all.length === 1 ? '' : 'es'} were found across <strong>${withMatches.length}</strong> of ${devices.length} devices.
       Highest matched severity: ${severityBadge(dist.find(d => d.count > 0)!.sev)}</p>`

  const distHtml = `<table style="border-collapse:collapse;font-size:13px;margin:12px 0">
    <tr>${dist.map(d => `<td style="padding:6px 14px;text-align:center;border:1px solid #1e2d3d"><div style="font-size:20px;font-weight:bold;color:${SEVERITY_COLORS[d.sev]}">${d.count}</div><div style="color:#718096;font-size:11px">${esc(d.sev)}</div></td>`).join('')}</tr>
  </table>`

  const deviceTables = withMatches.map(d => `
    <h4 style="margin:18px 0 8px;color:#e2e8f0">${esc(d.vendor)} ${esc(d.model)} <span style="color:#718096;font-weight:normal;font-size:12px">${esc(d.ip_address)}</span></h4>
    <table style="width:100%;border-collapse:collapse;font-size:13px;color:#e2e8f0">
      <thead><tr style="background:#0f1629">
        <th style="padding:8px;text-align:left;color:#00d4ff">Vulnerability</th>
        <th style="padding:8px;text-align:left;color:#00d4ff">Severity</th>
        <th style="padding:8px;text-align:left;color:#00d4ff">Confidence</th>
        <th style="padding:8px;text-align:left;color:#00d4ff">Risk +</th>
        <th style="padding:8px;text-align:left;color:#00d4ff">Matched reason</th>
        <th style="padding:8px;text-align:left;color:#00d4ff">Recommendation</th>
      </tr></thead>
      <tbody>${(d.community_matches ?? []).map(m => {
        const href = safeHref(m.vulnerability.reference_url)
        return `<tr>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d"><strong>${esc(m.vulnerability.title)}</strong><br>
            <span style="color:#718096;font-size:11px">${esc(m.vulnerability.vuln_id)} &middot; ${esc(m.vulnerability.category)} &middot; ${esc(m.vulnerability.source_type)}${href ? ` &middot; <a href="${esc(href)}" style="color:#00d4ff">reference</a>` : ''}</span></td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d">${severityBadge(m.vulnerability.severity)}</td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d">${esc(confidenceLabel(m.match_confidence))}</td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d">+${esc(m.risk_score_added)}</td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d;font-size:12px;color:#718096">${esc(m.matched_reason)}</td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d;font-size:12px;color:#718096">${esc(m.vulnerability.recommendation)}</td>
        </tr>`
      }).join('')}</tbody>
    </table>`).join('')

  return `
<div class="section">
  <div class="section-title">COMMUNITY VULNERABILITY SUMMARY</div>
  <div class="summary-box">
    ${summary}
    ${distHtml}
    <p style="font-size:13px"><strong>Match confidence:</strong></p>
    <ul style="font-size:13px;color:#a0aec0">
      <li><strong>High</strong> — vendor and exact model (or model pattern with firmware) match. Full risk score applied.</li>
      <li><strong>Medium</strong> — vendor matches together with a model pattern, firmware, port or protocol. 75% of the risk score applied.</li>
      <li><strong>Potential Match (Low)</strong> — broad match on a generic record, vendor only, or device type/keywords. 50% of the risk score applied; verify before acting.</li>
    </ul>
    ${deviceTables}
    ${recommendations.length > 0 ? `<p style="margin-top:18px"><strong>Recommendations for matched vulnerabilities:</strong></p>
    <ul style="font-size:13px">${recommendations.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
    <p style="margin-top:18px;padding:10px 14px;border-left:3px solid #ffcc00;background:#ffcc0010;font-size:12px;color:#a0aec0"><strong>Note:</strong> ${esc(REPORT_NOTE)}</p>
  </div>
</div>`
}

function getRiskBadgeHtml(risk: RiskLevel): string {
  const colors: Record<string, string> = {
    secure: '#00ff9d', low: '#60a5fa', medium: '#ffcc00', high: '#fb923c', critical: '#ff3b5c',
  }
  const color = colors[risk] || '#718096'
  return `<span style="background:${color}20;color:${color};border:1px solid ${color}40;padding:2px 10px;border-radius:4px;font-size:12px;font-weight:bold;text-transform:uppercase">${risk}</span>`
}

export function generateReportHtml(scan: Scan, devices: DeviceWithVulns[]): string {
  // Same classification as the dashboard, Devices page and scan results
  const statusOf = (d: DeviceWithVulns) => getSecurityStatus(d.vulnerabilities.length, d.community_matches ?? [])
  const secureDevices = devices.filter(d => statusOf(d) === 'secure').length
  const potentialDevices = devices.filter(d => statusOf(d) === 'potential').length
  const vulnerableDevices = devices.filter(d => statusOf(d) === 'vulnerable').length
  const criticalRiskDevices = devices.filter(d => d.risk_level === 'critical').length
  const allVulns = devices.flatMap(d => d.vulnerabilities)
  // Confirmed issues: check findings plus High/Medium-confidence database matches
  const confidentMatches = devices.flatMap(d => (d.community_matches ?? []).filter(m => m.match_confidence !== 'Low'))
  const criticalVulns = allVulns.filter(v => v.severity === 'critical').length +
    confidentMatches.filter(m => m.vulnerability.severity === 'Critical').length
  const highVulns = allVulns.filter(v => v.severity === 'high').length +
    confidentMatches.filter(m => m.vulnerability.severity === 'High').length
  // Critical records matched only at Low confidence: not confirmed, but they
  // still feed the risk score, so the summary must account for them.
  const potentialCritical = devices.flatMap(d => (d.community_matches ?? [])
    .filter(m => m.match_confidence === 'Low' && m.vulnerability.severity === 'Critical')).length
  const highRated = scan.overall_risk === 'critical' || scan.overall_risk === 'high'
  const criticalSentence = criticalVulns > 0
    ? `There ${criticalVulns === 1 ? 'is' : 'are'} <strong style="color:#ff3b5c">${criticalVulns} confirmed critical issue${criticalVulns === 1 ? '' : 's'}</strong> that require${criticalVulns === 1 ? 's' : ''} immediate attention.`
    : highRated
      ? `No confirmed critical issues were detected; the ${esc(scan.overall_risk)} rating comes from the combined score of ${highVulns} high-severity issue${highVulns === 1 ? '' : 's'}${potentialCritical > 0 ? ` and ${potentialCritical} potential critical match${potentialCritical === 1 ? '' : 'es'}` : ''} and other findings across ${criticalRiskDevices} critical-risk device${criticalRiskDevices === 1 ? '' : 's'}. Review them in the sections below.`
      : 'No critical issues were detected.'
  // Key findings: each distinct issue once, with how many devices it affects
  const keyFindings = new Map<string, { severity: 'CRITICAL' | 'HIGH'; title: string; devices: Set<string> }>()
  const addFinding = (severity: 'CRITICAL' | 'HIGH', title: string, deviceId: string) => {
    const key = `${severity}|${title}`
    if (!keyFindings.has(key)) keyFindings.set(key, { severity, title, devices: new Set() })
    keyFindings.get(key)!.devices.add(deviceId)
  }
  for (const d of devices) {
    for (const v of d.vulnerabilities) {
      if (v.severity === 'critical') addFinding('CRITICAL', v.title, d.id)
      if (v.severity === 'high') addFinding('HIGH', v.title, d.id)
    }
    for (const m of (d.community_matches ?? []).filter(x => x.match_confidence !== 'Low')) {
      if (m.vulnerability.severity === 'Critical') addFinding('CRITICAL', m.vulnerability.title, d.id)
      if (m.vulnerability.severity === 'High') addFinding('HIGH', m.vulnerability.title, d.id)
    }
  }
  const keyFindingsHtml = Array.from(keyFindings.values())
    .sort((a, b) => (a.severity === b.severity ? b.devices.size - a.devices.size : a.severity === 'CRITICAL' ? -1 : 1))
    .map(f => `<li style="color:${f.severity === 'CRITICAL' ? '#ff3b5c' : '#fb923c'}">${f.severity}: ${esc(f.title)} <span style="color:#718096">(${f.devices.size} device${f.devices.size === 1 ? '' : 's'})</span></li>`)
    .join('')

  const devicesHtml = devices.map(device => {
    const vulnsHtml = device.vulnerabilities.length > 0
      ? device.vulnerabilities.map(v => `
        <tr>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d">${esc(v.title)}</td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d">${getRiskBadgeHtml(v.severity as RiskLevel)}</td>
          <td style="padding:8px;border-bottom:1px solid #1e2d3d;font-size:13px;color:#718096">${esc(v.recommendation)}</td>
        </tr>`).join('')
      : '<tr><td colspan="3" style="padding:8px;color:#00ff9d;text-align:center">No failed security checks (see Community Vulnerability Summary for database matches)</td></tr>'

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
  <div class="stat-card"><div class="stat-value" style="color:#00d4ff">${devices.length}</div><div class="stat-label">CCTV Devices</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#00ff9d">${secureDevices}</div><div class="stat-label">Secure Devices</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#a78bfa">${potentialDevices}</div><div class="stat-label">Potential Issues</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#ffcc00">${vulnerableDevices}</div><div class="stat-label">Vulnerable Devices</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#ff3b5c">${criticalRiskDevices}</div><div class="stat-label">Critical Risk Devices</div></div>
  <div class="stat-card"><div class="stat-value" style="color:#ff3b5c">${criticalVulns}</div><div class="stat-label">Confirmed Critical Issues</div></div>
  ${potentialCritical > 0 ? `<div class="stat-card"><div class="stat-value" style="color:#a78bfa">${potentialCritical}</div><div class="stat-label">Potential Critical Matches</div></div>` : ''}
  <div class="stat-card"><div class="stat-value" style="color:#fb923c">${highVulns}</div><div class="stat-label">High Issues</div></div>
</div>

<div class="section">
  <div class="section-title">EXECUTIVE SUMMARY</div>
  <div class="summary-box">
    <p>This security audit was conducted on the network range <strong>${esc(scan.network_range)}</strong> on ${formatDate(scan.started_at)}. The scan identified <strong>${devices.length} IP CCTV device${devices.length === 1 ? '' : 's'}</strong> (non-CCTV hosts are excluded from the audit). <strong>${vulnerableDevices} device${vulnerableDevices === 1 ? '' : 's'} (${Math.round(vulnerableDevices / Math.max(devices.length, 1) * 100)}%)</strong> ${vulnerableDevices === 1 ? 'has' : 'have'} confirmed security issues, ${potentialDevices} ${potentialDevices === 1 ? 'has' : 'have'} only potential matches to review, and ${secureDevices} ${secureDevices === 1 ? 'is' : 'are'} secure.</p>
    <p>The overall network security posture is rated as <strong>${esc(scan.overall_risk.toUpperCase())}</strong>. ${criticalSentence}</p>
    ${keyFindingsHtml ? `<p><strong>Key Findings:</strong></p><ul>${keyFindingsHtml}</ul>` : ''}
  </div>
</div>

${communitySectionHtml(devices)}

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
