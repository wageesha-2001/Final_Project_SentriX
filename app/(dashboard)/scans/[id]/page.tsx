'use client'

import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'next/navigation'
import { motion } from 'framer-motion'
import Link from 'next/link'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Scan, Device, Vulnerability, EnrichedMatch, SecurityStatus } from '@/types'
import { getSecurityStatus } from '@/lib/risk/calculator'
import { MatchCard, SEVERITY_CLASS } from '@/components/vuln-db/MatchCard'
import { SEVERITIES } from '@/lib/vuln-db/constants'
import { formatDate, formatDuration, cn } from '@/lib/utils'
import { Cpu, Shield, AlertTriangle, FileText, ExternalLink, ChevronDown, ChevronUp, Database, Filter } from 'lucide-react'
import toast from 'react-hot-toast'

interface DeviceWithVulns extends Device { vulnerabilities: Vulnerability[]; community_matches: EnrichedMatch[] }
interface DiscoverySummary { mode: string; hosts_discovered: number; cctv_devices_identified: number }

/** Explain why a scan stored no devices, so an empty result isn't mistaken for a bug. */
function emptyScanReason(scan: Scan, discovery: DiscoverySummary | null): string {
  if (!discovery) return `The scan of ${scan.network_range} did not find any CCTV devices.`
  if (discovery.mode === 'real') {
    return discovery.hosts_discovered === 0
      ? `No host in ${scan.network_range} answered on any CCTV port (23, 80, 443, 554, 8000, 8080, 37777). ` +
        'Check that this server can reach that network (VPN, routing, firewall) and that the range is correct.'
      : `${discovery.hosts_discovered} host(s) in ${scan.network_range} responded, but none showed enough CCTV evidence (RTSP, ONVIF, vendor API) to be classified as a CCTV device.`
  }
  return `Simulation mode: none of the demo CCTV hosts fall inside ${scan.network_range}. ` +
    'Start the server with SENTRIX_REAL_SCAN=1 to probe the real network.'
}

export default function ScanResultsPage() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<Scan | null>(null)
  const [devices, setDevices] = useState<DeviceWithVulns[]>([])
  const [discovery, setDiscovery] = useState<DiscoverySummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [generatingReport, setGeneratingReport] = useState(false)
  const [expandedDevice, setExpandedDevice] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState('')
  const [vendorFilter, setVendorFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')

  useEffect(() => {
    fetch(`/api/scans/${id}/results`)
      .then(r => r.json())
      .then(data => {
        if (data.data) {
          setScan(data.data.scan)
          setDiscovery(data.data.discovery ?? null)
          const devMap = new Map(data.data.devices.map((d: Device) => [d.id, { ...d, vulnerabilities: [], community_matches: [] }]))
          data.data.vulnerabilities.forEach((v: Vulnerability) => {
            const dev = devMap.get(v.device_id) as DeviceWithVulns | undefined
            if (dev) dev.vulnerabilities.push(v)
          });
          (data.data.community_matches ?? []).forEach((m: EnrichedMatch) => {
            const dev = devMap.get(m.device_id) as DeviceWithVulns | undefined
            if (dev) dev.community_matches.push(m)
          })
          setDevices(Array.from(devMap.values()) as DeviceWithVulns[])
        }
      })
      .finally(() => setLoading(false))
  }, [id])

  const handleGenerateReport = async () => {
    setGeneratingReport(true)
    try {
      const res = await fetch(`/api/reports/${id}/generate`, { method: 'POST' })
      if (res.ok) { toast.success('Report generated!'); window.location.href = `/reports/${id}` }
      else toast.error((await res.json().catch(() => ({}))).error || 'Failed to generate report')
    } catch { toast.error('Error generating report') }
    finally { setGeneratingReport(false) }
  }

  const allMatches = useMemo(() => devices.flatMap(d => d.community_matches), [devices])
  const statusCount = (status: SecurityStatus) =>
    devices.filter(d => getSecurityStatus(d.vulnerabilities.length, d.community_matches) === status).length
  const filterActive = !!(severityFilter || vendorFilter || categoryFilter)
  const matchPasses = (m: EnrichedMatch) =>
    (!severityFilter || m.vulnerability.severity === severityFilter) &&
    (!vendorFilter || m.vulnerability.vendor === vendorFilter) &&
    (!categoryFilter || m.vulnerability.category === categoryFilter)
  const visibleDevices = useMemo(
    () => filterActive ? devices.filter(d => d.community_matches.some(matchPasses)) : devices,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [devices, severityFilter, vendorFilter, categoryFilter, filterActive],
  )
  const highestSeverity = SEVERITIES.find(sev => allMatches.some(m => m.vulnerability.severity === sev))
  const vendorOptions = Array.from(new Set(allMatches.map(m => m.vulnerability.vendor))).sort()
  const categoryOptions = Array.from(new Set(allMatches.map(m => m.vulnerability.category))).sort()

  if (loading) return <DashboardLayout title="Scan Results"><LoadingSpinner size="lg" text="Loading results..." className="h-64" /></DashboardLayout>
  if (!scan) return <DashboardLayout title="Scan Results"><EmptyState icon={Cpu} title="Scan not found" /></DashboardLayout>

  return (
    <DashboardLayout title="Scan Results" subtitle={scan.scan_name}>
      <div className="space-y-6">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="cyber-card p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="text-xl font-bold text-white">{scan.scan_name}</h2>
              <p className="text-cyber-muted font-mono text-sm">{scan.network_range}</p>
              <p className="text-cyber-text-muted text-xs mt-1">{formatDate(scan.started_at)}
                {scan.completed_at && ` • Duration: ${formatDuration(scan.started_at, scan.completed_at)}`}</p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              {scan.status === 'completed' ? (
                <>
                  <RiskBadge level={scan.overall_risk} size="lg" />
                  <Link href={`/devices?scan=${scan.id}`}
                    className="px-4 py-2 rounded-lg border border-cyber-border text-xs text-cyber-text-muted hover:text-white hover:border-cyber-muted transition-colors flex items-center gap-2">
                    <Cpu className="w-3.5 h-3.5" /> View Devices
                  </Link>
                  <button onClick={handleGenerateReport} disabled={generatingReport}
                    className="cyber-btn-primary px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-2">
                    {generatingReport ? <span className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> : <FileText className="w-3.5 h-3.5" />}
                    {generatingReport ? 'Generating...' : 'Generate Report'}
                  </button>
                </>
              ) : (
                <span className="px-3 py-1.5 rounded-lg border border-cyber-border text-xs font-bold uppercase text-cyber-yellow">
                  {scan.status}
                </span>
              )}
            </div>
          </div>
          {scan.status === 'running' || scan.status === 'pending' ? (
            <p className="mt-4 text-sm text-cyber-text-muted">
              This scan is still in progress. <Link href={`/scans/${scan.id}/progress`} className="text-cyber-accent hover:underline">View live progress</Link>
            </p>
          ) : scan.status === 'stopped' ? (
            <p className="mt-4 text-sm text-cyber-yellow">
              This scan was stopped before it finished. Only the devices analysed before the stop are shown; stopped scans are not included in the dashboard, device inventory or reports.
            </p>
          ) : null}

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 mt-5 pt-5 border-t border-cyber-border">
            {[
              { label: 'CCTV Devices', value: devices.length, color: 'text-cyber-accent' },
              { label: 'Secure', value: statusCount('secure'), color: 'text-cyber-green' },
              { label: 'Potential Issues', value: statusCount('potential'), color: 'text-cyber-purple' },
              { label: 'Vulnerable', value: statusCount('vulnerable'), color: 'text-cyber-yellow' },
              { label: 'Critical', value: devices.filter(d => d.risk_level === 'critical').length, color: 'text-cyber-red' },
            ].map(stat => (
              <div key={stat.label} className="text-center">
                <p className={`text-2xl font-black ${stat.color}`}>{stat.value}</p>
                <p className="text-xs text-cyber-muted uppercase tracking-wider mt-1">{stat.label}</p>
              </div>
            ))}
          </div>

          <div className="mt-5 pt-5 border-t border-cyber-border">
            <p className="text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-3 flex items-center gap-2">
              <Database className="w-3.5 h-3.5 text-cyber-accent" /> Community Vulnerability Matches
            </p>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-black text-cyber-accent">{allMatches.length}</p>
                <p className="text-xs text-cyber-muted uppercase tracking-wider mt-1">Total Matches</p>
              </div>
              <div>
                {highestSeverity
                  ? <span className={cn('inline-block text-xs px-2 py-1 rounded border font-bold uppercase tracking-wider', SEVERITY_CLASS[highestSeverity])}>{highestSeverity}</span>
                  : <p className="text-2xl font-black text-cyber-green">—</p>}
                <p className="text-xs text-cyber-muted uppercase tracking-wider mt-1">Highest Severity</p>
              </div>
              <div>
                <p className="text-2xl font-black text-cyber-yellow">{devices.filter(d => d.community_matches.length > 0).length}</p>
                <p className="text-xs text-cyber-muted uppercase tracking-wider mt-1">Devices With Known Vulns</p>
              </div>
            </div>
          </div>
        </motion.div>

        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h3 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider">Discovered Devices ({visibleDevices.length}{filterActive ? ` of ${devices.length}` : ''})</h3>
            {allMatches.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {[
                  { label: 'All Severities', value: severityFilter, set: setSeverityFilter, options: SEVERITIES.filter(sev => allMatches.some(m => m.vulnerability.severity === sev)) },
                  { label: 'All Vendors', value: vendorFilter, set: setVendorFilter, options: vendorOptions },
                  { label: 'All Categories', value: categoryFilter, set: setCategoryFilter, options: categoryOptions },
                ].map(f => (
                  <div key={f.label} className="relative">
                    <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
                    <select value={f.value} onChange={e => f.set(e.target.value)} aria-label={f.label}
                      className="cyber-input pl-9 pr-8 py-2 rounded-lg text-xs appearance-none cursor-pointer max-w-[12rem]">
                      <option value="">{f.label}</option>
                      {f.options.map(o => <option key={o} value={o}>{o}</option>)}
                    </select>
                  </div>
                ))}
              </div>
            )}
          </div>
          {devices.length === 0 ? (
            <EmptyState icon={Cpu} title="No CCTV devices discovered" description={emptyScanReason(scan, discovery)} />
          ) : visibleDevices.length === 0 ? (
            <EmptyState icon={Cpu} title="No devices match the selected filters" />
          ) : (
            visibleDevices.map((device, i) => (
              <motion.div key={device.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                className="cyber-card overflow-hidden">
                <div className="p-4 flex items-center justify-between cursor-pointer hover:bg-white/2"
                  onClick={() => setExpandedDevice(expandedDevice === device.id ? null : device.id)}>
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-cyber-surface border border-cyber-border flex items-center justify-center">
                      <Cpu className="w-5 h-5 text-cyber-accent" />
                    </div>
                    <div>
                      <p className="font-semibold text-white text-sm">{device.vendor} {device.model}</p>
                      <p className="text-xs text-cyber-muted font-mono">{device.ip_address}{device.mac_address ? ` • ${device.mac_address}` : ''}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {device.community_matches.length > 0 && (
                      <span className="text-[10px] px-2 py-0.5 rounded border border-cyber-accent/30 bg-cyber-accent/10 text-cyber-accent font-semibold">
                        {device.community_matches.length} known
                      </span>
                    )}
                    <RiskBadge level={device.risk_level} showScore={device.risk_score} size="sm" />
                    <Link href={`/devices/${device.id}`} onClick={e => e.stopPropagation()}
                      className="p-1.5 rounded text-cyber-muted hover:text-cyber-accent">
                      <ExternalLink className="w-4 h-4" />
                    </Link>
                    {expandedDevice === device.id ? <ChevronUp className="w-4 h-4 text-cyber-muted" /> : <ChevronDown className="w-4 h-4 text-cyber-muted" />}
                  </div>
                </div>

                {expandedDevice === device.id && (
                  <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} className="border-t border-cyber-border">
                    <div className="p-4 space-y-3">
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                        <div><span className="text-cyber-muted">Type:</span> <span className="text-white capitalize ml-1">{device.device_type}</span></div>
                        <div><span className="text-cyber-muted">Firmware:</span> <span className="text-white ml-1">{device.firmware_version}</span></div>
                        <div><span className="text-cyber-muted">Ports:</span> <span className="text-white ml-1">{device.open_ports.map(p => p.port).join(', ')}</span></div>
                        <div><span className="text-cyber-muted">Protocols:</span> <span className="text-white ml-1">{device.protocols.join(', ')}</span></div>
                      </div>
                      {device.community_matches.length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">Community Vulnerability Matches</p>
                          <div className="space-y-2">
                            {device.community_matches.filter(matchPasses).map(m => <MatchCard key={m.id} match={m} compact />)}
                          </div>
                        </div>
                      )}
                      {device.vulnerabilities.length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">Vulnerabilities</p>
                          <div className="space-y-2">
                            {device.vulnerabilities.map(v => (
                              <div key={v.id} className="bg-cyber-surface rounded-lg p-3 flex items-start justify-between gap-3">
                                <div>
                                  <p className="text-sm font-medium text-white">{v.title}</p>
                                  <p className="text-xs text-cyber-text-muted mt-0.5">{v.description}</p>
                                  <p className="text-xs text-cyber-accent mt-1">Fix: {v.recommendation}</p>
                                </div>
                                <RiskBadge level={v.severity} size="sm" />
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </motion.div>
            ))
          )}
        </div>
      </div>
    </DashboardLayout>
  )
}
