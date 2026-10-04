'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import { motion } from 'framer-motion'
import Link from 'next/link'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Scan, Device, Vulnerability } from '@/types'
import { formatDate, formatDuration } from '@/lib/utils'
import { Cpu, Shield, AlertTriangle, FileText, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react'
import toast from 'react-hot-toast'

interface DeviceWithVulns extends Device { vulnerabilities: Vulnerability[] }

export default function ScanResultsPage() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<Scan | null>(null)
  const [devices, setDevices] = useState<DeviceWithVulns[]>([])
  const [loading, setLoading] = useState(true)
  const [generatingReport, setGeneratingReport] = useState(false)
  const [expandedDevice, setExpandedDevice] = useState<string | null>(null)

  useEffect(() => {
    fetch(`/api/scans/${id}/results`)
      .then(r => r.json())
      .then(data => {
        if (data.data) {
          setScan(data.data.scan)
          const devMap = new Map(data.data.devices.map((d: Device) => [d.id, { ...d, vulnerabilities: [] }]))
          data.data.vulnerabilities.forEach((v: Vulnerability) => {
            const dev = devMap.get(v.device_id) as DeviceWithVulns | undefined
            if (dev) dev.vulnerabilities.push(v)
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
      else toast.error('Failed to generate report')
    } catch { toast.error('Error generating report') }
    finally { setGeneratingReport(false) }
  }

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
            <div className="flex items-center gap-3">
              <RiskBadge level={scan.overall_risk} size="lg" />
              <button onClick={handleGenerateReport} disabled={generatingReport}
                className="cyber-btn-primary px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-2">
                {generatingReport ? <span className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> : <FileText className="w-3.5 h-3.5" />}
                {generatingReport ? 'Generating...' : 'Generate Report'}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5 pt-5 border-t border-cyber-border">
            {[
              { label: 'Total Devices', value: scan.total_devices, color: 'text-cyber-accent' },
              { label: 'Secure', value: scan.total_devices - scan.vulnerable_devices, color: 'text-cyber-green' },
              { label: 'Vulnerable', value: scan.vulnerable_devices, color: 'text-cyber-yellow' },
              { label: 'Critical', value: scan.critical_devices, color: 'text-cyber-red' },
            ].map(stat => (
              <div key={stat.label} className="text-center">
                <p className={`text-2xl font-black ${stat.color}`}>{stat.value}</p>
                <p className="text-xs text-cyber-muted uppercase tracking-wider mt-1">{stat.label}</p>
              </div>
            ))}
          </div>
        </motion.div>

        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider">Discovered Devices ({devices.length})</h3>
          {devices.length === 0 ? (
            <EmptyState icon={Cpu} title="No devices discovered" description="The scan did not find any devices on the network." />
          ) : (
            devices.map((device, i) => (
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
                      <p className="text-xs text-cyber-muted font-mono">{device.ip_address} • {device.mac_address}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
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
