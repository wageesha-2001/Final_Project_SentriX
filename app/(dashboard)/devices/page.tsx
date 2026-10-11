'use client'

import { Suspense, useEffect, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { SimulatedDataBanner, SimulatedTag } from '@/components/ui/SimulatedDataBanner'
import { DeviceListItem, SecurityStatus } from '@/types'
import { formatDate } from '@/lib/utils'
import { Cpu, Search, Filter, ExternalLink } from 'lucide-react'

const SECURITY_STATUS: Record<SecurityStatus, { label: string; className: string }> = {
  vulnerable: { label: 'Vulnerable', className: 'text-cyber-red border-cyber-red/30 bg-cyber-red/10' },
  potential: { label: 'Potential issues', className: 'text-cyber-yellow border-cyber-yellow/30 bg-cyber-yellow/10' },
  secure: { label: 'Secure', className: 'text-cyber-green border-cyber-green/30 bg-cyber-green/10' },
}

const DEVICE_TYPE_LABEL: Record<string, string> = { camera: 'IP Camera', nvr: 'NVR', dvr: 'DVR', router: 'Router', unknown: 'Unknown' }

const onlineLabel = (status: string) => (status === 'active' || status === 'online' ? 'Online at last scan' : status || 'Unknown')

function DevicesContent() {
  const [devices, setDevices] = useState<DeviceListItem[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterRisk, setFilterRisk] = useState('all')
  const [filterType, setFilterType] = useState('all')
  const [filterStatus, setFilterStatus] = useState('all')
  const searchParams = useSearchParams()
  const scanFilter = searchParams.get('scan')

  useEffect(() => {
    fetch(scanFilter ? `/api/devices?scan=${encodeURIComponent(scanFilter)}` : '/api/devices')
      .then(r => r.json())
      .then(d => setDevices(d.data || []))
      .catch(() => setDevices([]))
      .finally(() => setLoading(false))
  }, [scanFilter])

  const filtered = devices.filter(d => {
    const matchSearch = d.ip_address.includes(search) || d.vendor.toLowerCase().includes(search.toLowerCase()) || d.model.toLowerCase().includes(search.toLowerCase())
    const matchRisk = filterRisk === 'all' || d.risk_level === filterRisk
    const matchType = filterType === 'all' || d.device_type === filterType
    const matchStatus = filterStatus === 'all' || d.security_status === filterStatus
    return matchSearch && matchRisk && matchType && matchStatus
  })

  const count = (pred: (d: DeviceListItem) => boolean) => devices.filter(pred).length

  return (
    <DashboardLayout title="Devices"
      subtitle={scanFilter ? 'CCTV devices found by this scan' : 'CCTV device inventory — each device once, from its latest scan'}>
      <div className="space-y-4">
        {!loading && devices.some(d => d.simulated) && <SimulatedDataBanner context={scanFilter ? 'scan' : 'dashboard'} />}
        {!loading && devices.length > 0 && (
          <div className="cyber-card p-4 flex flex-wrap gap-x-6 gap-y-2 text-xs">
            <span className="text-cyber-muted">Identified: <strong className="text-white">{devices.length}</strong> devices</span>
            <span className="text-cyber-muted">IP Cameras: <strong className="text-white">{count(d => d.device_type === 'camera')}</strong></span>
            <span className="text-cyber-muted">NVRs: <strong className="text-white">{count(d => d.device_type === 'nvr')}</strong></span>
            <span className="text-cyber-muted">Vulnerable: <strong className="text-cyber-red">{count(d => d.security_status === 'vulnerable')}</strong></span>
            <span className="text-cyber-muted">Potential issues: <strong className="text-cyber-yellow">{count(d => d.security_status === 'potential')}</strong></span>
            <span className="text-cyber-muted">Secure: <strong className="text-cyber-green">{count(d => d.security_status === 'secure')}</strong></span>
          </div>
        )}
        <div className="flex flex-wrap gap-3">
          <div className="relative flex-1 min-w-48">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by IP, vendor, or model..."
              className="cyber-input w-full pl-10 pr-4 py-2.5 rounded-lg text-sm" />
          </div>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <select value={filterRisk} onChange={e => setFilterRisk(e.target.value)}
              className="cyber-input pl-10 pr-8 py-2.5 rounded-lg text-sm appearance-none cursor-pointer">
              <option value="all">All Risk Levels</option>
              <option value="secure">Secure</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <select value={filterType} onChange={e => setFilterType(e.target.value)} aria-label="Device type"
            className="cyber-input px-3 py-2.5 rounded-lg text-sm cursor-pointer">
            <option value="all">All Device Types</option>
            <option value="camera">IP Cameras</option>
            <option value="nvr">NVRs</option>
          </select>
          <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)} aria-label="Security status"
            className="cyber-input px-3 py-2.5 rounded-lg text-sm cursor-pointer">
            <option value="all">All Statuses</option>
            <option value="vulnerable">Vulnerable</option>
            <option value="potential">Potential issues</option>
            <option value="secure">Secure</option>
          </select>
        </div>

        {loading ? <LoadingSpinner size="lg" text="Loading devices..." className="h-48" /> :
         filtered.length === 0 ? (
           <EmptyState icon={Cpu} title="No devices found"
             description={devices.length > 0 ? 'No devices match your search or filters.' : 'Run a scan to discover devices on your network.'} />
         ) : (
           <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
             {filtered.map((device, i) => (
               <motion.div key={device.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                 className="cyber-card p-4 hover:border-cyber-accent/30 transition-colors group">
                 <div className="flex items-start justify-between mb-3">
                   <div className="flex items-center gap-3">
                     <div className="w-10 h-10 rounded-lg bg-cyber-surface border border-cyber-border flex items-center justify-center group-hover:border-cyber-accent/40 transition-colors">
                       <Cpu className="w-5 h-5 text-cyber-accent" />
                     </div>
                     <div>
                       <p className="font-semibold text-white text-sm flex items-center gap-2">{device.vendor}{device.simulated && <SimulatedTag />}</p>
                       <p className="text-xs text-cyber-muted">{device.model}</p>
                     </div>
                   </div>
                   <RiskBadge level={device.risk_level} showScore={device.risk_score} size="sm" />
                 </div>
                 <div className="space-y-1.5 text-xs mb-3">
                   <div className="flex justify-between"><span className="text-cyber-muted">IP:</span><span className="text-white font-mono">{device.ip_address}</span></div>
                   <div className="flex justify-between"><span className="text-cyber-muted">Type:</span><span className="text-white">{DEVICE_TYPE_LABEL[device.device_type] ?? device.device_type}</span></div>
                   <div className="flex justify-between items-center"><span className="text-cyber-muted">Status:</span>
                     <span className="flex items-center gap-2">
                       <span className="flex items-center gap-1 text-white"><span className="w-1.5 h-1.5 rounded-full bg-cyber-green" />{onlineLabel(device.status)}</span>
                       {device.security_status && (
                         <span className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold ${SECURITY_STATUS[device.security_status].className}`}>
                           {SECURITY_STATUS[device.security_status].label}
                         </span>
                       )}
                     </span>
                   </div>
                   <div className="flex justify-between"><span className="text-cyber-muted">Findings:</span>
                     <span className="text-white">{device.findings_count} check{device.findings_count === 1 ? '' : 's'} • {device.community_match_count} DB match{device.community_match_count === 1 ? '' : 'es'}</span></div>
                   <div className="flex justify-between"><span className="text-cyber-muted">Ports:</span><span className="text-white font-mono">{device.open_ports.map(p => p.port).join(', ')}</span></div>
                   <div className="flex justify-between"><span className="text-cyber-muted">Scanned:</span><span className="text-white">{formatDate(device.created_at)}</span></div>
                 </div>
                 <Link href={`/devices/${device.id}`}
                   className="flex items-center justify-center gap-2 w-full py-2 rounded-lg border border-cyber-border text-xs text-cyber-text-muted hover:text-cyber-accent hover:border-cyber-accent/30 transition-colors">
                   <ExternalLink className="w-3.5 h-3.5" /> View Details
                 </Link>
               </motion.div>
             ))}
           </div>
         )}
      </div>
    </DashboardLayout>
  )
}

export default function DevicesPage() {
  return (
    <Suspense fallback={<DashboardLayout title="Devices"><LoadingSpinner size="lg" className="h-64" /></DashboardLayout>}>
      <DevicesContent />
    </Suspense>
  )
}
