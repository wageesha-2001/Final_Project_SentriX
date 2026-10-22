'use client'

import { useCallback, useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import toast from 'react-hot-toast'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { CommunityVulnerability, VulnDbRun } from '@/types'
import { formatDate, cn } from '@/lib/utils'
import {
  Database, Search, Filter, RefreshCw, Github, FileUp, CheckCircle2, XCircle, AlertTriangle, History, ChevronDown, ChevronUp,
} from 'lucide-react'

interface Status {
  enabled: boolean
  sync_mode: string
  local_path: string
  remote_url: string
  total_records: number
  total_matches: number
  last_load: LoadInfo | null
  last_remote_load: LoadInfo | null
  last_sync: VulnDbRun | null
  last_successful_sync_at: string | null
  check: { id: string; enabled: boolean } | null
  is_admin: boolean
}

interface LoadInfo {
  status: string
  message: string
  total_records: number
  loaded_records: number
  skipped_records: number
  issues: { index: number; id?: string; errors: string[] }[]
}

interface Filters { vendors: string[]; categories: string[]; severities: string[]; source_types: string[] }
type RecordRow = CommunityVulnerability

const SEV_CLASS: Record<string, string> = {
  Critical: 'text-cyber-red bg-cyber-red/10 border-cyber-red/30',
  High: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  Medium: 'text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/30',
  Low: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  Informational: 'text-purple-400 bg-purple-400/10 border-purple-400/30',
}
const RUN_CLASS: Record<string, string> = {
  success: 'text-cyber-green', partial: 'text-cyber-yellow', failed: 'text-cyber-red', running: 'text-cyber-accent',
}
const PAGE_SIZE = 25

export default function CommunityVulnsPage() {
  const [loading, setLoading] = useState(true)
  const [status, setStatus] = useState<Status | null>(null)
  const [records, setRecords] = useState<RecordRow[]>([])
  const [total, setTotal] = useState(0)
  const [filters, setFilters] = useState<Filters>({ vendors: [], categories: [], severities: [], source_types: [] })
  const [q, setQ] = useState('')
  const [vendor, setVendor] = useState('')
  const [category, setCategory] = useState('')
  const [severity, setSeverity] = useState('')
  const [sourceType, setSourceType] = useState('')
  const [page, setPage] = useState(0)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [busy, setBusy] = useState<'local' | 'remote' | 'toggle' | null>(null)
  const [history, setHistory] = useState<VulnDbRun[]>([])
  const [showHistory, setShowHistory] = useState(false)
  const [lastSummary, setLastSummary] = useState<{ message: string; status: string; imported: number; skipped: number; issues: { index: number; id?: string; errors: string[] }[] } | null>(null)

  const loadStatus = useCallback(async () => {
    const res = await fetch('/api/community-vulns/status')
    if (res.ok) setStatus((await res.json()).data)
  }, [])

  const loadRecords = useCallback(async () => {
    const params = new URLSearchParams({ q, vendor, category, severity, source_type: sourceType, page: String(page), limit: String(PAGE_SIZE) })
    const res = await fetch(`/api/community-vulns?${params}`)
    if (res.ok) {
      const d = (await res.json()).data
      setRecords(d.records); setTotal(d.total); setFilters(d.filters)
    }
  }, [q, vendor, category, severity, sourceType, page])

  const loadHistory = useCallback(async () => {
    const res = await fetch('/api/community-vulns/sync')
    if (res.ok) setHistory((await res.json()).data ?? [])
  }, [])

  useEffect(() => { loadStatus().finally(() => setLoading(false)) }, [loadStatus])
  useEffect(() => { setPage(0) }, [q, vendor, category, severity, sourceType])
  useEffect(() => {
    const t = setTimeout(loadRecords, q ? 250 : 0)
    return () => clearTimeout(t)
  }, [loadRecords, q])
  useEffect(() => { if (status?.is_admin && showHistory) loadHistory() }, [status?.is_admin, showHistory, loadHistory])

  const runSync = async (source: 'local' | 'remote') => {
    setBusy(source)
    try {
      const res = await fetch('/api/community-vulns/sync', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ source }),
      })
      const body = await res.json()
      if (body.data) {
        const s = body.data
        setLastSummary({ message: s.message, status: s.status, imported: s.loaded_records, skipped: s.skipped_records, issues: s.issues ?? [] })
        if (s.status === 'success') toast.success(s.message)
        else if (s.status === 'partial') toast(s.message, { icon: '⚠️' })
        else toast.error(s.message)
      } else {
        toast.error(body.error || 'Sync failed')
      }
      await Promise.all([loadStatus(), loadRecords(), showHistory ? loadHistory() : Promise.resolve()])
    } catch {
      toast.error('Network error')
    } finally {
      setBusy(null)
    }
  }

  const toggleCheck = async () => {
    if (!status?.check) return
    setBusy('toggle')
    try {
      const enabled = !status.check.enabled
      const res = await fetch(`/api/vulnerability-checks/${status.check.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }),
      })
      if (res.ok) { toast.success(`Community Vulnerability Mapping ${enabled ? 'enabled' : 'disabled'}`); await loadStatus() }
      else toast.error((await res.json()).error || 'Failed to update check')
    } finally { setBusy(null) }
  }

  if (loading) return <DashboardLayout title="Community Vulnerability Database"><LoadingSpinner size="lg" className="h-64" /></DashboardLayout>
  if (!status) return <DashboardLayout title="Community Vulnerability Database"><EmptyState icon={Database} title="Unable to load status" /></DashboardLayout>

  const isAdmin = status.is_admin
  const totalPages = Math.max(Math.ceil(total / PAGE_SIZE), 1)
  const last = status.last_sync
  const remoteConfigured = status.remote_url !== ''

  return (
    <DashboardLayout title="Community Vulnerability Database" subtitle="Locally maintained and GitHub-hosted CCTV vulnerability knowledge base">
      <div className="space-y-6 max-w-6xl">

        {/* ── Status & actions ───────────────────────────────────────────── */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="cyber-card p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Database className="w-5 h-5 text-cyber-accent" /> Database Status
              </h2>
              <p className="text-xs text-cyber-text-muted mt-1">
                Defensive identification only — records are matched to detected devices, never executed.
                {!isAdmin && <span className="text-amber-400 ml-1">(Admin access required to reload or sync)</span>}
              </p>
            </div>
            {isAdmin && (
              <div className="flex flex-wrap gap-2">
                <button onClick={() => runSync('local')} disabled={busy !== null || !status.enabled}
                  className="cyber-btn-primary px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-2 disabled:opacity-50">
                  {busy === 'local' ? <span className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> : <FileUp className="w-3.5 h-3.5" />}
                  Reload local file
                </button>
                <button onClick={() => runSync('remote')} disabled={busy !== null || !status.enabled || !remoteConfigured}
                  title={remoteConfigured ? undefined : 'Set COMMUNITY_VULN_DB_REMOTE_URL to enable'}
                  className="px-4 py-2 rounded-lg text-xs font-bold flex items-center gap-2 bg-cyber-surface border border-cyber-border text-white hover:border-cyber-accent disabled:opacity-50 disabled:cursor-not-allowed">
                  {busy === 'remote' ? <span className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" /> : <Github className="w-3.5 h-3.5" />}
                  Sync from GitHub
                </button>
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5 pt-5 border-t border-cyber-border">
            <Stat label="Total Records" value={status.total_records} color="text-cyber-accent" />
            <Stat label="Matches on Current Devices" value={status.total_matches} color="text-cyber-yellow" />
            <div className="text-center">
              <p className={cn('text-sm font-bold', status.enabled ? 'text-cyber-green' : 'text-cyber-red')}>{status.enabled ? 'Enabled' : 'Disabled'}</p>
              <p className="text-xs text-cyber-muted uppercase tracking-wider mt-1">Database</p>
            </div>
            <div className="text-center">
              <p className="text-sm font-bold text-white uppercase">{status.sync_mode}</p>
              <p className="text-xs text-cyber-muted uppercase tracking-wider mt-1">Sync Mode</p>
            </div>
          </div>

          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 mt-5 text-xs">
            <Info label="Local file path" value={status.local_path} mono />
            <Info label="Remote GitHub raw URL" value={status.remote_url || 'Not configured'} mono />
            <Info label="Last sync status" value={last ? <span className={cn('font-semibold capitalize', RUN_CLASS[last.status])}>{last.status} ({last.source}) — {formatDate(last.at)}</span> : 'Never synced'} />
            <Info label="Last successful sync" value={status.last_successful_sync_at ? formatDate(status.last_successful_sync_at) : '—'} />
            <Info label="Local file" value={status.last_load ? `${status.last_load.loaded_records} of ${status.last_load.total_records} records valid${status.last_load.skipped_records ? `, ${status.last_load.skipped_records} skipped` : ''}` : '—'} />
          </dl>

          {status.last_load && status.last_load.issues.length > 0 && (
            <div className="mt-4 text-xs text-cyber-yellow bg-cyber-yellow/5 border border-cyber-yellow/20 rounded-lg p-3">
              <p className="font-semibold">{status.last_load.message}</p>
              <ul className="list-disc pl-5 mt-1 max-h-32 overflow-y-auto">
                {status.last_load.issues.slice(0, 10).map(i => (
                  <li key={`${i.index}-${i.id ?? ''}`}>Record #{i.index + 1}{i.id ? ` (${i.id})` : ''}: {i.errors.join('; ')}</li>
                ))}
              </ul>
            </div>
          )}

          {status.check && (
            <div className="mt-5 flex items-center justify-between gap-4 p-4 bg-cyber-surface rounded-lg">
              <div>
                <p className="text-sm font-medium text-white">Community Vulnerability Mapping check</p>
                <p className="text-xs text-cyber-text-muted mt-0.5">When enabled, scans map detected devices to these records and add the matched risk to the device score.</p>
              </div>
              <button type="button" onClick={toggleCheck} disabled={!isAdmin || busy !== null} aria-pressed={status.check.enabled}
                className={cn('relative inline-flex h-6 w-11 flex-shrink-0 items-center rounded-full transition-colors', status.check.enabled ? 'bg-cyber-accent' : 'bg-cyber-border', (!isAdmin || busy) && 'opacity-50 cursor-not-allowed')}>
                <span className={cn('inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform', status.check.enabled ? 'translate-x-6' : 'translate-x-1')} />
              </button>
            </div>
          )}

          {lastSummary && (
            <div className="mt-5 p-4 rounded-lg border border-cyber-border bg-cyber-surface text-xs space-y-2">
              <p className={cn('font-semibold flex items-center gap-2', RUN_CLASS[lastSummary.status])}>
                {lastSummary.status === 'success' ? <CheckCircle2 className="w-4 h-4" /> : lastSummary.status === 'partial' ? <AlertTriangle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                {lastSummary.message}
              </p>
              <p className="text-cyber-text-muted">Loaded {lastSummary.imported} · Skipped {lastSummary.skipped}</p>
              {lastSummary.issues.length > 0 && (
                <ul className="list-disc pl-5 text-cyber-muted max-h-40 overflow-y-auto">
                  {lastSummary.issues.slice(0, 20).map(i => (
                    <li key={`${i.index}-${i.id ?? ''}`}>Record #{i.index}{i.id ? ` (${i.id})` : ''}: {i.errors.join('; ')}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </motion.div>

        {/* ── Sync history (admin) ───────────────────────────────────────── */}
        {isAdmin && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="cyber-card overflow-hidden">
            <button type="button" onClick={() => setShowHistory(s => !s)} className="w-full flex items-center justify-between px-6 py-4 hover:bg-cyber-surface/40">
              <span className="text-sm font-semibold text-white flex items-center gap-2"><History className="w-4 h-4 text-cyber-accent" /> Sync History</span>
              {showHistory ? <ChevronUp className="w-4 h-4 text-cyber-muted" /> : <ChevronDown className="w-4 h-4 text-cyber-muted" />}
            </button>
            {showHistory && (
              history.length === 0 ? <p className="px-6 pb-6 text-xs text-cyber-muted">No sync runs yet.</p> : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="border-y border-cyber-border bg-cyber-surface/40 text-cyber-text-muted uppercase tracking-wider">
                      {['When', 'Source', 'Status', 'Total', 'Loaded', 'Skipped'].map(h => <th key={h} className="text-left px-4 py-2 font-semibold">{h}</th>)}
                    </tr></thead>
                    <tbody className="divide-y divide-cyber-border/30">
                      {history.map((r, i) => (
                        <tr key={`${r.at}-${i}`} title={r.message}>
                          <td className="px-4 py-2 font-mono text-cyber-muted whitespace-nowrap">{formatDate(r.at)}</td>
                          <td className="px-4 py-2 text-white capitalize">{r.source}</td>
                          <td className={cn('px-4 py-2 font-semibold capitalize', RUN_CLASS[r.status])}>{r.status}</td>
                          <td className="px-4 py-2 text-white">{r.total_records}</td>
                          <td className="px-4 py-2 text-white">{r.loaded_records}</td>
                          <td className="px-4 py-2 text-white">{r.skipped_records}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )
            )}
          </motion.div>
        )}

        {/* ── Records browser ────────────────────────────────────────────── */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="cyber-card overflow-hidden">
          <div className="p-6 border-b border-cyber-border space-y-4">
            <h2 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider">Vulnerability Records ({total})</h2>
            <div className="flex flex-wrap gap-3">
              <div className="relative flex-1 min-w-48">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
                <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search by ID, title, vendor, model..."
                  className="cyber-input w-full pl-9 pr-4 py-2 rounded-lg text-xs" />
              </div>
              <FilterSelect label="All Vendors" value={vendor} onChange={setVendor} options={filters.vendors} />
              <FilterSelect label="All Categories" value={category} onChange={setCategory} options={filters.categories} />
              <FilterSelect label="All Severities" value={severity} onChange={setSeverity} options={filters.severities} />
              <FilterSelect label="All Sources" value={sourceType} onChange={setSourceType} options={filters.source_types} />
            </div>
          </div>

          {records.length === 0 ? (
            <div className="p-10">
              <EmptyState icon={Database} title="No vulnerability records found."
                description={status.total_records === 0 ? (isAdmin ? 'Add records to the text file, then use “Reload local file”.' : 'Ask an administrator to check the vulnerability text file.') : 'Try changing the search or filters.'} />
            </div>
          ) : (
            <div className="divide-y divide-cyber-border/30">
              {records.map(r => (
                <div key={r.id}>
                  <button type="button" onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                    className="w-full text-left px-6 py-3 flex items-start justify-between gap-4 hover:bg-cyber-surface/30">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-white truncate">{r.title}</p>
                      <p className="text-xs text-cyber-muted mt-0.5">
                        <span className="font-mono">{r.vuln_id}</span> · {r.vendor} · {r.category} · {r.device_type}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-cyber-surface border border-cyber-border text-cyber-text-muted">{r.source_type}</span>
                      <span className={cn('text-[10px] px-2 py-0.5 rounded border font-bold uppercase tracking-wider', SEV_CLASS[r.severity])}>{r.severity}</span>
                    </div>
                  </button>
                  {expanded === r.id && (
                    <div className="px-6 pb-4 text-xs space-y-3 bg-cyber-surface/20">
                      <p className="text-cyber-text-muted leading-relaxed">{r.description}</p>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        <Info label="Models" value={r.affected_models.join(', ')} />
                        <Info label="Firmware" value={r.affected_firmware.join(', ')} />
                        <Info label="Ports / Protocols" value={[...r.affected_ports, ...r.affected_protocols].join(', ') || '—'} />
                        <Info label="CVSS / Risk" value={`${r.cvss_score} / +${r.risk_score}`} />
                      </div>
                      <p className="text-cyber-accent"><span className="font-semibold">Recommendation:</span> {r.recommendation}</p>
                      <p className="text-cyber-muted italic">{r.confidence_note}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {total > PAGE_SIZE && (
            <div className="flex items-center justify-between px-6 py-3 border-t border-cyber-border">
              <span className="text-xs text-cyber-muted">Page {page + 1} of {totalPages}</span>
              <div className="flex gap-2">
                <button onClick={() => setPage(p => p - 1)} disabled={page === 0}
                  className="px-3 py-1 text-xs rounded border border-cyber-border text-cyber-text-muted hover:text-white disabled:opacity-40 disabled:cursor-not-allowed">Prev</button>
                <button onClick={() => setPage(p => p + 1)} disabled={page >= totalPages - 1}
                  className="px-3 py-1 text-xs rounded border border-cyber-border text-cyber-text-muted hover:text-white disabled:opacity-40 disabled:cursor-not-allowed">Next</button>
              </div>
            </div>
          )}
        </motion.div>

        <button onClick={() => { loadStatus(); loadRecords() }}
          className="flex items-center gap-1.5 text-xs text-cyber-muted hover:text-white">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>
    </DashboardLayout>
  )
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center">
      <p className={cn('text-2xl font-black', color)}>{value}</p>
      <p className="text-xs text-cyber-muted uppercase tracking-wider mt-1">{label}</p>
    </div>
  )
}

function Info({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-cyber-muted uppercase tracking-wider text-[10px]">{label}</dt>
      <dd className={cn('text-white mt-0.5 break-words', mono && 'font-mono')}>{value}</dd>
    </div>
  )
}

function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <div className="relative">
      <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
      <select value={value} onChange={e => onChange(e.target.value)} aria-label={label}
        className="cyber-input pl-9 pr-8 py-2 rounded-lg text-xs appearance-none cursor-pointer max-w-[12rem]">
        <option value="">{label}</option>
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </div>
  )
}
