'use client'

import { useEffect, useState, useMemo } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { motion, AnimatePresence } from 'framer-motion'
import toast from 'react-hot-toast'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { ConfirmDialog } from '@/components/ui/ConfirmDialog'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { settingsSchema, SettingsInput } from '@/lib/validators/schemas'
import { DefaultCredential, VulnerabilityCheck } from '@/types'
import {
  Settings, Shield, Plus, Trash2, ToggleLeft, ToggleRight,
  Search, CheckCircle2, XCircle, ChevronDown, ChevronUp,
  Info, Zap, AlertTriangle, Filter
} from 'lucide-react'
import { cn } from '@/lib/utils'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational']
const CREDS_PER_PAGE = 25

const severityConfig: Record<string, { color: string; bg: string; border: string; icon: React.ReactNode }> = {
  critical: { color: 'text-cyber-red', bg: 'bg-cyber-red/10', border: 'border-cyber-red/30', icon: <Zap className="w-3.5 h-3.5" /> },
  high: { color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/30', icon: <AlertTriangle className="w-3.5 h-3.5" /> },
  medium: { color: 'text-cyber-yellow', bg: 'bg-cyber-yellow/10', border: 'border-cyber-yellow/30', icon: <AlertTriangle className="w-3.5 h-3.5" /> },
  low: { color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/30', icon: <Info className="w-3.5 h-3.5" /> },
  informational: { color: 'text-purple-400', bg: 'bg-purple-400/10', border: 'border-purple-400/30', icon: <Info className="w-3.5 h-3.5" /> },
}

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = severityConfig[severity] ?? severityConfig.low
  return (
    <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider', cfg.color, cfg.bg, cfg.border)}>
      {cfg.icon}{severity}
    </span>
  )
}

function ToggleSwitch({ enabled, onChange, disabled }: { enabled: boolean; onChange: () => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      onClick={onChange}
      disabled={disabled}
      className={cn(
        'relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 focus:outline-none',
        enabled ? 'bg-cyber-accent' : 'bg-cyber-border',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    >
      <span className={cn(
        'inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform duration-200',
        enabled ? 'translate-x-6' : 'translate-x-1'
      )} />
    </button>
  )
}

function RecommendationModal({ check, onClose }: { check: VulnerabilityCheck; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <motion.div initial={{ opacity: 0, scale: 0.9, y: 20 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.9 }}
        className="relative cyber-card p-6 w-full max-w-lg z-10">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-white">{check.name}</h3>
            <div className="flex items-center gap-2 mt-1">
              <SeverityBadge severity={check.severity} />
              {check.risk_score > 0 && (
                <span className="text-xs text-cyber-muted">+{check.risk_score} risk score</span>
              )}
            </div>
          </div>
          <button onClick={onClose} className="text-cyber-muted hover:text-white ml-4">
            <XCircle className="w-5 h-5" />
          </button>
        </div>
        <div className="space-y-4">
          <div>
            <p className="text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-1">Description</p>
            <p className="text-sm text-cyber-text-muted leading-relaxed">{check.description}</p>
          </div>
          <div className="p-3 bg-cyber-accent/5 border border-cyber-accent/20 rounded-lg">
            <p className="text-xs font-semibold text-cyber-accent uppercase tracking-wider mb-1 flex items-center gap-1">
              <Shield className="w-3 h-3" /> Recommendation
            </p>
            <p className="text-sm text-cyber-text-muted leading-relaxed">{check.recommendation}</p>
          </div>
          <div className="flex justify-between text-xs text-cyber-muted pt-2 border-t border-cyber-border">
            <span>Slug: <code className="text-cyber-accent font-mono">{check.slug}</code></span>
            <span>Status: <span className={check.enabled ? 'text-cyber-green' : 'text-cyber-red'}>{check.enabled ? 'Enabled' : 'Disabled'}</span></span>
          </div>
        </div>
      </motion.div>
    </div>
  )
}

export default function SettingsPage() {
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [credentials, setCredentials] = useState<DefaultCredential[]>([])
  const [deleteCredId, setDeleteCredId] = useState<string | null>(null)
  const [newCred, setNewCred] = useState<{ vendor: string; username: string; password: string; risk_level: DefaultCredential['risk_level'] }>({ vendor: '', username: '', password: '', risk_level: 'critical' })
  const [isAdmin, setIsAdmin] = useState(false)

  // Credentials search / filter / pagination state
  const [credSearch, setCredSearch] = useState('')
  const [credRiskFilter, setCredRiskFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')
  const [credPage, setCredPage] = useState(0)

  // Vulnerability checks state
  const [vulnChecks, setVulnChecks] = useState<VulnerabilityCheck[]>([])
  const [vulnSearch, setVulnSearch] = useState('')
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState('all')
  const [togglingId, setTogglingId] = useState<string | null>(null)
  const [bulkLoading, setBulkLoading] = useState(false)
  const [selectedCheck, setSelectedCheck] = useState<VulnerabilityCheck | null>(null)
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({
    critical: true, high: true, medium: true, low: true, informational: false,
  })

  const { register, handleSubmit, setValue, watch, formState: { errors } } = useForm<SettingsInput>({
    resolver: zodResolver(settingsSchema),
  })
  const safeScanMode = watch('safe_scan_mode')

  useEffect(() => {
    Promise.all([
      fetch('/api/settings').then(r => r.json()),
      fetch('/api/default-credentials').then(r => r.json()),
      fetch('/api/vulnerability-checks').then(r => r.json()),
      fetch('/api/auth/me').then(r => r.json()),
    ]).then(([settings, creds, checks, me]) => {
      if (settings.data) {
        setValue('safe_scan_mode', settings.data.safe_scan_mode)
        setValue('scan_timeout', settings.data.scan_timeout)
        setValue('login_attempt_limit', settings.data.login_attempt_limit)
      }
      setCredentials(creds.data || [])
      setVulnChecks(checks.data || [])
      if (me.data?.role === 'admin') setIsAdmin(true)
    }).finally(() => setLoading(false))
  }, [setValue])

  const onSubmit = async (data: SettingsInput) => {
    setSaving(true)
    const res = await fetch('/api/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) })
    if (res.ok) toast.success('Settings saved successfully')
    else toast.error('Failed to save settings')
    setSaving(false)
  }

  // ── Vulnerability check actions ───────────────────────────────────────────

  const handleToggleCheck = async (check: VulnerabilityCheck) => {
    if (!isAdmin) { toast.error('Admin access required to modify checks'); return }
    setTogglingId(check.id)
    try {
      const res = await fetch(`/api/vulnerability-checks/${check.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !check.enabled }),
      })
      if (res.ok) {
        setVulnChecks(prev => prev.map(c => c.id === check.id ? { ...c, enabled: !c.enabled } : c))
        toast.success(`${check.name} ${!check.enabled ? 'enabled' : 'disabled'}`)
      } else {
        const d = await res.json()
        toast.error(d.error || 'Failed to update check')
      }
    } catch {
      toast.error('Network error')
    } finally {
      setTogglingId(null)
    }
  }

  const handleBulkAction = async (action: 'enable_all' | 'disable_all', severity?: string) => {
    if (!isAdmin) { toast.error('Admin access required'); return }
    setBulkLoading(true)
    try {
      const res = await fetch('/api/vulnerability-checks/bulk', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, severity }),
      })
      if (res.ok) {
        const d = await res.json()
        const newEnabled = action === 'enable_all'
        setVulnChecks(prev => prev.map(c =>
          severity ? (c.severity === severity ? { ...c, enabled: newEnabled } : c) : { ...c, enabled: newEnabled }
        ))
        toast.success(`${d.data.updated} checks ${newEnabled ? 'enabled' : 'disabled'}`)
      } else toast.error('Bulk action failed')
    } catch {
      toast.error('Network error')
    } finally {
      setBulkLoading(false)
    }
  }

  // ── Filtered / grouped checks ─────────────────────────────────────────────

  const filteredChecks = useMemo(() => {
    return vulnChecks.filter(c => {
      const matchSearch = !vulnSearch ||
        c.name.toLowerCase().includes(vulnSearch.toLowerCase()) ||
        c.description.toLowerCase().includes(vulnSearch.toLowerCase()) ||
        c.slug.includes(vulnSearch.toLowerCase())
      const matchSeverity = vulnSeverityFilter === 'all' || c.severity === vulnSeverityFilter
      return matchSearch && matchSeverity
    })
  }, [vulnChecks, vulnSearch, vulnSeverityFilter])

  const groupedChecks = useMemo(() => {
    return SEVERITY_ORDER.reduce((acc, sev) => {
      const group = filteredChecks.filter(c => c.severity === sev)
      if (group.length > 0) acc[sev] = group
      return acc
    }, {} as Record<string, VulnerabilityCheck[]>)
  }, [filteredChecks])

  const enabledCount = vulnChecks.filter(c => c.enabled).length
  const totalCount = vulnChecks.length

  // ── Filtered / paged credentials ──────────────────────────────────────────

  const filteredCreds = useMemo(() => {
    const result = credentials.filter(c => {
      const search = credSearch.toLowerCase()
      const matchSearch = !credSearch ||
        c.vendor.toLowerCase().includes(search) ||
        (c.username || '').toLowerCase().includes(search)
      const matchRisk = credRiskFilter === 'all' || c.risk_level === credRiskFilter
      return matchSearch && matchRisk
    })
    return result
  }, [credentials, credSearch, credRiskFilter])

  // Reset page when filters change
  useEffect(() => { setCredPage(0) }, [credSearch, credRiskFilter])

  const pagedCreds = useMemo(() => {
    const start = credPage * CREDS_PER_PAGE
    return filteredCreds.slice(start, start + CREDS_PER_PAGE)
  }, [filteredCreds, credPage])

  const credTotalPages = Math.ceil(filteredCreds.length / CREDS_PER_PAGE)
  const credStart = credPage * CREDS_PER_PAGE + 1
  const credEnd = Math.min((credPage + 1) * CREDS_PER_PAGE, filteredCreds.length)

  // ── Credentials actions ───────────────────────────────────────────────────

  const handleAddCred = async () => {
    if (!newCred.vendor) { toast.error('Vendor is required'); return }
    const res = await fetch('/api/default-credentials', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newCred) })
    if (res.ok) {
      const d = await res.json()
      setCredentials([...credentials, d.data])
      setNewCred({ vendor: '', username: '', password: '', risk_level: 'critical' })
      toast.success('Credential added')
    } else toast.error('Failed to add credential (admin only)')
  }

  const handleDeleteCred = async () => {
    if (!deleteCredId) return
    const res = await fetch(`/api/default-credentials/${deleteCredId}`, { method: 'DELETE' })
    if (res.ok) { setCredentials(credentials.filter(c => c.id !== deleteCredId)); toast.success('Credential removed') }
    else toast.error('Failed to delete (admin only)')
    setDeleteCredId(null)
  }

  if (loading) return <DashboardLayout title="Settings"><LoadingSpinner size="lg" className="h-64" /></DashboardLayout>

  return (
    <DashboardLayout title="Settings" subtitle="Configure scanner and security preferences">
      <div className="space-y-6 max-w-4xl">

        {/* ── Scan Settings ─────────────────────────────────────────────── */}
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="cyber-card p-6">
            <h2 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-4 flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyber-accent" /> Scan Settings
            </h2>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-cyber-surface rounded-lg">
                <div>
                  <p className="font-medium text-white text-sm">Safe Scan Mode</p>
                  <p className="text-xs text-cyber-text-muted mt-0.5">Disables credential testing checks for safer auditing</p>
                </div>
                <button type="button" onClick={() => setValue('safe_scan_mode', !safeScanMode)}>
                  {safeScanMode
                    ? <ToggleRight className="w-8 h-8 text-cyber-green" />
                    : <ToggleLeft className="w-8 h-8 text-cyber-muted" />}
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                    Scan Timeout (seconds)
                  </label>
                  <input {...register('scan_timeout', { valueAsNumber: true })} type="number" min="60" max="3600"
                    className="cyber-input w-full px-4 py-2.5 rounded-lg text-sm" />
                  {errors.scan_timeout && <p className="text-cyber-red text-xs mt-1">{errors.scan_timeout.message}</p>}
                </div>
                <div>
                  <label className="block text-xs font-semibold text-cyber-text-muted uppercase tracking-wider mb-2">
                    Login Attempt Limit
                  </label>
                  <input {...register('login_attempt_limit', { valueAsNumber: true })} type="number" min="3" max="20"
                    className="cyber-input w-full px-4 py-2.5 rounded-lg text-sm" />
                  {errors.login_attempt_limit && <p className="text-cyber-red text-xs mt-1">{errors.login_attempt_limit.message}</p>}
                </div>
              </div>
            </div>
          </motion.div>

          <div className="flex justify-end">
            <button type="submit" disabled={saving}
              className="cyber-btn-primary px-6 py-2.5 rounded-lg text-sm font-bold flex items-center gap-2">
              {saving
                ? <><span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />Saving...</>
                : <><Settings className="w-4 h-4" />Save Settings</>}
            </button>
          </div>
        </form>

        {/* ── Vulnerability Checks Module ────────────────────────────────── */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="cyber-card overflow-hidden">

          {/* Header */}
          <div className="p-6 border-b border-cyber-border">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Shield className="w-5 h-5 text-cyber-accent" />
                  Enabled Vulnerability Checks
                </h2>
                <p className="text-xs text-cyber-text-muted mt-1">
                  Control which security checks run during network scans.
                  {!isAdmin && <span className="text-amber-400 ml-1">(Admin access required to modify)</span>}
                </p>
              </div>
              {/* Enabled counter */}
              <div className="flex items-center gap-2">
                <div className="text-right">
                  <p className="text-2xl font-black text-cyber-accent">{enabledCount}<span className="text-cyber-muted text-base font-normal">/{totalCount}</span></p>
                  <p className="text-[10px] text-cyber-muted uppercase tracking-wider">Checks Active</p>
                </div>
                <div className="w-12 h-12 relative">
                  <svg viewBox="0 0 36 36" className="w-12 h-12 -rotate-90">
                    <circle cx="18" cy="18" r="14" fill="none" stroke="#1e2d3d" strokeWidth="3" />
                    <circle cx="18" cy="18" r="14" fill="none" stroke="#00d4ff" strokeWidth="3"
                      strokeDasharray={`${totalCount > 0 ? (enabledCount / totalCount) * 87.96 : 0} 87.96`}
                      strokeLinecap="round" />
                  </svg>
                </div>
              </div>
            </div>

            {/* Bulk actions */}
            {isAdmin && (
              <div className="flex flex-wrap gap-2 mt-4">
                <button onClick={() => handleBulkAction('enable_all')} disabled={bulkLoading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-green/10 border border-cyber-green/30 text-cyber-green text-xs font-semibold hover:bg-cyber-green/20 transition-colors disabled:opacity-50">
                  <CheckCircle2 className="w-3.5 h-3.5" />Enable All
                </button>
                <button onClick={() => handleBulkAction('disable_all')} disabled={bulkLoading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-red/10 border border-cyber-red/30 text-cyber-red text-xs font-semibold hover:bg-cyber-red/20 transition-colors disabled:opacity-50">
                  <XCircle className="w-3.5 h-3.5" />Disable All
                </button>
                {bulkLoading && <span className="flex items-center gap-1 text-xs text-cyber-muted">
                  <span className="w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />Applying...
                </span>}
              </div>
            )}

            {/* Search & filter */}
            <div className="flex flex-wrap gap-3 mt-4">
              <div className="relative flex-1 min-w-48">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
                <input value={vulnSearch} onChange={e => setVulnSearch(e.target.value)}
                  placeholder="Search checks by name, description or slug..."
                  className="cyber-input w-full pl-9 pr-4 py-2 rounded-lg text-xs" />
              </div>
              <div className="relative">
                <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
                <select value={vulnSeverityFilter} onChange={e => setVulnSeverityFilter(e.target.value)}
                  className="cyber-input pl-9 pr-8 py-2 rounded-lg text-xs appearance-none cursor-pointer">
                  <option value="all">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="informational">Informational</option>
                </select>
              </div>
            </div>
          </div>

          {/* Grouped check list */}
          <div className="divide-y divide-cyber-border/50">
            {Object.entries(groupedChecks).length === 0 ? (
              <div className="p-10 text-center text-cyber-muted text-sm">
                No checks match your search.
              </div>
            ) : (
              Object.entries(groupedChecks).map(([severity, checks]) => {
                const cfg = severityConfig[severity]
                const isOpen = expandedGroups[severity]
                const groupEnabled = checks.filter(c => c.enabled).length

                return (
                  <div key={severity}>
                    {/* Group header: a div with button semantics, because it contains
                        the enable/disable group buttons (a <button> cannot nest a <button>) */}
                    <div
                      role="button"
                      tabIndex={0}
                      aria-expanded={!!isOpen}
                      onClick={() => setExpandedGroups(prev => ({ ...prev, [severity]: !prev[severity] }))}
                      onKeyDown={(e) => {
                        if (e.target !== e.currentTarget || (e.key !== 'Enter' && e.key !== ' ')) return
                        e.preventDefault()
                        setExpandedGroups(prev => ({ ...prev, [severity]: !prev[severity] }))
                      }}
                      className="w-full flex items-center justify-between px-6 py-3 bg-cyber-surface/40 hover:bg-cyber-surface/70 transition-colors group cursor-pointer"
                    >
                      <div className="flex items-center gap-3">
                        <SeverityBadge severity={severity} />
                        <span className="text-xs text-cyber-text-muted">
                          {groupEnabled}/{checks.length} enabled
                        </span>
                        {isAdmin && (
                          <span className="hidden group-hover:flex items-center gap-2 ml-2">
                            <button type="button" onClick={(e) => { e.stopPropagation(); handleBulkAction('enable_all', severity) }}
                              className="text-[10px] text-cyber-green hover:underline">enable group</button>
                            <span className="text-cyber-border">·</span>
                            <button type="button" onClick={(e) => { e.stopPropagation(); handleBulkAction('disable_all', severity) }}
                              className="text-[10px] text-cyber-red hover:underline">disable group</button>
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-24 bg-cyber-border rounded-full overflow-hidden">
                          <div className={cn('h-full rounded-full transition-all', cfg.bg.replace('/10', '/60'))}
                            style={{ width: `${(groupEnabled / checks.length) * 100}%` }} />
                        </div>
                        {isOpen ? <ChevronUp className="w-4 h-4 text-cyber-muted" /> : <ChevronDown className="w-4 h-4 text-cyber-muted" />}
                      </div>
                    </div>

                    {/* Check rows */}
                    <AnimatePresence initial={false}>
                      {isOpen && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.2 }}
                          className="overflow-hidden"
                        >
                          {checks.map((check, idx) => (
                            <motion.div
                              key={check.id}
                              initial={{ opacity: 0, x: -10 }}
                              animate={{ opacity: 1, x: 0 }}
                              transition={{ delay: idx * 0.03 }}
                              className={cn(
                                'flex items-start gap-4 px-6 py-4 border-b border-cyber-border/30 last:border-0 transition-colors',
                                check.enabled ? 'bg-cyber-card' : 'bg-cyber-bg/50 opacity-70'
                              )}
                            >
                              {/* Toggle */}
                              <div className="mt-0.5 flex-shrink-0">
                                <ToggleSwitch
                                  enabled={check.enabled}
                                  onChange={() => handleToggleCheck(check)}
                                  disabled={!isAdmin || togglingId === check.id}
                                />
                              </div>

                              {/* Content */}
                              <div className="flex-1 min-w-0">
                                <div className="flex flex-wrap items-center gap-2 mb-1">
                                  <p className={cn('text-sm font-semibold', check.enabled ? 'text-white' : 'text-cyber-muted')}>
                                    {check.name}
                                  </p>
                                  {togglingId === check.id && (
                                    <span className="w-3.5 h-3.5 border-2 border-cyber-accent border-t-transparent rounded-full animate-spin" />
                                  )}
                                </div>
                                <p className="text-xs text-cyber-text-muted leading-relaxed line-clamp-2">
                                  {check.description}
                                </p>
                              </div>

                              {/* Meta */}
                              <div className="flex flex-col items-end gap-2 flex-shrink-0">
                                {check.risk_score > 0 ? (
                                  <span className={cn('text-xs font-bold font-mono', cfg.color)}>
                                    +{check.risk_score} pts
                                  </span>
                                ) : (
                                  <span className="text-xs text-purple-400 font-mono">dynamic</span>
                                )}
                                <button
                                  type="button"
                                  onClick={() => setSelectedCheck(check)}
                                  className="flex items-center gap-1 text-[10px] text-cyber-muted hover:text-cyber-accent transition-colors"
                                >
                                  <Info className="w-3 h-3" /> Details
                                </button>
                              </div>
                            </motion.div>
                          ))}
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                )
              })
            )}
          </div>

          {/* Footer summary */}
          <div className="px-6 py-3 bg-cyber-surface/40 border-t border-cyber-border flex flex-wrap gap-4 text-xs text-cyber-muted">
            {SEVERITY_ORDER.map(sev => {
              const count = vulnChecks.filter(c => c.severity === sev && c.enabled).length
              const total = vulnChecks.filter(c => c.severity === sev).length
              if (total === 0) return null
              const cfg = severityConfig[sev]
              return (
                <span key={sev} className="flex items-center gap-1">
                  <span className={cn('w-2 h-2 rounded-full', cfg.bg.replace('/10', '/80'), 'border', cfg.border)}/>
                  <span className={cn('capitalize', cfg.color)}>{sev}</span>
                  <span>{count}/{total}</span>
                </span>
              )
            })}
          </div>
        </motion.div>

        {/* ── Default Credentials Database ──────────────────────────────── */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="cyber-card p-6">
          <h2 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-4">
            Default Credentials Database ({filteredCreds.length})
          </h2>

          {/* Search + risk filter row */}
          <div className="flex flex-wrap gap-3 mb-4">
            <div className="relative flex-1 min-w-48">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
              <input value={credSearch} onChange={e => setCredSearch(e.target.value)}
                placeholder="Search by vendor or username..."
                className="cyber-input w-full pl-9 pr-4 py-2 rounded-lg text-xs" />
            </div>
            <div className="relative">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
              <select value={credRiskFilter} onChange={e => setCredRiskFilter(e.target.value as typeof credRiskFilter)}
                className="cyber-input pl-9 pr-8 py-2 rounded-lg text-xs appearance-none cursor-pointer">
                <option value="all">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 mb-3 text-xs font-semibold text-cyber-text-muted uppercase px-2">
            <span>Vendor</span><span>Username</span><span>Password</span><span>Risk</span><span />
          </div>
          <div className="space-y-1.5">
            {pagedCreds.length === 0 ? (
              <p className="text-center text-cyber-muted text-xs py-6">No credentials match your search.</p>
            ) : pagedCreds.map(c => (
              <div key={c.id} className="grid grid-cols-2 sm:grid-cols-5 gap-2 items-center p-2 bg-cyber-surface rounded text-xs">
                <span className="text-white font-medium">{c.vendor}</span>
                <span className="font-mono text-cyber-accent">{c.username || '(empty)'}</span>
                <span className="font-mono text-cyber-muted">{c.password || '(empty)'}</span>
                <span className={`capitalize font-semibold risk-${c.risk_level}`}>{c.risk_level}</span>
                {isAdmin ? (
                  <button onClick={() => setDeleteCredId(c.id)} className="text-cyber-red/60 hover:text-cyber-red justify-self-end">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                ) : <span />}
              </div>
            ))}
          </div>

          {/* Pagination controls */}
          {filteredCreds.length > CREDS_PER_PAGE && (
            <div className="flex items-center justify-between mt-3 pt-3 border-t border-cyber-border/50">
              <span className="text-xs text-cyber-muted">
                Showing {credStart}–{credEnd} of {filteredCreds.length}
              </span>
              <div className="flex gap-2">
                <button onClick={() => setCredPage(p => p - 1)} disabled={credPage === 0}
                  className="px-3 py-1 text-xs rounded border border-cyber-border text-cyber-text-muted hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                  Prev
                </button>
                <button onClick={() => setCredPage(p => p + 1)} disabled={credPage >= credTotalPages - 1}
                  className="px-3 py-1 text-xs rounded border border-cyber-border text-cyber-text-muted hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                  Next
                </button>
              </div>
            </div>
          )}

          {isAdmin && (
            <div className="mt-4 pt-4 border-t border-cyber-border grid grid-cols-2 sm:grid-cols-5 gap-2">
              <input value={newCred.vendor} onChange={e => setNewCred({ ...newCred, vendor: e.target.value })}
                placeholder="Vendor" className="cyber-input px-2 py-1.5 rounded text-xs" />
              <input value={newCred.username} onChange={e => setNewCred({ ...newCred, username: e.target.value })}
                placeholder="Username" className="cyber-input px-2 py-1.5 rounded text-xs font-mono" />
              <input value={newCred.password} onChange={e => setNewCred({ ...newCred, password: e.target.value })}
                placeholder="Password" className="cyber-input px-2 py-1.5 rounded text-xs font-mono" />
              <select value={newCred.risk_level} onChange={e => setNewCred({ ...newCred, risk_level: e.target.value as DefaultCredential['risk_level'] })}
                className="cyber-input px-2 py-1.5 rounded text-xs">
                <option value="low">Low</option><option value="medium">Medium</option>
                <option value="high">High</option><option value="critical">Critical</option>
              </select>
              <button type="button" onClick={handleAddCred}
                className="cyber-btn-primary px-2 py-1.5 rounded text-xs font-bold flex items-center gap-1">
                <Plus className="w-3.5 h-3.5" /> Add
              </button>
            </div>
          )}
        </motion.div>
      </div>

      {/* Recommendation modal */}
      <AnimatePresence>
        {selectedCheck && (
          <RecommendationModal check={selectedCheck} onClose={() => setSelectedCheck(null)} />
        )}
      </AnimatePresence>

      <ConfirmDialog isOpen={!!deleteCredId} title="Delete Credential" variant="danger"
        message="Remove this default credential from the database? This cannot be undone."
        confirmLabel="Delete" onConfirm={handleDeleteCred} onCancel={() => setDeleteCredId(null)} />
    </DashboardLayout>
  )
}
