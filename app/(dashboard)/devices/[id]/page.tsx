'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { DashboardLayout } from '@/components/layout/DashboardLayout'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { Device, Vulnerability, EnrichedMatch } from '@/types'
import { MatchCard } from '@/components/vuln-db/MatchCard'
import { calculateTrustScore, getSecurityStatus } from '@/lib/risk/calculator'
import { formatDate } from '@/lib/utils'
import { Cpu, Wifi, Shield, AlertTriangle, CheckCircle, Server } from 'lucide-react'

export default function DeviceDetailsPage() {
  const { id } = useParams<{ id: string }>()
  const [device, setDevice] = useState<Device | null>(null)
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [matches, setMatches] = useState<EnrichedMatch[]>([])
  const [scan, setScan] = useState<{ id: string; scan_name: string; status: string; started_at: string } | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`/api/devices/${id}`).then(r => r.json()).then(d => {
      if (d.data) { setDevice(d.data.device); setVulns(d.data.vulnerabilities); setMatches(d.data.community_matches ?? []); setScan(d.data.scan ?? null) }
    }).finally(() => setLoading(false))
  }, [id])

  if (loading) return <DashboardLayout title="Device Details"><LoadingSpinner size="lg" className="h-64" /></DashboardLayout>
  if (!device) return <DashboardLayout title="Device Details"><div className="text-cyber-muted text-center py-20">Device not found</div></DashboardLayout>

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }
  const confirmedVulns = vulns.filter(v => !v.informational)
  const informationalVulns = vulns.filter(v => v.informational)
  const confirmedMatches = matches.filter(m => m.match_confidence === 'High')

  // Prefer persisted statuses; fall back for devices scanned before they existed.
  const overall = device.overall_security_status
    ?? (getSecurityStatus(confirmedVulns.length, confirmedMatches) === 'vulnerable' ? 'VULNERABLE'
      : matches.length > 0 ? 'NOT_VERIFIED' : 'HEALTHY')
  const knownStatus = device.known_vulnerability_status
    ?? (confirmedMatches.length > 0 ? 'MATCHED' : matches.length > 0 ? 'UNVERIFIED' : 'NO_MATCH')
  const authStatus = device.authentication_status ?? 'NOT_TESTED'
  const trustScore = device.trust_score ?? calculateTrustScore(device.risk_score)

  const STATUS_STYLE = {
    VULNERABLE: { label: 'Vulnerable', className: 'text-cyber-red border-cyber-red/30 bg-cyber-red/10' },
    NOT_VERIFIED: { label: 'Not Verified', className: 'text-cyber-purple border-cyber-purple/30 bg-cyber-purple/10' },
    HEALTHY: { label: 'Healthy', className: 'text-cyber-green border-cyber-green/30 bg-cyber-green/10' },
  }[overall]
  const AUTH_LABEL: Record<string, string> = {
    CONFIRMED_DEFAULT_CREDENTIALS: 'Default credentials confirmed',
    AUTHENTICATION_REJECTED: 'Credentials rejected (good)',
    NOT_TESTED: 'Not tested',
    AUTHENTICATION_ERROR: 'Could not test',
  }
  const KNOWN_LABEL: Record<string, string> = { MATCHED: 'Matched', NO_MATCH: 'No match', UNVERIFIED: 'Unverified' }
  const sortedVulns = [...confirmedVulns].sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4))

  return (
    <DashboardLayout title="Device Details" subtitle={`${device.vendor} ${device.model}`}>
      <div className="space-y-6 max-w-4xl">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="cyber-card p-6">
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div className="flex items-start gap-4">
              <div className="w-14 h-14 rounded-xl bg-cyber-accent/10 border border-cyber-accent/20 flex items-center justify-center">
                <Cpu className="w-7 h-7 text-cyber-accent" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-white">{device.vendor} {device.model}</h2>
                <p className="text-cyber-muted font-mono text-sm">{device.ip_address}</p>
                <p className="text-xs text-cyber-text-muted mt-0.5">MAC: {device.mac_address || 'Not available (needs device login / same-segment access)'} | Scanned: {formatDate(device.created_at)}</p>
                {scan && (
                  <p className="text-xs text-cyber-text-muted mt-0.5">
                    Scan: <Link href={`/scans/${scan.id}`} className="text-cyber-accent hover:underline">{scan.scan_name}</Link>
                  </p>
                )}
              </div>
            </div>
            <div className="flex flex-col items-end gap-2">
              <RiskBadge level={device.risk_level} showScore={device.risk_score} size="lg" />
              <span className={`px-2 py-0.5 rounded border text-xs font-semibold ${STATUS_STYLE.className}`}>{STATUS_STYLE.label}</span>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-5 pt-5 border-t border-cyber-border">
            {[
              { label: 'Device Type', value: device.device_type.toUpperCase(), icon: Server },
              { label: 'Firmware', value: device.firmware_version, icon: Shield },
              { label: 'Known Vulnerability', value: KNOWN_LABEL[knownStatus], icon: AlertTriangle },
              { label: 'Authentication', value: AUTH_LABEL[authStatus], icon: Shield },
              { label: 'Overall Status', value: STATUS_STYLE.label, icon: Shield },
              { label: 'Risk / Trust', value: `${device.risk_score} / ${trustScore}`, icon: Shield },
              { label: 'Open Ports', value: device.open_ports.length.toString(), icon: Wifi },
              { label: 'Confirmed Findings', value: `${confirmedVulns.length + confirmedMatches.length}`, icon: AlertTriangle },
            ].map(item => (
              <div key={item.label} className="bg-cyber-surface rounded-lg p-3">
                <item.icon className="w-4 h-4 text-cyber-muted mb-1" />
                <p className="text-sm font-bold text-white">{item.value}</p>
                <p className="text-xs text-cyber-muted">{item.label}</p>
              </div>
            ))}
          </div>
        </motion.div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="cyber-card p-5">
            <h3 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-3">Open Ports</h3>
            <div className="space-y-2">
              {device.open_ports.map((port) => (
                <div key={port.port} className="flex items-center justify-between py-2 border-b border-cyber-border/50">
                  <div className="flex items-center gap-2">
                    <span className="text-cyber-accent font-mono text-sm font-bold">{port.port}</span>
                    <span className="text-xs text-cyber-text-muted">/{port.protocol}</span>
                  </div>
                  <span className="text-xs bg-cyber-surface px-2 py-1 rounded text-cyber-text-muted">{port.service}</span>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="cyber-card p-5">
            <h3 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-3">Protocols</h3>
            <div className="flex flex-wrap gap-2">
              {device.protocols.map((p: string) => (
                <span key={p} className="px-3 py-1.5 bg-cyber-accent/10 border border-cyber-accent/20 rounded-lg text-xs text-cyber-accent font-mono">{p}</span>
              ))}
            </div>
            <div className="mt-4 pt-4 border-t border-cyber-border">
              <h4 className="text-xs text-cyber-text-muted uppercase mb-2">Risk Score Breakdown</h4>
              <div className="relative h-3 bg-cyber-surface rounded-full overflow-hidden border border-cyber-border">
                <div className="h-full scan-progress-bar rounded-full" style={{ width: `${device.risk_score}%` }} />
              </div>
              <p className="text-right text-xs text-cyber-muted mt-1 font-mono">
                Risk {device.risk_score}/100 · Trust {trustScore}/100
              </p>
              <div className="mt-4 pt-4 border-t border-cyber-border">
                <h4 className="text-xs text-cyber-text-muted uppercase mb-2">Authentication Assessment</h4>
                <p className="text-xs text-cyber-text-muted">
                  {authStatus === 'CONFIRMED_DEFAULT_CREDENTIALS'
                    ? 'An authorized check confirmed this device accepts default credentials. Change them immediately.'
                    : authStatus === 'AUTHENTICATION_REJECTED'
                      ? 'An authorized default-credential attempt was rejected — no default-credential finding.'
                      : authStatus === 'AUTHENTICATION_ERROR'
                        ? 'The authentication check could not be completed (timeout, lockout or service error).'
                        : 'No authorized credential test was performed for this device.'}
                </p>
                <p className="text-[10px] text-cyber-text-muted mt-1">Passwords are never displayed, logged or stored in results.</p>
              </div>
            </div>
          </motion.div>
        </div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="cyber-card p-5">
          <h3 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-4">
            Confirmed Findings ({confirmedVulns.length})
          </h3>
          {sortedVulns.length === 0 ? (
            <div className="flex items-center gap-3 p-4 bg-cyber-green/5 border border-cyber-green/20 rounded-lg">
              <CheckCircle className="w-5 h-5 text-cyber-green" />
              <div>
                <p className="text-sm font-semibold text-cyber-green">No Confirmed Findings</p>
                <p className="text-xs text-cyber-text-muted">
                  No confirmed vulnerability or default-credential finding for this device.{matches.length > 0 ? ' Review the database matches below.' : ''}
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              {sortedVulns.map((v, i) => (
                <motion.div key={v.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.05 }}
                  className="p-4 bg-cyber-surface rounded-lg border border-cyber-border/50">
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <p className="font-semibold text-white text-sm">{v.title}</p>
                    <RiskBadge level={v.severity} showScore={v.score} size="sm" />
                  </div>
                  <p className="text-xs text-cyber-text-muted mb-2">{v.description}</p>
                  <div className="flex items-start gap-2 mt-2 pt-2 border-t border-cyber-border/50">
                    <Shield className="w-3.5 h-3.5 text-cyber-accent mt-0.5 flex-shrink-0" />
                    <p className="text-xs text-cyber-accent">{v.recommendation}</p>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </motion.div>

        {informationalVulns.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }} className="cyber-card p-5">
            <h3 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-1">
              Informational Observations ({informationalVulns.length})
            </h3>
            <p className="text-xs text-cyber-muted mb-3">
              Service and configuration observations. These do not match a known vulnerability record and do not affect the risk score or status.
            </p>
            <div className="space-y-2">
              {informationalVulns.map(v => (
                <div key={v.id} className="p-3 bg-cyber-surface rounded-lg border border-cyber-border/50">
                  <p className="font-medium text-white text-sm">{v.title}</p>
                  <p className="text-xs text-cyber-text-muted mt-0.5">{v.description}</p>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }} className="cyber-card p-5">
          <h3 className="text-sm font-semibold text-cyber-text-muted uppercase tracking-wider mb-1">
            Community Vulnerability Matches ({matches.length})
          </h3>
          <p className="text-xs text-cyber-muted mb-4">
            Matched against the community vulnerability database. Some matches may be approximate — verify against official vendor advisories before remediation.
          </p>
          {matches.length === 0 ? (
            <div className="flex items-center gap-3 p-4 bg-cyber-green/5 border border-cyber-green/20 rounded-lg">
              <CheckCircle className="w-5 h-5 text-cyber-green" />
              <p className="text-xs text-cyber-text-muted">No community vulnerability records matched this device.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {matches.map(m => <MatchCard key={m.id} match={m} />)}
            </div>
          )}
        </motion.div>
      </div>
    </DashboardLayout>
  )
}
