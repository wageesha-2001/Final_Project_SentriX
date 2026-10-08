import { EnrichedMatch } from '@/types'
import { confidenceLabel } from '@/lib/vuln-db/constants'
import { cn } from '@/lib/utils'
import { Shield, ExternalLink, Info } from 'lucide-react'

export const SEVERITY_CLASS: Record<string, string> = {
  Critical: 'text-cyber-red bg-cyber-red/10 border-cyber-red/30',
  High: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  Medium: 'text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/30',
  Low: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  Informational: 'text-purple-400 bg-purple-400/10 border-purple-400/30',
}

const CONFIDENCE_CLASS: Record<string, string> = {
  High: 'text-cyber-green border-cyber-green/30 bg-cyber-green/10',
  Medium: 'text-cyber-yellow border-cyber-yellow/30 bg-cyber-yellow/10',
  Low: 'text-cyber-muted border-cyber-border bg-cyber-bg/40',
}

/** Only http(s) links are rendered as anchors. */
function safeUrl(url: string): string | null {
  return /^https?:\/\//i.test(url) ? url : null
}

export function MatchCard({ match, compact = false }: { match: EnrichedMatch; compact?: boolean }) {
  const v = match.vulnerability
  const href = safeUrl(v.reference_url)
  return (
    <div className="p-4 bg-cyber-surface rounded-lg border border-cyber-border/50">
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0">
          <p className="font-semibold text-white text-sm">{v.title}</p>
          <p className="text-xs text-cyber-muted mt-0.5">
            <span className="font-mono">{v.vuln_id}</span> · {v.vendor} · {v.category} · Source: {v.source_type}
          </p>
        </div>
        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          <span className={cn('text-[10px] px-2 py-0.5 rounded border font-bold uppercase tracking-wider', SEVERITY_CLASS[v.severity])}>
            {v.severity}
          </span>
          <span className="text-[10px] font-mono text-cyber-muted">risk +{match.risk_score_added}{match.risk_score_added !== v.risk_score && ` of ${v.risk_score}`}</span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 mb-2">
        <span className={cn('text-[10px] px-2 py-0.5 rounded border font-semibold', CONFIDENCE_CLASS[match.match_confidence])}>
          {confidenceLabel(match.match_confidence)}
        </span>
        <span className="text-[10px] text-cyber-muted">{match.matched_reason}</span>
      </div>

      {!compact && <p className="text-xs text-cyber-text-muted mb-2">{v.description}</p>}

      <div className="flex items-start gap-2 pt-2 border-t border-cyber-border/50">
        <Shield className="w-3.5 h-3.5 text-cyber-accent mt-0.5 flex-shrink-0" />
        <p className="text-xs text-cyber-accent">{v.recommendation}</p>
      </div>

      {!compact && v.remediation_steps.length > 0 && (
        <ol className="list-decimal pl-9 mt-2 space-y-0.5 text-xs text-cyber-text-muted">
          {v.remediation_steps.map((step, i) => <li key={i}>{step}</li>)}
        </ol>
      )}

      {!compact && (
        <div className="flex items-start gap-2 mt-3 text-[11px] text-cyber-muted">
          <Info className="w-3 h-3 mt-0.5 flex-shrink-0" />
          <span>
            {v.confidence_note}
            {href && (
              <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 ml-2 text-cyber-accent hover:underline">
                Reference <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </span>
        </div>
      )}
    </div>
  )
}
