/**
 * Parser for the plain-text vulnerability file (data/vulnerabilities.txt).
 *
 * Format: records are blocks of "Label: value" lines separated by a line of
 * three or more dashes. Lines starting with # are comments. A long value may
 * continue on the next line(s). "Steps:" takes a list of lines starting "- ".
 * Parsing only produces plain data — it is then checked by validateRecord().
 */

const FIELD_BY_LABEL: Record<string, string> = {
  'id': 'id',
  'title': 'title',
  'vendor': 'vendor',
  'models': 'affected_models',
  'firmware': 'affected_firmware',
  'device type': 'device_type',
  'category': 'category',
  'severity': 'severity',
  'cvss': 'cvss_score',
  'risk score': 'risk_score',
  'ports': 'affected_ports',
  'protocols': 'affected_protocols',
  'keywords': 'detection_keywords',
  'match fields': 'match_fields',
  'source': 'source_type',
  'reference': 'reference_url',
  'published': 'published_date',
  'updated': 'last_updated',
  'description': 'description',
  'recommendation': 'recommendation',
  'steps': 'remediation_steps',
  'note': 'confidence_note',
}

const LIST_FIELDS = new Set(['affected_models', 'affected_firmware', 'affected_protocols', 'detection_keywords', 'match_fields'])
const LABEL_LINE = /^([A-Za-z][A-Za-z ]*?)\s*:\s*(.*)$/
const SEPARATOR = /^\s*-{3,}\s*$/
const BULLET = /^\s*(?:[-*]|\d+[.)])\s+(.*)$/

export const PARSE_ERRORS_KEY = '__parse_errors'

const splitList = (v: string) => v.split(',').map(s => s.trim()).filter(Boolean)

function convert(field: string, raw: string): unknown {
  const v = raw.trim()
  if (LIST_FIELDS.has(field)) return splitList(v)
  if (field === 'affected_ports') return splitList(v).map(Number)
  if (field === 'cvss_score' || field === 'risk_score') return v === '' ? NaN : Number(v)
  return v
}

function parseBlock(lines: string[]): Record<string, unknown> | null {
  const text: Record<string, string> = {}
  const steps: string[] = []
  const errors: string[] = []
  let current: string | null = null

  for (const line of lines) {
    if (line.trim() === '' || line.trim().startsWith('#')) continue
    const m = LABEL_LINE.exec(line)
    const field = m ? FIELD_BY_LABEL[m[1].trim().toLowerCase()] : undefined
    if (m && field) {
      current = field
      if (field === 'remediation_steps') {
        // Inline form: "Steps: first | second"
        if (m[2].trim()) steps.push(...m[2].split('|').map(s => s.trim()).filter(Boolean))
      } else {
        if (field in text) errors.push(`"${m[1].trim()}" is written twice`)
        text[field] = m[2]
      }
      continue
    }
    // A short capitalised "Word:" that is not a known label is almost certainly a typo.
    if (m && !field && /^[A-Z]/.test(m[1]) && m[1].trim().split(/\s+/).length <= 2) {
      errors.push(`unknown label "${m[1].trim()}"`)
      continue
    }
    if (current === 'remediation_steps') {
      const b = BULLET.exec(line)
      steps.push((b ? b[1] : line).trim())
    } else if (current) {
      text[current] = `${text[current]} ${line.trim()}`
    } else {
      errors.push(`text outside a labelled field: "${line.trim().slice(0, 40)}"`)
    }
  }

  if (Object.keys(text).length === 0 && steps.length === 0 && errors.length === 0) return null // comments / blanks only

  const record: Record<string, unknown> = {}
  for (const [field, value] of Object.entries(text)) record[field] = convert(field, value)
  if (steps.length > 0) record.remediation_steps = steps
  if (errors.length > 0) record[PARSE_ERRORS_KEY] = errors
  return record
}

/** Split file text into raw (unvalidated) record objects. */
export function parseTextDatabase(text: string): Record<string, unknown>[] {
  const lines = text.replace(/^﻿/, '').split(/\r?\n/)
  const blocks: string[][] = [[]]
  for (const line of lines) {
    if (SEPARATOR.test(line)) blocks.push([])
    else blocks[blocks.length - 1].push(line)
  }
  return blocks.map(parseBlock).filter((b): b is Record<string, unknown> => b !== null)
}

const LABEL_FOR_FIELD: Record<string, string> = {
  id: 'ID', title: 'Title', vendor: 'Vendor', affected_models: 'Models', affected_firmware: 'Firmware',
  device_type: 'Device Type', category: 'Category', severity: 'Severity', cvss_score: 'CVSS', risk_score: 'Risk Score',
  affected_ports: 'Ports', affected_protocols: 'Protocols', detection_keywords: 'Keywords', match_fields: 'Match Fields',
  source_type: 'Source', reference_url: 'Reference', published_date: 'Published', last_updated: 'Updated',
  description: 'Description', recommendation: 'Recommendation', remediation_steps: 'Steps', confidence_note: 'Note',
}

/** Render one record as a text block (used by tools that convert or generate the file). */
export function formatRecordAsText(rec: Record<string, unknown>): string {
  const out: string[] = []
  for (const field of Object.keys(LABEL_FOR_FIELD)) {
    const v = rec[field]
    if (v === undefined) continue
    if (field === 'remediation_steps') {
      out.push('Steps:')
      for (const s of v as string[]) out.push(`- ${s}`)
    } else {
      out.push(`${LABEL_FOR_FIELD[field]}: ${Array.isArray(v) ? v.join(', ') : v}`)
    }
  }
  return out.join('\n')
}
