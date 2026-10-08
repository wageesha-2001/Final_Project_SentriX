/**
 * Schema validation for community vulnerability records.
 * Pure functions — no I/O — so it can be reused by the importer, the tests,
 * and any future CI check on the public vulnerability repository.
 */
import type { CommunityVulnRecord } from '@/types'
import { PARSE_ERRORS_KEY, parseTextDatabase } from './parser'
import {
  CATEGORIES, DEVICE_TYPES, MATCH_FIELDS, SEVERITIES, SEVERITY_RISK_RANGE, SOURCE_TYPES,
} from './constants'

export interface ValidationIssue {
  index: number
  id?: string
  errors: string[]
}

export type RecordValidation =
  | { ok: true; record: CommunityVulnRecord }
  | { ok: false; id?: string; errors: string[] }

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/
const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/
const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/

/** Command / script fragments that have no place in a defensive knowledge base. */
const FORBIDDEN_CONTENT = /(<script|javascript:|\/bin\/(ba)?sh|\bnc\s+-e\b|\bcmd\.exe\b|\bpowershell\s+-|\bwget\s+https?:|\bcurl\s+-|\bbase64\s+-d\b)/i

export function isValidDate(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (DATE_ONLY.test(value)) {
    const d = new Date(`${value}T00:00:00Z`)
    return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value
  }
  return ISO_DATETIME.test(value) && !Number.isNaN(Date.parse(value))
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(x => typeof x === 'string')
}

function checkText(errors: string[], obj: Record<string, unknown>, field: string, max: number) {
  const v = obj[field]
  if (typeof v !== 'string' || v.trim() === '') {
    errors.push(`${field} is required and must be a non-empty string`)
  } else if (v.length > max) {
    errors.push(`${field} must be at most ${max} characters`)
  } else if (FORBIDDEN_CONTENT.test(v)) {
    errors.push(`${field} contains command or script content, which is not allowed`)
  }
}

function checkOptionalList(errors: string[], obj: Record<string, unknown>, field: string, maxItems = 50) {
  const v = obj[field]
  if (v === undefined) return
  if (!isStringArray(v)) errors.push(`${field} must be an array of strings`)
  else if (v.length > maxItems) errors.push(`${field} must have at most ${maxItems} entries`)
  else if (v.some(s => FORBIDDEN_CONTENT.test(s))) errors.push(`${field} contains command or script content, which is not allowed`)
}

export function validateRecord(raw: unknown): RecordValidation {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { ok: false, errors: ['record is not a valid block of Label: value lines'] }
  }
  const r = raw as Record<string, unknown>
  const errors: string[] = []
  const id = typeof r.id === 'string' ? r.id : undefined

  if (Array.isArray(r[PARSE_ERRORS_KEY])) errors.push(...(r[PARSE_ERRORS_KEY] as string[]))

  if (!id || !ID_PATTERN.test(id)) {
    errors.push('id is required (3-64 chars: letters, digits, ".", "_" or "-")')
  }

  checkText(errors, r, 'title', 200)
  checkText(errors, r, 'description', 2000)
  checkText(errors, r, 'vendor', 100)
  checkText(errors, r, 'recommendation', 1000)
  checkText(errors, r, 'confidence_note', 500)

  if (!isStringArray(r.affected_models) || r.affected_models.length === 0) {
    errors.push('affected_models must be a non-empty array of strings (use ["*"] for any model)')
  }
  if (!isStringArray(r.affected_firmware) || r.affected_firmware.length === 0) {
    errors.push('affected_firmware must be a non-empty array of strings (use ["*"] for any firmware)')
  }

  if (!DEVICE_TYPES.includes(r.device_type as never)) {
    errors.push(`device_type must be one of: ${DEVICE_TYPES.join(', ')}`)
  }
  if (typeof r.category !== 'string' || !(CATEGORIES as readonly string[]).includes(r.category)) {
    errors.push('category is not a recognised category (see vulnerability-schema.md)')
  }

  const severityOk = SEVERITIES.includes(r.severity as never)
  if (!severityOk) errors.push(`severity must be one of: ${SEVERITIES.join(', ')}`)

  if (typeof r.cvss_score !== 'number' || !Number.isFinite(r.cvss_score) || r.cvss_score < 0 || r.cvss_score > 10) {
    errors.push('cvss_score must be a number between 0 and 10')
  }

  if (typeof r.risk_score !== 'number' || !Number.isInteger(r.risk_score)) {
    errors.push('risk_score must be an integer')
  } else if (severityOk) {
    const [lo, hi] = SEVERITY_RISK_RANGE[r.severity as keyof typeof SEVERITY_RISK_RANGE]
    if (r.risk_score < lo || r.risk_score > hi) {
      errors.push(`risk_score ${r.risk_score} is outside the ${lo}-${hi} range for severity ${String(r.severity)}`)
    }
  }

  if (!SOURCE_TYPES.includes(r.source_type as never)) {
    errors.push(`source_type must be one of: ${SOURCE_TYPES.join(', ')}`)
  } else if (r.source_type === 'CVE' && !(id && CVE_PATTERN.test(id))) {
    errors.push('records with source_type CVE must use the real CVE identifier as id (CVE-YYYY-NNNN)')
  }

  if (!isValidDate(r.published_date)) errors.push('published_date must be a valid date (YYYY-MM-DD or ISO 8601)')
  if (!isValidDate(r.last_updated)) errors.push('last_updated must be a valid date (YYYY-MM-DD or ISO 8601)')
  if (isValidDate(r.published_date) && isValidDate(r.last_updated) && Date.parse(r.last_updated) < Date.parse(r.published_date)) {
    errors.push('last_updated must not be earlier than published_date')
  }

  if (!isStringArray(r.remediation_steps) || r.remediation_steps.length === 0) {
    errors.push('remediation_steps must be a non-empty array of strings')
  } else if (r.remediation_steps.length > 20 || r.remediation_steps.some(s => s.length > 500 || FORBIDDEN_CONTENT.test(s))) {
    errors.push('remediation_steps must have at most 20 entries of at most 500 characters, with no command or script content')
  }

  // Optional fields
  if (r.affected_ports !== undefined &&
      !(Array.isArray(r.affected_ports) && r.affected_ports.every(p => Number.isInteger(p) && p >= 1 && p <= 65535))) {
    errors.push('affected_ports must be an array of integers between 1 and 65535')
  }
  checkOptionalList(errors, r, 'affected_protocols')
  checkOptionalList(errors, r, 'detection_keywords')
  if (r.match_fields !== undefined &&
      !(Array.isArray(r.match_fields) && r.match_fields.every(f => MATCH_FIELDS.includes(f as never)))) {
    errors.push(`match_fields must be an array containing only: ${MATCH_FIELDS.join(', ')}`)
  }
  if (r.reference_url !== undefined && r.reference_url !== '') {
    try {
      const u = new URL(String(r.reference_url))
      if (u.protocol !== 'http:' && u.protocol !== 'https:') errors.push('reference_url must be an http(s) URL')
    } catch {
      errors.push('reference_url must be a valid URL')
    }
  }

  if (errors.length > 0) return { ok: false, id, errors }

  return {
    ok: true,
    record: {
      id: r.id as string,
      title: (r.title as string).trim(),
      description: (r.description as string).trim(),
      vendor: (r.vendor as string).trim(),
      affected_models: r.affected_models as string[],
      affected_firmware: r.affected_firmware as string[],
      device_type: r.device_type as CommunityVulnRecord['device_type'],
      category: r.category as string,
      severity: r.severity as CommunityVulnRecord['severity'],
      cvss_score: r.cvss_score as number,
      risk_score: r.risk_score as number,
      affected_ports: (r.affected_ports as number[] | undefined) ?? [],
      affected_protocols: (r.affected_protocols as string[] | undefined) ?? [],
      detection_keywords: (r.detection_keywords as string[] | undefined) ?? [],
      match_fields: (r.match_fields as CommunityVulnRecord['match_fields'] | undefined) ?? [],
      source_type: r.source_type as CommunityVulnRecord['source_type'],
      reference_url: (r.reference_url as string | undefined) ?? '',
      published_date: r.published_date as string,
      last_updated: r.last_updated as string,
      recommendation: (r.recommendation as string).trim(),
      remediation_steps: r.remediation_steps as string[],
      confidence_note: (r.confidence_note as string).trim(),
    },
  }
}

export class DatabaseFormatError extends Error {
  constructor(public userMessage: string, detail?: string) {
    super(detail ?? userMessage)
  }
}

/** Split the text file into raw records. Throws if the file contains no records at all. */
export function parseDatabaseText(text: string): unknown[] {
  const records = parseTextDatabase(text)
  if (records.length === 0) throw new DatabaseFormatError('No vulnerability records found.')
  return records
}

/** Validate every record; invalid and in-file duplicate records are reported, not thrown. */
export function validateDatabase(rawRecords: unknown[]): {
  valid: CommunityVulnRecord[]
  issues: ValidationIssue[]
  duplicates: number
} {
  const valid: CommunityVulnRecord[] = []
  const issues: ValidationIssue[] = []
  const seen = new Set<string>()
  let duplicates = 0

  rawRecords.forEach((raw, index) => {
    const result = validateRecord(raw)
    if (!result.ok) {
      issues.push({ index, id: result.id, errors: result.errors })
      return
    }
    if (seen.has(result.record.id)) {
      duplicates++
      issues.push({ index, id: result.record.id, errors: ['duplicate id within the file (first occurrence kept)'] })
      return
    }
    seen.add(result.record.id)
    valid.push(result.record)
  })
  return { valid, issues, duplicates }
}
