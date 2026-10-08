import fs from 'fs'
import path from 'path'
import { validateRecord, validateDatabase, parseDatabaseText, DatabaseFormatError } from '@/lib/vuln-db/validator'
import { formatRecordAsText, parseTextDatabase } from '@/lib/vuln-db/parser'
import { matchDevice, globMatch, applyConfidenceFactor, MatchableDevice, MatchableRecord } from '@/lib/vuln-db/matcher'
import { calculateRiskScoreWithMatches, calculateTrustScore } from '@/lib/risk/calculator'
import { generateReportHtml } from '@/lib/scanner/report-generator'
import { REPORT_NOTE, confidenceLabel } from '@/lib/vuln-db/constants'
import type { CommunityVulnRecord, EnrichedMatch, Scan, Device, Vulnerability } from '@/types'

const DB_PATH = path.join(process.cwd(), 'data', 'vulnerabilities.txt')
const toText = (...recs: object[]) => recs.map(r => formatRecordAsText(r as Record<string, unknown>)).join('\n---\n') + '\n---\n'
const loadShipped = () => validateDatabase(parseDatabaseText(fs.readFileSync(DB_PATH, 'utf8')))

function record(overrides: Partial<CommunityVulnRecord> = {}): CommunityVulnRecord {
  return {
    id: 'TEST-0001',
    title: 'HTTP-Only Interface on test camera',
    description: 'The web interface is served over HTTP.',
    vendor: 'Hikvision',
    affected_models: ['DS-2CD2043G0-I'],
    affected_firmware: ['V5.5.*'],
    device_type: 'camera',
    category: 'HTTP-Only Interface',
    severity: 'Medium',
    cvss_score: 5.3,
    risk_score: 12,
    affected_ports: [80],
    affected_protocols: ['HTTP'],
    detection_keywords: ['hikvision'],
    match_fields: [],
    source_type: 'SIMULATED',
    reference_url: '',
    published_date: '2026-01-01',
    last_updated: '2026-01-02',
    recommendation: 'Enable HTTPS.',
    remediation_steps: ['Enable HTTPS.'],
    confidence_note: 'SIMULATED test record.',
    ...overrides,
  }
}

const device: MatchableDevice = {
  vendor: 'Hikvision',
  model: 'DS-2CD2043G0-I',
  firmware_version: 'V5.5.800',
  device_type: 'camera',
  open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }, { port: 554, service: 'RTSP', protocol: 'tcp' }],
  protocols: ['HTTP', 'RTSP'],
}

const asMatchable = (r: CommunityVulnRecord, id = r.id): MatchableRecord => ({ ...r, id })

// ─── Schema validation ───────────────────────────────────────────────────────

describe('validateRecord', () => {
  it('accepts a valid record', () => {
    expect(validateRecord(record()).ok).toBe(true)
  })

  it('rejects an invalid severity', () => {
    const r = validateRecord({ ...record(), severity: 'Severe' })
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.join()).toMatch(/severity must be one of/)
  })

  it('rejects a risk_score outside the severity range', () => {
    const r = validateRecord(record({ severity: 'Critical', risk_score: 12 }))
    expect(r.ok).toBe(false)
    if (!r.ok) expect(r.errors.join()).toMatch(/outside the 30-40 range/)
  })

  it('accepts Informational only with risk_score 0', () => {
    expect(validateRecord(record({ severity: 'Informational', cvss_score: 0, risk_score: 0 })).ok).toBe(true)
    expect(validateRecord(record({ severity: 'Informational', cvss_score: 0, risk_score: 1 })).ok).toBe(false)
  })

  it.each(['2026-13-40', '2026-02-30', 'yesterday', ''])('rejects invalid date %p', bad => {
    expect(validateRecord(record({ published_date: bad })).ok).toBe(false)
  })

  it('rejects last_updated earlier than published_date', () => {
    expect(validateRecord(record({ published_date: '2026-03-01', last_updated: '2026-01-01' })).ok).toBe(false)
  })

  it('rejects unknown source_type and category', () => {
    expect(validateRecord({ ...record(), source_type: 'MADE_UP' }).ok).toBe(false)
    expect(validateRecord(record({ category: 'Made Up Category' })).ok).toBe(false)
  })

  it('does not allow a CVE source record without a real CVE id', () => {
    expect(validateRecord(record({ source_type: 'CVE', id: 'SXV-2026-0001' })).ok).toBe(false)
    expect(validateRecord(record({ source_type: 'CVE', id: 'CVE-2021-36260' })).ok).toBe(true)
  })

  it('rejects out-of-range ports and non-http reference URLs', () => {
    expect(validateRecord(record({ affected_ports: [70000] })).ok).toBe(false)
    expect(validateRecord(record({ reference_url: 'javascript:alert(1)' })).ok).toBe(false)
    expect(validateRecord(record({ reference_url: 'https://owasp.org/' })).ok).toBe(true)
  })

  it('rejects command/script content', () => {
    expect(validateRecord(record({ description: 'Run <script>alert(1)</script>' })).ok).toBe(false)
    expect(validateRecord(record({ remediation_steps: ['curl -X POST http://x'] })).ok).toBe(false)
  })

  it('rejects missing required fields', () => {
    const { title: _t, ...rest } = record()
    expect(validateRecord(rest).ok).toBe(false)
    expect(validateRecord('nope').ok).toBe(false)
  })
})

describe('text file parser', () => {
  it('parses blocks, comments, list fields, numbers and steps', () => {
    const text = '# comment\n\n' + toText(record({ remediation_steps: ['One', 'Two'] }))
    const [raw] = parseTextDatabase(text)
    expect(raw).toMatchObject({
      id: 'TEST-0001', affected_models: ['DS-2CD2043G0-I'], affected_ports: [80], cvss_score: 5.3,
      risk_score: 12, remediation_steps: ['One', 'Two'],
    })
  })

  it('round-trips a record through text and validation', () => {
    const rec = record({ affected_models: ['A', 'B'], affected_firmware: ['*'], remediation_steps: ['One', 'Two'] })
    const { valid, issues } = validateDatabase(parseDatabaseText(toText(rec)))
    expect(issues).toEqual([])
    expect(valid[0]).toMatchObject({ ...rec, match_fields: [] })
  })

  it('accepts CRLF line endings, a BOM, mixed-case labels and inline steps', () => {
    const text = '﻿' + toText(record()).replace(/\n/g, '\r\n').replace('Steps:\r\n- Enable HTTPS.', 'steps: Enable HTTPS. | Verify')
    const { valid, issues } = validateDatabase(parseDatabaseText(text.replace('Title:', 'TITLE:')))
    expect(issues).toEqual([])
    expect(valid[0].remediation_steps).toEqual(['Enable HTTPS.', 'Verify'])
  })

  it('joins a description that continues on the next line', () => {
    const text = toText(record()).replace('Description: The web interface', 'Description: The web\nInterface')
    expect(validateDatabase(parseDatabaseText(text)).valid[0].description).toMatch(/^The web Interface/)
  })

  it('reports a misspelled label and a missing field as record errors', () => {
    const text = toText(record()).replace('Severity:', 'Severty:')
    const { valid, issues } = validateDatabase(parseDatabaseText(text))
    expect(valid).toEqual([])
    expect(issues[0].errors.join()).toMatch(/unknown label "Severty"/)
    expect(issues[0].errors.join()).toMatch(/severity must be one of/)
  })

  it('rejects an empty file with a friendly message', () => {
    for (const t of ['', '# only comments\n', '---\n---\n']) {
      expect(() => parseDatabaseText(t)).toThrow(DatabaseFormatError)
    }
    try { parseDatabaseText('') } catch (e) { expect((e as DatabaseFormatError).userMessage).toBe('No vulnerability records found.') }
  })

  it('skips invalid and duplicate records and reports them', () => {
    const bad = { ...record({ id: 'TEST-0002' }), severity: 'Nope' }
    const { valid, issues, duplicates } = validateDatabase(parseDatabaseText(toText(record(), record(), bad, record({ id: 'TEST-0003' }))))
    expect(valid.map(r => r.id)).toEqual(['TEST-0001', 'TEST-0003'])
    expect(duplicates).toBe(1)
    expect(issues).toHaveLength(2)
  })
})

describe('data/vulnerabilities.txt', () => {
  const { valid, issues } = loadShipped()

  it('has more than 100 records and every record is valid', () => {
    expect(issues).toEqual([])
    expect(valid.length).toBeGreaterThan(100)
  })

  it('covers the required vendors, severities and categories', () => {
    const vendors = new Set(valid.map(r => r.vendor))
    for (const v of ['Hikvision', 'Dahua', 'Axis', 'Uniview', 'Hanwha', 'Bosch', 'Avigilon', 'Reolink', 'Amcrest', 'TP-Link VIGI', 'Generic ONVIF Camera', 'Generic NVR', 'Generic DVR']) {
      expect(vendors.has(v)).toBe(true)
    }
    const sev = new Set(valid.map(r => r.severity))
    for (const s of ['Low', 'Medium', 'High', 'Critical', 'Informational']) expect(sev.has(s as never)).toBe(true)
    expect(new Set(valid.map(r => r.category)).size).toBe(20)
  })

  it('never claims verified sources for demo data and fabricates no CVE ids', () => {
    expect(valid.every(r => r.source_type === 'SIMULATED' || r.source_type === 'COMMUNITY_REPORTED')).toBe(true)
    expect(valid.some(r => /^CVE-/.test(r.id))).toBe(false)
  })
})

// ─── Loading from the text file / GitHub (mocked fetch) ──────────────────────

describe('vulnerability store', () => {
  type Store = typeof import('@/lib/vuln-db/store')
  let store: Store
  let db: ReturnType<typeof import('@/lib/supabase/local-db').createLocalClient>
  const originalFetch = global.fetch
  const originalEnv = { ...process.env }
  const tmpFiles: string[] = []

  const writeTmp = (name: string, text: string) => {
    const file = path.join(process.cwd(), 'data', name)
    fs.writeFileSync(file, text)
    tmpFiles.push(file)
    process.env.COMMUNITY_VULN_DB_LOCAL_PATH = `data/${name}`
  }

  beforeEach(() => {
    jest.resetModules()
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    store = require('@/lib/vuln-db/store')
    store.resetVulnStore()
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const localDb = require('@/lib/supabase/local-db')
    localDb.resetLocalDb()
    db = localDb.createLocalClient()
    process.env.COMMUNITY_VULN_DB_LOCAL_PATH = 'data/vulnerabilities.txt'
    process.env.COMMUNITY_VULN_DB_REMOTE_URL = 'https://raw.githubusercontent.com/example/sentrix-vuln-db/main/vulnerabilities.txt'
    process.env.COMMUNITY_VULN_DB_SYNC_MODE = 'local'
  })

  afterEach(() => {
    global.fetch = originalFetch
    process.env = { ...originalEnv }
    tmpFiles.splice(0).forEach(f => fs.rmSync(f, { force: true }))
  })

  const actions = async () => ((await db.from('audit_logs').select('*')).data as { action: string }[]).map(a => a.action)
  const mockFetch = (body: string, ok = true, status = 200) => {
    global.fetch = jest.fn().mockResolvedValue({ ok, status, headers: new Headers(), text: async () => body }) as unknown as typeof fetch
  }

  it('loads the shipped text file without touching any database table', async () => {
    const summary = await store.reloadLocal(db, 'u1')
    expect(summary).toMatchObject({ status: 'success', message: 'Vulnerability database imported successfully.', skipped_records: 0 })
    expect(summary.loaded_records).toBeGreaterThan(100)
    expect(await actions()).toEqual(['vuln_db_local_import_started', 'vuln_db_local_import_completed'])
    expect((await db.from('community_vulnerabilities').select('*')).data).toEqual([])
    const records = await store.getCommunityRecords(db, 'u1')
    expect(records).toHaveLength(summary.loaded_records)
    expect(records[0].vuln_id).toBe(records[0].id)
  })

  it('picks up an edited file automatically (no reload needed)', async () => {
    writeTmp('tmp-edit.txt', toText(record()))
    expect(await store.getCommunityRecords(db, null)).toHaveLength(1)
    await new Promise(r => setTimeout(r, 20))
    writeTmp('tmp-edit.txt', toText(record(), record({ id: 'TEST-0002' })))
    expect(await store.getCommunityRecords(db, null)).toHaveLength(2)
  })

  it('skips invalid records and reports a partial load', async () => {
    writeTmp('tmp-partial.txt', toText(record(), record({ id: 'TEST-0002' }), { ...record({ id: 'TEST-0003' }), severity: 'Bogus' }))
    const summary = await store.reloadLocal(db, 'u1')
    expect(summary).toMatchObject({ status: 'partial', loaded_records: 2, invalid_records: 1, skipped_records: 1 })
    expect(summary.message).toBe('Some records were skipped due to validation errors.')
    expect(summary.issues[0].errors.join()).toMatch(/severity/)
    expect(await store.getCommunityRecords(db, null)).toHaveLength(2)
  })

  it('does not duplicate repeated ids', async () => {
    writeTmp('tmp-dupe.txt', toText(record(), record(), record()))
    const summary = await store.reloadLocal(db, 'u1')
    expect(summary).toMatchObject({ loaded_records: 1, duplicate_records: 2 })
  })

  it('fails with the format message when no record is valid', async () => {
    writeTmp('tmp-bad.txt', 'this is not a vulnerability file\n{ "json": true }\n')
    const summary = await store.reloadLocal(db, 'u1')
    expect(summary.status).toBe('failed')
    expect(summary.message).toBe('Invalid vulnerability database format.')
    expect(await actions()).toContain('vuln_db_local_import_failed')
  })

  it('reports an empty file and a missing file', async () => {
    writeTmp('tmp-empty.txt', '# nothing here\n')
    expect((await store.reloadLocal(db, 'u1')).message).toBe('No vulnerability records found.')
    process.env.COMMUNITY_VULN_DB_LOCAL_PATH = 'data/does-not-exist.txt'
    const missing = await store.reloadLocal(db, 'u1')
    expect(missing).toMatchObject({ status: 'failed', message: 'Local vulnerability database file was not found.' })
  })

  it('refuses local paths outside the project or not ending in .txt', async () => {
    for (const p of ['../outside.txt', 'package.json']) {
      process.env.COMMUNITY_VULN_DB_LOCAL_PATH = p
      expect((await store.reloadLocal(db, 'u1')).status).toBe('failed')
    }
  })

  it('syncs from a mocked GitHub raw response', async () => {
    mockFetch(toText(record({ id: 'REMOTE-0001' }), record({ id: 'REMOTE-0002' })))
    const summary = await store.syncRemote(db, 'u1')
    expect(global.fetch).toHaveBeenCalledWith(process.env.COMMUNITY_VULN_DB_REMOTE_URL, expect.objectContaining({ redirect: 'error' }))
    expect(summary).toMatchObject({ status: 'success', source: 'remote', loaded_records: 2 })
    expect(summary.message).toBe('GitHub vulnerability sync completed successfully.')
    expect(await actions()).toEqual(['vuln_db_github_sync_started', 'vuln_db_github_sync_completed'])
  })

  it('uses remote data in remote mode and merges (newer wins) in both mode', async () => {
    writeTmp('tmp-local.txt', toText(record({ id: 'A-1', title: 'Local A1', last_updated: '2026-01-10' }), record({ id: 'L-1', title: 'Local only' })))
    mockFetch(toText(record({ id: 'A-1', title: 'Remote A1', last_updated: '2026-02-10' }), record({ id: 'R-1', title: 'Remote only' })))
    await store.syncRemote(db, 'u1')

    process.env.COMMUNITY_VULN_DB_SYNC_MODE = 'remote'
    expect((await store.getCommunityRecords(db, null)).map(r => r.id).sort()).toEqual(['A-1', 'R-1'])

    process.env.COMMUNITY_VULN_DB_SYNC_MODE = 'both'
    const merged = await store.getCommunityRecords(db, null)
    expect(merged.map(r => r.id).sort()).toEqual(['A-1', 'L-1', 'R-1'])
    expect(merged.find(r => r.id === 'A-1')!.title).toBe('Remote A1') // newer last_updated wins
  })

  it('keeps the older record when the local copy is newer (both mode)', async () => {
    writeTmp('tmp-local2.txt', toText(record({ id: 'A-1', title: 'Local newer', last_updated: '2026-05-01' })))
    mockFetch(toText(record({ id: 'A-1', title: 'Remote older', last_updated: '2026-02-01' })))
    await store.syncRemote(db, 'u1')
    process.env.COMMUNITY_VULN_DB_SYNC_MODE = 'both'
    expect((await store.getCommunityRecords(db, null))[0].title).toBe('Local newer')
  })

  it('falls back to local data when GitHub is unavailable', async () => {
    mockFetch('', false, 404)
    const summary = await store.syncRemote(db, 'u1')
    expect(summary.message).toBe('Remote vulnerability database is unavailable. Local data will be used.')
    expect(summary.fell_back_to_local).toBe(true)
    expect(await actions()).toContain('vuln_db_github_sync_failed')
    process.env.COMMUNITY_VULN_DB_SYNC_MODE = 'remote'
    expect((await store.getCommunityRecords(db, null)).length).toBeGreaterThan(100)
  })

  it('treats a network timeout as remote unavailable', async () => {
    global.fetch = jest.fn().mockRejectedValue(Object.assign(new Error('aborted'), { name: 'AbortError' })) as unknown as typeof fetch
    expect((await store.syncRemote(db, 'u1')).message).toBe('Remote vulnerability database is unavailable. Local data will be used.')
  })

  it('only allows https raw.githubusercontent.com URLs', async () => {
    for (const url of ['', 'http://raw.githubusercontent.com/a/b/main/v.txt', 'https://evil.example.com/v.txt', 'https://169.254.169.254/latest']) {
      process.env.COMMUNITY_VULN_DB_REMOTE_URL = url
      global.fetch = jest.fn() as unknown as typeof fetch
      const summary = await store.syncRemote(db, 'u1')
      expect(global.fetch).not.toHaveBeenCalled()
      expect(summary.message).toBe('Remote vulnerability database is unavailable. Local data will be used.')
    }
  })

  it('returns no records when the database is disabled', async () => {
    process.env.COMMUNITY_VULN_DB_ENABLED = 'false'
    expect(await store.getCommunityRecords(db, null)).toEqual([])
  })
})

// ─── Matching ────────────────────────────────────────────────────────────────

describe('matchDevice', () => {
  it('globMatch handles wildcards and firmware prefixes', () => {
    expect(globMatch('DS-2CD2*', 'ds-2cd2043g0-i')).toBe(true)
    expect(globMatch('V5.5.*', 'V5.5.800')).toBe(true)
    expect(globMatch('V5.5.*', 'V5.50')).toBe(false)
    expect(globMatch('a.b', 'axb')).toBe(false)
  })

  it('High: vendor + exact model + firmware', () => {
    const [m] = matchDevice(device, [asMatchable(record())])
    expect(m.match_confidence).toBe('High')
    expect(m.match_type).toBe('vendor_model_firmware')
    expect(m.matched_fields).toEqual(expect.arrayContaining(['vendor', 'model', 'firmware', 'port']))
    expect(m.risk_score_added).toBe(12)
    expect(m.matched_reason).toMatch(/model DS-2CD2043G0-I is listed/)
  })

  it('High: exact model match without firmware restriction', () => {
    const [m] = matchDevice(device, [asMatchable(record({ affected_firmware: ['*'] }))])
    expect(m).toMatchObject({ match_confidence: 'High', match_type: 'exact_model' })
  })

  it('Medium: vendor + protocol/port match on any model', () => {
    const rec = record({ category: 'RTSP Exposure', affected_models: ['*'], affected_firmware: ['*'], affected_ports: [554], affected_protocols: ['RTSP'], risk_score: 20, severity: 'High', cvss_score: 7.5 })
    const [m] = matchDevice(device, [asMatchable(rec)])
    expect(m.match_confidence).toBe('Medium')
    expect(m.risk_score_added).toBe(15) // 75% of 20
  })

  it('Medium: model pattern (not exact) without firmware', () => {
    const [m] = matchDevice(device, [asMatchable(record({ affected_models: ['DS-2CD2*'], affected_firmware: ['*'] }))])
    expect(m).toMatchObject({ match_confidence: 'Medium', match_type: 'vendor_model_pattern' })
  })

  it('Low: generic record on another vendor → Potential Match at 50%', () => {
    const rec = record({ vendor: 'Generic ONVIF Camera', affected_models: ['*'], affected_firmware: ['*'], category: 'RTSP Exposure', affected_ports: [554], affected_protocols: ['RTSP'], risk_score: 20, severity: 'High', cvss_score: 7 })
    const [m] = matchDevice(device, [asMatchable(rec)])
    expect(m.match_confidence).toBe('Low')
    expect(m.risk_score_added).toBe(10)
    expect(m.matched_reason).toMatch(/^Potential match:/)
    expect(confidenceLabel(m.match_confidence)).toBe('Potential Match')
  })

  it('Low: vendor-only record with no other signal', () => {
    const rec = record({ affected_models: ['*'], affected_firmware: ['*'], affected_ports: [], affected_protocols: [], category: 'Default Credentials', severity: 'Critical', cvss_score: 9, risk_score: 30 })
    const [m] = matchDevice(device, [asMatchable(rec)])
    expect(m).toMatchObject({ match_confidence: 'Low', match_type: 'vendor_only', risk_score_added: 15 })
  })

  it('does not match a different vendor, model, firmware, device type, or unexposed service', () => {
    expect(matchDevice(device, [asMatchable(record({ vendor: 'Dahua' }))])).toEqual([])
    expect(matchDevice(device, [asMatchable(record({ affected_models: ['OTHER-MODEL'] }))])).toEqual([])
    expect(matchDevice(device, [asMatchable(record({ affected_firmware: ['V6.*'] }))])).toEqual([])
    expect(matchDevice(device, [asMatchable(record({ device_type: 'nvr' }))])).toEqual([])
    expect(matchDevice(device, [asMatchable(record({ affected_ports: [23], affected_protocols: ['Telnet'] }))])).toEqual([])
  })

  it('a generic record with only a device-type match is too weak to report', () => {
    const rec = record({ vendor: 'Generic IP Camera', device_type: 'camera', affected_models: ['*'], affected_firmware: ['*'], affected_ports: [], affected_protocols: [], detection_keywords: [] })
    expect(matchDevice(device, [asMatchable(rec)])).toEqual([])
  })

  it('honours match_fields (ignores signals that are not listed)', () => {
    const rec = record({ affected_models: ['OTHER-MODEL'], match_fields: ['vendor', 'port'] })
    const [m] = matchDevice(device, [asMatchable(rec)])
    expect(m.match_confidence).toBe('Medium')
  })

  it('keeps only the strongest match per category', () => {
    const specific = asMatchable(record(), 'a')
    const generic = asMatchable(record({ vendor: 'Generic NVR', affected_models: ['*'], affected_firmware: ['*'], risk_score: 19, severity: 'Medium' }), 'b')
    const result = matchDevice(device, [generic, specific])
    expect(result).toHaveLength(1)
    expect(result[0].vulnerability_id).toBe('a')
  })

  it('matches the generic NVR demo device exactly (generic vendor + model)', () => {
    const nvr: MatchableDevice = { vendor: 'Generic', model: 'NVR-8CH-4K', firmware_version: 'V1.0.0', device_type: 'nvr', open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }], protocols: ['HTTP'] }
    const rec = record({ vendor: 'Generic NVR', device_type: 'nvr', affected_models: ['NVR-8CH-4K'], affected_firmware: ['V1.0.*'], category: 'Web Interface Security' })
    expect(matchDevice(nvr, [asMatchable(rec)])[0].match_confidence).toBe('High')
  })

  it('shipped dataset yields sensible matches for the demo Hikvision camera', () => {
    const records = loadShipped().valid.map((r, i) => asMatchable(r, `id-${i}`))
    const hik: MatchableDevice = {
      vendor: 'Hikvision', model: 'DS-2CD2043G0-I', firmware_version: 'V5.5.800', device_type: 'camera',
      open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }, { port: 554, service: 'RTSP', protocol: 'tcp' }, { port: 8000, service: 'SDK', protocol: 'tcp' }],
      protocols: ['HTTP', 'RTSP', 'ONVIF', 'Hikvision-SDK'],
    }
    const result = matchDevice(hik, records)
    expect(result.length).toBeGreaterThan(3)
    expect(result.some(r => r.match_confidence === 'High')).toBe(true)
    expect(new Set(result.map(r => r.category)).size).toBe(result.length) // one per category
  })
})

// ─── Risk scoring ────────────────────────────────────────────────────────────

describe('risk scoring with matches', () => {
  it('applies 100% / 75% / 50% by confidence', () => {
    expect(applyConfidenceFactor(30, 'High')).toBe(30)
    expect(applyConfidenceFactor(30, 'Medium')).toBe(23) // 22.5 → 23
    expect(applyConfidenceFactor(30, 'Low')).toBe(15)
  })

  it('adds matched risk to the scanner findings', () => {
    expect(calculateRiskScoreWithMatches([{ score: 10 }], [{ risk_score_added: 15 }, { risk_score_added: 5 }])).toBe(30)
  })

  it('caps the device risk at 100 and trust = 100 - risk', () => {
    const risk = calculateRiskScoreWithMatches([{ score: 35 }, { score: 35 }], [{ risk_score_added: 30 }, { risk_score_added: 30 }])
    expect(risk).toBe(100)
    expect(calculateTrustScore(risk)).toBe(0)
    expect(calculateTrustScore(30)).toBe(70)
  })
})

// ─── Device details data + reports ───────────────────────────────────────────

describe('stored matches → device details and report', () => {
  it('getEnrichedMatches returns saved matches with their record snapshot (device details payload)', async () => {
    jest.resetModules()
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const localDb = require('@/lib/supabase/local-db')
    localDb.resetLocalDb()
    const db = localDb.createLocalClient()
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { getEnrichedMatches, snapshotOf } = require('@/lib/vuln-db/queries') as typeof import('@/lib/vuln-db/queries')

    const med = { ...record(), vuln_id: 'TEST-0001' }
    const high = { ...record({ id: 'TEST-0002', severity: 'High', cvss_score: 7.5, risk_score: 22, category: 'RTSP Exposure' }), vuln_id: 'TEST-0002' }
    await db.from('device_vulnerability_matches').insert([
      { device_id: 'dev-1', scan_id: 'scan-1', vulnerability_id: 'TEST-0001', vulnerability_snapshot: snapshotOf(med), match_type: 'exact_model', match_confidence: 'High', matched_fields: ['vendor'], matched_reason: 'r1', risk_score_added: 12 },
      { device_id: 'dev-1', scan_id: 'scan-1', vulnerability_id: 'TEST-0002', vulnerability_snapshot: snapshotOf(high), match_type: 'generic_service', match_confidence: 'Low', matched_fields: ['port'], matched_reason: 'r2', risk_score_added: 11 },
      { device_id: 'dev-2', scan_id: 'scan-1', vulnerability_id: 'TEST-0001', vulnerability_snapshot: snapshotOf(med), match_type: 'exact_model', match_confidence: 'High', matched_fields: [], matched_reason: 'r3', risk_score_added: 12 },
    ])

    const matches = await getEnrichedMatches(db, ['dev-1'])
    expect(matches).toHaveLength(2)
    expect(matches[0].vulnerability.vuln_id).toBe('TEST-0002') // most severe first
    expect(matches[0].vulnerability).toMatchObject({ recommendation: 'Enable HTTPS.', source_type: 'SIMULATED', category: 'RTSP Exposure' })
    expect(matches[0]).not.toHaveProperty('vulnerability_snapshot')
    expect(await getEnrichedMatches(db, [])).toEqual([])
  })

  const scan: Scan = {
    id: 's', user_id: 'u', scan_name: 'Scan', network_range: '10.0.0.0/24', status: 'completed', total_devices: 1,
    vulnerable_devices: 1, critical_devices: 0, overall_risk: 'high', started_at: '2026-01-01T00:00:00Z',
  }
  const dev: Device & { vulnerabilities: Vulnerability[]; community_matches: EnrichedMatch[] } = {
    id: 'd', scan_id: 's', ip_address: '10.0.0.5', mac_address: 'AA:BB', vendor: 'Hikvision', model: 'DS-2CD2043G0-I',
    firmware_version: 'V5.5.800', device_type: 'camera', open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }],
    protocols: ['HTTP'], risk_score: 40, risk_level: 'medium', status: 'active', created_at: '2026-01-01T00:00:00Z',
    vulnerabilities: [],
    community_matches: [{
      id: 'm1', device_id: 'd', scan_id: 's', vulnerability_id: 'v1', match_type: 'exact_model', match_confidence: 'Low',
      matched_fields: ['vendor'], matched_reason: 'Potential match: vendor Hikvision matches.', risk_score_added: 6,
      created_at: '2026-01-01T00:00:00Z',
      vulnerability: {
        vuln_id: 'SXV-2026-0001', title: 'Test <b>Title</b>', description: 'd', vendor: 'Hikvision', category: 'HTTP-Only Interface',
        severity: 'High', cvss_score: 7, risk_score: 12, recommendation: 'Enable HTTPS everywhere', remediation_steps: ['s'],
        source_type: 'SIMULATED', reference_url: 'javascript:alert(1)', confidence_note: 'n',
      },
    }],
  }

  it('includes the community section, severity distribution, confidence explanation, recommendation and note', () => {
    const html = generateReportHtml(scan, [dev])
    expect(html).toContain('COMMUNITY VULNERABILITY SUMMARY')
    expect(html).toContain('SXV-2026-0001')
    expect(html).toContain('Potential Match')
    expect(html).toContain('Match confidence')
    expect(html).toContain('Enable HTTPS everywhere')
    expect(html).toContain(REPORT_NOTE)
    expect(html).toMatch(/>1<\/div><div style="color:#718096;font-size:11px">High</)
  })

  it('escapes record text and does not link unsafe reference URLs', () => {
    const html = generateReportHtml(scan, [dev])
    expect(html).not.toContain('<b>Title</b>')
    expect(html).toContain('Test &lt;b&gt;Title&lt;/b&gt;')
    expect(html).not.toContain('javascript:alert')
  })

  it('still renders (with the note) when there are no matches', () => {
    const html = generateReportHtml(scan, [{ ...dev, community_matches: [] }])
    expect(html).toContain('No community vulnerability records were matched')
    expect(html).toContain(REPORT_NOTE)
  })
})
