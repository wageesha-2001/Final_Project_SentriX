/**
 * @jest-environment node
 *
 * The twelve classification cases from the fix spec, exercised through the pure
 * matching + classification functions (no network). Each asserts the separated
 * statuses and the overall VULNERABLE / HEALTHY / NOT_VERIFIED outcome.
 */
import { matchDevice, knownVulnerabilityStatus, MatchableDevice, MatchableRecord } from '@/lib/vuln-db/matcher'
import {
  getOverallSecurityStatus, calculateDeviceRisk, calculateTrustScore, getRiskLevel,
} from '@/lib/risk/calculator'
import type { CommunityVulnRecord, AuthenticationStatus } from '@/types'

const rec = (o: Partial<CommunityVulnRecord> = {}): MatchableRecord => ({
  id: 'SXV-TEST', vendor: 'Hikvision', affected_models: ['DS-2CD2043G0-I'], affected_firmware: ['V5.5.*'],
  device_type: 'camera', category: 'Outdated Firmware', severity: 'High', risk_score: 25,
  affected_ports: [80], affected_protocols: ['HTTP'], detection_keywords: [], match_fields: [], ...o,
} as MatchableRecord)

const cam = (o: Partial<MatchableDevice> = {}): MatchableDevice => ({
  vendor: 'Hikvision', model: 'DS-2CD2043G0-I', firmware_version: 'V5.5.800', device_type: 'camera',
  open_ports: [{ port: 80, service: 'HTTP', protocol: 'tcp' }, { port: 554, service: 'RTSP', protocol: 'tcp' }],
  protocols: ['HTTP', 'RTSP'], ip_address: '192.168.1.10', ...o,
})

/** Mirror the scanner's per-device decision from its building blocks. */
function classify(device: MatchableDevice, records: MatchableRecord[], auth: AuthenticationStatus, policyActive = false) {
  const matches = matchDevice(device, records)
  const confirmed = matches.filter(m => m.confirmed)
  const known = knownVulnerabilityStatus(matches)
  const essentialChecksComplete = !(policyActive && auth === 'NOT_TESTED')
  const overall = getOverallSecurityStatus({ knownStatus: known, authStatus: auth, essentialChecksComplete })
  const risk = calculateDeviceRisk(confirmed, auth)
  const riskLevel = getRiskLevel(risk)
  return { known, overall, risk, riskLevel, trust: calculateTrustScore(risk), matched: confirmed.length, auth }
}

it('Case 1: model in file and firmware matches → VULNERABLE', () => {
  const r = classify(cam(), [rec()], 'AUTHENTICATION_REJECTED')
  expect(r).toMatchObject({ known: 'MATCHED', overall: 'VULNERABLE' })
  expect(r.risk).toBeGreaterThan(0)
})

it('Case 2: same vendor, different model → NO_MATCH, not vulnerable from that record', () => {
  const r = classify(cam({ model: 'DS-2CD2347G2-LU' }), [rec()], 'AUTHENTICATION_REJECTED')
  expect(r).toMatchObject({ known: 'NO_MATCH', overall: 'HEALTHY', matched: 0, risk: 0 })
})

it('Case 3: model matches but firmware is outside the affected range → NO_MATCH', () => {
  const r = classify(cam({ firmware_version: 'V6.1.0' }), [rec({ affected_firmware: ['V5.5.*'] })], 'AUTHENTICATION_REJECTED')
  expect(r).toMatchObject({ known: 'NO_MATCH', overall: 'HEALTHY' })
})

it('Case 4: not in file and authentication rejected → HEALTHY', () => {
  const r = classify(cam({ model: 'UNLISTED-CAM' }), [rec()], 'AUTHENTICATION_REJECTED')
  expect(r).toMatchObject({ known: 'NO_MATCH', overall: 'HEALTHY', risk: 0 })
})

it('Case 5: no file match but default credentials confirmed → VULNERABLE (Critical, auth only)', () => {
  const r = classify(cam({ model: 'UNLISTED-CAM' }), [rec()], 'CONFIRMED_DEFAULT_CREDENTIALS')
  expect(r).toMatchObject({ known: 'NO_MATCH', overall: 'VULNERABLE', riskLevel: 'critical' })
})

it('Case 5b: no file match but a WEAK password accepted → VULNERABLE at LOW risk', () => {
  const r = classify(cam({ model: 'UNLISTED-CAM' }), [rec()], 'CONFIRMED_WEAK_PASSWORD')
  expect(r).toMatchObject({ known: 'NO_MATCH', overall: 'VULNERABLE', riskLevel: 'low' })
  expect(r.risk).toBeGreaterThan(0)
  expect(r.risk).toBeLessThanOrEqual(20) // Low band
})

it('Case 6: no file match, credential test unsupported, policy active → NOT_VERIFIED', () => {
  const r = classify(cam({ model: 'UNLISTED-CAM' }), [rec()], 'NOT_TESTED', /* policyActive */ true)
  expect(r).toMatchObject({ known: 'NO_MATCH', overall: 'NOT_VERIFIED' })
})

it('Case 7: file match but credentials rejected → VULNERABLE (file only)', () => {
  const r = classify(cam(), [rec()], 'AUTHENTICATION_REJECTED')
  expect(r.overall).toBe('VULNERABLE')
})

it('Case 8: ports 80 and 554 open but no record matches → not vulnerable from ports alone', () => {
  const portsOnly = rec({ affected_models: ['*'], affected_firmware: ['*'], affected_ports: [80, 554], affected_protocols: ['HTTP', 'RTSP'] })
  const r = classify(cam({ model: 'UNLISTED-CAM' }), [portsOnly], 'AUTHENTICATION_REJECTED')
  expect(r).toMatchObject({ known: 'NO_MATCH', overall: 'HEALTHY', matched: 0 })
})

it('Case 9: two similar Hikvision models, only the listed one matches', () => {
  const onlyG0 = rec({ affected_models: ['DS-2CD2043G0-I'], affected_firmware: ['*'] })
  expect(classify(cam({ model: 'DS-2CD2043G0-I' }), [onlyG0], 'NOT_TESTED').overall).toBe('VULNERABLE')
  expect(classify(cam({ model: 'DS-2CD2347G2-LU' }), [onlyG0], 'NOT_TESTED').overall).toBe('HEALTHY')
})

it('Case 10: after a record is removed, a rescan no longer reports it', () => {
  const withRecord = classify(cam(), [rec()], 'NOT_TESTED')
  const afterRemoval = classify(cam(), [], 'NOT_TESTED') // record gone from the file
  expect(withRecord.overall).toBe('VULNERABLE')
  expect(afterRemoval).toMatchObject({ known: 'NO_MATCH', overall: 'HEALTHY', matched: 0 })
})

it('Case 11: a real-discovered device with Unknown model inherits no simulated vuln', () => {
  // Real discovery that could not read the model: nothing confirms against the file.
  const r = classify(cam({ model: 'Unknown', firmware_version: 'Unknown', vendor: 'Unknown' }), [rec()], 'NOT_TESTED')
  expect(r).toMatchObject({ known: 'NO_MATCH', overall: 'HEALTHY', matched: 0 })
})

it('Case 12: five devices → 2 vulnerable, 2 healthy, 1 not verified', () => {
  const records = [rec()]
  const devices = [
    classify(cam(), records, 'NOT_TESTED'),                                   // file match → VULNERABLE
    classify(cam({ model: 'UNLISTED-CAM' }), records, 'CONFIRMED_DEFAULT_CREDENTIALS'), // creds → VULNERABLE
    classify(cam({ model: 'UNLISTED-CAM' }), records, 'AUTHENTICATION_REJECTED'),       // clean → HEALTHY
    classify(cam({ model: 'OTHER' }), records, 'AUTHENTICATION_REJECTED'),              // clean → HEALTHY
    classify(cam({ model: 'UNLISTED-CAM' }), records, 'NOT_TESTED', true),              // untestable → NOT_VERIFIED
  ]
  const n = (s: string) => devices.filter(d => d.overall === s).length
  expect([n('VULNERABLE'), n('HEALTHY'), n('NOT_VERIFIED')]).toEqual([2, 2, 1])
})
