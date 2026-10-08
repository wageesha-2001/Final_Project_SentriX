/**
 * Shared constants for the Community Vulnerability Database.
 * Client-safe: no fs / network / database imports here.
 */
import type {
  CommunityDeviceType, CommunityMatchField, CommunitySeverity, CommunitySourceType, MatchConfidence,
} from '@/types'

export const COMMUNITY_CHECK_SLUG = 'community-vulnerability-mapping'

export const SEVERITIES: CommunitySeverity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational']
export const SOURCE_TYPES: CommunitySourceType[] = ['SIMULATED', 'COMMUNITY_REPORTED', 'VENDOR_ADVISORY', 'CVE']
export const DEVICE_TYPES: CommunityDeviceType[] = ['camera', 'nvr', 'dvr', 'router', 'any']
export const MATCH_FIELDS: CommunityMatchField[] = ['vendor', 'model', 'firmware', 'device_type', 'port', 'protocol', 'keyword']

export const CATEGORIES = [
  'Default Credentials',
  'Weak Authentication',
  'Open Risky Ports',
  'HTTP-Only Interface',
  'RTSP Exposure',
  'Outdated Firmware',
  'Web Interface Security',
  'Missing Security Headers',
  'Telnet Enabled',
  'ONVIF Anonymous Access',
  'Internet Exposure',
  'Session Cookie Weakness',
  'Insecure API Endpoint',
  'UPnP Exposure',
  'FTP Exposure',
  'SNMP Exposure',
  'Snapshot URL Exposure',
  'Insecure Configuration Backup',
  'Weak TLS Configuration',
  'Unsupported Firmware',
] as const

/** Inclusive risk_score range allowed for each severity. */
export const SEVERITY_RISK_RANGE: Record<CommunitySeverity, [number, number]> = {
  Critical: [30, 40],
  High: [20, 29],
  Medium: [10, 19],
  Low: [1, 9],
  Informational: [0, 0],
}

/** Share of a record's risk_score applied to a device, by match confidence. */
export const CONFIDENCE_FACTOR: Record<MatchConfidence, number> = {
  High: 1,
  Medium: 0.75,
  Low: 0.5,
}

/** Low-confidence matches are never presented as findings. */
export function confidenceLabel(confidence: MatchConfidence): string {
  return confidence === 'Low' ? 'Potential Match' : `${confidence} Confidence`
}

export const REPORT_NOTE =
  'Community vulnerability matches are based on locally maintained or GitHub-hosted vulnerability data. ' +
  'Some matches may be approximate and should be verified against official vendor advisories before remediation.'

export const MESSAGES = {
  localSuccess: 'Vulnerability database imported successfully.',
  remoteSuccess: 'GitHub vulnerability sync completed successfully.',
  invalidFormat: 'Invalid vulnerability database format.',
  noRecords: 'No vulnerability records found.',
  partial: 'Some records were skipped due to validation errors.',
  remoteUnavailable: 'Remote vulnerability database is unavailable. Local data will be used.',
  localMissing: 'Local vulnerability database file was not found.',
} as const
