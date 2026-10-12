export type UserRole = 'admin' | 'technician';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  created_at: string;
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'stopped' | 'failed';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical' | 'secure';

export interface Scan {
  id: string;
  user_id: string;
  scan_name: string;
  network_range: string;
  status: ScanStatus;
  total_devices: number;
  vulnerable_devices: number;
  critical_devices: number;
  overall_risk: RiskLevel;
  started_at: string;
  completed_at?: string;
  progress?: number;
  /** Discovery engine used; absent on scans created before it was recorded. */
  scan_mode?: 'real' | 'simulated';
}

export type DeviceType = 'camera' | 'nvr' | 'dvr' | 'router' | 'unknown';

export interface OpenPort {
  port: number;
  service: string;
  protocol: string;
}

export interface Device {
  id: string;
  scan_id: string;
  ip_address: string;
  mac_address: string;
  vendor: string;
  model: string;
  firmware_version: string;
  device_type: DeviceType;
  open_ports: OpenPort[];
  protocols: string[];
  risk_score: number;
  risk_level: RiskLevel;
  status: string;
  created_at: string;
  /** Persisted assessment statuses (absent on scans created before they existed). */
  known_vulnerability_status?: KnownVulnerabilityStatus;
  authentication_status?: AuthenticationStatus;
  overall_security_status?: OverallSecurityStatus;
  trust_score?: number;
}

export type SecurityStatus = 'vulnerable' | 'potential' | 'secure';

// ─── Separated per-device assessment statuses ────────────────────────────────
// Discovery, known-vulnerability matching and authentication are independent.

/** Result of matching the device against data/vulnerabilities.txt. */
export type KnownVulnerabilityStatus = 'MATCHED' | 'NO_MATCH' | 'UNVERIFIED';

/** Result of the authorized credential verification stage. */
export type AuthenticationStatus =
  | 'CONFIRMED_DEFAULT_CREDENTIALS'
  | 'CONFIRMED_WEAK_PASSWORD'
  | 'AUTHENTICATION_REJECTED'
  | 'NOT_TESTED'
  | 'AUTHENTICATION_ERROR';

/** Overall per-device classification derived from the two statuses above. */
export type OverallSecurityStatus = 'VULNERABLE' | 'HEALTHY' | 'NOT_VERIFIED';

/** Device as returned by GET /api/devices, with its security summary. */
export interface DeviceListItem extends Device {
  /** Confirmed findings: file matches + confirmed default credentials. */
  findings_count: number;
  community_match_count: number;
  known_vulnerability_count: number;
  /** Legacy tri-state kept for existing UI: vulnerable | potential | secure. */
  security_status: SecurityStatus;
  known_vulnerability_status: KnownVulnerabilityStatus;
  authentication_status: AuthenticationStatus;
  overall_security_status: OverallSecurityStatus;
  /** Observations (open ports, HTTP-only, …) that do NOT affect risk. */
  informational_count: number;
  trust_score: number;
  /** Found by a simulation-mode scan (built-in demo device). */
  simulated?: boolean;
}

export type VulnerabilitySeverity = 'low' | 'medium' | 'high' | 'critical';

export interface Vulnerability {
  id: string;
  device_id: string;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  score: number;
  recommendation: string;
  /** Observation only (open port, HTTP-only, …): shown but excluded from risk/status. */
  informational?: boolean;
  created_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  report_title: string;
  report_html: string;
  created_at: string;
}

export interface Settings {
  id: string;
  user_id: string;
  safe_scan_mode: boolean;
  scan_timeout: number;
  login_attempt_limit: number;
  created_at: string;
  updated_at: string;
}

export interface DefaultCredential {
  id: string;
  vendor: string;
  username: string;
  password: string;
  risk_level: RiskLevel;
  created_at: string;
}

export interface AuditLog {
  id: string;
  user_id: string;
  action: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface DashboardStats {
  total_devices: number;
  secure_devices: number;
  vulnerable_devices: number;
  critical_devices: number;
  total_scans: number;
  latest_scan?: Scan;
}

export interface ScanProgress {
  scan_id: string;
  progress: number;
  current_ip?: string;
  devices_found: number;
  status: ScanStatus;
  message?: string;
}

export interface JWTPayload {
  sub: string;
  email: string;
  role: UserRole;
  name: string;
  iat: number;
  exp: number;
  jti?: string;
}

export interface ApiResponse<T = unknown> {
  data?: T;
  error?: string;
  message?: string;
}

export interface VulnerabilityCheck {
  id: string
  name: string
  slug: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
  risk_score: number
  recommendation: string
  enabled: boolean
  created_at: string
  updated_at: string
}

// ─── Community Vulnerability Database ────────────────────────────────────────

export type CommunitySeverity = 'Low' | 'Medium' | 'High' | 'Critical' | 'Informational'
export type CommunitySourceType = 'SIMULATED' | 'COMMUNITY_REPORTED' | 'VENDOR_ADVISORY' | 'CVE'
export type MatchConfidence = 'High' | 'Medium' | 'Low'
export type CommunityDeviceType = 'camera' | 'nvr' | 'dvr' | 'any'
export type CommunityMatchField = 'vendor' | 'model' | 'firmware' | 'device_type' | 'port' | 'protocol' | 'keyword'

/** One record as it appears in vulnerabilities.json (the public schema). */
export interface CommunityVulnRecord {
  id: string
  title: string
  description: string
  vendor: string
  affected_models: string[]
  affected_firmware: string[]
  device_type: CommunityDeviceType
  category: string
  severity: CommunitySeverity
  cvss_score: number
  risk_score: number
  affected_ports: number[]
  affected_protocols: string[]
  detection_keywords: string[]
  match_fields: CommunityMatchField[]
  source_type: CommunitySourceType
  reference_url: string
  published_date: string
  last_updated: string
  recommendation: string
  remediation_steps: string[]
  confidence_note: string
}

/** A loaded record. `id` and `vuln_id` are both the record ID from the text file. */
export type CommunityVulnerability = CommunityVulnRecord & { vuln_id: string }

/** One entry of import/sync history (derived from the audit log; nothing is stored separately). */
export interface VulnDbRun {
  at: string
  source: 'local' | 'remote'
  status: 'success' | 'partial' | 'failed'
  total_records: number
  loaded_records: number
  skipped_records: number
  message: string
}

export interface DeviceVulnerabilityMatch {
  id: string
  device_id: string
  scan_id: string
  /** ID of the record in the text file (e.g. SXV-2026-0001). */
  vulnerability_id: string
  match_type: string
  match_confidence: MatchConfidence
  matched_fields: string[]
  matched_reason: string
  risk_score_added: number
  /** Copy of the matched record, kept so old scans/reports stay readable after the file is edited. */
  vulnerability_snapshot?: EnrichedMatch['vulnerability']
  created_at: string
}

/** A match joined with the vulnerability it points to (what the UI and reports consume). */
export interface EnrichedMatch extends Omit<DeviceVulnerabilityMatch, 'vulnerability_snapshot'> {
  vulnerability: Pick<
    CommunityVulnerability,
    | 'vuln_id' | 'title' | 'description' | 'vendor' | 'category' | 'severity' | 'cvss_score'
    | 'risk_score' | 'recommendation' | 'remediation_steps' | 'source_type' | 'reference_url'
    | 'confidence_note'
  >
}
