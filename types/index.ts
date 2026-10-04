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
