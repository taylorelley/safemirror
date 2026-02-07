// User and Auth types
export interface User {
  id: string;
  email: string;
  username: string;
  full_name?: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  role?: Role;
}

export interface Role {
  id: string;
  name: string;
  description?: string;
  permissions: Permission[];
}

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token?: string;
  token_type: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

// Package types
export interface Package {
  id: string;
  name: string;
  version: string;
  mirror_id: string;
  mirror_name?: string;
  created_at: string;
  updated_at?: string;
  vulnerability_count: number;
  highest_severity?: string;
  status: string;
}

export interface PackageDetail extends Package {
  description?: string;
  dependencies: Dependency[];
  vulnerabilities: Vulnerability[];
  scans: Scan[];
}

export interface Dependency {
  name: string;
  version: string;
  type: string;
}

// Vulnerability types
export interface Vulnerability {
  id: string;
  cve_id?: string;
  title: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  cvss_score?: number;
  affected_packages: string[];
  fixed_version?: string;
  published_at?: string;
  references: string[];
}

// Scan types
export interface Scan {
  id: string;
  package_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string;
  completed_at?: string;
  vulnerability_count: number;
  findings: ScanFinding[];
}

export interface ScanFinding {
  vulnerability_id: string;
  severity: string;
  location?: string;
}

// Mirror types
export interface Mirror {
  id: string;
  name: string;
  type: 'npm' | 'pypi' | 'maven' | 'docker';
  url: string;
  status: 'active' | 'syncing' | 'error' | 'disabled';
  last_sync?: string;
  package_count: number;
  created_at: string;
}

// Approval types
export interface Approval {
  id: string;
  package_id: string;
  package_name: string;
  requested_by: string;
  requested_at: string;
  status: ApprovalStatus;
  reviewed_by?: string;
  reviewed_at?: string;
  comments?: string;
  policy_id?: string;
}

export type ApprovalStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'escalated'
  | 'expired'
  | 'cancelled';

// Policy types
export interface Policy {
  id: string;
  name: string;
  description?: string;
  is_active: boolean;
  conditions: PolicyCondition[];
  actions: PolicyAction[];
  created_at: string;
}

export interface PolicyCondition {
  field: string;
  operator: string;
  value: string | number;
}

export interface PolicyAction {
  type: string;
  config: Record<string, unknown>;
}

// Audit types
export interface AuditLog {
  id: string;
  user_id?: string;
  username?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
  created_at: string;
}

// API Key types
export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  permissions: string[];
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
  is_active: boolean;
}

// Notification types
export interface NotificationSettings {
  email_enabled: boolean;
  email_recipients: string[];
  webhook_enabled: boolean;
  webhook_url?: string;
  events: string[];
}

// Dashboard types
export interface DashboardMetrics {
  total_packages: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  pending_approvals: number;
  active_mirrors: number;
  recent_scans: number;
}

export interface Activity {
  id: string;
  type: string;
  message: string;
  user?: string;
  created_at: string;
}

// Report types
export interface VulnerabilityReport {
  summary: {
    total: number;
    by_severity: Record<string, number>;
  };
  vulnerabilities: Vulnerability[];
  generated_at: string;
}

export interface ComplianceReport {
  status: 'compliant' | 'non_compliant' | 'partial';
  policies: PolicyStatus[];
  generated_at: string;
}

export interface PolicyStatus {
  policy_id: string;
  policy_name: string;
  status: 'pass' | 'fail' | 'warning';
  details?: string;
}

// Pagination
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

// API Error
export interface ApiError {
  detail: string;
  status_code?: number;
}
