import Cookies from 'js-cookie';
import type {
  AuthTokens,
  LoginCredentials,
  User,
  Package,
  PackageDetail,
  Vulnerability,
  Scan,
  Mirror,
  Approval,
  Policy,
  AuditLog,
  ApiKey,
  Role,
  DashboardMetrics,
  VulnerabilityReport,
  ComplianceReport,
  NotificationSettings,
  PaginatedResponse,
} from '@/types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private getAuthHeader(): Record<string, string> {
    const token = Cookies.get('access_token');
    if (token) {
      return { Authorization: `Bearer ${token}` };
    }
    return {};
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...this.getAuthHeader(),
      ...(options.headers as Record<string, string>),
    };

    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      // Try to refresh token
      const refreshed = await this.refreshToken();
      if (refreshed) {
        // Retry the request
        headers.Authorization = `Bearer ${Cookies.get('access_token')}`;
        const retryResponse = await fetch(url, { ...options, headers });
        if (!retryResponse.ok) {
          throw new Error(`API error: ${retryResponse.status}`);
        }
        return retryResponse.json();
      }
      // Redirect to login
      window.location.href = '/login';
      throw new Error('Unauthorized');
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(error.detail || `API error: ${response.status}`);
    }

    return response.json();
  }

  private async refreshToken(): Promise<boolean> {
    const refreshToken = Cookies.get('refresh_token');
    if (!refreshToken) return false;

    try {
      const response = await fetch(`${this.baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (response.ok) {
        const tokens: AuthTokens = await response.json();
        Cookies.set('access_token', tokens.access_token, { expires: 1 });
        if (tokens.refresh_token) {
          Cookies.set('refresh_token', tokens.refresh_token, { expires: 7 });
        }
        return true;
      }
    } catch {
      // Refresh failed
    }
    return false;
  }

  // Auth endpoints
  async login(credentials: LoginCredentials): Promise<AuthTokens> {
    const formData = new URLSearchParams();
    formData.append('username', credentials.username);
    formData.append('password', credentials.password);

    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(error.detail || 'Login failed');
    }

    const tokens: AuthTokens = await response.json();
    Cookies.set('access_token', tokens.access_token, { expires: 1 });
    if (tokens.refresh_token) {
      Cookies.set('refresh_token', tokens.refresh_token, { expires: 7 });
    }
    return tokens;
  }

  logout(): void {
    Cookies.remove('access_token');
    Cookies.remove('refresh_token');
  }

  async getCurrentUser(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  // Dashboard
  async getDashboardMetrics(): Promise<DashboardMetrics> {
    return this.request<DashboardMetrics>('/dashboard/metrics');
  }

  // Packages
  async getPackages(params?: {
    page?: number;
    page_size?: number;
    search?: string;
    severity?: string;
    status?: string;
  }): Promise<PaginatedResponse<Package>> {
    const query = new URLSearchParams();
    if (params?.page) query.set('page', params.page.toString());
    if (params?.page_size) query.set('page_size', params.page_size.toString());
    if (params?.search) query.set('search', params.search);
    if (params?.severity) query.set('severity', params.severity);
    if (params?.status) query.set('status', params.status);
    return this.request<PaginatedResponse<Package>>(`/packages?${query}`);
  }

  async getPackage(id: string): Promise<PackageDetail> {
    return this.request<PackageDetail>(`/packages/${id}`);
  }

  async getPackageVersions(id: string): Promise<string[]> {
    return this.request<string[]>(`/packages/${id}/versions`);
  }

  async compareVersions(id: string, v1: string, v2: string): Promise<{
    version1: PackageDetail;
    version2: PackageDetail;
    diff: { added: Vulnerability[]; removed: Vulnerability[]; unchanged: Vulnerability[] };
  }> {
    return this.request(`/packages/${id}/compare?${new URLSearchParams({ v1, v2 })}`);
  }

  // Vulnerabilities
  async getVulnerabilities(params?: {
    page?: number;
    page_size?: number;
    severity?: string;
    cve_id?: string;
  }): Promise<PaginatedResponse<Vulnerability>> {
    const query = new URLSearchParams();
    if (params?.page) query.set('page', params.page.toString());
    if (params?.page_size) query.set('page_size', params.page_size.toString());
    if (params?.severity) query.set('severity', params.severity);
    if (params?.cve_id) query.set('cve_id', params.cve_id);
    return this.request<PaginatedResponse<Vulnerability>>(`/vulnerabilities?${query}`);
  }

  async getVulnerability(cveId: string): Promise<Vulnerability> {
    return this.request<Vulnerability>(`/vulnerabilities/${cveId}`);
  }

  // Scans
  async getScans(packageId?: string): Promise<Scan[]> {
    const query = packageId ? `?package_id=${packageId}` : '';
    return this.request<Scan[]>(`/scans${query}`);
  }

  async triggerScan(packageId: string): Promise<Scan> {
    return this.request<Scan>(`/scans`, {
      method: 'POST',
      body: JSON.stringify({ package_id: packageId }),
    });
  }

  // Mirrors
  async getMirrors(): Promise<Mirror[]> {
    return this.request<Mirror[]>('/mirrors');
  }

  async getMirror(id: string): Promise<Mirror> {
    return this.request<Mirror>(`/mirrors/${id}`);
  }

  async createMirror(data: Partial<Mirror>): Promise<Mirror> {
    return this.request<Mirror>('/mirrors', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateMirror(id: string, data: Partial<Mirror>): Promise<Mirror> {
    return this.request<Mirror>(`/mirrors/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async deleteMirror(id: string): Promise<void> {
    await this.request(`/mirrors/${id}`, { method: 'DELETE' });
  }

  async syncMirror(id: string): Promise<void> {
    await this.request(`/mirrors/${id}/sync`, { method: 'POST' });
  }

  // Approvals
  async getApprovals(params?: {
    page?: number;
    status?: string;
  }): Promise<PaginatedResponse<Approval>> {
    const query = new URLSearchParams();
    if (params?.page) query.set('page', params.page.toString());
    if (params?.status) query.set('status', params.status);
    return this.request<PaginatedResponse<Approval>>(`/approvals?${query}`);
  }

  async getApproval(id: string): Promise<Approval> {
    return this.request<Approval>(`/approvals/${id}`);
  }

  async approveRequest(id: string, comments?: string): Promise<Approval> {
    return this.request<Approval>(`/approvals/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ comments }),
    });
  }

  async rejectRequest(id: string, comments?: string): Promise<Approval> {
    return this.request<Approval>(`/approvals/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ comments }),
    });
  }

  async batchApprove(ids: string[], comments?: string): Promise<void> {
    await this.request('/approvals/batch/approve', {
      method: 'POST',
      body: JSON.stringify({ ids, comments }),
    });
  }

  async batchReject(ids: string[], comments?: string): Promise<void> {
    await this.request('/approvals/batch/reject', {
      method: 'POST',
      body: JSON.stringify({ ids, comments }),
    });
  }

  // Policies
  async getPolicies(): Promise<Policy[]> {
    return this.request<Policy[]>('/policies');
  }

  async getPolicy(id: string): Promise<Policy> {
    return this.request<Policy>(`/policies/${id}`);
  }

  async createPolicy(data: Partial<Policy>): Promise<Policy> {
    return this.request<Policy>('/policies', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updatePolicy(id: string, data: Partial<Policy>): Promise<Policy> {
    return this.request<Policy>(`/policies/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async deletePolicy(id: string): Promise<void> {
    await this.request(`/policies/${id}`, { method: 'DELETE' });
  }

  async togglePolicy(id: string, isActive: boolean): Promise<Policy> {
    return this.request<Policy>(`/policies/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ is_active: isActive }),
    });
  }

  // Audit
  async getAuditLogs(params?: {
    page?: number;
    page_size?: number;
    action?: string;
    user_id?: string;
    start_date?: string;
    end_date?: string;
  }): Promise<PaginatedResponse<AuditLog>> {
    const query = new URLSearchParams();
    if (params?.page) query.set('page', params.page.toString());
    if (params?.page_size) query.set('page_size', params.page_size.toString());
    if (params?.action) query.set('action', params.action);
    if (params?.user_id) query.set('user_id', params.user_id);
    if (params?.start_date) query.set('start_date', params.start_date);
    if (params?.end_date) query.set('end_date', params.end_date);
    return this.request<PaginatedResponse<AuditLog>>(`/audit?${query}`);
  }

  // Users and Roles
  async getUsers(): Promise<User[]> {
    return this.request<User[]>('/users');
  }

  async getUser(id: string): Promise<User> {
    return this.request<User>(`/users/${id}`);
  }

  async createUser(data: { email: string; username: string; password: string; role_id?: string }): Promise<User> {
    return this.request<User>('/users', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateUser(id: string, data: Partial<User>): Promise<User> {
    return this.request<User>(`/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async deleteUser(id: string): Promise<void> {
    await this.request(`/users/${id}`, { method: 'DELETE' });
  }

  async getRoles(): Promise<Role[]> {
    return this.request<Role[]>('/roles');
  }

  async assignRole(userId: string, roleId: string): Promise<void> {
    await this.request(`/users/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role_id: roleId }),
    });
  }

  // API Keys
  async getApiKeys(): Promise<ApiKey[]> {
    return this.request<ApiKey[]>('/api-keys');
  }

  async createApiKey(data: { name: string; permissions: string[]; expires_at?: string }): Promise<{ key: string; api_key: ApiKey }> {
    return this.request('/api-keys', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async revokeApiKey(id: string): Promise<void> {
    await this.request(`/api-keys/${id}`, { method: 'DELETE' });
  }

  // Reports
  async getVulnerabilityReport(): Promise<VulnerabilityReport> {
    return this.request<VulnerabilityReport>('/reports/vulnerabilities');
  }

  async getComplianceReport(): Promise<ComplianceReport> {
    return this.request<ComplianceReport>('/reports/compliance');
  }

  async getTrendData(params?: { days?: number }): Promise<{
    dates: string[];
    vulnerabilities: number[];
    packages: number[];
  }> {
    const query = params?.days ? `?days=${params.days}` : '';
    return this.request(`/reports/trends${query}`);
  }

  // Notifications
  async getNotificationSettings(): Promise<NotificationSettings> {
    return this.request<NotificationSettings>('/notifications/settings');
  }

  async updateNotificationSettings(data: Partial<NotificationSettings>): Promise<NotificationSettings> {
    return this.request<NotificationSettings>('/notifications/settings', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // Health check
  async health(): Promise<{ status: string; version: string }> {
    return this.request('/health');
  }
}

export const api = new ApiClient(API_URL);
export default api;
