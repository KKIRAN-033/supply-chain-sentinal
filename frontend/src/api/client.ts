/** API client for Supply-Chain Sentinel backend. */

const RAW_API_URL = (import.meta.env.VITE_API_URL || '').trim();
const API_BASE = RAW_API_URL
  ? (RAW_API_URL.endsWith('/api/v1') ? RAW_API_URL : `${RAW_API_URL.replace(/\/$/, '')}/api/v1`)
  : '/api/v1';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const apiKey = localStorage.getItem('sentinel_api_key') || '';
  const authToken = localStorage.getItem('sentinel_auth_token') || '';
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }
  const res = await fetch(url, {
    headers,
    ...options,
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({ message: res.statusText }));
    const errorMsg = (typeof error.detail === 'string' ? error.detail : error.detail?.message) || error.message || `API error ${res.status}`;
    throw new Error(errorMsg);
  }

  return res.json();
}

export const api = {
  // Auth
  login: (data: { username: string; password: string }) =>
    request<{ access_token: string; token_type: string; expires_in: number; user: any }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  getMe: () => request<any>('/auth/me'),
  logout: () => request<any>('/auth/logout', { method: 'POST' }),

  // Projects
  listProjects: () => request<any[]>('/projects'),
  createProject: (data: { name: string; repo_url?: string; environment?: string; criticality?: string }) =>
    request<any>('/projects', { method: 'POST', body: JSON.stringify(data) }),
  getProject: (id: string) => request<any>(`/projects/${id}`),
  getProjectManifests: (projectId: string) => request<{manifests: {name: string, path: string, format: string, download_url: string}[]}>(`/projects/${projectId}/manifests`),
  getProjectManifestContent: (projectId: string, path: string) => request<{path: string, format: string, content: string}>(`/projects/${projectId}/manifest-content?path=${encodeURIComponent(path)}`),
  getManifestsFromUrl: (repoUrl: string) => request<{repo_url: string, manifests: {name: string, path: string, format: string, download_url: string}[]}>(`/projects/manifests-from-url?repo_url=${encodeURIComponent(repoUrl)}`),
  getManifestContentFromUrl: (repoUrl: string, path: string) => request<{path: string, format: string, content: string}>(`/projects/manifest-content-from-url?repo_url=${encodeURIComponent(repoUrl)}&path=${encodeURIComponent(path)}`),
  getOrCreateProjectByRepo: (data: { name?: string; repo_url: string; environment?: string; criticality?: string }) =>
    request<any>('/projects/by-repo', { method: 'POST', body: JSON.stringify(data) }),

  // Scans
  createScan: (projectId: string, data: { input_type?: string; ecosystem?: string; raw_content: string; source?: string }) =>
    request<{ scan_id: string; status: string; created_at: string }>(
      `/projects/${projectId}/scans`,
      { method: 'POST', body: JSON.stringify(data) },
    ),
  getScanStatus: (scanId: string) => request<any>(`/scans/${scanId}/status`),
  getScanReport: (scanId: string) => request<any>(`/scans/${scanId}/report`),
  getScanFindings: (scanId: string) => request<any[]>(`/scans/${scanId}/findings`),
  getScanDiff: (scanId: string, baseScanId?: string) =>
    request<any>(`/scans/${scanId}/diff${baseScanId ? `?base_scan_id=${baseScanId}` : ''}`),
  compareScans: (scanId: string, baseScanId: string) => request<any>(`/scans/${scanId}/compare/${baseScanId}`),
  getScanExplain: (scanId: string) => request<any>(`/scans/${scanId}/explain`),
  getScanRaw: (scanId: string) => request<{raw_content: string}>(`/scans/${scanId}/raw`),

  // Risk History
  getRiskHistory: (projectId: string) => request<any[]>(`/projects/${projectId}/risk-history`),

  // Dependencies
  getDependencies: (projectId: string) => request<any>(`/projects/${projectId}/dependencies`),

  // Policies
  getPolicies: (projectId: string) => request<any[]>(`/projects/${projectId}/policies`),
  createPolicy: (projectId: string, data: { name: string; environment: string; rules: Record<string, any> }) =>
    request<any>(`/projects/${projectId}/policies`, { method: 'POST', body: JSON.stringify(data) }),
  generateAIPolicy: (projectId: string, data?: { environment?: string; criticality?: string }) =>
    request<any>(`/projects/${projectId}/policies/ai-generate`, { method: 'POST', body: JSON.stringify(data || {}) }),
  deletePolicy: (projectId: string, policyId: string) =>
    request<any>(`/projects/${projectId}/policies/${policyId}`, { method: 'DELETE' }),

  // Audit Logs
  listAuditLogs: (orgId?: string, limit: number = 100, projectId?: string) =>
    request<any[]>(`/audit-logs?limit=${limit}${orgId ? `&org_id=${encodeURIComponent(orgId)}` : ''}${projectId ? `&project_id=${encodeURIComponent(projectId)}` : ''}`),

  // What-If Simulator
  simulateRemediation: (scanId: string, data: { action: string; component_purl: string; target_version?: string }) =>
    request<any>(`/scans/${scanId}/simulate`, { method: 'POST', body: JSON.stringify(data) }),

  // Attack Paths
  getAttackPaths: (scanId: string) =>
    request<{ paths: any[]; total_paths: number }>(`/scans/${scanId}/attack-paths`),

  // Continuous Monitoring
  getMonitoringStatus: (projectId: string) =>
    request<any>(`/monitoring/${projectId}/status`),

  // Unified AI Security Analyst
  analyzeAI: (data: {
    project_id: string;
    scan_id?: string;
    finding_id?: string;
    component_purl?: string;
    question?: string;
    mode?: string;
  }) => request<any>('/ai/analyze', { method: 'POST', body: JSON.stringify(data) }),

  getSuggestedQuestions: (projectId: string, findingId?: string) =>
    request<{ id: string; text: string; mode: string }[]>(
      `/ai/suggested-questions?project_id=${encodeURIComponent(projectId)}${findingId ? `&finding_id=${encodeURIComponent(findingId)}` : ''}`
    ),
};



