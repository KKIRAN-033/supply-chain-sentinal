/** Core TypeScript types matching backend API contracts. */

export interface Project {
  id: string;
  name: string;
  repo_url?: string;
  environment: string;
  criticality: string;
  created_at: string;
  total_scans?: number;
  latest_scan?: ScanSummaryInfo;
}

export interface ScanSummaryInfo {
  id: string;
  status: string;
  overall_score?: number;
  risk_level?: string;
  created_at: string;
}

export interface ScanStatus {
  scan_id: string;
  status: string;
  progress: number;
  message: string;
  created_at: string;
  overall_score?: number;
  risk_level?: string;
  policy_decision?: string;
  error?: { code: string; message: string };
}

export interface ScanReport {
  scan_id: string;
  project_id: string;
  summary: ScanSummary;
  metrics_breakdown: MetricsBreakdown;
  policy_decision?: string;
  provenance?: ProvenanceInfo;
  explainability?: ExplainabilityInfo;
  findings: Finding[];
  components: ComponentInfo[];
  dependencies: DependencyEdge[];
}

export interface ProvenanceInfo {
  format?: string;
  sbom_hash?: string;
  spec_version?: string;
  serial_number?: string;
  tools?: string[];
  authors?: string[];
  timestamp?: string;
}

export interface ExplainabilityInfo {
  deterministic_summary: string;
  primary_risk_driver: string;
  confidence_assessment: string;
  policy_impact: string;
  recommendations: string[];
  llm_summary?: string | null;
  llm_status?: string;
}

export interface ScanDiff {
  base_scan_id: string | null;
  target_scan_id: string;
  base_score: number;
  target_score: number;
  risk_delta: number;
  counts: {
    resolved: number;
    new: number;
    still_open: number;
    base_total: number;
    target_total: number;
  };
  resolved_findings: Finding[];
  new_findings: Finding[];
  still_open_findings: Finding[];
}

export interface ScanSummary {
  overall_score: number | null;
  risk_level: string | null;
  confidence: number | null;
  data_quality: string;
  total_dependencies: number;
  vulnerable_count: number;
  suspicious_count: number;
  outdated_count: number;
}

export interface MetricsBreakdown {
  vulnerability: number;
  behavioral: number;
  typosquatting: number;
  health: number;
  reputation: number;
}

export interface Finding {
  id: string;
  scan_id?: string;
  project_id?: string;
  component_purl: string;
  component_name?: string;
  category: string;
  severity: string;
  score: number;
  confidence: number;
  title?: string;
  description?: string;
  cve_id?: string;
  evidence?: Record<string, unknown>;
  remediation?: RemediationInfo;
  is_suppressed: boolean;
}

export interface RemediationInfo {
  action?: string;
  reason?: string;
  recommended_action?: string;
  target_version?: string;
  verification?: string;
  priority?: string;
}

export interface ComponentInfo {
  purl: string;
  name: string;
  version: string;
  ecosystem: string;
  scope: string;
  is_direct: boolean;
  is_pinned?: boolean;
}

export interface DependencyEdge {
  parent: string;
  child: string;
}

export interface RiskHistoryEntry {
  scan_id: string;
  score: number;
  risk_level: string;
  confidence?: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  created_at: string;
}

export interface PolicyInfo {
  id: string;
  project_id: string;
  name: string;
  environment: string;
  rules: Record<string, string>;
  is_active: boolean;
}

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';
export type SeverityLevel = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';
export type PolicyDecision = 'ALLOW' | 'REVIEW' | 'BLOCK';
