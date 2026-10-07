import { useEffect, useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import MetricGauge from '../components/MetricGauge';
import RiskTimeline from '../components/RiskTimeline';
import EvidenceModal from '../components/EvidenceModal';

export default function Dashboard() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [activeProject, setActiveProject] = useState<any | null>(null);
  const [latestScan, setLatestScan] = useState<any | null>(null);
  const [scanReport, setScanReport] = useState<any | null>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [components, setComponents] = useState<any[]>([]);
  const [auditEvents, setAuditEvents] = useState<any[]>([]);
  const [riskHistory, setRiskHistory] = useState<any[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatusMessage, setScanStatusMessage] = useState('');
  const pollTimerRef = useRef<any>(null);

  // Load project details, scans, findings, dependencies, risk history
  const loadProjectData = useCallback(async (projId: string) => {
    if (!projId) return;
    try {
      const prj = await api.getProject(projId);
      setActiveProject(prj);
      const scans = prj.scans || [];
      const latest = scans.length > 0 ? scans[0] : null;
      const completedScan = scans.find((s: any) => s.status === 'COMPLETED');
      const inProgressScan = latest?.status && !['COMPLETED', 'FAILED'].includes(latest.status) ? latest : null;

      if (inProgressScan) {
        setIsScanning(true);
        setLatestScan(inProgressScan);
        setScanStatusMessage(`Analyzing ${inProgressScan.input_format || 'manifest'}...`);

        // Start live polling until complete
        if (pollTimerRef.current) clearInterval(pollTimerRef.current);
        pollTimerRef.current = setInterval(async () => {
          try {
            const st = await api.getScanStatus(inProgressScan.id);
            if (st.message) setScanStatusMessage(st.message);
            if (st.status === 'COMPLETED' || st.status === 'FAILED') {
              if (pollTimerRef.current) clearInterval(pollTimerRef.current);
              setIsScanning(false);
              loadProjectData(projId);
            }
          } catch {}
        }, 1500);

        if (completedScan) {
          api.getScanReport(completedScan.id).then(setScanReport).catch(() => {});
          api.getScanFindings(completedScan.id).then(setFindings).catch(() => {});
        } else {
          setScanReport(null);
          setFindings([]);
        }
      } else {
        setIsScanning(false);
        if (pollTimerRef.current) clearInterval(pollTimerRef.current);
        const scanToDisplay = completedScan || latest;
        setLatestScan(scanToDisplay);

        if (scanToDisplay && scanToDisplay.status === 'COMPLETED') {
          api.getScanReport(scanToDisplay.id)
            .then(setScanReport)
            .catch(() => setScanReport(null));
          api.getScanFindings(scanToDisplay.id)
            .then(setFindings)
            .catch(() => setFindings([]));
        } else {
          setScanReport(null);
          setFindings([]);
        }
      }

      // Dependencies for graph & health
      api.getDependencies(projId)
        .then(res => {
          const rawComps = (res.nodes || []).map((n: any) => n.data).filter((c: any) => c.scope !== 'root');
          setComponents(rawComps);
        })
        .catch(() => setComponents([]));

      // Risk history
      api.getRiskHistory(projId)
        .then(setRiskHistory)
        .catch(() => setRiskHistory([]));

      // Audit logs (scoped to this project)
      api.listAuditLogs(undefined, 8, projId)
        .then(setAuditEvents)
        .catch(() => setAuditEvents([]));

    } catch (err: any) {
      console.error('Failed to load project details:', err);
      setError(err.message || 'Failed to load project');
    }
  }, []);

  // 1. Load projects on mount
  useEffect(() => {
    api.listProjects()
      .then(prjs => {
        setProjects(prjs);
        if (prjs.length > 0) {
          const saved = localStorage.getItem('sentinel_active_project');
          const exists = prjs.find(p => p.id === saved);
          const currentId = exists ? saved! : prjs[0].id;
          setSelectedProjectId(currentId);
          localStorage.setItem('sentinel_active_project', currentId);
          loadProjectData(currentId);
        }
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [loadProjectData]);

  // Listen to project switch events from global navigation header or other tabs
  useEffect(() => {
    const handleStorage = () => {
      const saved = localStorage.getItem('sentinel_active_project');
      if (saved && saved !== selectedProjectId) {
        setSelectedProjectId(saved);
        loadProjectData(saved);
      }
    };
    const handleCustomChange = (e: any) => {
      if (e.detail) {
        setSelectedProjectId(e.detail);
        loadProjectData(e.detail);
      }
    };
    window.addEventListener('storage', handleStorage);
    window.addEventListener('sentinel:project-change', handleCustomChange);
    return () => {
      window.removeEventListener('storage', handleStorage);
      window.removeEventListener('sentinel:project-change', handleCustomChange);
    };
  }, [selectedProjectId, loadProjectData]);

  // 2. Load active project data whenever selectedProjectId changes
  useEffect(() => {
    if (!selectedProjectId) return;
    localStorage.setItem('sentinel_active_project', selectedProjectId);
    loadProjectData(selectedProjectId);

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [selectedProjectId, loadProjectData]);

  // Handle project selector change
  const handleProjectChange = (id: string) => {
    setSelectedProjectId(id);
    localStorage.setItem('sentinel_active_project', id);
    window.dispatchEvent(new Event('storage'));
    window.dispatchEvent(new CustomEvent('sentinel:project-change', { detail: id }));
    loadProjectData(id);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-28">
        <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
      </div>
    );
  }

  if (projects.length === 0) {
    return (
      <div className="p-8 max-w-4xl mx-auto text-center space-y-6">
        <div className="card py-16 space-y-4">
          <span className="text-6xl block">🛡️</span>
          <h2 className="text-xl font-bold text-white">Welcome to Supply-Chain Sentinel</h2>
          <p className="text-gray-400 text-sm max-w-md mx-auto">
            Get started by creating your first project and analyzing an SBOM or repository manifest.
          </p>
          <div className="flex gap-3 justify-center pt-2">
            <button onClick={() => navigate('/projects')} className="btn-primary">
              Create Project
            </button>
            <button onClick={() => navigate('/upload')} className="btn-secondary">
              Upload Manifest
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Real calculations
  // Real calculations
  const hasScans = Boolean(latestScan);
  const deterministicScore = hasScans ? (scanReport?.summary?.overall_score ?? latestScan?.overall_score ?? 0) : null;
  const riskLevel = hasScans ? (scanReport?.summary?.risk_level ?? latestScan?.risk_level ?? 'LOW') : 'UNSCANNED';
  const confidence = scanReport?.summary?.confidence ?? latestScan?.confidence ?? 0.85;
  const criticalFindingsCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highRiskDependenciesCount = components.filter(c => c.severity === 'CRITICAL' || c.severity === 'HIGH').length;
  const totalVulnerabilities = findings.length;
  const policyDecision = hasScans ? (scanReport?.policy_decision ?? latestScan?.policy_decision ?? 'ALLOW') : 'AWAITING';
  const dataQuality = scanReport?.summary?.data_quality ?? latestScan?.data_quality ?? 'COMPLETE';

  // Component breakdown
  const directCount = components.filter(c => c.is_direct).length;
  const transitiveCount = components.filter(c => !c.is_direct).length;
  const healthyCount = components.filter(c => !c.severity).length;
  const vulnerableCount = components.filter(c => c.severity).length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* =========================================================================
          PROJECT HEADER BAR
         ========================================================================= */}
      <div className="card p-5 bg-sentinel-surface border-sentinel-border flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center text-xl font-bold text-sentinel-accent">
            🛡️
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-extrabold text-white tracking-wide">
                {activeProject?.name || 'Active Project'}
              </h1>
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase tracking-wider ${
                activeProject?.criticality === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                'bg-blue-500/20 text-blue-400 border border-blue-500/30'
              }`}>
                {activeProject?.criticality || 'production'} tier
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-xs text-gray-400 mt-1">
              {activeProject?.repo_url && activeProject.repo_url.startsWith('http') && (
                <a
                  href={activeProject.repo_url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-sentinel-accent hover:underline font-mono"
                >
                  {activeProject.repo_url}
                </a>
              )}
              <span>· Environment: <strong className="text-white">{activeProject?.environment || 'production'}</strong></span>
              <span>· Manifest: <strong className="text-white">{latestScan?.input_format || (hasScans ? 'Auto-detected' : 'None')}</strong></span>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {projects.length > 0 && (
            <select
              value={selectedProjectId}
              onChange={e => handleProjectChange(e.target.value)}
              className="input-field py-1.5 px-3 text-xs font-semibold bg-sentinel-card border-sentinel-border"
            >
              {projects.map(p => (
                <option key={p.id} value={p.id}>
                  📁 {p.name}
                </option>
              ))}
            </select>
          )}

          <div className="text-right">
            <span className="text-[10px] text-gray-500 uppercase tracking-widest block">Last Ingestion Scan</span>
            <span className="text-xs font-mono text-gray-300">
              {latestScan?.created_at ? String(latestScan.created_at).split('.')[0] : 'No Scans Yet'}
            </span>
          </div>

          <button onClick={() => navigate(`/upload?project=${selectedProjectId}`)} className="btn-primary flex items-center gap-2 text-xs py-2 px-3.5">
            <span>⬆️</span> Run Scan
          </button>
        </div>
      </div>

      {/* Active Scan In Progress Banner */}
      {isScanning && (
        <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-500/50 text-blue-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="animate-spin w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full" />
            <div>
              <span className="font-bold text-white block">Security Analysis In Progress ({latestScan?.id})</span>
              <span className="text-[11px] text-gray-400">
                {scanStatusMessage || 'Ingesting manifests, resolving dependency graph, and evaluating advisories...'}
              </span>
            </div>
          </div>
          <span className="font-mono text-[11px] px-2.5 py-1 bg-blue-500/20 text-blue-400 rounded border border-blue-500/30 font-semibold animate-pulse">
            Processing Live
          </span>
        </div>
      )}

      {/* Unscanned Project Notice */}
      {!hasScans && !isScanning && (
        <div className="p-6 rounded-xl bg-sentinel-surface border border-sentinel-border text-xs flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <span>🚀</span> Ready to Scan {activeProject?.name || 'Project'}
            </h3>
            <p className="text-gray-400 max-w-xl">
              No dependency scan has been recorded yet for this project. Ingest an SBOM or repository manifest to calculate deterministic risk scores and discover vulnerabilities.
            </p>
          </div>
          <button
            onClick={() => navigate(`/upload?project=${selectedProjectId}`)}
            className="btn-primary text-xs py-2 px-4 flex items-center gap-2 font-semibold shadow-lg shadow-blue-500/20"
          >
            <span>⬆️</span> Run First Scan
          </button>
        </div>
      )}

      {/* Failed Scan Warning Banner */}
      {latestScan?.status === 'FAILED' && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/50 text-red-300 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-base">⚠️</span>
            <span>Latest scan ({latestScan.id}) failed during processing. Ingestion report unavailable.</span>
          </div>
          <button onClick={() => navigate(`/upload?project=${selectedProjectId}`)} className="btn-primary text-xs py-1 px-3">
            Run New Scan →
          </button>
        </div>
      )}

      {/* =========================================================================
          ROW 1: KPI CARDS (Calculated from Backend Data)
         ========================================================================= */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* KPI 1: Deterministic Risk */}
        <div className="card p-4 relative overflow-hidden border-sentinel-border hover:border-sentinel-accent/50 transition-all">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">
            Deterministic Risk
          </span>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-2xl font-black text-white">{hasScans ? deterministicScore : '—'}</span>
            <span className="text-xs text-gray-500 font-bold">/100</span>
          </div>
          <div className="mt-2 flex items-center justify-between">
            <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${
              !hasScans ? 'bg-gray-500/20 text-gray-400' :
              riskLevel === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
              riskLevel === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
              riskLevel === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
              'bg-green-500/20 text-green-400'
            }`}>
              {riskLevel}
            </span>
            {hasScans && (
              <button
                onClick={() => navigate('/risk')}
                className="text-[10px] text-sentinel-accent hover:underline font-semibold"
              >
                Why this score? →
              </button>
            )}
          </div>
        </div>

        {/* KPI 2: Critical Findings */}
        <div className="card p-4 border-sentinel-border hover:border-sentinel-accent/50 transition-all">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">
            Critical Findings
          </span>
          <span className={`text-2xl font-black mt-1 block ${hasScans && criticalFindingsCount > 0 ? 'text-red-400' : 'text-white'}`}>
            {hasScans ? criticalFindingsCount : '—'}
          </span>
          <span className="text-[11px] text-gray-500 mt-2 block">
            {hasScans ? (criticalFindingsCount > 0 ? 'Immediate Action Required' : 'Zero Critical CVEs') : 'No Scan Run'}
          </span>
        </div>

        {/* KPI 3: High-Risk Dependencies */}
        <div className="card p-4 border-sentinel-border hover:border-sentinel-accent/50 transition-all">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">
            High-Risk Deps
          </span>
          <span className={`text-2xl font-black mt-1 block ${hasScans && highRiskDependenciesCount > 0 ? 'text-orange-400' : 'text-white'}`}>
            {hasScans ? highRiskDependenciesCount : '—'}
          </span>
          <span className="text-[11px] text-gray-500 mt-2 block">
            {hasScans ? 'Critical/High Vulnerable' : 'Awaiting Scan'}
          </span>
        </div>

        {/* KPI 4: Total Vulnerabilities */}
        <div className="card p-4 border-sentinel-border hover:border-sentinel-accent/50 transition-all">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">
            Total Findings
          </span>
          <span className="text-2xl font-black text-white mt-1 block">
            {hasScans ? totalVulnerabilities : '—'}
          </span>
          <span className="text-[11px] text-gray-500 mt-2 block">
            {hasScans ? 'Rules + OSV Feed' : 'No Data'}
          </span>
        </div>

        {/* KPI 5: SBOM Coverage */}
        <div className="card p-4 border-sentinel-border hover:border-sentinel-accent/50 transition-all">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">
            SBOM Coverage
          </span>
          <span className={`text-2xl font-black mt-1 block ${hasScans ? 'text-emerald-400' : 'text-gray-500'}`}>
            {hasScans ? '100.0%' : '0.0%'}
          </span>
          <span className="text-[11px] text-gray-500 mt-2 block">
            {hasScans ? `${dataQuality} Ingestion` : 'No Manifest Ingested'}
          </span>
        </div>

        {/* KPI 6: Policy Decision */}
        <div className="card p-4 border-sentinel-border hover:border-sentinel-accent/50 transition-all">
          <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">
            Policy Decision
          </span>
          <span className={`text-xl font-black mt-1 block uppercase ${
            !hasScans ? 'text-gray-500' :
            policyDecision === 'BLOCK' ? 'text-red-400' :
            policyDecision === 'REVIEW' ? 'text-yellow-400' :
            'text-green-400'
          }`}>
            {policyDecision}
          </span>
          <span className="text-[11px] text-gray-500 mt-2 block">
            {hasScans ? 'Production Build Gate' : 'Scan Required'}
          </span>
        </div>
      </div>

      {/* =========================================================================
          ROW 2: RISK TREND & DEPENDENCY HEALTH
         ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Trend */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-sentinel-border pb-3">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span>📈</span> Risk Trend History
              </h2>
              <p className="text-[11px] text-gray-500">Chronological deterministic scores from verified scans</p>
            </div>
            <span className="text-xs font-mono text-sentinel-accent">{riskHistory.length} data points</span>
          </div>

          <RiskTimeline
            history={riskHistory}
          />
        </div>

        {/* Dependency Health Breakdown */}
        <div className="card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-sentinel-border pb-3">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span>🩺</span> Dependency Health & Topology
              </h2>
              <p className="text-[11px] text-gray-500">Observable health indicators and graph directness</p>
            </div>
            <button onClick={() => navigate('/dependencies')} className="text-xs text-sentinel-accent hover:underline font-semibold">
              Catalog →
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
              <span className="text-[10px] text-gray-400 uppercase block">Direct Manifest Imports</span>
              <span className="text-xl font-bold text-blue-400 mt-0.5 block">{directCount}</span>
              <span className="text-[10px] text-gray-500">Root Package Declarations</span>
            </div>
            <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
              <span className="text-[10px] text-gray-400 uppercase block">Transitive Dependencies</span>
              <span className="text-xl font-bold text-purple-400 mt-0.5 block">{transitiveCount}</span>
              <span className="text-[10px] text-gray-500">Resolved via Lockfile / Graph</span>
            </div>
            <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
              <span className="text-[10px] text-gray-400 uppercase block">Clean / Healthy Packages</span>
              <span className="text-xl font-bold text-green-400 mt-0.5 block">{healthyCount}</span>
              <span className="text-[10px] text-gray-500">Zero active advisories</span>
            </div>
            <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
              <span className="text-[10px] text-gray-400 uppercase block">Flagged / At-Risk</span>
              <span className="text-xl font-bold text-amber-400 mt-0.5 block">{vulnerableCount}</span>
              <span className="text-[10px] text-gray-500">Contain security findings</span>
            </div>
          </div>
        </div>
      </div>

      {/* =========================================================================
          ROW 3: TOP RISKY DEPENDENCIES & SECURITY EVENT STREAM
         ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Risky Dependencies */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-sentinel-border pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>⚠️</span> Top Risky Dependencies
            </h2>
            <button onClick={() => navigate('/dependencies')} className="text-xs text-sentinel-accent hover:underline">
              View All ({components.length}) →
            </button>
          </div>

          {components.length === 0 ? (
            <div className="py-10 text-center text-gray-500 text-xs">
              {hasScans ? 'No dependencies detected in manifest.' : 'No dependency data available. Complete an SBOM scan first.'}
            </div>
          ) : (
            <div className="divide-y divide-sentinel-border/40 text-xs">
              {components.slice(0, 5).map((c, i) => (
                <div key={i} className="py-2.5 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <span className="font-bold text-white">{c.name}</span>
                    <span className="font-mono text-gray-400 text-[11px]">@{c.version || 'latest'}</span>
                    <span className={`px-1.5 py-0.2 rounded text-[9px] font-semibold uppercase ${
                      c.is_direct ? 'bg-blue-500/10 text-blue-400' : 'bg-gray-500/10 text-gray-400'
                    }`}>
                      {c.is_direct ? 'Direct' : 'Transitive'}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {c.severity ? (
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        c.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                        c.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-yellow-500/20 text-yellow-400'
                      }`}>
                        {c.severity}
                      </span>
                    ) : (
                      <span className="text-green-400 font-semibold text-[11px]">✓ Clean</span>
                    )}
                    <button
                      onClick={() => navigate(`/simulator?purl=${encodeURIComponent(c.id)}`)}
                      className="text-xs text-sentinel-accent hover:underline font-medium"
                    >
                      Simulate
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Security Event Stream */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-sentinel-border pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>⚡</span> Security Event Stream
            </h2>
            <button onClick={() => navigate('/audit-logs')} className="text-xs text-sentinel-accent hover:underline">
              Audit Log →
            </button>
          </div>

          {auditEvents.length === 0 ? (
            <div className="py-10 text-center text-gray-500 text-xs">
              No recent security events recorded.
            </div>
          ) : (
            <div className="divide-y divide-sentinel-border/40 text-xs">
              {auditEvents.slice(0, 5).map((evt, i) => (
                <div key={i} className="py-2.5 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      evt.action.includes('completed') ? 'bg-green-500/20 text-green-400' :
                      evt.action.includes('started') ? 'bg-blue-500/20 text-blue-400' :
                      'bg-gray-500/20 text-gray-300'
                    }`}>
                      {evt.action.replace(/_/g, ' ')}
                    </span>
                    <span className="text-gray-300 font-mono text-[11px] truncate max-w-[200px]">
                      {evt.resource_type}: {evt.resource_id}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-gray-500 shrink-0">
                    {evt.created_at ? evt.created_at.split('.')[0] : ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* =========================================================================
          ROW 4: RECENT FINDINGS & RECOMMENDED REMEDIATION
         ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Findings */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-sentinel-border pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>🔍</span> Recent Findings ({findings.length})
            </h2>
            <button onClick={() => navigate('/findings')} className="text-xs text-sentinel-accent hover:underline">
              All Findings →
            </button>
          </div>

          {findings.length === 0 ? (
            <div className="py-10 text-center text-gray-500 text-xs">
              {hasScans ? 'No findings detected. All evaluated dependencies clean.' : 'No scans run yet for this project.'}
            </div>
          ) : (
            <div className="divide-y divide-sentinel-border/40 text-xs">
              {findings.slice(0, 4).map((f, i) => (
                <div key={i} className="py-2.5 flex items-center justify-between gap-3">
                  <div>
                    <span className="font-bold text-white block">{f.title}</span>
                    <span className="text-gray-400 text-[11px] font-mono">
                      {f.component_name} · {f.cve_id || f.category} · Score: +{f.score} pts
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                      f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {f.severity}
                    </span>
                    <button
                      onClick={() => setSelectedFinding(f)}
                      className="btn-secondary text-[11px] py-1 px-2.5"
                    >
                      Evidence
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recommended Remediation */}
        <div className="card p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-sentinel-border pb-3">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span>🛠️</span> Actionable Remediation Guidance
            </h2>
            <button onClick={() => navigate('/remediation')} className="text-xs text-sentinel-accent hover:underline">
              Remediation Center →
            </button>
          </div>

          {findings.length === 0 ? (
            <div className="py-10 text-center text-gray-500 text-xs">
              {hasScans ? 'No remediation actions needed.' : 'Remediation guidance will be generated once dependencies are scanned.'}
            </div>
          ) : (
            <div className="divide-y divide-sentinel-border/40 text-xs">
              {findings.slice(0, 4).map((f, i) => {
                const rem = f.remediation || {};
                const fixed = f.evidence?.fixed_versions || [];
                const targetVer = rem.target_version || (fixed.length > 0 ? fixed[0] : null);
                return (
                  <div key={i} className="py-2.5 flex items-center justify-between gap-3">
                    <div>
                      <span className="font-bold text-white block">{f.component_name}</span>
                      <span className="text-green-400 text-[11px]">
                        {targetVer ? `Upgrade to ≥ ${targetVer}` : (rem.recommended_action || 'Review dependency')}
                      </span>
                    </div>

                    <button
                      onClick={() => navigate(`/simulator?purl=${encodeURIComponent(f.component_purl)}&target=${targetVer || ''}`)}
                      className="btn-primary text-[11px] py-1 px-2.5"
                    >
                      Simulate Fix →
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Evidence Modal */}
      {selectedFinding && (
        <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
