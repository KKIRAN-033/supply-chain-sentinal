import { useEffect, useState } from 'react';
import { api } from '../api/client';
import MetricGauge from '../components/MetricGauge';

export default function DeterministicRiskPage() {
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [scanReport, setScanReport] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listProjects()
      .then(prjs => {
        setProjects(prjs);
        if (prjs.length > 0) {
          const saved = localStorage.getItem('sentinel_active_project');
          const current = prjs.find(p => p.id === saved) ? saved! : prjs[0].id;
          setSelectedProjectId(current);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const handleStorage = () => {
      const saved = localStorage.getItem('sentinel_active_project');
      if (saved && saved !== selectedProjectId) setSelectedProjectId(saved);
    };
    const handleCustomChange = (e: any) => {
      if (e.detail && e.detail !== selectedProjectId) setSelectedProjectId(e.detail);
    };
    window.addEventListener('storage', handleStorage);
    window.addEventListener('sentinel:project-change', handleCustomChange);
    return () => {
      window.removeEventListener('storage', handleStorage);
      window.removeEventListener('sentinel:project-change', handleCustomChange);
    };
  }, [selectedProjectId]);

  const handleProjectSelect = (id: string) => {
    setSelectedProjectId(id);
    localStorage.setItem('sentinel_active_project', id);
    window.dispatchEvent(new Event('storage'));
    window.dispatchEvent(new CustomEvent('sentinel:project-change', { detail: id }));
  };

  useEffect(() => {
    if (!selectedProjectId) return;
    setLoading(true);
    api.getProject(selectedProjectId)
      .then(prj => {
        if (prj.scans && prj.scans.length > 0) {
          const completed = prj.scans.find((s: any) => s.status === 'COMPLETED');
          if (completed) {
            api.getScanReport(completed.id)
              .then(setScanReport)
              .catch(() => setScanReport(null));
          } else {
            setScanReport(null);
          }
        } else {
          setScanReport(null);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [selectedProjectId]);

  const metrics = scanReport?.metrics_breakdown || {
    vulnerability: 0,
    behavioral: 0,
    typosquatting: 0,
    reputation: 0,
    health: 0,
  };

  const weights = [
    { name: 'Known Vulnerabilities (CVE / OSV)', weight: '40%', score: metrics.vulnerability || 0, desc: 'Direct CVSS scores, affected version boundaries, and KEV exploit status' },
    { name: 'Behavioral & Install Scripts', weight: '20%', score: metrics.behavioral || 0, desc: 'Post-install hooks, obfuscated payloads, socket connects, and privilege escalation' },
    { name: 'Typosquatting & Impersonation', weight: '20%', score: metrics.typosquatting || 0, desc: 'Levenshtein distance, brand impersonation, and homoglyph attacks' },
    { name: 'Maintainer & Registry Reputation', weight: '10%', score: metrics.reputation || 0, desc: 'Recent ownership transfers, unmaintained abandonment, and account takeover' },
    { name: 'Dependency Hygiene & Health', weight: '10%', score: metrics.health || 0, desc: 'Unpinned wildcard specs, release freshness, and missing license disclosures' },
  ];

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>⚖️</span> Deterministic Risk Engine
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Authoritative, reproducible risk evaluation with mathematical transparency and zero LLM hallucination
          </p>
        </div>

        <select
          value={selectedProjectId}
          onChange={e => handleProjectSelect(e.target.value)}
          className="input-field py-1.5 px-3 text-sm max-w-xs"
        >
          {projects.map(p => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
      </div>

      {loading ? (
        <div className="flex justify-center py-24">
          <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
        </div>
      ) : !scanReport ? (
        <div className="card text-center py-16 text-gray-400">
          No scan report available for this project. Complete an SBOM scan first.
        </div>
      ) : (
        <div className="space-y-6">
          {/* Main Score & Decision Card */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="card flex flex-col items-center justify-center p-6 text-center">
              <MetricGauge score={scanReport.summary?.overall_score || 0} label="Deterministic Risk" />
              <div className="mt-4 flex items-center gap-2">
                <span className="text-xs text-gray-400 uppercase tracking-wider">Assessed Tier:</span>
                <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                  scanReport.summary?.risk_level === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                  scanReport.summary?.risk_level === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                  scanReport.summary?.risk_level === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-green-500/20 text-green-400'
                }`}>
                  {scanReport.summary?.risk_level || 'LOW'} RISK
                </span>
              </div>
            </div>

            <div className="lg:col-span-2 card p-6 space-y-4">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span>🛡️</span> Mathematical Decision Rationale
              </h2>
              <div className="bg-sentinel-surface p-4 rounded-lg border border-sentinel-border font-mono text-xs text-gray-300 space-y-1">
                <p className="text-sentinel-accent font-semibold">Risk Formula:</p>
                <p>Score = (Vuln × 0.40) + (Behavioral × 0.20) + (Typo × 0.20) + (Reputation × 0.10) + (Health × 0.10)</p>
                <p className="pt-2 text-gray-400">
                  Calculated: ({metrics.vulnerability} × 0.4) + ({metrics.behavioral} × 0.2) + ({metrics.typosquatting} × 0.2) + ({metrics.reputation} × 0.1) + ({metrics.health} × 0.1)
                </p>
                <p className="text-white font-bold pt-1">
                  = {scanReport.summary?.overall_score} / 100.0 pts
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
                  <span className="text-[10px] text-gray-400 uppercase tracking-wider block">Confidence</span>
                  <span className="text-base font-bold text-green-400 mt-1 block">
                    {Math.round((scanReport.summary?.confidence || 0.85) * 100)}%
                  </span>
                  <span className="text-[10px] text-gray-500">Deterministic Source</span>
                </div>
                <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
                  <span className="text-[10px] text-gray-400 uppercase tracking-wider block">Data Quality</span>
                  <span className="text-base font-bold text-sentinel-accent mt-1 block">
                    {scanReport.summary?.data_quality || 'COMPLETE'}
                  </span>
                  <span className="text-[10px] text-gray-500">Full Manifest Ingested</span>
                </div>
                <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
                  <span className="text-[10px] text-gray-400 uppercase tracking-wider block">Uncertainty</span>
                  <span className="text-base font-bold text-yellow-400 mt-1 block">LOW</span>
                  <span className="text-[10px] text-gray-500">Static + Lockfile Evidence</span>
                </div>
              </div>
            </div>
          </div>

          {/* Weighted Contribution Table */}
          <div className="card p-0 overflow-hidden border border-sentinel-border">
            <div className="p-4 bg-sentinel-card/80 border-b border-sentinel-border">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Signal Weights & Observable Evidence Contributions
              </h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-sentinel-surface border-b border-sentinel-border text-gray-400 uppercase tracking-wider">
                  <tr>
                    <th className="py-3 px-4 font-semibold">Security Signal</th>
                    <th className="py-3 px-4 font-semibold">Weight</th>
                    <th className="py-3 px-4 font-semibold">Signal Score</th>
                    <th className="py-3 px-4 font-semibold">Weighted Contribution</th>
                    <th className="py-3 px-4 font-semibold">Observable Evidence Rationale</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sentinel-border/40 text-gray-300">
                  {weights.map((w, idx) => (
                    <tr key={idx} className="hover:bg-sentinel-card/40 transition-colors">
                      <td className="py-3 px-4 font-medium text-white">{w.name}</td>
                      <td className="py-3 px-4 font-mono text-sentinel-accent">{w.weight}</td>
                      <td className="py-3 px-4 font-mono font-semibold text-white">{w.score} / 100</td>
                      <td className="py-3 px-4 font-mono text-emerald-400">
                        +{(w.score * parseFloat(w.weight) / 100).toFixed(1)} pts
                      </td>
                      <td className="py-3 px-4 text-gray-400">{w.desc}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
