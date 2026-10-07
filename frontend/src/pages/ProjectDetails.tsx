import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import MetricGauge from '../components/MetricGauge';
import RiskTimeline from '../components/RiskTimeline';
import DependencyGraph from '../components/DependencyGraph';

export default function ProjectDetails() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const [project, setProject] = useState<any>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [deps, setDeps] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState<any[]>([]);

  useEffect(() => {
    if (!projectId) return;
    Promise.all([
      api.getProject(projectId),
      api.getRiskHistory(projectId),
      api.getDependencies(projectId),
    ])
      .then(([proj, hist, depData]) => {
        setProject(proj);
        setHistory(hist);
        setDeps(depData);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [projectId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
      </div>
    );
  }

  if (!project) {
    return (
      <div className="p-6 text-center">
        <p className="text-red-400">Project not found</p>
      </div>
    );
  }

  const latest = project.latest_scan;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{project.name}</h1>
          <div className="flex gap-3 text-xs text-gray-500 mt-1">
            <span>📌 {project.environment}</span>
            <span>⚡ {project.criticality}</span>
            {project.repo_url && <span className="text-blue-400/60">🔗 {project.repo_url}</span>}
          </div>
        </div>
        <div className="flex gap-3">
          <button onClick={() => navigate('/upload')} className="btn-primary">New Scan</button>
          {latest && <button onClick={() => navigate(`/scan/${latest.id}`)} className="btn-secondary">View Latest</button>}
        </div>
      </div>

      {/* Risk overview */}
      {latest ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="card flex justify-center">
            <MetricGauge score={latest.overall_score ?? 0} />
          </div>
          <div className="lg:col-span-2">
            <RiskTimeline history={history} />
          </div>
        </div>
      ) : (
        <div className="card text-center py-12">
          <span className="text-4xl mb-4 block">🔍</span>
          <p className="text-gray-400">No scans completed yet</p>
          <button onClick={() => navigate('/upload')} className="btn-primary mt-4">Upload SBOM to scan</button>
        </div>
      )}

      {/* Dependency Graph */}
      <DependencyGraph nodes={deps.nodes || []} edges={deps.edges || []} />

      {/* Scan History Table */}
      {history.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Scan History</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 uppercase tracking-wider">
                  <th className="text-left px-4 py-2">Scan</th>
                  <th className="text-left px-4 py-2">Score</th>
                  <th className="text-left px-4 py-2">Level</th>
                  <th className="text-left px-4 py-2">Findings</th>
                  <th className="text-left px-4 py-2">Critical</th>
                  <th className="text-left px-4 py-2">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border">
                {history.map((h, i) => (
                  <tr
                    key={h.scan_id}
                    onClick={() => navigate(`/scan/${h.scan_id}`)}
                    className="hover:bg-sentinel-surface cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-2 font-mono text-xs text-blue-400">{h.scan_id}</td>
                    <td className="px-4 py-2 font-bold">{h.score?.toFixed(1)}</td>
                    <td className="px-4 py-2">
                      <span className={`badge ${h.risk_level === 'CRITICAL' ? 'badge-critical' : h.risk_level === 'HIGH' ? 'badge-high' : h.risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>
                        {h.risk_level}
                      </span>
                    </td>
                    <td className="px-4 py-2">{h.total_findings}</td>
                    <td className="px-4 py-2 text-red-400">{h.critical_count}</td>
                    <td className="px-4 py-2 text-gray-500 text-xs">{new Date(h.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
