import { useEffect, useState } from 'react';
import { api } from '../api/client';
import EvidenceModal from '../components/EvidenceModal';

export default function AlertsPage() {
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [findings, setFindings] = useState<any[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
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
          const completed = prj.scans.find((s: any) => s.status === 'COMPLETED') || prj.scans[0];
          api.getScanFindings(completed.id)
            .then(setFindings)
            .catch(() => setFindings([]));
        } else {
          setFindings([]);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [selectedProjectId]);

  const alertItems = findings.filter(f => f.severity in { CRITICAL: 1, HIGH: 1, MEDIUM: 1, MODERATE: 1 });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>🚨</span> Active Security Alerts
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Real-time security notifications triggered by deterministic rules and vulnerability advisories
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
      ) : alertItems.length === 0 ? (
        <div className="card text-center py-16 text-gray-400 space-y-2">
          <span className="text-4xl block">🟢</span>
          <p className="font-semibold text-white">No Critical or High Alerts</p>
          <p className="text-xs text-gray-500">
            All dependencies are compliant with currently evaluated security thresholds.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {alertItems.map((f, i) => (
            <div
              key={i}
              className="card p-4 flex flex-wrap items-center justify-between gap-3 border hover:border-sentinel-accent/50 transition-all"
            >
              <div className="flex items-center gap-3">
                <span className={`px-2.5 py-1 text-xs font-bold rounded uppercase ${
                  f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                  f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                  'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                }`}>
                  {f.severity} ALERT
                </span>
                <div>
                  <h3 className="text-white font-bold text-sm flex items-center gap-2">
                    {f.title}
                  </h3>
                  <p className="text-xs text-gray-400 font-mono">
                    Package: {f.component_name} · Score Impact: +{f.score} pts · {f.cve_id || f.category}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setSelectedFinding(f)}
                  className="btn-secondary text-xs py-1.5 px-3"
                >
                  View Evidence →
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {selectedFinding && (
        <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
