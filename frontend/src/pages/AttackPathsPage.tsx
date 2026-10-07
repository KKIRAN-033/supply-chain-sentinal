import { useEffect, useState } from 'react';
import { api } from '../api/client';
import EvidenceModal from '../components/EvidenceModal';

export default function AttackPathsPage() {
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [attackPaths, setAttackPaths] = useState<any[]>([]);
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
          const scanId = completed.id;
          api.getAttackPaths(scanId)
            .then(res => setAttackPaths(res.paths || []))
            .catch(() => setAttackPaths([]));

          api.getScanFindings(scanId)
            .then(setFindings)
            .catch(() => setFindings([]));
        } else {
          setAttackPaths([]);
          setFindings([]);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [selectedProjectId]);

  const handleInspectFinding = (path: any) => {
    const f = findings.find(x => x.component_purl === path.target_purl || x.title === path.title);
    if (f) {
      setSelectedFinding(f);
    } else {
      setSelectedFinding({
        title: path.title,
        component_name: path.target_component,
        component_purl: path.target_purl,
        severity: path.severity,
        score: path.score,
        cve_id: path.cve_id,
        evidence: { exploitability: 'Active in Dependency Chain' }
      });
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>⚡</span> Dependency Attack Paths
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Reachable supply-chain traversal chains from application root down to affected libraries
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
      ) : attackPaths.length === 0 ? (
        <div className="card text-center py-16 text-gray-400 space-y-2">
          <span className="text-4xl block">🛡️</span>
          <p className="font-semibold text-white">No Transitive Attack Chains Identified</p>
          <p className="text-xs text-gray-500 max-w-md mx-auto">
            All installed libraries are either direct dependencies or contain zero known reachable vulnerabilities.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>Found {attackPaths.length} deterministic attack paths:</span>
            <span>Sorted by risk contribution</span>
          </div>

          <div className="grid gap-4">
            {attackPaths.map((p, idx) => (
              <div key={idx} className="card p-5 space-y-4 border hover:border-sentinel-accent/50 transition-all">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase ${
                      p.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                      p.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                      'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                    }`}>
                      {p.severity}
                    </span>
                    <div>
                      <h3 className="text-white font-bold text-sm">{p.title}</h3>
                      <p className="text-xs text-gray-400 font-mono">{p.cve_id || p.target_purl}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <span className="text-xs text-gray-400">
                      Chain Depth: <strong className="text-white">{p.length} hop{p.length > 1 ? 's' : ''}</strong>
                    </span>
                    <button
                      onClick={() => handleInspectFinding(p)}
                      className="btn-secondary text-xs py-1.5 px-3"
                    >
                      Inspect Evidence →
                    </button>
                  </div>
                </div>

                {/* Path Visualizer */}
                <div className="bg-sentinel-surface p-4 rounded-lg border border-sentinel-border overflow-x-auto">
                  <div className="flex items-center gap-2 text-xs font-mono min-w-max">
                    <div className="px-3 py-1.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 font-semibold flex items-center gap-1.5">
                      <span>🚀</span> Application Root
                    </div>

                    {p.chain.map((step: any, sIdx: number) => (
                      <div key={sIdx} className="flex items-center gap-2">
                        <span className="text-gray-500 font-bold">➔</span>
                        <div className={`px-3 py-1.5 rounded font-semibold flex items-center gap-1.5 ${
                          sIdx === p.chain.length - 1
                            ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                            : 'bg-sentinel-card text-gray-300 border border-sentinel-border'
                        }`}>
                          <span>{sIdx === p.chain.length - 1 ? '⚠️' : '📦'}</span>
                          <span>{step.name}</span>
                          {step.version && <span className="text-gray-500 text-[10px]">@{step.version}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Evidence Modal */}
      {selectedFinding && (
        <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
