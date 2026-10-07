import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useNavigate } from 'react-router-dom';

export default function DependenciesPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [components, setComponents] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'ALL' | 'DIRECT' | 'TRANSITIVE'>('ALL');

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
    api.getDependencies(selectedProjectId)
      .then(res => {
        const rawComps = (res.nodes || []).map((n: any) => n.data).filter((c: any) => c.scope !== 'root');
        setComponents(rawComps);
      })
      .catch(console.error);

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

  const directCount = components.filter(c => c.is_direct).length;
  const transitiveCount = components.filter(c => !c.is_direct).length;

  const displayedComponents = components.filter(c => {
    if (tab === 'DIRECT') return c.is_direct;
    if (tab === 'TRANSITIVE') return !c.is_direct;
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>📦</span> Dependencies Catalog
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Complete inventory of direct and transitive libraries evaluated by the deterministic engine
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedProjectId}
            onChange={e => handleProjectSelect(e.target.value)}
            className="input-field py-1.5 px-3 text-sm max-w-xs"
          >
            {projects.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <button onClick={() => navigate('/graph')} className="btn-secondary text-xs py-2 px-3 flex items-center gap-1.5">
            <span>🕸️</span> Open Graph View
          </button>
        </div>
      </div>

      {/* KPI Tiers */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider block">Total Components</span>
          <span className="text-2xl font-bold text-white mt-1 block">{components.length}</span>
          <span className="text-[11px] text-gray-400 mt-1 block">Active Manifest Inventory</span>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider block">Direct Dependencies</span>
          <span className="text-2xl font-bold text-blue-400 mt-1 block">{directCount}</span>
          <span className="text-[11px] text-gray-400 mt-1 block">Explicitly Declared in Manifest</span>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider block">Transitive Dependencies</span>
          <span className="text-2xl font-bold text-purple-400 mt-1 block">{transitiveCount}</span>
          <span className="text-[11px] text-gray-400 mt-1 block">Sub-dependencies Resolved</span>
        </div>
        <div className="card p-4">
          <span className="text-xs text-gray-500 uppercase tracking-wider block">Vulnerable Dependencies</span>
          <span className="text-2xl font-bold text-red-400 mt-1 block">
            {components.filter(c => c.severity).length}
          </span>
          <span className="text-[11px] text-gray-400 mt-1 block">Packages with Active Findings</span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-2 border-b border-sentinel-border pb-2">
        {(['ALL', 'DIRECT', 'TRANSITIVE'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-xs font-semibold rounded-lg transition-colors ${
              tab === t ? 'bg-sentinel-accent text-white' : 'text-gray-400 hover:text-white'
            }`}
          >
            {t} ({t === 'ALL' ? components.length : t === 'DIRECT' ? directCount : transitiveCount})
          </button>
        ))}
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex justify-center py-16">
          <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
        </div>
      ) : displayedComponents.length === 0 ? (
        <div className="card text-center py-12 text-gray-400 text-sm">
          No dependencies found in selected scope.
        </div>
      ) : (
        <div className="card p-0 overflow-hidden border border-sentinel-border">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-sentinel-card/80 border-b border-sentinel-border text-gray-400 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4 font-semibold">Package Name</th>
                  <th className="py-3 px-4 font-semibold">Version</th>
                  <th className="py-3 px-4 font-semibold">Scope</th>
                  <th className="py-3 px-4 font-semibold">Ecosystem</th>
                  <th className="py-3 px-4 font-semibold">Associated Findings</th>
                  <th className="py-3 px-4 font-semibold">Risk Posture</th>
                  <th className="py-3 px-4 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/40 text-gray-300">
                {displayedComponents.map((c, idx) => {
                  const compFindings = findings.filter(f => f.component_purl === c.id || f.component_name?.toLowerCase() === c.name?.toLowerCase());
                  return (
                    <tr key={idx} className="hover:bg-sentinel-card/40 transition-colors">
                      <td className="py-3 px-4 font-semibold text-white">
                        {c.name}
                      </td>
                      <td className="py-3 px-4 font-mono text-gray-200">
                        {c.version || 'unpinned'}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          c.is_direct ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'
                        }`}>
                          {c.is_direct ? 'Direct' : 'Transitive'}
                        </span>
                      </td>
                      <td className="py-3 px-4 uppercase font-semibold text-gray-400">
                        {c.ecosystem || 'npm'}
                      </td>
                      <td className="py-3 px-4">
                        {compFindings.length > 0 ? (
                          <span className="text-amber-400 font-semibold">
                            {compFindings.length} issue(s) detected
                          </span>
                        ) : (
                          <span className="text-gray-500">0 issues</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {c.severity ? (
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            c.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                            c.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                            'bg-yellow-500/20 text-yellow-400'
                          }`}>
                            {c.severity}
                          </span>
                        ) : (
                          <span className="text-green-400 text-[11px] font-semibold">Clean</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <button
                          onClick={() => navigate(`/simulator?purl=${encodeURIComponent(c.id)}`)}
                          className="text-xs text-sentinel-accent hover:underline font-medium"
                        >
                          Simulate Change →
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
