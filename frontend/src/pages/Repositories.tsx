import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useNavigate } from 'react-router-dom';

export default function Repositories() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listProjects()
      .then(setProjects)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>📦</span> Connected Repositories
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Source code repositories and package manifests registered for supply chain analysis
          </p>
        </div>
        <button onClick={() => navigate('/upload')} className="btn-primary flex items-center gap-2">
          <span>➕</span> Connect Repository / Scan
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center py-20">
          <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
        </div>
      ) : projects.length === 0 ? (
        <div className="card text-center py-16 space-y-3">
          <span className="text-5xl block">📂</span>
          <h2 className="text-lg font-bold text-white">No Repositories Connected</h2>
          <p className="text-gray-400 text-sm max-w-md mx-auto">
            Connect a GitHub repository or upload a manifest to start continuous dependency tracking.
          </p>
        </div>
      ) : (
        <div className="grid gap-4">
          {projects.map(p => (
            <div key={p.id} className="card p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 flex items-center justify-center text-lg">
                    🐙
                  </div>
                  <div>
                    <h3 className="text-white font-bold text-base flex items-center gap-2">
                      {p.name}
                      <span className="text-xs font-mono font-normal text-gray-500">({p.id})</span>
                    </h3>
                    {p.repo_url && p.repo_url.startsWith('http') ? (
                      <a
                        href={p.repo_url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-xs text-sentinel-accent hover:underline font-mono"
                      >
                        {p.repo_url}
                      </a>
                    ) : (
                      <span className="text-xs text-gray-500 font-mono">
                        {p.repo_url || 'No git remote URL specified'}
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 text-xs rounded uppercase font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    {p.environment}
                  </span>
                  <span className={`px-2.5 py-1 text-xs rounded uppercase font-semibold ${
                    p.criticality === 'critical' ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-gray-500/10 text-gray-400'
                  }`}>
                    {p.criticality} tier
                  </span>
                  <button
                    onClick={() => navigate(`/upload?project=${p.id}`)}
                    className="btn-secondary text-xs py-1.5 px-3"
                  >
                    Scan Manifest
                  </button>
                </div>
              </div>

              {/* Status Details */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-3 border-t border-sentinel-border/50 text-xs text-gray-400">
                <div>
                  <span className="block text-gray-500 uppercase tracking-wider text-[10px]">Active Webhook</span>
                  <span className="text-green-400 font-semibold flex items-center gap-1 mt-0.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span> Listening (/api/v1/webhooks/github)
                  </span>
                </div>
                <div>
                  <span className="block text-gray-500 uppercase tracking-wider text-[10px]">Default Branch</span>
                  <span className="text-white font-mono mt-0.5 block">main</span>
                </div>
                <div>
                  <span className="block text-gray-500 uppercase tracking-wider text-[10px]">Ecosystems / Formats</span>
                  <span className="text-white mt-0.5 block">
                    {Array.from(new Set((p.scans || []).map((s: any) => s.input_format).filter(Boolean))).join(', ') || 'Auto-detect on scan'}
                  </span>
                </div>
                <div>
                  <span className="block text-gray-500 uppercase tracking-wider text-[10px]">Security Audit Policy</span>
                  <span className="text-sentinel-accent mt-0.5 block">{p.criticality === 'critical' ? 'Strict Critical-Tier Policy' : 'Production Build Gate'}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
