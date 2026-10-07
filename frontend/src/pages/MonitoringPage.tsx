import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function MonitoringPage() {
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [status, setStatus] = useState<any | null>(null);
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
    api.getMonitoringStatus(selectedProjectId)
      .then(setStatus)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [selectedProjectId]);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>📡</span> Continuous Supply Chain Monitoring
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Real-time advisory sync, periodic manifest re-evaluation, and automated drift detection
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
      ) : !status ? (
        <div className="card text-center py-16 text-gray-400">
          Monitoring state not available.
        </div>
      ) : (
        <div className="space-y-6">
          {/* Status Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="card p-4">
              <span className="text-xs text-gray-500 uppercase tracking-wider block">Service State</span>
              <span className="text-base font-bold text-green-400 mt-1 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                {status.status_label}
              </span>
              <span className="text-[11px] text-gray-400 mt-1 block">Daemon background runner</span>
            </div>

            <div className="card p-4">
              <span className="text-xs text-gray-500 uppercase tracking-wider block">Last Verification</span>
              <span className="text-xs font-mono text-white mt-1 block truncate">
                {status.last_scan_at ? status.last_scan_at.split('.')[0] : 'None'}
              </span>
              <span className="text-[11px] text-gray-400 mt-1 block">Total Scans: {status.total_scans}</span>
            </div>

            <div className="card p-4">
              <span className="text-xs text-gray-500 uppercase tracking-wider block">Monitored Ecosystems</span>
              <span className="text-sm font-semibold text-white mt-1 block">
                {status.monitored_ecosystems.join(', ') || 'npm / pypi'}
              </span>
              <span className="text-[11px] text-gray-400 mt-1 block">Live OSV Intelligence feed</span>
            </div>

            <div className="card p-4">
              <span className="text-xs text-gray-500 uppercase tracking-wider block">Enforced Policies</span>
              <span className="text-base font-bold text-sentinel-accent mt-1 block">
                {status.active_policies} Active Policy Gate
              </span>
              <span className="text-[11px] text-gray-400 mt-1 block">Production Tier Protection</span>
            </div>
          </div>

          {/* Real Security Event Stream */}
          <div className="card p-0 overflow-hidden border border-sentinel-border">
            <div className="p-4 bg-sentinel-card/80 border-b border-sentinel-border flex items-center justify-between">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span>⚡</span> Security Event Stream ({status.recent_events?.length || 0})
              </h2>
              <span className="text-xs text-gray-400 font-mono">Backend Audit Sync</span>
            </div>

            {(!status.recent_events || status.recent_events.length === 0) ? (
              <div className="p-8 text-center text-gray-500 text-xs">
                No recent security monitoring events recorded.
              </div>
            ) : (
              <div className="divide-y divide-sentinel-border/40">
                {status.recent_events.map((evt: any, idx: number) => {
                  const details = typeof evt.details === 'string' ? JSON.parse(evt.details) : evt.details;
                  return (
                    <div key={idx} className="p-4 hover:bg-sentinel-card/40 transition-colors flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            evt.action.includes('completed') ? 'bg-green-500/20 text-green-400' :
                            evt.action.includes('started') ? 'bg-blue-500/20 text-blue-400' :
                            'bg-gray-500/20 text-gray-300'
                          }`}>
                            {evt.action.replace(/_/g, ' ')}
                          </span>
                          <span className="text-xs font-mono text-gray-400">{evt.resource_type}: {evt.id}</span>
                        </div>
                        {details && (
                          <p className="text-xs text-gray-300 font-mono">
                            {details.risk_score !== undefined && `Score: ${details.risk_score} pts (${details.risk_level}) · Findings: ${details.findings_count} · Policy: ${details.policy_decision}`}
                            {details.input_type && `Input: ${details.input_type} · Hash: ${details.sbom_hash?.slice(0, 12)}...`}
                          </p>
                        )}
                      </div>
                      <span className="text-xs font-mono text-gray-500 shrink-0">
                        {evt.created_at ? evt.created_at.split('.')[0] : ''}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
