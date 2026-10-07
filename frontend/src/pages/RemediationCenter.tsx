import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useNavigate } from 'react-router-dom';
import EvidenceModal from '../components/EvidenceModal';

export default function RemediationCenter() {
  const navigate = useNavigate();
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

  const actionableFindings = findings.filter(f => f.severity in { CRITICAL: 1, HIGH: 1, MEDIUM: 1, MODERATE: 1 });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>🛠️</span> Remediation Center
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Prioritized remediation actions, verified patch targets, and non-breaking version guidance
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              window.dispatchEvent(
                new CustomEvent('open-ai-analyst', {
                  detail: {
                    projectId: selectedProjectId,
                    mode: 'prioritize',
                    question: 'Which finding should I fix first and what is the remediation roadmap?',
                  },
                })
              );
            }}
            className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600/30 to-cyan-600/30 hover:from-blue-600/50 hover:to-cyan-600/50 border border-cyan-500/50 text-cyan-300 hover:text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm shadow-cyan-500/10 transition-all cursor-pointer"
          >
            <span>🤖</span>
            <span>AI Remediation Roadmap</span>
          </button>

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
      </div>

      {loading ? (
        <div className="flex justify-center py-24">
          <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
        </div>
      ) : actionableFindings.length === 0 ? (
        <div className="card text-center py-16 text-gray-400 space-y-2">
          <span className="text-4xl block">✨</span>
          <p className="font-semibold text-white">Zero High-Priority Fixes Required</p>
          <p className="text-xs text-gray-500">
            No critical or high severity vulnerabilities require immediate patching in this project.
          </p>
        </div>
      ) : (
        <div className="card p-0 overflow-hidden border border-sentinel-border">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-sentinel-card/80 border-b border-sentinel-border text-gray-400 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4 font-semibold">Package</th>
                  <th className="py-3 px-4 font-semibold">Current</th>
                  <th className="py-3 px-4 font-semibold">Recommended Fix</th>
                  <th className="py-3 px-4 font-semibold">Priority</th>
                  <th className="py-3 px-4 font-semibold">Risk Contribution</th>
                  <th className="py-3 px-4 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/40 text-gray-300">
                {actionableFindings.map((f, i) => {
                  const rem = f.remediation || {};
                  const fixed = f.evidence?.fixed_versions || [];
                  const targetVer = rem.target_version || (fixed.length > 0 ? fixed[0] : null);
                  return (
                    <tr key={i} className="hover:bg-sentinel-card/40 transition-colors">
                      <td className="py-3 px-4">
                        <span className="font-bold text-white block">{f.component_name}</span>
                        <span className="text-[10px] text-gray-500 font-mono">{f.cve_id || f.title}</span>
                      </td>
                      <td className="py-3 px-4 font-mono text-amber-400">
                        {f.evidence?.version || 'Installed'}
                      </td>
                      <td className="py-3 px-4">
                        {targetVer ? (
                          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-green-500/20 text-green-300 border border-green-500/30">
                            Upgrade to ≥ {targetVer}
                          </span>
                        ) : (
                          <span className="text-gray-400">
                            {rem.recommended_action || 'Review dependency alternative'}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'
                        }`}>
                          {rem.priority || (f.severity === 'CRITICAL' ? 'Immediate' : 'Planned')}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono font-semibold text-white">
                        +{f.score || 0} pts
                      </td>
                      <td className="py-3 px-4 space-x-2">
                        <button
                          onClick={() => {
                            window.dispatchEvent(
                              new CustomEvent('open-ai-analyst', {
                                detail: {
                                  projectId: selectedProjectId,
                                  findingId: f.id,
                                  finding: f,
                                  mode: 'remediate',
                                  question: `How do I remediate ${f.component_name} (${f.cve_id || f.title})?`,
                                },
                              })
                            );
                          }}
                          className="px-2 py-1 rounded bg-cyan-950/30 hover:bg-cyan-900/50 border border-cyan-500/40 text-cyan-300 hover:text-white text-[11px] font-semibold inline-flex items-center gap-1 transition-all"
                          title="Generate AI Fix Plan & Shell Commands"
                        >
                          <span>🤖</span> Fix Plan
                        </button>
                        <button
                          onClick={() => setSelectedFinding(f)}
                          className="btn-secondary text-[11px] py-1 px-2.5"
                        >
                          Evidence
                        </button>
                        <button
                          onClick={() => navigate(`/simulator?purl=${encodeURIComponent(f.component_purl)}&target=${targetVer || ''}`)}
                          className="btn-primary text-[11px] py-1 px-2.5"
                        >
                          Simulate →
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

      {selectedFinding && (
        <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
