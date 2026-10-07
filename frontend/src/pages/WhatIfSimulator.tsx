import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useSearchParams } from 'react-router-dom';

export default function WhatIfSimulator() {
  const [searchParams] = useSearchParams();
  const initialPurl = searchParams.get('purl') || '';
  const initialTarget = searchParams.get('target') || '';

  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [components, setComponents] = useState<any[]>([]);
  const [activeScanId, setActiveScanId] = useState<string>('');

  // Simulation form
  const [selectedPurl, setSelectedPurl] = useState<string>(initialPurl);
  const [action, setAction] = useState<'upgrade' | 'remove'>('upgrade');
  const [targetVersion, setTargetVersion] = useState<string>(initialTarget);

  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<any | null>(null);
  const [error, setError] = useState<string>('');

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
      .catch(console.error);
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
    api.getProject(selectedProjectId)
      .then(prj => {
        if (prj.scans && prj.scans.length > 0) {
          const completed = prj.scans.find((s: any) => s.status === 'COMPLETED') || prj.scans[0];
          setActiveScanId(completed.id);
        } else {
          setActiveScanId('');
        }
      })
      .catch(console.error);

    api.getDependencies(selectedProjectId)
      .then(res => {
        const rawComps = (res.nodes || []).map((n: any) => n.data).filter((c: any) => c.scope !== 'root');
        setComponents(rawComps);
        if (!selectedPurl && rawComps.length > 0) {
          setSelectedPurl(rawComps[0].id);
        }
      })
      .catch(console.error);
  }, [selectedProjectId]);

  const handleSimulate = async () => {
    if (!activeScanId || !selectedPurl) return;
    setSimulating(true);
    setError('');
    try {
      const res = await api.simulateRemediation(activeScanId, {
        action,
        component_purl: selectedPurl,
        target_version: action === 'upgrade' ? targetVersion : undefined,
      });
      setSimResult(res);
    } catch (e: any) {
      setError(e.message || 'Simulation failed');
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>🔮</span> What-If Deterministic Simulator
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Simulate dependency upgrades and removals to forecast risk posture before modifying code
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Controls Card */}
        <div className="card p-6 space-y-5 lg:col-span-1">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <span>⚙️</span> Simulation Parameters
          </h2>

          <div className="space-y-2">
            <label className="text-xs text-gray-400 uppercase tracking-wider block">Target Component</label>
            <select
              value={selectedPurl}
              onChange={e => setSelectedPurl(e.target.value)}
              className="input-field text-xs py-2"
            >
              {components.map((c, i) => (
                <option key={i} value={c.id}>
                  {c.name} {c.version ? `@${c.version}` : ''} {c.severity ? `[${c.severity}]` : ''}
                </option>
              ))}
            </select>
          </div>

          <div className="space-y-2">
            <label className="text-xs text-gray-400 uppercase tracking-wider block">Action</label>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setAction('upgrade')}
                className={`py-2 text-xs font-semibold rounded-lg border transition-all ${
                  action === 'upgrade'
                    ? 'bg-sentinel-accent text-white border-sentinel-accent'
                    : 'bg-sentinel-card text-gray-400 border-sentinel-border hover:text-white'
                }`}
              >
                Upgrade
              </button>
              <button
                type="button"
                onClick={() => setAction('remove')}
                className={`py-2 text-xs font-semibold rounded-lg border transition-all ${
                  action === 'remove'
                    ? 'bg-red-500/20 text-red-300 border-red-500/50'
                    : 'bg-sentinel-card text-gray-400 border-sentinel-border hover:text-white'
                }`}
              >
                Remove
              </button>
            </div>
          </div>

          {action === 'upgrade' && (
            <div className="space-y-2">
              <label className="text-xs text-gray-400 uppercase tracking-wider block">
                Target Safe Version (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. 4.19.2"
                value={targetVersion}
                onChange={e => setTargetVersion(e.target.value)}
                className="input-field text-xs py-2 font-mono"
              />
              <span className="text-[11px] text-gray-500 block">
                Leave blank to simulate resolving all known advisory versions.
              </span>
            </div>
          )}

          <button
            onClick={handleSimulate}
            disabled={simulating || !activeScanId}
            className="btn-primary w-full py-2.5 text-xs font-semibold uppercase tracking-wider flex items-center justify-center gap-2"
          >
            {simulating ? 'Calculating Deterministic Impact...' : '▶ Run Simulation'}
          </button>

          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>

        {/* Results Card */}
        <div className="card p-6 lg:col-span-2 space-y-6">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <span>📊</span> Projected Risk Impact
          </h2>

          {!simResult ? (
            <div className="py-20 text-center text-gray-500 space-y-2">
              <span className="text-4xl block">⚡</span>
              <p className="text-sm">Select a component and click "Run Simulation" to model projected risk.</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Score Comparison Row */}
              <div className="grid grid-cols-3 gap-4 text-center">
                <div className="bg-sentinel-surface p-4 rounded-lg border border-sentinel-border">
                  <span className="text-xs text-gray-400 block uppercase tracking-wider">Current Risk</span>
                  <span className="text-3xl font-bold text-white mt-1 block">
                    {simResult.original_score}
                  </span>
                  <span className="text-[10px] text-gray-500">Baseline Score</span>
                </div>

                <div className="bg-sentinel-surface p-4 rounded-lg border border-sentinel-border">
                  <span className="text-xs text-gray-400 block uppercase tracking-wider">Projected Risk</span>
                  <span className="text-3xl font-bold text-sentinel-accent mt-1 block">
                    {simResult.projected_score}
                  </span>
                  <span className="text-[10px] text-green-400 uppercase font-semibold">
                    {simResult.projected_risk_level}
                  </span>
                </div>

                <div className="bg-sentinel-surface p-4 rounded-lg border border-sentinel-border">
                  <span className="text-xs text-gray-400 block uppercase tracking-wider">Risk Delta</span>
                  <span className={`text-3xl font-bold mt-1 block ${simResult.risk_delta < 0 ? 'text-green-400' : 'text-gray-300'}`}>
                    {simResult.risk_delta > 0 ? `+${simResult.risk_delta}` : simResult.risk_delta} pts
                  </span>
                  <span className="text-[10px] text-gray-500">
                    {simResult.risk_delta < 0 ? 'Improvement' : 'Unchanged'}
                  </span>
                </div>
              </div>

              {/* Explanation Banner */}
              <div className="p-4 rounded-lg bg-sentinel-accent/10 border border-sentinel-accent/30 text-xs text-sentinel-accent-glow leading-relaxed">
                <p className="font-semibold text-white mb-1">Deterministic Model Result:</p>
                {simResult.explanation}
              </div>

              {/* Mitigated Findings */}
              <div className="space-y-2">
                <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider">
                  Findings Mitigated ({simResult.mitigated_count})
                </h3>
                {simResult.mitigated_findings.length === 0 ? (
                  <p className="text-xs text-gray-500 italic">No existing findings on this component were eliminated.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {simResult.mitigated_findings.map((item: string, i: number) => (
                      <li key={i} className="text-xs text-green-300 flex items-center gap-2">
                        <span>✓</span> {item}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
