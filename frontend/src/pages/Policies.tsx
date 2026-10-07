import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function Policies() {
  const [projects, setProjects] = useState<any[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState('');
  const [policies, setPolicies] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [isGeneratingAI, setIsGeneratingAI] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    name: '',
    environment: 'production',
    critical: 'BLOCK',
    high: 'REVIEW',
    medium: 'ALLOW',
    low: 'ALLOW',
  });

  const selectedProject = projects.find(p => p.id === selectedProjectId);

  useEffect(() => {
    api.listProjects().then(data => {
      setProjects(data || []);
      if (data && data.length > 0) {
        const saved = localStorage.getItem('sentinel_active_project');
        const current = data.find(p => p.id === saved) ? saved! : data[0].id;
        setSelectedProjectId(current);
      }
    }).catch(() => {});
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

  const fetchPolicies = async (projectId: string) => {
    if (!projectId) return;
    setLoading(true);
    try {
      const data = await api.getPolicies(projectId);
      setPolicies(data || []);
    } catch {
      setPolicies([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedProjectId) {
      fetchPolicies(selectedProjectId);
    }
  }, [selectedProjectId]);

  const handleGenerateAI = async () => {
    if (!selectedProjectId) return;
    setIsGeneratingAI(true);
    try {
      await api.generateAIPolicy(selectedProjectId);
      await fetchPolicies(selectedProjectId);
    } catch {
      alert('Failed to generate AI policy');
    } finally {
      setIsGeneratingAI(false);
    }
  };

  const handleDeletePolicy = async (policyId: string) => {
    if (!confirm('Are you sure you want to delete this policy?')) return;
    try {
      await api.deletePolicy(selectedProjectId, policyId);
      await fetchPolicies(selectedProjectId);
    } catch {
      alert('Failed to delete policy');
    }
  };

  const handleCreateManual = async () => {
    if (!selectedProjectId || !form.name) return;
    try {
      await api.createPolicy(selectedProjectId, {
        name: form.name,
        environment: form.environment,
        rules: {
          CRITICAL: form.critical,
          HIGH: form.high,
          MEDIUM: form.medium,
          LOW: form.low,
        },
      });
      setShowCreate(false);
      setForm({
        name: '',
        environment: 'production',
        critical: 'BLOCK',
        high: 'REVIEW',
        medium: 'ALLOW',
        low: 'ALLOW',
      });
      await fetchPolicies(selectedProjectId);
    } catch {
      alert('Failed to create policy');
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-white">Security Policies</h1>
            <span className="badge bg-purple-500/20 text-purple-400 border border-purple-500/30 text-xs">
              🤖 AI Policy Engine
            </span>
          </div>
          <p className="text-sm text-gray-400 mt-1">
            Automated supply chain risk gates, enforcement rules, and compliance guardrails tailored to your project.
          </p>
        </div>

        {selectedProjectId && (
          <div className="flex items-center gap-2.5">
            <button
              onClick={handleGenerateAI}
              disabled={isGeneratingAI}
              className="bg-gradient-to-r from-purple-600 via-indigo-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white font-medium px-4 py-2 rounded-lg text-sm flex items-center gap-2 shadow-lg shadow-purple-500/20 transition-all border border-purple-400/30 disabled:opacity-50"
            >
              {isGeneratingAI ? (
                <>
                  <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full" />
                  Synthesizing AI Policy...
                </>
              ) : (
                <>
                  ✨ Generate AI Policy
                </>
              )}
            </button>
            <button
              onClick={() => setShowCreate(!showCreate)}
              className="btn-secondary text-sm"
            >
              {showCreate ? 'Cancel' : '+ Custom Policy'}
            </button>
          </div>
        )}
      </div>

      {/* Project Selector & Context Card */}
      <div className="card space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-center">
          <div>
            <label className="text-xs text-gray-400 uppercase tracking-wider block mb-1.5 font-semibold">
              Select Project
            </label>
            <select
              value={selectedProjectId}
              onChange={e => handleProjectSelect(e.target.value)}
              className="input-field"
            >
              {projects.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name} {p.environment ? `(${p.environment})` : ''}
                </option>
              ))}
            </select>
          </div>

          {selectedProject && (
            <div className="md:col-span-2 flex flex-wrap items-center gap-2 pt-2 md:pt-4 text-xs">
              <span className="text-gray-400">Context:</span>
              <span className="px-2.5 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300">
                Tier: <b className="text-white capitalize">{selectedProject.environment || 'production'}</b>
              </span>
              <span className="px-2.5 py-1 rounded bg-red-500/10 border border-red-500/30 text-red-300">
                Criticality: <b className="uppercase">{selectedProject.criticality || 'critical'}</b>
              </span>
              {selectedProject.repo_url && (
                <span className="px-2.5 py-1 rounded bg-blue-500/10 border border-blue-500/30 text-blue-300 truncate max-w-xs">
                  Repo: {selectedProject.repo_url.replace('https://github.com/', '')}
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Manual Create Form */}
      {showCreate && (
        <div className="card border-purple-500/30 bg-purple-950/10 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-white font-semibold flex items-center gap-2">
              🛠️ Create Custom Policy
            </h3>
            <span className="text-xs text-gray-400">Manual rule specification</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-gray-400 uppercase block mb-1">Policy Name</label>
              <input
                placeholder="e.g. Production Strict Gate"
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                className="input-field"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 uppercase block mb-1">Environment Tier</label>
              <select
                value={form.environment}
                onChange={e => setForm({ ...form, environment: e.target.value })}
                className="input-field"
              >
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {(['critical', 'high', 'medium', 'low'] as const).map(level => (
              <div key={level}>
                <label className="text-xs text-gray-400 uppercase block mb-1 font-semibold">{level}</label>
                <select
                  value={form[level]}
                  onChange={e => setForm({ ...form, [level]: e.target.value })}
                  className="input-field text-sm"
                >
                  <option value="BLOCK">🛑 BLOCK</option>
                  <option value="REVIEW">⚠️ REVIEW</option>
                  <option value="ALLOW">✅ ALLOW</option>
                </select>
              </div>
            ))}
          </div>
          <div className="flex gap-3 justify-end pt-2">
            <button onClick={() => setShowCreate(false)} className="btn-secondary text-xs">
              Cancel
            </button>
            <button onClick={handleCreateManual} className="btn-primary text-xs">
              Save Policy
            </button>
          </div>
        </div>
      )}

      {/* Loading */}
      {loading ? (
        <div className="card flex items-center justify-center py-12">
          <div className="flex items-center gap-3 text-purple-400">
            <div className="animate-spin w-5 h-5 border-2 border-purple-400 border-t-transparent rounded-full" />
            <span>Loading policies...</span>
          </div>
        </div>
      ) : policies.length === 0 ? (
        <div className="card text-center py-12 space-y-4 border border-dashed border-gray-700">
          <div className="text-4xl">🛡️</div>
          <div>
            <h3 className="text-lg font-semibold text-white">No Policy Configured</h3>
            <p className="text-sm text-gray-400 max-w-md mx-auto mt-1">
              There is currently no active security policy for <b className="text-white">{selectedProject?.name}</b>.
              Synthesize a tailored AI policy based on its critical production profile.
            </p>
          </div>
          <button
            onClick={handleGenerateAI}
            disabled={isGeneratingAI}
            className="bg-purple-600 hover:bg-purple-500 text-white font-medium px-5 py-2.5 rounded-lg text-sm inline-flex items-center gap-2 shadow-lg shadow-purple-600/20"
          >
            ✨ Synthesize AI Policy for {selectedProject?.name}
          </button>
        </div>
      ) : (
        /* Policies List */
        <div className="space-y-6">
          {policies.map(p => {
            const rules = p.rules || {};
            const isAI = rules.ai_generated;
            const rationale = rules.ai_rationale;
            const guardrails = rules.guardrails || [];
            const sla = rules.sla_days || {};
            const compliance = rules.compliance || [];

            return (
              <div
                key={p.id}
                className="card space-y-5 border border-gray-800 hover:border-gray-700 transition-colors shadow-lg"
              >
                {/* Policy Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-gray-800">
                  <div className="flex items-center gap-3 flex-wrap">
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                      {isAI && <span className="text-purple-400">✨</span>}
                      {p.name}
                    </h3>
                    <span className="badge bg-purple-500/10 text-purple-300 border border-purple-500/30 uppercase text-[11px] font-semibold">
                      {p.environment}
                    </span>
                    {isAI && (
                      <span className="badge bg-indigo-500/10 text-indigo-300 border border-indigo-500/30 text-[11px]">
                        AI Synthesized
                      </span>
                    )}
                    <span className="badge bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[11px]">
                      Active Gate
                    </span>
                  </div>

                  <button
                    onClick={() => handleDeletePolicy(p.id)}
                    className="text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 px-2.5 py-1 rounded transition-colors self-start sm:self-auto"
                    title="Delete Policy"
                  >
                    🗑️ Remove
                  </button>
                </div>

                {/* Gate Decision Matrix */}
                <div>
                  <label className="text-xs font-semibold text-gray-400 uppercase tracking-wider block mb-2">
                    Automated Pipeline Gate Matrix
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(lvl => {
                      const dec = rules[lvl] || 'ALLOW';
                      const badgeClass =
                        dec === 'BLOCK'
                          ? 'bg-red-500/15 border-red-500/40 text-red-400'
                          : dec === 'REVIEW'
                          ? 'bg-amber-500/15 border-amber-500/40 text-amber-400'
                          : 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400';
                      const icon = dec === 'BLOCK' ? '🛑' : dec === 'REVIEW' ? '⚠️' : '✅';

                      return (
                        <div key={lvl} className="bg-gray-900/60 border border-gray-800 rounded-lg p-3 text-center">
                          <span className="text-xs font-mono text-gray-400 block mb-1">{lvl}</span>
                          <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-bold border ${badgeClass}`}>
                            {icon} {dec}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* AI Rationale Panel */}
                {rationale && (
                  <div className="bg-gradient-to-r from-purple-950/20 via-gray-900/60 to-indigo-950/20 border border-purple-500/20 rounded-lg p-4 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-purple-300 flex items-center gap-1.5">
                        🤖 AI Security Policy Rationale
                      </span>
                      {rules.ai_model && (
                        <span className="text-[10px] text-gray-400 font-mono">
                          Synthesizer: {rules.ai_model}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-gray-300 leading-relaxed whitespace-pre-line space-y-2">
                      {rationale}
                    </div>
                  </div>
                )}

                {/* Guardrails & SLAs */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
                  {guardrails.length > 0 && (
                    <div className="bg-gray-900/40 rounded-lg p-3 border border-gray-800/80 space-y-2">
                      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
                        🛡️ Active Security Guardrails
                      </span>
                      <ul className="space-y-1.5 text-xs text-gray-300">
                        {guardrails.map((g: string, idx: number) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="text-blue-400 mt-0.5">•</span>
                            <span>{g}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="space-y-3">
                    {Object.keys(sla).length > 0 && (
                      <div className="bg-gray-900/40 rounded-lg p-3 border border-gray-800/80 space-y-2">
                        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
                          ⏱️ Remediation SLAs
                        </span>
                        <div className="grid grid-cols-4 gap-2 text-center text-xs">
                          {Object.entries(sla).map(([lvl, days]) => (
                            <div key={lvl} className="bg-gray-800/50 rounded p-1.5 border border-gray-700/50">
                              <span className="text-[10px] text-gray-400 block">{lvl}</span>
                              <span className="font-bold text-white">{days as number}d</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {compliance.length > 0 && (
                      <div className="bg-gray-900/40 rounded-lg p-3 border border-gray-800/80 space-y-1.5">
                        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider block">
                          📜 Compliance Frameworks
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {compliance.map((c: string, idx: number) => (
                            <span key={idx} className="text-[11px] px-2 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-300">
                              {c}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
