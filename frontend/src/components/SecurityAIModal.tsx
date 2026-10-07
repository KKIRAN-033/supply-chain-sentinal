import React, { useState, useEffect } from 'react';
import { api } from '../api/client';

export interface SecurityAIContext {
  projectId: string;
  scanId?: string;
  findingId?: string;
  finding?: any;
  componentPurl?: string;
  initialQuestion?: string;
  initialMode?: string;
}

interface SecurityAIModalProps {
  isOpen: boolean;
  onClose: () => void;
  context: SecurityAIContext;
  onSelectFinding?: (findingId: string) => void;
}

export default function SecurityAIModal({
  isOpen,
  onClose,
  context,
}: SecurityAIModalProps) {
  const [question, setQuestion] = useState('');
  const [suggestedQuestions, setSuggestedQuestions] = useState<
    { id: string; text: string; mode: string }[]
  >([]);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  // Fetch suggested questions whenever context changes
  useEffect(() => {
    if (!isOpen || !context.projectId) return;

    api
      .getSuggestedQuestions(context.projectId, context.findingId)
      .then((res) => setSuggestedQuestions(res))
      .catch(() => setSuggestedQuestions([]));

    // Auto-trigger analysis if context specified initial question or finding
    if (context.initialQuestion || context.findingId) {
      handleAnalyze(context.initialQuestion, context.initialMode || (context.findingId ? 'explain' : 'risk'));
    } else {
      // Default to general overview
      handleAnalyze(undefined, 'risk');
    }
  }, [isOpen, context.projectId, context.findingId]);

  const handleAnalyze = async (q?: string, mode?: string) => {
    if (!context.projectId) return;
    setLoading(true);
    setError(null);

    try {
      const payload: any = {
        project_id: context.projectId,
        scan_id: context.scanId,
        finding_id: context.findingId,
        component_purl: context.componentPurl || context.finding?.component_purl,
        question: q || (question.trim() ? question.trim() : undefined),
        mode: mode || 'auto',
      };

      const res = await api.analyzeAI(payload);
      setAnalysisResult(res);
      if (q) setQuestion('');
    } catch (err: any) {
      console.error('AI Analysis failed:', err);
      setError(err.message || 'Failed to query AI Security Analyst');
    } finally {
      setLoading(false);
    }
  };

  const handleCopyCommand = (cmd: string, index: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  if (!isOpen) return null;

  const finding = context.finding;
  const sol = analysisResult?.recommended_solution;
  const impact = analysisResult?.risk_impact;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/75 backdrop-blur-md animate-fadeIn">
      <div className="bg-sentinel-surface border border-sentinel-border rounded-2xl w-full max-w-4xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-sentinel-border flex items-center justify-between bg-sentinel-card/70 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-xl shadow-lg shadow-cyan-500/20">
              🤖
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white tracking-wide">
                  AI Security Analyst & Remediation Assistant
                </h2>
                <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  GROUNDED & DETERMINISTIC
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-0.5">
                {context.findingId ? (
                  <span>
                    Focusing on finding: <strong className="text-white font-mono">{finding?.component_name || context.findingId}</strong>
                    {finding?.cve_id && <span className="text-cyan-400 font-mono ml-1">({finding.cve_id})</span>}
                  </span>
                ) : (
                  <span>Project-level supply-chain intelligence & remediation planning</span>
                )}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-sentinel-card hover:bg-gray-800 text-gray-400 hover:text-white flex items-center justify-center text-base transition-colors"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Modal Content Scrollable Area */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
          {/* Quick Context & Status Badges */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-sentinel-card/40 border border-sentinel-border/70 text-xs">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="flex items-center gap-1.5 text-gray-300">
                <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                <span className="font-semibold text-gray-400 uppercase text-[10px] tracking-wider">Engine:</span>
                <strong className="text-white font-mono">{analysisResult?.provider || 'Authoritative Security Core'}</strong>
              </span>

              <span className="text-gray-600">|</span>

              <span className="flex items-center gap-1.5 text-gray-300">
                <span className="font-semibold text-gray-400 uppercase text-[10px] tracking-wider">Status:</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                  {analysisResult?.status_label || 'DETERMINISTIC RESULT + AI GUIDANCE'}
                </span>
              </span>
            </div>

            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
                {analysisResult?.verification_status || 'PENDING RE-SCAN'}
              </span>
            </div>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-500/50 text-red-300 text-xs flex items-center justify-between">
              <span>⚠️ {error}</span>
              <button
                onClick={() => handleAnalyze()}
                className="underline text-red-200 hover:text-white ml-3 font-semibold"
              >
                Retry
              </button>
            </div>
          )}

          {/* Loading Skeleton */}
          {loading && (
            <div className="space-y-4 py-8 text-center animate-pulse">
              <div className="w-10 h-10 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
              <p className="text-sm text-gray-300 font-semibold">Consulting Supply-Chain Sentinel Intelligence Core...</p>
              <p className="text-xs text-gray-500">Cross-referencing CVE feeds, blast radius metrics, and dependency graphs</p>
            </div>
          )}

          {/* Main Results View */}
          {!loading && analysisResult && (
            <div className="space-y-5">
              {/* Executive Answer Card */}
              <div className="p-4 sm:p-5 rounded-xl bg-gradient-to-r from-blue-950/40 via-cyan-950/30 to-sentinel-card border border-blue-500/40 shadow-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-widest flex items-center gap-1.5">
                    <span>💡</span> Executive Security Assessment
                  </span>
                  <span className="text-[10px] font-mono text-gray-400">
                    Confidence: <strong className="text-white">{analysisResult.confidence || 'HIGH'}</strong>
                  </span>
                </div>
                <h3 className="text-base sm:text-lg font-bold text-white leading-snug">
                  {analysisResult.answer}
                </h3>
              </div>

              {/* 4 Pillars Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Pillar 1: Authoritative Deterministic Result */}
                <div className="card p-4 space-y-3 border-amber-500/30 bg-sentinel-surface/80">
                  <div className="flex items-center justify-between border-b border-sentinel-border pb-2">
                    <span className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>⚖️</span> [DETERMINISTIC RESULT]
                    </span>
                    <span className="text-[10px] text-gray-500 font-mono">NON-MODIFIABLE</span>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-sentinel-border/40">
                      <span className="text-gray-400">Project Risk Score:</span>
                      <span className="font-mono font-bold text-white">
                        {impact?.score ?? '—'}/100 ({impact?.level ?? 'UNKNOWN'})
                      </span>
                    </div>

                    {finding && (
                      <>
                        <div className="flex justify-between py-1 border-b border-sentinel-border/40">
                          <span className="text-gray-400">Finding Severity:</span>
                          <span className={`font-bold px-1.5 py-0.2 rounded text-[10px] ${
                            finding.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                            finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                            'bg-yellow-500/20 text-yellow-400'
                          }`}>
                            {finding.severity}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-sentinel-border/40">
                          <span className="text-gray-400">CVSS / Base Score:</span>
                          <span className="font-mono text-gray-200">+{finding.score || 0} pts</span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-sentinel-border/40">
                          <span className="text-gray-400">CISA KEV Listed:</span>
                          <span className={`font-semibold ${finding.evidence?.is_kev ? 'text-red-400' : 'text-gray-300'}`}>
                            {finding.evidence?.is_kev ? 'YES (Active Exploits)' : 'NO'}
                          </span>
                        </div>
                      </>
                    )}

                    {impact?.contributors && impact.contributors.length > 0 && (
                      <div className="pt-1">
                        <span className="text-gray-400 block text-[11px] mb-1">Risk Contributors:</span>
                        <div className="space-y-1">
                          {impact.contributors.slice(0, 3).map((c: string, idx: number) => (
                            <div key={idx} className="font-mono text-[11px] text-gray-300 bg-sentinel-card p-1 rounded">
                              {c}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Pillar 2: AI Security Analysis */}
                <div className="card p-4 space-y-3 border-cyan-500/30 bg-sentinel-surface/80">
                  <div className="flex items-center justify-between border-b border-sentinel-border pb-2">
                    <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <span>🔍</span> [AI SECURITY ANALYSIS]
                    </span>
                    <span className="text-[10px] text-gray-500 font-mono">EXPLAINABILITY</span>
                  </div>

                  <div className="space-y-2.5 text-xs text-gray-300">
                    <div>
                      <strong className="text-white block mb-0.5 text-[11px] uppercase tracking-wide">What Happened:</strong>
                      <p className="text-gray-300 leading-relaxed bg-sentinel-card/60 p-2 rounded border border-sentinel-border/40 text-[11px]">
                        {analysisResult.what_happened}
                      </p>
                    </div>

                    <div>
                      <strong className="text-white block mb-0.5 text-[11px] uppercase tracking-wide">Why It Matters:</strong>
                      <p className="text-gray-300 leading-relaxed bg-sentinel-card/60 p-2 rounded border border-sentinel-border/40 text-[11px]">
                        {analysisResult.why_it_matters}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Pillar 3: Grounded Evidence Trace */}
              {analysisResult.evidence && analysisResult.evidence.length > 0 && (
                <div className="card p-4 space-y-2 border-sentinel-border">
                  <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                    <span>📑</span> Authoritative Evidence Trace
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                    {analysisResult.evidence.map((ev: string, idx: number) => (
                      <div key={idx} className="bg-sentinel-card p-2 rounded border border-sentinel-border/60 text-gray-300 flex items-center gap-2">
                        <span className="text-cyan-400">›</span>
                        <span className="truncate">{ev}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Pillar 4: Recommended Solution & Actionable Guidance */}
              {sol && (
                <div className="card p-5 space-y-4 border-green-500/40 bg-gradient-to-b from-green-950/20 to-sentinel-surface">
                  <div className="flex items-center justify-between border-b border-sentinel-border pb-3">
                    <div className="flex items-center gap-2">
                      <span className="text-base">🛠️</span>
                      <div>
                        <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                          Recommended Solution & Fix Commands
                        </h4>
                        <span className="text-[11px] text-green-400 font-medium">
                          Action: {sol.action?.replace('_', ' ').toUpperCase()} {sol.target_version && `→ ${sol.target_version}`}
                        </span>
                      </div>
                    </div>
                    {sol.files && sol.files.length > 0 && (
                      <div className="text-right">
                        <span className="text-[10px] text-gray-400 uppercase tracking-wider block">Manifest Files:</span>
                        <span className="font-mono text-xs text-white">{sol.files.join(', ')}</span>
                      </div>
                    )}
                  </div>

                  {/* Shell Commands to Run */}
                  {sol.commands && sol.commands.length > 0 && (
                    <div className="space-y-2">
                      <span className="text-[11px] font-bold text-gray-300 uppercase tracking-wider block">
                        Exact Ecosystem Shell Commands:
                      </span>
                      <div className="space-y-1.5">
                        {sol.commands.map((cmd: string, idx: number) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between p-2.5 rounded-lg bg-gray-950 border border-gray-800 font-mono text-xs text-green-400"
                          >
                            <span className="select-all overflow-x-auto">$ {cmd}</span>
                            <button
                              onClick={() => handleCopyCommand(cmd, idx)}
                              className="ml-3 px-2.5 py-1 text-[11px] font-semibold rounded bg-sentinel-card hover:bg-gray-800 text-gray-300 hover:text-white transition-colors shrink-0"
                            >
                              {copiedIndex === idx ? '✓ Copied' : 'Copy'}
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Step-by-Step Remediation Plan */}
                  {sol.steps && sol.steps.length > 0 && (
                    <div className="space-y-1.5 pt-1">
                      <span className="text-[11px] font-bold text-gray-300 uppercase tracking-wider block">
                        Step-by-Step Remediation Plan:
                      </span>
                      <ol className="space-y-1 text-xs text-gray-300 list-decimal list-inside pl-1">
                        {sol.steps.map((st: string, idx: number) => (
                          <li key={idx} className="leading-relaxed">
                            <span className="text-gray-200">{st}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}

                  {/* Compatibility & Tests */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 text-xs">
                    {analysisResult.compatibility_risks && analysisResult.compatibility_risks.length > 0 && (
                      <div className="bg-amber-950/20 border border-amber-500/30 p-2.5 rounded-lg">
                        <strong className="text-amber-300 block mb-1 text-[11px] uppercase tracking-wide">
                          ⚠️ Compatibility & Breaking Changes:
                        </strong>
                        <ul className="space-y-1 text-gray-300 text-[11px]">
                          {analysisResult.compatibility_risks.map((c: string, idx: number) => (
                            <li key={idx}>• {c}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {analysisResult.tests && analysisResult.tests.length > 0 && (
                      <div className="bg-blue-950/20 border border-blue-500/30 p-2.5 rounded-lg">
                        <strong className="text-blue-300 block mb-1 text-[11px] uppercase tracking-wide">
                          🧪 Verification Tests:
                        </strong>
                        <ul className="space-y-1 text-gray-300 text-[11px]">
                          {analysisResult.tests.map((t: string, idx: number) => (
                            <li key={idx}>• {t}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* What The System Does NOT Know / Uncertainty */}
              {analysisResult.uncertainty && analysisResult.uncertainty.length > 0 && (
                <div className="card p-3.5 bg-sentinel-card/40 border-sentinel-border space-y-1.5 text-xs">
                  <h5 className="font-bold text-gray-400 uppercase tracking-wider text-[11px] flex items-center gap-1.5">
                    <span>❓</span> What The System Does NOT Know (Explicit Uncertainty)
                  </h5>
                  <ul className="space-y-1 text-gray-400 text-[11px]">
                    {analysisResult.uncertainty.map((u: string, idx: number) => (
                      <li key={idx}>• {u}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Suggested Question Chips */}
          <div className="space-y-2 pt-2 border-t border-sentinel-border">
            <span className="text-[11px] font-bold text-gray-400 uppercase tracking-wider block">
              Contextual Suggested Questions:
            </span>
            <div className="flex flex-wrap gap-2">
              {suggestedQuestions.map((q) => (
                <button
                  key={q.id}
                  onClick={() => handleAnalyze(q.text, q.mode)}
                  disabled={loading}
                  className="px-3 py-1.5 rounded-lg bg-sentinel-card hover:bg-sentinel-border border border-sentinel-border/80 text-xs text-cyan-300 hover:text-white transition-all text-left flex items-center gap-1.5 disabled:opacity-50"
                >
                  <span className="text-cyan-400">💬</span>
                  <span>{q.text}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Modal Footer: Free-Form Question Input */}
        <div className="p-4 border-t border-sentinel-border bg-sentinel-card/80 shrink-0">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (question.trim() && !loading) {
                handleAnalyze(question.trim());
              }
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              placeholder={
                context.findingId
                  ? 'Ask about this finding (e.g., Can I safely upgrade? What tests should I run?)...'
                  : 'Ask about project security, risk contributors, blocking policies, or remediation...'
              }
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              disabled={loading}
              className="input-field flex-1 text-xs py-2 px-3 bg-sentinel-bg border-sentinel-border focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={loading || !question.trim()}
              className="btn-primary text-xs py-2 px-4 flex items-center gap-1.5 shrink-0 disabled:opacity-50 font-semibold"
            >
              <span>🚀</span> Ask Analyst
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
