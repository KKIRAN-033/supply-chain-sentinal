import React from 'react';

interface EvidenceModalProps {
  finding: any | null;
  onClose: () => void;
}

export default function EvidenceModal({ finding, onClose }: EvidenceModalProps) {
  if (!finding) return null;

  const evidence = finding.evidence || {};
  const remediation = finding.remediation || {};
  const cve = finding.cve_id || finding.cve || finding.evidence?.cve_id || 'N/A';
  const installed = finding.evidence?.version || finding.version || 'Unknown';
  const fixedVersions = finding.evidence?.fixed_versions || (remediation.target_version ? [remediation.target_version] : []);
  const source = finding.evidence?.source || 'OSV.dev Intelligence';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fadeIn">
      <div className="bg-sentinel-surface border border-sentinel-border rounded-xl w-full max-w-3xl max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-sentinel-border sticky top-0 bg-sentinel-surface z-10">
          <div className="flex items-center gap-3">
            <span className={`px-2.5 py-1 text-xs font-bold rounded uppercase ${
              finding.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
              finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
              finding.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
              'bg-blue-500/20 text-blue-400 border border-blue-500/30'
            }`}>
              {finding.severity || 'UNKNOWN'}
            </span>
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                {finding.component_name} {installed !== 'Unknown' && <span className="text-gray-400 text-sm font-mono">@{installed}</span>}
              </h2>
              <p className="text-xs text-gray-400 font-mono">{finding.component_purl}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                window.dispatchEvent(
                  new CustomEvent('open-ai-analyst', {
                    detail: {
                      projectId: finding.project_id || localStorage.getItem('sentinel_active_project'),
                      scanId: finding.scan_id,
                      findingId: finding.id,
                      finding: finding,
                      mode: 'explain',
                    },
                  })
                );
                onClose();
              }}
              className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600/30 to-cyan-600/30 hover:from-blue-600/50 hover:to-cyan-600/50 border border-cyan-500/50 text-cyan-300 hover:text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm shadow-cyan-500/10 transition-all cursor-pointer"
              title="Consult AI Security Analyst"
            >
              <span>🤖</span>
              <span>Ask AI Analyst</span>
            </button>
            <button 
              onClick={onClose}
              className="w-8 h-8 rounded-lg bg-sentinel-card hover:bg-gray-800 text-gray-400 hover:text-white flex items-center justify-center text-lg transition-colors"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Content Body - 6 Core Security Questions */}
        <div className="p-6 space-y-6">
          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-sentinel-card/60 p-4 rounded-lg border border-sentinel-border">
            <div>
              <span className="text-[11px] text-gray-400 uppercase tracking-wider block">Identifier</span>
              <span className="font-mono text-sm font-semibold text-sentinel-accent">{cve}</span>
            </div>
            <div>
              <span className="text-[11px] text-gray-400 uppercase tracking-wider block">Risk Contribution</span>
              <span className="text-sm font-semibold text-white">+{finding.score || 0} pts</span>
            </div>
            <div>
              <span className="text-[11px] text-gray-400 uppercase tracking-wider block">Intelligence Source</span>
              <span className="text-sm font-semibold text-gray-300">{source}</span>
            </div>
            <div>
              <span className="text-[11px] text-gray-400 uppercase tracking-wider block">Exploitability</span>
              <span className="text-sm font-semibold text-amber-400">{finding.evidence?.exploitability || 'UNPROVEN'}</span>
            </div>
          </div>

          {/* 1. WHAT happened? */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sentinel-accent text-sm font-semibold uppercase tracking-wider">
              <span>📌</span> 1. What Happened?
            </div>
            <div className="bg-sentinel-card p-4 rounded-lg border border-sentinel-border text-sm text-gray-200 leading-relaxed">
              <p className="font-semibold text-white mb-1">{finding.title}</p>
              <p className="text-gray-400 text-xs">{finding.description || 'Deterministic security check flagged this package against open-source vulnerability feeds and behavioral rules.'}</p>
            </div>
          </div>

          {/* 2. WHY does it matter? */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sentinel-accent text-sm font-semibold uppercase tracking-wider">
              <span>🎯</span> 2. Why Does It Matter?
            </div>
            <div className="bg-sentinel-card p-4 rounded-lg border border-sentinel-border text-sm text-gray-300">
              <p>
                In a software supply chain, unpatched or unverified packages provide an entry point for remote code execution, denial of service, parameter smuggling, or data exfiltration.
              </p>
              {finding.blast_radius && (
                <div className="mt-3 pt-3 border-t border-sentinel-border/50 text-xs text-gray-400 flex items-center gap-4">
                  <span>Blast Radius: <strong className="text-white">{finding.blast_radius.impact_tier || 'Direct'}</strong></span>
                  <span>Dependents Impacted: <strong className="text-white">{finding.blast_radius.dependents_count || 1}</strong></span>
                </div>
              )}
            </div>
          </div>

          {/* 3. HOW serious is it? */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sentinel-accent text-sm font-semibold uppercase tracking-wider">
              <span>⚖️</span> 3. How Serious Is It?
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="bg-sentinel-card p-3 rounded-lg border border-sentinel-border">
                <span className="text-xs text-gray-400 block">Severity Level</span>
                <span className="text-base font-bold text-white">{finding.severity}</span>
                <span className="text-[10px] text-gray-500 block mt-0.5">Assigned by Security Rules</span>
              </div>
              <div className="bg-sentinel-card p-3 rounded-lg border border-sentinel-border">
                <span className="text-xs text-gray-400 block">Confidence Metric</span>
                <span className="text-base font-bold text-white">{Math.round((finding.confidence || 0.85) * 100)}%</span>
                <span className="text-[10px] text-gray-500 block mt-0.5">High Confidence Evidence</span>
              </div>
              <div className="bg-sentinel-card p-3 rounded-lg border border-sentinel-border">
                <span className="text-xs text-gray-400 block">CISA KEV Catalog</span>
                <span className="text-base font-bold text-white">{evidence.is_kev ? 'YES (Active Exploitation)' : 'NO'}</span>
                <span className="text-[10px] text-gray-500 block mt-0.5">Known Exploited Catalog</span>
              </div>
            </div>
          </div>

          {/* 4. WHAT evidence supports it? */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sentinel-accent text-sm font-semibold uppercase tracking-wider">
              <span>🔍</span> 4. What Evidence Supports It?
            </div>
            <div className="bg-sentinel-card p-4 rounded-lg border border-sentinel-border space-y-2 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-sentinel-border/40">
                <span className="text-gray-400">Package PURL:</span>
                <span className="text-gray-200">{finding.component_purl}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-sentinel-border/40">
                <span className="text-gray-400">Installed Version:</span>
                <span className="text-amber-400 font-semibold">{installed}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-sentinel-border/40">
                <span className="text-gray-400">Fixed In Version(s):</span>
                <span className="text-green-400 font-semibold">
                  {fixedVersions.length > 0 ? fixedVersions.join(', ') : 'No fixed version declared yet'}
                </span>
              </div>
              {evidence.affected_versions && (
                <div className="flex justify-between py-1 border-b border-sentinel-border/40">
                  <span className="text-gray-400">Affected Range:</span>
                  <span className="text-red-400">{evidence.affected_versions.join(' || ')}</span>
                </div>
              )}
              {evidence.references && evidence.references.length > 0 && (
                <div className="pt-2">
                  <span className="text-gray-400 block mb-1">Advisory References:</span>
                  <div className="space-y-1">
                    {evidence.references.slice(0, 3).map((ref: string, idx: number) => (
                      <a 
                        key={idx} 
                        href={ref} 
                        target="_blank" 
                        rel="noreferrer" 
                        className="text-sentinel-accent hover:underline block truncate"
                      >
                        🔗 {ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* 5. WHAT should the user do? */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-green-400 text-sm font-semibold uppercase tracking-wider">
              <span>🛠️</span> 5. Recommended Action
            </div>
            <div className="bg-green-950/20 border border-green-500/30 p-4 rounded-lg text-sm text-green-300">
              <p className="font-semibold text-white mb-1">
                {remediation.recommended_action || (fixedVersions[0] ? `Upgrade ${finding.component_name} to version ${fixedVersions[0]}` : 'Review dependency usage and apply workaround')}
              </p>
              <p className="text-xs text-gray-400 mt-1">
                Priority: <strong className="text-amber-400 uppercase">{remediation.priority || 'High'}</strong> · Verification: Re-scan manifest to verify that fix resolves finding without breaking builds.
              </p>
            </div>
          </div>

          {/* 6. WHAT happens if ignored? */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-red-400 text-sm font-semibold uppercase tracking-wider">
              <span>⚠️</span> 6. What Happens If Ignored?
            </div>
            <div className="bg-red-950/20 border border-red-500/30 p-4 rounded-lg text-xs text-gray-300 leading-relaxed">
              Automated deployment gates will mark the project as <strong className="text-red-400">BLOCK</strong> or <strong className="text-yellow-400">REVIEW</strong> per security policies. Production environments remain exposed to published attack payloads matching this CVE advisory.
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-sentinel-border bg-sentinel-card/40 flex justify-between items-center">
          <button
            onClick={() => {
              window.dispatchEvent(
                new CustomEvent('open-ai-analyst', {
                  detail: {
                    projectId: finding.project_id || localStorage.getItem('sentinel_active_project'),
                    scanId: finding.scan_id,
                    findingId: finding.id,
                    finding: finding,
                    mode: 'remediate',
                    question: `How do I remediate this ${finding.severity} finding in ${finding.component_name}?`,
                  },
                })
              );
              onClose();
            }}
            className="btn-primary text-xs py-2 px-3 flex items-center gap-1.5"
          >
            <span>🛠️</span>
            <span>Generate AI Fix Plan & Commands</span>
          </button>
          <button onClick={onClose} className="btn-secondary text-xs">
            Close Evidence
          </button>
        </div>
      </div>
    </div>
  );
}
