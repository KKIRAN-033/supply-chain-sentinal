import type { Finding } from '../types';

interface RemediationPanelProps {
  finding: Finding;
  onClose: () => void;
}

export default function RemediationPanel({ finding, onClose }: RemediationPanelProps) {
  const remediation = finding.remediation;
  const evidence = finding.evidence;

  const priorityColors: Record<string, string> = {
    immediate: 'badge-critical',
    soon: 'badge-high',
    planned: 'badge-medium',
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end" onClick={onClose}>
      <div
        className="w-full max-w-lg bg-sentinel-surface border-l border-sentinel-border h-full overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 bg-sentinel-surface border-b border-sentinel-border p-5 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-white">Finding Details</h2>
            <p className="text-xs text-gray-500 mt-0.5">{finding.component_name || finding.component_purl}</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-xl">✕</button>
        </div>

        <div className="p-5 space-y-6">
          {/* Severity + Score */}
          <div className="flex gap-3">
            <div className={`badge ${finding.severity === 'CRITICAL' ? 'badge-critical' : finding.severity === 'HIGH' ? 'badge-high' : finding.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>
              {finding.severity}
            </div>
            <span className="text-sm text-gray-400">Score: <strong className="text-white">{finding.score}</strong></span>
            <span className="text-sm text-gray-400">Confidence: <strong className="text-white">{(finding.confidence * 100).toFixed(0)}%</strong></span>
          </div>

          {/* Title + Description */}
          <div>
            <h3 className="text-white font-semibold">{finding.title}</h3>
            <p className="text-sm text-gray-400 mt-2">{finding.description}</p>
          </div>

          {/* CVE */}
          {finding.cve_id && (
            <div className="bg-sentinel-card rounded-lg p-3 border border-sentinel-border">
              <span className="text-xs text-gray-500 uppercase">CVE ID</span>
              <p className="font-mono text-blue-400 mt-1">{finding.cve_id}</p>
            </div>
          )}

          {/* Evidence */}
          {evidence && (
            <div>
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Evidence</h4>
              <div className="bg-sentinel-bg rounded-lg p-4 border border-sentinel-border text-xs font-mono text-gray-300 max-h-60 overflow-y-auto">
                <pre className="whitespace-pre-wrap">{JSON.stringify(evidence, null, 2)}</pre>
              </div>
            </div>
          )}

          {/* Remediation */}
          {remediation && (
            <div>
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Remediation</h4>
              <div className="bg-sentinel-card rounded-lg p-4 border border-sentinel-border space-y-3">
                {remediation.priority && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-500">Priority:</span>
                    <span className={`badge ${priorityColors[remediation.priority] || 'badge-unknown'}`}>
                      {remediation.priority}
                    </span>
                  </div>
                )}
                {remediation.action && (
                  <div>
                    <span className="text-xs text-gray-500">Action: </span>
                    <span className="text-sm text-white capitalize">{remediation.action}</span>
                  </div>
                )}
                {remediation.recommended_action && (
                  <div>
                    <span className="text-xs text-gray-500">Recommendation: </span>
                    <span className="text-sm text-green-400">{remediation.recommended_action}</span>
                  </div>
                )}
                {remediation.reason && (
                  <div>
                    <span className="text-xs text-gray-500">Reason: </span>
                    <span className="text-sm text-gray-300">{remediation.reason}</span>
                  </div>
                )}
                {remediation.target_version && (
                  <div>
                    <span className="text-xs text-gray-500">Target Version: </span>
                    <span className="text-sm font-mono text-blue-400">{remediation.target_version}</span>
                  </div>
                )}
                {remediation.verification && (
                  <div>
                    <span className="text-xs text-gray-500">Verification: </span>
                    <span className="text-sm text-gray-300">{remediation.verification}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
