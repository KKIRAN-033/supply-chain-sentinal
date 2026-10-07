import { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import MetricGauge from '../components/MetricGauge';
import StatCounters from '../components/StatCounters';
import ScanProgress from '../components/ScanProgress';
import FindingsTable from '../components/FindingsTable';
import ExplainabilityPanel from '../components/ExplainabilityPanel';
import RemediationPanel from '../components/RemediationPanel';
import ScanDiffPanel from '../components/ScanDiffPanel';
import DependencyGraph from '../components/DependencyGraph';
import type { Finding, ScanDiff } from '../types';


export default function ScanDetails() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [status, setStatus] = useState<any>(null);
  const [report, setReport] = useState<any>(null);
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval>>();

  useEffect(() => {
    if (!scanId) return;
    // Poll status
    const poll = async () => {
      try {
        const s = await api.getScanStatus(scanId);
        setStatus(s);
        setLoading(false);

        if (s.status === 'COMPLETED') {
          clearInterval(pollRef.current);
          const r = await api.getScanReport(scanId);
          setReport(r);
          setLoadingDiff(true);
          try {
            const d = await api.getScanDiff(scanId);
            setDiff(d);
          } catch {
            // initial scan has no diff
          } finally {
            setLoadingDiff(false);
          }
        } else if (s.status === 'FAILED') {
          clearInterval(pollRef.current);
        }
      } catch {
        setLoading(false);
      }
    };

    poll();
    pollRef.current = setInterval(poll, 1500);
    return () => clearInterval(pollRef.current);
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
      </div>
    );
  }

  const isRunning = status && !['COMPLETED', 'FAILED'].includes(status.status);
  const isComplete = status?.status === 'COMPLETED';
  const isFailed = status?.status === 'FAILED';

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Scan Results</h1>
          <p className="text-xs text-gray-500 font-mono mt-1">{scanId}</p>
        </div>
        {report && (
          <button onClick={() => navigate(`/findings/${scanId}`)} className="btn-secondary">
            View All Findings
          </button>
        )}
      </div>

      {/* Progress */}
      {status && (
        <ScanProgress
          status={status.status}
          progress={status.progress}
          message={status.message}
        />
      )}

      {/* Failed state */}
      {isFailed && status?.error && (
        <div className="card border-red-500/30">
          <h3 className="text-red-400 font-semibold mb-2">⚠️ Scan Failed</h3>
          <p className="text-sm text-gray-400">Error: <span className="font-mono text-red-300">{status.error.code}</span></p>
          <p className="text-sm text-gray-500 mt-1">{status.error.message}</p>
        </div>
      )}

      {/* Completed results */}
      {isComplete && report && (
        <>
          {/* Score + Stats */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <div className="card flex flex-col items-center justify-center gap-3">
              <MetricGauge score={report.summary.overall_score ?? 0} />
              <div className={`badge ${report.policy_decision === 'ALLOW' ? 'badge-allow' : report.policy_decision === 'BLOCK' ? 'badge-block' : 'badge-review'}`}>
                {report.policy_decision}
              </div>
            </div>
            <div className="lg:col-span-3">
              <StatCounters stats={[
                { label: 'Dependencies', value: report.summary.total_dependencies, icon: '📦', color: 'blue' },
                { label: 'Vulnerable', value: report.summary.vulnerable_count, icon: '🔓', color: 'red' },
                { label: 'Suspicious', value: report.summary.suspicious_count, icon: '⚠️', color: 'orange' },
                { label: 'Outdated', value: report.summary.outdated_count, icon: '📅', color: 'yellow' },
              ]} />
            </div>
          </div>

          {/* Provenance Card */}
          {report.provenance && (
            <div className="card">
              <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">SBOM Provenance & Integrity</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-gray-500 block">Format</span>
                  <span className="font-mono text-gray-200">{report.provenance.format || 'Unknown'}</span>
                </div>
                <div>
                  <span className="text-gray-500 block">Spec Version</span>
                  <span className="font-mono text-gray-200">{report.provenance.spec_version || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-gray-500 block">Serial Number</span>
                  <span className="font-mono text-gray-200 truncate block">{report.provenance.serial_number || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-gray-500 block">SHA-256 Digest</span>
                  <span className="font-mono text-sentinel-accent truncate block">{report.provenance.sbom_hash || 'Verified'}</span>
                </div>
              </div>
            </div>
          )}

          {/* Fix Verification Diff */}
          <ScanDiffPanel diff={diff} loading={loadingDiff} />

          {/* Interactive Dependency Graph with Node Evidence Inspector */}
          {report.components && report.components.length > 0 && (
            <DependencyGraph
              nodes={(report.components || []).map((c: any) => ({
                data: {
                  id: c.purl || c.name,
                  label: c.version ? `${c.name}@${c.version}` : c.name,
                  name: c.name,
                  version: c.version,
                  ecosystem: c.ecosystem,
                  is_direct: c.is_direct,
                  scope: c.scope,
                  severity: (report.findings || []).find(
                    (f: any) =>
                      f.component_purl === c.purl ||
                      (f.component_name && f.component_name.toLowerCase() === c.name?.toLowerCase())
                  )?.severity,
                },
              }))}
              edges={(report.dependencies || []).map((d: any, idx: number) => ({
                data: {
                  id: `e${idx}`,
                  source: d.parent || d.parent_purl,
                  target: d.child || d.child_purl,
                },
              }))}
              findings={report.findings || []}
            />
          )}


          {/* Explainability */}
          <ExplainabilityPanel
            breakdown={report.metrics_breakdown}
            confidence={report.summary.confidence ?? 0}
            dataQuality={report.summary.data_quality}
            policyDecision={report.policy_decision}
            explanation={report.explainability}
          />

          {/* Findings */}
          <div>
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Security Findings</h2>
            <FindingsTable
              findings={report.findings}
              onSelect={setSelectedFinding}
            />
          </div>
        </>
      )}

      {/* Remediation slide-out */}
      {selectedFinding && (
        <RemediationPanel finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
