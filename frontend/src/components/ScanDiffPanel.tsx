import React, { useState } from 'react';
import type { ScanDiff, Finding } from '../types';

interface ScanDiffPanelProps {
  diff: ScanDiff | null;
  loading: boolean;
}

export default function ScanDiffPanel({ diff, loading }: ScanDiffPanelProps) {
  const [activeTab, setActiveTab] = useState<'resolved' | 'new' | 'still_open'>('resolved');

  if (loading) {
    return (
      <div className="card text-center py-6">
        <span className="text-sm text-gray-400">Comparing with baseline scan...</span>
      </div>
    );
  }

  if (!diff || !diff.base_scan_id) {
    return (
      <div className="card text-center py-6">
        <div className="text-2xl mb-1">📊</div>
        <h4 className="text-sm font-semibold text-gray-300">Initial Baseline Scan</h4>
        <p className="text-xs text-gray-500 mt-1">No prior scan found for comparison. This scan establishes the initial security baseline for this project.</p>
      </div>
    );
  }

  const { counts, risk_delta, resolved_findings, new_findings, still_open_findings } = diff;
  const deltaColor = risk_delta < 0 ? 'text-green-400' : risk_delta > 0 ? 'text-red-400' : 'text-gray-400';
  const deltaSign = risk_delta > 0 ? `+${risk_delta}` : `${risk_delta}`;

  const currentList: Finding[] =
    activeTab === 'resolved'
      ? resolved_findings
      : activeTab === 'new'
      ? new_findings
      : still_open_findings;

  return (
    <div className="card space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-sentinel-border pb-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Fix Verification & Scan Diff</h3>
          <p className="text-xs text-gray-500">
            Comparing against base scan <span className="font-mono text-gray-400">{diff.base_scan_id?.slice(0, 12)}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <span className="text-xs text-gray-500 block">Risk Score Delta</span>
            <span className={`text-base font-bold ${deltaColor}`}>
              {deltaSign} pts {risk_delta < 0 ? '↓ (Improved)' : risk_delta > 0 ? '↑ (Degraded)' : '(Unchanged)'}
            </span>
          </div>
        </div>
      </div>

      {/* Metric badges */}
      <div className="grid grid-cols-3 gap-3">
        <button
          onClick={() => setActiveTab('resolved')}
          className={`p-3 rounded-lg text-left transition-all ${
            activeTab === 'resolved'
              ? 'bg-green-500/20 border border-green-500/40 text-green-300'
              : 'bg-sentinel-bg hover:bg-sentinel-border/50 text-gray-400'
          }`}
        >
          <span className="text-xs block">Resolved Issues</span>
          <span className="text-xl font-bold text-green-400">{counts.resolved}</span>
        </button>

        <button
          onClick={() => setActiveTab('new')}
          className={`p-3 rounded-lg text-left transition-all ${
            activeTab === 'new'
              ? 'bg-red-500/20 border border-red-500/40 text-red-300'
              : 'bg-sentinel-bg hover:bg-sentinel-border/50 text-gray-400'
          }`}
        >
          <span className="text-xs block">New Issues</span>
          <span className="text-xl font-bold text-red-400">{counts.new}</span>
        </button>

        <button
          onClick={() => setActiveTab('still_open')}
          className={`p-3 rounded-lg text-left transition-all ${
            activeTab === 'still_open'
              ? 'bg-yellow-500/20 border border-yellow-500/40 text-yellow-300'
              : 'bg-sentinel-bg hover:bg-sentinel-border/50 text-gray-400'
          }`}
        >
          <span className="text-xs block">Still Open</span>
          <span className="text-xl font-bold text-yellow-400">{counts.still_open}</span>
        </button>
      </div>

      {/* Items list */}
      <div className="space-y-2">
        {currentList.length === 0 ? (
          <p className="text-sm text-gray-500 italic py-2">No {activeTab.replace('_', ' ')} findings detected.</p>
        ) : (
          currentList.map((item, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between p-3 rounded-lg bg-sentinel-bg border border-sentinel-border text-sm"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`badge ${
                      item.severity === 'CRITICAL'
                        ? 'badge-critical'
                        : item.severity === 'HIGH'
                        ? 'badge-high'
                        : item.severity === 'MEDIUM'
                        ? 'badge-medium'
                        : 'badge-low'
                    }`}
                  >
                    {item.severity}
                  </span>
                  <span className="font-semibold text-white">{item.component_name || item.component_purl}</span>
                  {item.cve_id && <span className="font-mono text-xs text-blue-400">{item.cve_id}</span>}
                </div>
                <p className="text-xs text-gray-400">{item.title}</p>
              </div>
              <div className="text-right">
                <span
                  className={`text-xs font-semibold px-2 py-0.5 rounded ${
                    activeTab === 'resolved'
                      ? 'bg-green-500/10 text-green-400'
                      : activeTab === 'new'
                      ? 'bg-red-500/10 text-red-400'
                      : 'bg-yellow-500/10 text-yellow-400'
                  }`}
                >
                  {activeTab.toUpperCase().replace('_', ' ')}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
