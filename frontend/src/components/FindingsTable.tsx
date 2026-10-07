import { useState } from 'react';
import type { Finding } from '../types';

interface FindingsTableProps {
  findings: Finding[];
  onSelect?: (finding: Finding) => void;
}

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4, NONE: 5 };

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    CRITICAL: 'badge-critical',
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-low',
  };
  return <span className={`badge ${cls[severity] || 'badge-unknown'}`}>{severity}</span>;
}

function CategoryBadge({ category }: { category: string }) {
  const icons: Record<string, string> = {
    VULNERABILITY: '🔓',
    BEHAVIORAL: '⚠️',
    TYPOSQUATTING: '🎭',
    REPUTATION: '👁️',
    DEPENDENCY_HEALTH: '💊',
  };
  return (
    <span className="badge bg-sentinel-card border-sentinel-border text-gray-300">
      {icons[category] || '❓'} {category.replace('_', ' ')}
    </span>
  );
}

export default function FindingsTable({ findings, onSelect }: FindingsTableProps) {
  const [sortBy, setSortBy] = useState<'score' | 'severity'>('score');
  const [filterCategory, setFilterCategory] = useState<string>('');

  const categories = [...new Set(findings.map(f => f.category))];

  const sorted = [...findings]
    .filter(f => !filterCategory || f.category === filterCategory)
    .sort((a, b) => {
      if (sortBy === 'score') return b.score - a.score;
      return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
    });

  if (findings.length === 0) {
    return (
      <div className="card text-center py-12">
        <span className="text-4xl mb-4 block">✅</span>
        <p className="text-gray-400">No findings detected</p>
        <p className="text-xs text-gray-600 mt-1">All components passed security analysis</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex gap-2 flex-wrap items-center">
        <button
          onClick={() => setFilterCategory('')}
          className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${!filterCategory ? 'bg-sentinel-accent text-white' : 'bg-sentinel-card text-gray-400 hover:text-white'}`}
        >
          All ({findings.length})
        </button>
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setFilterCategory(cat)}
            className={`px-3 py-1 rounded-lg text-xs font-medium transition-all ${filterCategory === cat ? 'bg-sentinel-accent text-white' : 'bg-sentinel-card text-gray-400 hover:text-white'}`}
          >
            {cat.replace('_', ' ')} ({findings.filter(f => f.category === cat).length})
          </button>
        ))}
        <div className="ml-auto flex gap-2">
          <button
            onClick={() => setSortBy('score')}
            className={`text-xs ${sortBy === 'score' ? 'text-sentinel-accent' : 'text-gray-500'}`}
          >
            Sort: Score
          </button>
          <button
            onClick={() => setSortBy('severity')}
            className={`text-xs ${sortBy === 'severity' ? 'text-sentinel-accent' : 'text-gray-500'}`}
          >
            Sort: Severity
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-sentinel-border">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-sentinel-surface text-gray-400 text-xs uppercase tracking-wider">
              <th className="text-left px-4 py-3">Component</th>
              <th className="text-left px-4 py-3">Category</th>
              <th className="text-left px-4 py-3">Severity</th>
              <th className="text-left px-4 py-3">Score</th>
              <th className="text-left px-4 py-3">Title</th>
              <th className="text-left px-4 py-3">CVE</th>
              <th className="text-right px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-sentinel-border">
            {sorted.map(f => (
              <tr
                key={f.id}
                onClick={() => onSelect?.(f)}
                className="bg-sentinel-card hover:bg-sentinel-surface cursor-pointer transition-colors"
              >
                <td className="px-4 py-3 font-mono text-xs text-blue-400">{f.component_name || f.component_purl.split('/').pop()}</td>
                <td className="px-4 py-3"><CategoryBadge category={f.category} /></td>
                <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                <td className="px-4 py-3 font-mono font-bold">{f.score}</td>
                <td className="px-4 py-3 text-gray-300 max-w-xs truncate">{f.title}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-500">{f.cve_id || '—'}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      window.dispatchEvent(
                        new CustomEvent('open-ai-analyst', {
                          detail: {
                            projectId: f.project_id || localStorage.getItem('sentinel_active_project'),
                            scanId: f.scan_id,
                            findingId: f.id,
                            finding: f,
                            mode: 'explain',
                          },
                        })
                      );
                    }}
                    className="px-2 py-1 rounded bg-cyan-950/30 hover:bg-cyan-900/50 border border-cyan-500/40 text-cyan-300 hover:text-white text-[11px] font-semibold inline-flex items-center gap-1 transition-all"
                    title="Consult AI Security Analyst"
                  >
                    <span>🤖</span> AI
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
