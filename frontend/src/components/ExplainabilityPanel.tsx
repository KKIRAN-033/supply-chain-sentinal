import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import type { MetricsBreakdown, ExplainabilityInfo } from '../types';

interface ExplainabilityPanelProps {
  breakdown: MetricsBreakdown;
  confidence: number;
  dataQuality: string;
  policyDecision?: string;
  explanation?: ExplainabilityInfo;
}

const CATEGORY_COLORS: Record<string, string> = {
  vulnerability: '#ef4444',
  behavioral: '#f97316',
  typosquatting: '#a855f7',
  health: '#3b82f6',
  reputation: '#eab308',
};

export default function ExplainabilityPanel({ breakdown, confidence, dataQuality, policyDecision, explanation }: ExplainabilityPanelProps) {
  const data = Object.entries(breakdown).map(([key, value]) => ({
    name: key.charAt(0).toUpperCase() + key.slice(1),
    value: Number(value) || 0,
    color: CATEGORY_COLORS[key] || '#6b7280',
  }));

  return (
    <div className="card space-y-5">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Risk Explainability & Narrative</h3>
        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              window.dispatchEvent(
                new CustomEvent('open-ai-analyst', {
                  detail: {
                    mode: 'risk',
                    question: 'Why is the risk score this high and what are the main risk contributors?',
                  },
                })
              );
            }}
            className="px-2.5 py-1 rounded bg-cyan-950/30 hover:bg-cyan-900/50 border border-cyan-500/40 text-cyan-300 hover:text-white text-xs font-semibold inline-flex items-center gap-1 transition-all"
          >
            <span>🤖</span> Ask AI Analyst
          </button>
          {explanation?.llm_status && (
            <span className="text-xs text-gray-500 font-mono">
              AI: <span className={explanation.llm_status === 'online' ? 'text-green-400' : 'text-gray-400'}>{explanation.llm_status}</span>
            </span>
          )}
        </div>
      </div>

      {/* Grounded narrative */}
      <div className="p-3.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-sm text-gray-300 leading-relaxed space-y-2">
        {explanation?.llm_summary ? (
          <div>
            <p>{explanation.llm_summary}</p>
          </div>
        ) : (
          <div>
            <span className="text-xs text-yellow-500 block mb-1">⚠️ AI Explanation unavailable — showing deterministic security analysis.</span>
            <p>{explanation?.deterministic_summary || 'No explanation available.'}</p>
          </div>
        )}
      </div>

      {/* Metrics breakdown chart */}
      <div className="h-40">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ left: 80 }}>
            <XAxis type="number" domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={{ stroke: '#1e293b' }} />
            <YAxis type="category" dataKey="name" tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} />
            <Tooltip
              contentStyle={{ background: '#1a2235', border: '1px solid #2a3550', borderRadius: '8px', fontSize: '12px' }}
            />
            <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={16}>
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Data quality indicators */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-sentinel-bg rounded-lg p-3 text-center">
          <span className="text-xs text-gray-500 block">Confidence</span>
          <span className="text-lg font-bold text-white">{(confidence * 100).toFixed(0)}%</span>
        </div>
        <div className="bg-sentinel-bg rounded-lg p-3 text-center">
          <span className="text-xs text-gray-500 block">Data Quality</span>
          <span className={`text-sm font-bold ${dataQuality === 'COMPLETE' ? 'text-green-400' : dataQuality === 'PARTIAL' ? 'text-yellow-400' : 'text-gray-400'}`}>
            {dataQuality}
          </span>
        </div>
        <div className="bg-sentinel-bg rounded-lg p-3 text-center">
          <span className="text-xs text-gray-500 block">Policy</span>
          <span className={`badge ${policyDecision === 'ALLOW' ? 'badge-allow' : policyDecision === 'BLOCK' ? 'badge-block' : 'badge-review'}`}>
            {policyDecision || 'N/A'}
          </span>
        </div>
      </div>

      {/* Key actionable recommendations */}
      {explanation?.recommendations && explanation.recommendations.length > 0 && (
        <div className="space-y-1.5 pt-2 border-t border-sentinel-border">
          <h4 className="text-xs font-semibold uppercase text-gray-400">Key Recommended Actions</h4>
          <ul className="space-y-1">
            {explanation.recommendations.map((rec, i) => (
              <li key={i} className="text-xs text-gray-300 flex items-start gap-1.5">
                <span className="text-sentinel-accent">›</span>
                <span>{rec}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
