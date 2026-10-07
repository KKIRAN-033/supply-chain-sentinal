import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';
import type { RiskHistoryEntry } from '../types';

interface RiskTimelineProps {
  history: RiskHistoryEntry[];
}

function getRiskColor(level: string): string {
  const map: Record<string, string> = {
    LOW: '#22c55e', MEDIUM: '#eab308', HIGH: '#f97316', CRITICAL: '#ef4444',
  };
  return map[level] || '#6b7280';
}

export default function RiskTimeline({ history }: RiskTimelineProps) {
  if (history.length === 0) {
    return (
      <div className="card text-center py-8">
        <span className="text-3xl mb-3 block">📈</span>
        <p className="text-gray-400 text-sm">No risk history yet</p>
        <p className="text-xs text-gray-600">Complete a scan to start tracking risk trends</p>
      </div>
    );
  }

  const data = history.map((h, i) => ({
    index: i + 1,
    name: `Scan ${i + 1}`,
    score: h.score,
    level: h.risk_level,
    findings: h.total_findings,
    critical: h.critical_count,
    date: h.created_at ? new Date(String(h.created_at).replace(' ', 'T')).toLocaleDateString() : 'N/A',
  }));

  const latestScore = data[data.length - 1]?.score ?? 0;
  const prevScore = data.length > 1 ? data[data.length - 2]?.score ?? 0 : latestScore;
  const delta = latestScore - prevScore;

  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Risk Trend</h3>
        {data.length > 1 && (
          <span className={`text-sm font-bold ${delta > 0 ? 'text-red-400' : delta < 0 ? 'text-green-400' : 'text-gray-400'}`}>
            {delta > 0 ? '▲' : delta < 0 ? '▼' : '—'} {Math.abs(delta).toFixed(1)}
          </span>
        )}
      </div>

      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={{ stroke: '#1e293b' }} />
            <YAxis domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={{ stroke: '#1e293b' }} />
            <Tooltip
              contentStyle={{ background: '#1a2235', border: '1px solid #2a3550', borderRadius: '8px', fontSize: '12px' }}
              labelStyle={{ color: '#9ca3af' }}
            />
            <Area type="monotone" dataKey="score" stroke="#3b82f6" fill="url(#riskGradient)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
