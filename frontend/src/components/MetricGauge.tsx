import { useMemo } from 'react';

interface MetricGaugeProps {
  score: number;
  label?: string;
  size?: number;
  showLevel?: boolean;
}

const RISK_COLORS: Record<string, { stroke: string; glow: string; text: string }> = {
  LOW: { stroke: '#22c55e', glow: 'rgba(34,197,94,0.3)', text: 'text-green-400' },
  MEDIUM: { stroke: '#eab308', glow: 'rgba(234,179,8,0.3)', text: 'text-yellow-400' },
  HIGH: { stroke: '#f97316', glow: 'rgba(249,115,22,0.3)', text: 'text-orange-400' },
  CRITICAL: { stroke: '#ef4444', glow: 'rgba(239,68,68,0.3)', text: 'text-red-400' },
};

function getRiskLevel(score: number): string {
  if (score <= 30) return 'LOW';
  if (score <= 60) return 'MEDIUM';
  if (score <= 80) return 'HIGH';
  return 'CRITICAL';
}

export default function MetricGauge({ score, label = 'Risk Score', size = 160, showLevel = true }: MetricGaugeProps) {
  const level = getRiskLevel(score);
  const colors = RISK_COLORS[level] || RISK_COLORS.LOW;

  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const dashOffset = circumference - progress;

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          {/* Background circle */}
          <circle
            cx={size / 2} cy={size / 2} r={radius}
            fill="none" stroke="#1e293b" strokeWidth="8"
          />
          {/* Progress circle */}
          <circle
            cx={size / 2} cy={size / 2} r={radius}
            fill="none"
            stroke={colors.stroke}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            style={{
              filter: `drop-shadow(0 0 8px ${colors.glow})`,
              transition: 'stroke-dashoffset 1s ease-out',
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold ${colors.text}`}>{Math.round(score)}</span>
          {showLevel && (
            <span className={`text-xs font-semibold uppercase tracking-wider ${colors.text}`}>
              {level}
            </span>
          )}
        </div>
      </div>
      <span className="text-xs text-gray-500 uppercase tracking-wider">{label}</span>
    </div>
  );
}
