interface ScanProgressProps {
  status: string;
  progress: number;
  message: string;
}

const STATUS_COLORS: Record<string, string> = {
  PENDING: 'bg-gray-500',
  PARSING: 'bg-blue-500',
  NORMALIZING: 'bg-blue-500',
  BUILDING_GRAPH: 'bg-cyan-500',
  ENRICHING: 'bg-purple-500',
  ANALYZING: 'bg-orange-500',
  SCORING: 'bg-yellow-500',
  APPLYING_POLICY: 'bg-green-500',
  COMPLETED: 'bg-green-500',
  FAILED: 'bg-red-500',
};

export default function ScanProgress({ status, progress, message }: ScanProgressProps) {
  const barColor = STATUS_COLORS[status] || 'bg-blue-500';
  const isComplete = status === 'COMPLETED';
  const isFailed = status === 'FAILED';
  const isRunning = !isComplete && !isFailed;

  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Scan Progress</h3>
        <span className={`badge ${isFailed ? 'badge-critical' : isComplete ? 'badge-low' : 'badge-medium'}`}>
          {status}
        </span>
      </div>

      {/* Progress bar */}
      <div className="relative w-full h-2 bg-sentinel-bg rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-1000 ease-out ${barColor}`}
          style={{ width: `${Math.max(progress, 0)}%` }}
        />
        {isRunning && (
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent animate-[shimmer_2s_infinite]" />
        )}
      </div>

      <div className="flex items-center justify-between text-xs text-gray-500">
        <span>{message}</span>
        <span>{progress >= 0 ? `${progress}%` : '—'}</span>
      </div>

      {/* Stage indicators */}
      <div className="flex justify-between text-[10px] text-gray-600 gap-1">
        {['Parse', 'Normalize', 'Graph', 'Intel', 'Analyze', 'Score', 'Policy'].map((stage, i) => {
          const stageProgress = (i + 1) * 14;
          const active = progress >= stageProgress;
          return (
            <div key={stage} className={`text-center transition-colors ${active ? 'text-sentinel-accent' : ''}`}>
              <div className={`w-2 h-2 mx-auto mb-1 rounded-full ${active ? barColor : 'bg-sentinel-border'}`} />
              {stage}
            </div>
          );
        })}
      </div>
    </div>
  );
}
