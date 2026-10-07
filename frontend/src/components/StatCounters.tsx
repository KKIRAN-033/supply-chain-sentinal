interface StatCountersProps {
  stats: Array<{
    label: string;
    value: number | string;
    color?: string;
    icon?: string;
  }>;
}

const COLOR_MAP: Record<string, string> = {
  red: 'from-red-500/20 to-red-600/5 border-red-500/20 text-red-400',
  orange: 'from-orange-500/20 to-orange-600/5 border-orange-500/20 text-orange-400',
  yellow: 'from-yellow-500/20 to-yellow-600/5 border-yellow-500/20 text-yellow-400',
  green: 'from-green-500/20 to-green-600/5 border-green-500/20 text-green-400',
  blue: 'from-blue-500/20 to-blue-600/5 border-blue-500/20 text-blue-400',
  gray: 'from-gray-500/20 to-gray-600/5 border-gray-500/20 text-gray-400',
};

export default function StatCounters({ stats }: StatCountersProps) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {stats.map((stat, i) => {
        const colorClass = COLOR_MAP[stat.color || 'blue'] || COLOR_MAP.blue;
        return (
          <div
            key={i}
            className={`bg-gradient-to-br ${colorClass} border rounded-xl p-4 transition-all duration-300 hover:scale-[1.02]`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-gray-400 uppercase tracking-wider">{stat.label}</span>
              {stat.icon && <span className="text-lg">{stat.icon}</span>}
            </div>
            <div className="text-2xl font-bold">{stat.value}</div>
          </div>
        );
      })}
    </div>
  );
}
