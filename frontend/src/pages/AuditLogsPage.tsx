import { useEffect, useState } from 'react';
import { api } from '../api/client';

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');

  useEffect(() => {
    api.listAuditLogs()
      .then(setLogs)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const filteredLogs = logs.filter(l => {
    const matchesSearch = !search ||
      l.action?.toLowerCase().includes(search.toLowerCase()) ||
      l.resource_id?.toLowerCase().includes(search.toLowerCase()) ||
      l.resource_type?.toLowerCase().includes(search.toLowerCase());
    if (!matchesSearch) return false;
    if (actionFilter === 'SCANS') return l.resource_type === 'scan';
    if (actionFilter === 'PROJECTS') return l.resource_type === 'project';
    if (actionFilter === 'POLICIES') return l.resource_type === 'policy';
    return true;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>📜</span> Audit Evidence Log
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Immutable system audit trail verifying scan provenance, policy decisions, and operator interventions
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 text-xs font-semibold rounded bg-green-500/10 text-green-400 border border-green-500/20 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-green-500"></span> Live SQLite Persistence Active
          </span>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-sentinel-card/40 p-3 rounded-lg border border-sentinel-border">
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <span className="text-gray-500">🔍</span>
          <input
            type="text"
            placeholder="Search action, resource ID, or type..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="input-field py-1.5 text-xs"
          />
        </div>

        <div className="flex items-center gap-2">
          {['ALL', 'SCANS', 'PROJECTS', 'POLICIES'].map(f => (
            <button
              key={f}
              onClick={() => setActionFilter(f)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors ${
                actionFilter === f ? 'bg-sentinel-accent text-white' : 'bg-sentinel-card text-gray-400 hover:text-white'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Logs Table */}
      {loading ? (
        <div className="flex justify-center py-24">
          <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
        </div>
      ) : filteredLogs.length === 0 ? (
        <div className="card text-center py-16 text-gray-400 text-sm">
          No audit records found matching search filters.
        </div>
      ) : (
        <div className="card p-0 overflow-hidden border border-sentinel-border">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-sentinel-card/80 border-b border-sentinel-border text-gray-400 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4 font-semibold">Timestamp</th>
                  <th className="py-3 px-4 font-semibold">Operator / Origin</th>
                  <th className="py-3 px-4 font-semibold">Action</th>
                  <th className="py-3 px-4 font-semibold">Resource</th>
                  <th className="py-3 px-4 font-semibold">Audit Details & Cryptographic Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/40 text-gray-300">
                {filteredLogs.map((l, i) => {
                  let parsedDetails = null;
                  try {
                    parsedDetails = typeof l.details === 'string' ? JSON.parse(l.details) : l.details;
                  } catch {
                    parsedDetails = l.details;
                  }

                  return (
                    <tr key={i} className="hover:bg-sentinel-card/40 transition-colors">
                      <td className="py-3 px-4 font-mono text-gray-400 whitespace-nowrap">
                        {l.created_at ? l.created_at.split('.')[0] : 'N/A'}
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-semibold text-white">{l.user_id || 'system'}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          l.action?.includes('completed') ? 'bg-green-500/20 text-green-400' :
                          l.action?.includes('started') ? 'bg-blue-500/20 text-blue-400' :
                          l.action?.includes('created') ? 'bg-purple-500/20 text-purple-400' :
                          'bg-gray-500/20 text-gray-300'
                        }`}>
                          {l.action}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-gray-300">
                        <span className="text-gray-500 uppercase text-[10px] block">{l.resource_type}</span>
                        {l.resource_id}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-gray-300 max-w-md truncate">
                        {parsedDetails ? (
                          typeof parsedDetails === 'object' ? (
                            <span title={JSON.stringify(parsedDetails)}>
                              {Object.entries(parsedDetails).map(([k, v]) => `${k}: ${v}`).join(' · ')}
                            </span>
                          ) : (
                            String(parsedDetails)
                          )
                        ) : (
                          <span className="text-gray-600">None</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
