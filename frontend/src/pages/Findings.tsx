import { useEffect, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import FindingsTable from '../components/FindingsTable';
import EvidenceModal from '../components/EvidenceModal';
import type { Finding } from '../types';

export default function Findings() {
  const { scanId } = useParams<{ scanId?: string }>();
  const [searchParams] = useSearchParams();
  const searchFilter = searchParams.get('search') || '';

  const [activeScanId, setActiveScanId] = useState<string>(scanId || '');
  const [projects, setProjects] = useState<any[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  useEffect(() => {
    if (scanId) {
      setActiveScanId(scanId);
      return;
    }

    const loadFindingsScan = () => {
      api.listProjects()
        .then(prjs => {
          setProjects(prjs);
          if (prjs.length > 0) {
            const saved = localStorage.getItem('sentinel_active_project');
            const current = prjs.find(p => p.id === saved) || prjs[0];
            const scans = current.scans || [];
            const completed = scans.find((s: any) => s.status === 'COMPLETED');
            const targetScan = completed || scans[0];
            if (targetScan) {
              setActiveScanId(targetScan.id);
            } else {
              setFindings([]);
              setLoading(false);
            }
          } else {
            setFindings([]);
            setLoading(false);
          }
        })
        .catch(() => setLoading(false));
    };

    loadFindingsScan();

    const handleProjChange = () => loadFindingsScan();
    window.addEventListener('storage', handleProjChange);
    window.addEventListener('sentinel:project-change', handleProjChange);
    return () => {
      window.removeEventListener('storage', handleProjChange);
      window.removeEventListener('sentinel:project-change', handleProjChange);
    };
  }, [scanId]);

  useEffect(() => {
    if (!activeScanId) return;
    setLoading(true);
    api.getScanFindings(activeScanId)
      .then(res => {
        if (searchFilter) {
          setFindings(res.filter((f: any) =>
            f.component_name?.toLowerCase().includes(searchFilter.toLowerCase()) ||
            f.title?.toLowerCase().includes(searchFilter.toLowerCase()) ||
            f.cve_id?.toLowerCase().includes(searchFilter.toLowerCase())
          ));
        } else {
          setFindings(res);
        }
      })
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));
  }, [activeScanId, searchFilter]);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>🔍</span> Vulnerability & Security Findings
          </h1>
          <p className="text-xs text-gray-400 font-mono mt-1">
            {activeScanId ? `Ingested Scan: ${activeScanId}` : 'Select a project to inspect findings'}
          </p>
        </div>

        {projects.length > 0 && !scanId && (
          <select
            value={activeScanId}
            onChange={e => setActiveScanId(e.target.value)}
            className="input-field py-1.5 px-3 text-xs max-w-xs"
          >
            {projects.map(p => (
              <optgroup key={p.id} label={`📁 ${p.name}`}>
                {(p.scans || []).map((s: any) => (
                  <option key={s.id} value={s.id}>
                    Scan {s.id.slice(0, 10)} ({s.input_format || 'auto'}) · {s.risk_level}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        )}
      </div>

      {loading ? (
        <div className="flex justify-center py-24">
          <div className="animate-spin w-8 h-8 border-2 border-sentinel-accent border-t-transparent rounded-full" />
        </div>
      ) : findings.length === 0 ? (
        <div className="card text-center py-16 space-y-2 text-gray-400">
          <span className="text-4xl block">🛡️</span>
          <p className="font-semibold text-white">No Findings Detected</p>
          <p className="text-xs text-gray-500">
            {searchFilter ? `No findings matched search filter "${searchFilter}".` : 'All evaluated packages in this scan are clean.'}
          </p>
        </div>
      ) : (
        <FindingsTable findings={findings} onSelect={setSelectedFinding} />
      )}

      {selectedFinding && (
        <EvidenceModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
