import { useState } from 'react';

export default function SettingsPage() {
  const [apiKey, setApiKey] = useState(localStorage.getItem('sentinel_api_key') || '');
  const [saved, setSaved] = useState(false);

  const handleSaveKey = () => {
    localStorage.setItem('sentinel_api_key', apiKey);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="border-b border-sentinel-border pb-4">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <span>⚙️</span> Platform Settings
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Organization preferences, API credentials, and deterministic engine thresholds
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* API Credentials */}
        <div className="card p-6 space-y-4">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <span>🔑</span> API Key Configuration
          </h2>
          <p className="text-xs text-gray-400">
            Configure authorization token sent to backend routes with <code className="bg-sentinel-surface px-1.5 py-0.5 rounded text-sentinel-accent font-mono">X-API-Key</code>.
          </p>
          <div className="space-y-2">
            <input
              type="password"
              placeholder="Enter Sentinel API Key (Optional in local dev)"
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
              className="input-field text-xs py-2 font-mono"
            />
            <div className="flex justify-between items-center pt-2">
              <span className="text-[11px] text-gray-500">Stored in browser localStorage</span>
              <button onClick={handleSaveKey} className="btn-primary text-xs py-1.5 px-4">
                {saved ? '✓ Saved!' : 'Save Key'}
              </button>
            </div>
          </div>
        </div>

        {/* Storage Architecture */}
        <div className="card p-6 space-y-4">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <span>💾</span> Backend Persistence Status
          </h2>
          <div className="space-y-3 text-xs">
            <div className="flex justify-between py-1.5 border-b border-sentinel-border">
              <span className="text-gray-400">Active Storage Engine:</span>
              <span className="text-green-400 font-semibold">SQLite (sentinel.db)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-sentinel-border">
              <span className="text-gray-400">PostgreSQL Ready:</span>
              <span className="text-sentinel-accent font-semibold">Enabled (SQLAlchemy Dialect)</span>
            </div>
            <div className="flex justify-between py-1.5 border-b border-sentinel-border">
              <span className="text-gray-400">Emergency JSON Fallback:</span>
              <span className="text-gray-300 font-semibold">Active at backend/data/json_fallback/</span>
            </div>
            <div className="flex justify-between py-1.5">
              <span className="text-gray-400">Intelligence Source:</span>
              <span className="text-white font-semibold">OSV.dev Network API (Live)</span>
            </div>
          </div>
        </div>

        {/* Engine Rules & Thresholds */}
        <div className="card p-6 space-y-4 md:col-span-2">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <span>🛡️</span> Deterministic Security Engine Parameters
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
              <span className="text-gray-400 block uppercase text-[10px]">Vulnerability Weight</span>
              <span className="text-base font-bold text-white mt-1 block">40%</span>
              <span className="text-gray-500 text-[10px]">OSV / GHSA / NVD</span>
            </div>
            <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
              <span className="text-gray-400 block uppercase text-[10px]">Behavioral Weight</span>
              <span className="text-base font-bold text-white mt-1 block">20%</span>
              <span className="text-gray-500 text-[10px]">Post-install hooks</span>
            </div>
            <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
              <span className="text-gray-400 block uppercase text-[10px]">Typosquatting Weight</span>
              <span className="text-base font-bold text-white mt-1 block">20%</span>
              <span className="text-gray-500 text-[10px]">Levenshtein distance</span>
            </div>
            <div className="bg-sentinel-surface p-3 rounded-lg border border-sentinel-border">
              <span className="text-gray-400 block uppercase text-[10px]">Health & Hygiene</span>
              <span className="text-base font-bold text-white mt-1 block">20%</span>
              <span className="text-gray-500 text-[10px]">Unpinned wildcards</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
