import { useState } from 'react';

export default function CICDSecurity() {
  const [activeTab, setActiveTab] = useState<'github' | 'gitlab'>('github');

  const githubWorkflow = `# .github/workflows/sentinel-audit.yml
name: Supply-Chain Sentinel Security Gate

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  sentinel-scan:
    name: Deterministic Supply Chain Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Send Manifest to Sentinel Engine
        env:
          SENTINEL_API_URL: "http://sentinel.internal:8001/api/v1"
          SENTINEL_API_KEY: \${{ secrets.SENTINEL_API_KEY }}
        run: |
          echo "Ingesting SBOM / Lockfile..."
          curl -X POST "\$SENTINEL_API_URL/projects/\${{ secrets.PROJECT_ID }}/scans" \\
            -H "Content-Type: application/json" \\
            -H "X-API-Key: \$SENTINEL_API_KEY" \\
            -d "{\\"raw_content\\": \\"$(cat package.json | jq -sRr @json)\\", \\"input_type\\": \\"package_json\\"}"
`;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-sentinel-border pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>⚙️</span> CI/CD Security Pipeline Gating
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Automated build prevention, pull request comments, and SLSA provenance checks
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              window.dispatchEvent(
                new CustomEvent('open-ai-analyst', {
                  detail: {
                    projectId: localStorage.getItem('sentinel_active_project') || '',
                    mode: 'policy',
                    question: 'Why was the build policy decision set and how do I clear the gate?',
                  },
                })
              );
            }}
            className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600/30 to-cyan-600/30 hover:from-blue-600/50 hover:to-cyan-600/50 border border-cyan-500/50 text-cyan-300 hover:text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm shadow-cyan-500/10 transition-all cursor-pointer"
          >
            <span>🤖</span>
            <span>Ask AI Why Gated</span>
          </button>
          <span className="px-2.5 py-1 text-xs font-semibold rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">
            Integration Listener Ready
          </span>
        </div>
      </div>

      {/* Visual Pipeline Flow */}
      <div className="card p-6 space-y-4">
        <h2 className="text-xs font-bold text-gray-400 uppercase tracking-wider">
          Enterprise Continuous Delivery Security Gate
        </h2>
        <div className="flex flex-wrap items-center justify-between gap-3 text-center">
          {[
            { label: '1. Commit / Push', icon: '💻', desc: 'Code committed to branch' },
            { label: '2. Build & Lock', icon: '📦', desc: 'Dependencies resolved' },
            { label: '3. SBOM Extraction', icon: '📑', desc: 'CycloneDX / SPDX gen' },
            { label: '4. Sentinel Scan', icon: '🛡️', desc: 'Deterministic analysis' },
            { label: '5. Policy Gate', icon: '⚖️', desc: 'ALLOW / REVIEW / BLOCK' },
          ].map((step, i) => (
            <div key={i} className="flex-1 min-w-[140px] bg-sentinel-surface p-4 rounded-lg border border-sentinel-border relative">
              <span className="text-2xl block mb-1">{step.icon}</span>
              <span className="text-xs font-bold text-white block">{step.label}</span>
              <span className="text-[10px] text-gray-500 mt-1 block">{step.desc}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Connection Status Box */}
      <div className="card p-5 border border-sentinel-border flex items-start gap-4 bg-sentinel-surface/50">
        <span className="text-2xl">ℹ️</span>
        <div className="space-y-1 text-xs">
          <h3 className="text-white font-bold text-sm">Webhook Endpoint Status</h3>
          <p className="text-gray-400">
            Active webhook receiver listening at: <code className="bg-sentinel-card px-2 py-0.5 rounded text-sentinel-accent font-mono">/api/v1/webhooks/github</code>.
          </p>
          <p className="text-gray-500">
            External CI/CD runner is not currently executing an active build. In production, configure the webhook secret in your repository settings to trigger automated scans upon pull requests.
          </p>
        </div>
      </div>

      {/* Integration Instructions */}
      <div className="card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Copy-Paste Pipeline Integration Config
          </h2>
          <div className="flex gap-2">
            <button
              onClick={() => setActiveTab('github')}
              className={`px-3 py-1 text-xs font-semibold rounded ${activeTab === 'github' ? 'bg-sentinel-accent text-white' : 'bg-sentinel-card text-gray-400'}`}
            >
              GitHub Actions
            </button>
            <button
              onClick={() => setActiveTab('gitlab')}
              className={`px-3 py-1 text-xs font-semibold rounded ${activeTab === 'gitlab' ? 'bg-sentinel-accent text-white' : 'bg-sentinel-card text-gray-400'}`}
            >
              GitLab CI
            </button>
          </div>
        </div>

        <pre className="p-4 rounded-lg bg-gray-950 font-mono text-xs text-green-400 overflow-x-auto border border-gray-800 leading-relaxed">
          {githubWorkflow}
        </pre>
      </div>
    </div>
  );
}
