# 🛡️ Supply-Chain Sentinel

**Software Supply-Chain Security Platform**

Evidence-based risk estimation, dependency security analysis, and supply-chain threat detection.

## Architecture

```
REACT FRONTEND → FASTAPI API → SCAN ORCHESTRATOR
                                      ↓
            SBOM/Manifest Parsing → Normalization → PURL
                                      ↓
                              Dependency Graph (NetworkX)
                                      ↓
                        Threat Intelligence (Local + OSV)
                                      ↓
              ┌─────────────┬──────────────┬────────────────┬──────────┐
        Vulnerability  Behavioral  Typosquatting  Reputation  Health
              └─────────────┴──────────────┴────────────────┴──────────┘
                                      ↓
                    Signal Processing → Context → Blast Radius
                                      ↓
                          Deterministic Risk Engine
                                      ↓
                    Policy Engine → ALLOW / REVIEW / BLOCK
                                      ↓
                      Remediation → Risk History → Storage
```

## Supported Inputs

| Format | Status |
|--------|--------|
| CycloneDX JSON | ✅ Primary |
| SPDX JSON | ✅ Primary |
| package.json | ✅ Manifest |
| requirements.txt | ✅ Manifest |

## Security Engines

1. **Vulnerability Engine** — Known CVEs via local fixtures + OSV enrichment
2. **Behavioral Engine** — Static detection of suspicious install scripts (curl, wget, eval, exec, child_process)
3. **Typosquatting Engine** — Levenshtein distance against protected package dictionary
4. **Reputation Engine** — Known malicious/suspicious package database
5. **Dependency Health** — Unpinned versions, wildcard ranges, missing licenses

## Risk Model

- **Score**: 0–100 deterministic weighted combination
- **Levels**: LOW (0–30), MEDIUM (31–60), HIGH (61–80), CRITICAL (81–100)
- **Confidence**: 0.0–1.0 based on data quality and source diversity
- **Data Quality**: COMPLETE / PARTIAL / MINIMAL / UNKNOWN

> Risk Score ≠ Confidence. A score of 87 with confidence 0.71 means "high risk signal with partial data."

## Policy Engine

| Environment | CRITICAL | HIGH | MEDIUM | LOW |
|-------------|----------|------|--------|-----|
| Production  | BLOCK    | REVIEW | ALLOW | ALLOW |
| Staging     | REVIEW   | REVIEW | ALLOW | ALLOW |
| Development | REVIEW   | ALLOW  | ALLOW | ALLOW |

Custom per-project policies supported.

## Quick Start

### Backend
```bash
cd backend
pip install -r requirements.txt
python main.py
# Runs on http://localhost:8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173
```

### API
```
POST /api/v1/projects                    — Create project
GET  /api/v1/projects                    — List projects
POST /api/v1/projects/{id}/scans         — Start scan (returns 202)
GET  /api/v1/scans/{id}/status           — Poll scan progress
GET  /api/v1/scans/{id}/report           — Full scan report
GET  /api/v1/scans/{id}/findings         — Findings list
GET  /api/v1/projects/{id}/risk-history  — Risk trend
GET  /api/v1/projects/{id}/dependencies  — Dependency graph
GET  /api/v1/projects/{id}/policies      — Policies
POST /api/v1/projects/{id}/policies      — Create policy
GET  /health                             — Health check
```


## Limitations

This system provides **evidence-based risk estimation**, not prediction guarantees.

- Same observable signals can be compatible with multiple future outcomes
- Unknown information remains UNKNOWN, never silently becomes SAFE
- Confidence and data quality are always reported alongside scores
- LLM/AI never determines final risk score, severity, or policy decisions
- External intelligence timeout does not fail a scan

## Tech Stack

- **Backend**: Python, FastAPI, SQLAlchemy, SQLite, NetworkX
- **Frontend**: React, TypeScript, Vite, Tailwind CSS, Recharts, Cytoscape.js
- **Intelligence**: Local CVE fixtures (always available) + OSV (optional enrichment)
