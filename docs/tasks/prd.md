# Supply-Chain Sentinel PRD

> **Version**: 1.0.0
> **Last Audit**: 2026-10-06
> **Repository**: `supply-chain-sentinel/`
> **Consumed By**: Ralph Loop / Autonomous Coding Agent

---

## 1. Product Overview

Supply-Chain Sentinel is a full-stack software supply-chain security platform. It ingests SBOMs and dependency manifests, normalizes components using PURLs, builds dependency relationships, enriches components with vulnerability intelligence, performs multiple security analyses, calculates an explainable deterministic risk score, applies organization policies, provides remediation guidance, verifies fixes through re-scanning, tracks risk history, and exposes results through a professional React dashboard and CI/CD integration.

**Category**: Software Supply-Chain Security Platform
**Stack**: React/Vite/TypeScript frontend + Python/FastAPI/SQLAlchemy backend
**Database**: SQLite (current) → PostgreSQL (future)
**Intelligence**: Local fixtures (always-on) + OSV (optional enrichment)

---

## 2. Problem Statement

Organizations lack visibility into the security posture of their software dependencies. Existing tools either:
- Provide only CVE lookup without behavioral, typosquatting, or health analysis
- Require complex infrastructure (PostgreSQL, Redis, Celery) for basic functionality
- Use opaque scoring without explainability
- Treat missing data as safe rather than unknown
- Cannot operate offline or with degraded connectivity

Supply-Chain Sentinel addresses these gaps with an evidence-based, deterministic, explainable risk assessment platform that operates reliably with zero external dependencies.

---

## 3. Goals

1. **Comprehensive Analysis**: Vulnerability, behavioral, typosquatting, reputation, and health analysis in a single platform
2. **Deterministic Risk**: Same input always produces same score — no LLM in the scoring path
3. **Evidence-Based**: Every finding has structured evidence, not opaque numbers
4. **Offline-First**: Full functionality using local intelligence; external enrichment is optional
5. **Explainability**: Users understand WHY a score was assigned
6. **Policy Automation**: ALLOW/REVIEW/BLOCK decisions based on configurable policy
7. **Fix Verification**: Re-scan to confirm remediation resolved findings
8. **Risk Trending**: Track security posture over time
9. **CI/CD Ready**: Architecture supports automated security gates

---

## 4. Non-Goals

These are NOT required for the current implementation:

- Mandatory PostgreSQL, Redis, or Celery
- Mandatory Docker deployment
- Dynamic package sandboxing or execution
- Full ML/AI-driven scoring
- Mandatory external vulnerability APIs
- Enterprise SSO or advanced RBAC
- Multi-tenant production deployment
- S3/MinIO object storage
- Distributed worker infrastructure

These are future production extensions. The current system must be structured so they can be introduced without rewriting core business logic.

---

## 5. Target Users

| User | Need |
|------|------|
| **Security Engineer** | Assess supply-chain risk, review findings, configure policies |
| **Developer** | Upload SBOMs, understand vulnerabilities, get remediation guidance |
| **DevOps / CI Pipeline** | Automated scan → policy decision → ALLOW/REVIEW/BLOCK |
| **Engineering Manager** | Dashboard risk overview, risk trends, posture reporting |
| **Compliance Officer** | Audit trail, policy enforcement evidence, historical reports |

---

## 6. User Journeys

### Journey 1: Manual SBOM Analysis
```
Developer → Upload SBOM → Scan → View Findings → Read Remediation → Fix → Re-scan → Verify
```

### Journey 2: CI/CD Integration
```
Commit → CI generates SBOM → POST to API → Scan → Policy Engine → ALLOW/REVIEW/BLOCK → Gate
```

### Journey 3: Risk Monitoring
```
Security Engineer → Dashboard → View Projects → Risk History → Identify Trends → Prioritize
```

### Journey 4: Policy Configuration
```
Security Lead → Create Policy → Set Thresholds → Apply to Project/Environment
```

---

## 7. Functional Requirements

### 7.1 Core Principle

The authoritative security path is deterministic. LLM/AI is optional and explanatory only.

**LLM MUST NOT**: determine risk score, severity, ALLOW/REVIEW/BLOCK decisions.
**LLM MAY**: summarize evidence, explain findings, generate human-readable descriptions.

### 7.2 Functional Domains

| ID | Domain | Priority |
|----|--------|----------|
| A | Authentication / Access | P1 |
| B | Organizations / Projects | P0 |
| C | SBOM Ingestion (CycloneDX) | P0 |
| D | Manifest Ingestion (package.json, requirements.txt) | P0 |
| E | SBOM Integrity / Provenance | P1 |
| F | Canonicalization / PURL | P0 |
| G | Dependency Graph | P0 |
| H | Vulnerability Intelligence | P0 |
| I | Behavioral Analysis | P0 |
| J | Typosquatting Detection | P0 |
| K | Reputation Analysis | P0 |
| L | Dependency Health Analysis | P0 |
| M | Signal Processing | P0 |
| N | Context / Reachability | P1 |
| O | Blast Radius | P1 |
| P | Deterministic Risk Engine | P0 |
| Q | Confidence / Data Quality | P0 |
| R | Policy Engine | P0 |
| S | CI/CD Security Gate | P1 |
| T | Explainability | P1 |
| U | Remediation | P0 |
| V | Fix Verification | P1 |
| W | Continuous Monitoring | P2 |
| X | Alerts | P1 |
| Y | Historical Risk | P0 |
| Z | Audit / Observability | P1 |
| AA | Reports | P1 |
| AB | Offline Evaluation | P2 |
| AC | Formal Prediction Limitation | P2 |
| AD | Storage Abstraction & Fallback | P0 |

---

## 8. Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| Scan completion (3 components, local only) | < 5 seconds |
| Scan completion (50 components, with OSV) | < 30 seconds |
| OSV timeout | 2 seconds strict |
| Maximum upload size | 50 MB |
| Risk score determinism | Identical input → identical output |
| Score bounds | 0 ≤ score ≤ 100 |
| Offline operation | Full scan without internet |
| Frontend build | TypeScript clean, Vite build passes |
| Backend startup | < 5 seconds including DB init |

---

## 9. System Architecture

### Approved Runtime Flow

```
USER / DEVELOPER
        ↓
REACT FRONTEND (Vite + TypeScript + Tailwind)
        ↓
FASTAPI API (Pydantic validation)
        ↓
SCAN ORCHESTRATOR (run_scan — portable, no FastAPI import)
        ↓
FORMAT DETECTION → PARSING → NORMALIZATION + PURL
        ↓
SBOM INTEGRITY + PROVENANCE
        ↓
DEPENDENCY GRAPH (NetworkX)
        ↓
THREAT INTELLIGENCE (Local + OSV)
        ↓
SECURITY ANALYSIS (5 engines)
        ↓
SIGNAL PROCESSOR (deduplicate, normalize, sort)
        ↓
CONTEXT ENGINE (environment, criticality multipliers)
        ↓
BLAST RADIUS (graph-derived, not hardcoded)
        ↓
DETERMINISTIC RISK ENGINE (weighted category scores)
        ↓
POLICY ENGINE (ALLOW / REVIEW / BLOCK)
        ↓
REMEDIATION ENGINE (upgrade, replace, remove, mitigate, configure)
        ↓
STORAGE (SQLAlchemy → SQLite + JSON fallback)
        ↓
RISK HISTORY + AUDIT LOG
```

### Key Architecture Rules

1. Orchestrator is decoupled from FastAPI — portable to Celery
2. Repository pattern isolates business logic from SQLAlchemy
3. Intelligence providers implement abstract `VulnerabilityProvider` interface
4. All parsers converge to `CanonicalComponent` — no format-specific security logic
5. JSON fallback activates on SQLite persistence failure
6. PostgreSQL migration requires only changing `DATABASE_URL` and removing `check_same_thread`

### File Structure

```
backend/
├── main.py                          # FastAPI entry point
├── requirements.txt                 # Python dependencies
├── app/
│   ├── core/
│   │   ├── config.py               # Pydantic Settings (SCS_ env prefix)
│   │   ├── constants.py            # Enums, thresholds, patterns
│   │   └── security.py             # ID generation, SHA-256, API key
│   ├── db/
│   │   ├── base.py                 # SQLAlchemy engine, Base, init_db
│   │   ├── models.py               # 8 ORM models
│   │   ├── repositories.py         # CRUD + JSON fallback
│   │   └── session.py              # Re-exports
│   ├── schemas/
│   │   ├── components.py           # CanonicalComponent (Pydantic)
│   │   ├── scans.py                # Request/response schemas
│   │   ├── findings.py             # Finding response
│   │   ├── policies.py             # Policy schemas
│   │   └── reports.py              # Report schema
│   ├── engine/
│   │   ├── orchestrator.py         # run_scan — core pipeline
│   │   ├── parser.py               # Multi-format parser
│   │   ├── normalizer.py           # PURL + dedup
│   │   ├── dependency_graph.py     # NetworkX graph + fallback
│   │   ├── signal_processor.py     # Dedup, normalize, sort
│   │   ├── context_engine.py       # Environment/criticality multipliers
│   │   ├── blast_radius.py         # Graph-derived blast radius
│   │   ├── intelligence/
│   │   │   ├── base.py             # VulnerabilityProvider ABC
│   │   │   ├── local.py            # Local CVE fixture provider
│   │   │   └── osv.py              # OSV.dev provider with timeout
│   │   ├── rules/
│   │   │   ├── vulnerability.py    # CVE matching engine
│   │   │   ├── behavioral.py       # Suspicious pattern detection
│   │   │   ├── typosquatting.py    # Levenshtein distance engine
│   │   │   ├── reputation.py       # Known-bad package engine
│   │   │   └── health.py           # Dependency hygiene engine
│   │   ├── scoring/
│   │   │   └── risk_engine.py      # Weighted deterministic scorer
│   │   ├── policy/
│   │   │   └── policy_engine.py    # ALLOW/REVIEW/BLOCK decisions
│   │   └── remediation/
│   │       └── remediation_engine.py # Structured remediation guidance
│   ├── api/v1/
│   │   ├── router.py               # Route aggregation
│   │   ├── projects.py             # Project CRUD
│   │   ├── scans.py                # Scan lifecycle + report
│   │   └── policies.py             # Policy CRUD
│   ├── integrations/               # Future: GitHub, GitLab
│   └── services/                   # Future: higher-level services
├── data/
│   ├── cve_fixtures.json           # 8 CVEs (lodash, express, jwt, etc.)
│   ├── protected_packages.json     # 50+ protected packages (npm, pypi)
│   ├── reputation.json             # Known suspicious/malicious packages
│   └── demo_cases/                 # Clean, CVE, Poisoned SBOMs
└── tests/
    ├── test_core.py                # 17 unit tests
    └── test_e2e.py                 # End-to-end API test

frontend/
├── index.html
├── package.json                    # React, Tailwind, Recharts, Cytoscape
├── vite.config.ts                  # Proxy /api → localhost:8000
├── tailwind.config.js
├── tsconfig.json
└── src/
    ├── App.tsx                     # Router + sidebar layout
    ├── main.tsx                    # React entry
    ├── index.css                   # Tailwind + cybersecurity theme
    ├── api/client.ts               # Typed API client
    ├── types/index.ts              # TypeScript contracts
    ├── pages/
    │   ├── Dashboard.tsx
    │   ├── Projects.tsx
    │   ├── ProjectDetails.tsx
    │   ├── SBOMUpload.tsx
    │   ├── ScanDetails.tsx
    │   ├── Findings.tsx
    │   └── Policies.tsx
    └── components/
        ├── MetricGauge.tsx
        ├── StatCounters.tsx
        ├── FindingsTable.tsx
        ├── ScanProgress.tsx
        ├── RiskTimeline.tsx
        ├── DependencyGraph.tsx
        ├── RemediationPanel.tsx
        └── ExplainabilityPanel.tsx
```

---

## 10. Data Model

### SQLAlchemy ORM Models (8 entities)

```
organizations
├── id (PK)
├── name
└── created_at

projects
├── id (PK)
├── organization_id (FK → organizations)
├── name
├── repo_url
├── environment
├── criticality
└── created_at

scans
├── id (PK)
├── project_id (FK → projects)
├── status (PENDING → COMPLETED/FAILED)
├── input_format
├── input_ecosystem
├── source
├── sbom_hash (SHA-256)
├── overall_score
├── risk_level
├── confidence
├── data_quality
├── policy_decision
├── total_components
├── vulnerable_count
├── suspicious_count
├── outdated_count
├── error_code
├── error_message
├── metrics_breakdown (JSON)
├── created_at
└── completed_at

components
├── id (PK)
├── scan_id (FK → scans)
├── purl
├── name
├── version
├── ecosystem
├── scope
├── is_direct
├── is_pinned
├── licenses (JSON)
└── install_scripts (JSON)

dependencies
├── id (PK)
├── scan_id (FK → scans)
├── parent_purl
└── child_purl

findings
├── id (PK)
├── scan_id (FK → scans)
├── component_purl
├── component_name
├── category
├── severity
├── score
├── confidence
├── title
├── description
├── cve_id
├── evidence (JSON)
├── remediation (JSON)
├── is_suppressed
├── suppression_reason
└── created_at

risk_history
├── id (PK)
├── project_id (FK → projects)
├── scan_id (FK → scans)
├── score
├── risk_level
├── confidence
├── total_findings
├── critical_count
├── high_count
├── medium_count
├── low_count
└── created_at

policies
├── id (PK)
├── project_id (FK → projects)
├── name
├── environment
├── rules (JSON)
├── is_active
└── created_at

audit_logs
├── id (PK)
├── organization_id (FK → organizations)
├── user_id
├── action
├── resource_type
├── resource_id
├── details (JSON)
└── created_at
```

### Canonical Component Model (Pydantic)

```python
class CanonicalComponent(BaseModel):
    component_id: str = ""
    name: str
    version: str = ""
    ecosystem: str = ""
    purl: str = ""
    scope: str = "runtime"
    is_direct: bool = True
    is_pinned: Optional[bool] = None
    install_scripts: list[str] = []
    licenses: list[str] = []
    dependencies: list[str] = []
```

**PURL Examples**:
- `pkg:npm/lodash@4.17.20`
- `pkg:pypi/requests@2.31.0`

**Rule**: Unknown values MUST remain UNKNOWN. Never silently convert to SAFE.

---

## 11. API Contracts

### Endpoints

| Method | Endpoint | Status Code | Purpose |
|--------|----------|-------------|---------|
| `GET` | `/health` | 200 | Health check |
| `POST` | `/api/v1/projects` | 201 | Create project |
| `GET` | `/api/v1/projects` | 200 | List projects |
| `GET` | `/api/v1/projects/{id}` | 200 | Get project details + latest scan |
| `POST` | `/api/v1/projects/{id}/scans` | 202 | Start async scan |
| `GET` | `/api/v1/scans/{id}/status` | 200 | Poll scan progress |
| `GET` | `/api/v1/scans/{id}/report` | 200 | Full scan report (completed only) |
| `GET` | `/api/v1/scans/{id}/findings` | 200 | Findings with filtering |
| `GET` | `/api/v1/projects/{id}/risk-history` | 200 | Risk trend data |
| `GET` | `/api/v1/projects/{id}/dependencies` | 200 | Dependency graph (Cytoscape format) |
| `GET` | `/api/v1/projects/{id}/policies` | 200 | List policies |
| `POST` | `/api/v1/projects/{id}/policies` | 201 | Create policy |

### Key Contracts

**POST /api/v1/projects/{id}/scans**
```json
Request:  { "input_type": "auto", "ecosystem": "", "raw_content": "...", "source": "upload" }
Response: { "scan_id": "scn_xxx", "status": "PENDING", "created_at": "..." }
```

**GET /api/v1/scans/{id}/status**
```json
Response: { "scan_id": "...", "status": "ANALYZING", "progress": 60, "message": "Running security analysis" }
```

**GET /api/v1/scans/{id}/report**
```json
Response: {
  "scan_id": "...", "project_id": "...",
  "summary": { "overall_score": 44.5, "risk_level": "MEDIUM", "confidence": 0.9, "data_quality": "COMPLETE", ... },
  "metrics_breakdown": { "vulnerability": 95, "behavioral": 0, ... },
  "policy_decision": "ALLOW",
  "findings": [...], "components": [...], "dependencies": [...]
}
```

---

## 12. Scan Lifecycle

### State Machine

```
PENDING (0%)
    ↓
PARSING (10%)
    ↓
NORMALIZING (20%)
    ↓
BUILDING_GRAPH (30%)
    ↓
ENRICHING (45%)
    ↓
ANALYZING (60%)
    ↓
SCORING (80%)
    ↓
APPLYING_POLICY (90%)
    ↓
COMPLETED (100%)

Any state → FAILED (-1%)
```

### Implementation Rules

1. Scan creation returns HTTP 202 immediately
2. `run_scan()` executes in `BackgroundTasks` with its own DB session
3. State is persisted to DB at each transition
4. Frontend polls `/status` and reads backend state
5. Failed scans have structured error (code + message)
6. Partial failures (e.g., OSV timeout) do NOT cause FAILED — scan continues

---

## 13. SBOM Requirements

### Supported Formats

| Format | Priority | Status |
|--------|----------|--------|
| CycloneDX JSON | P0 | **IMPLEMENTED** |
| SPDX JSON | P1 | **IMPLEMENTED** |
| package.json | P0 | **IMPLEMENTED** |
| requirements.txt | P0 | **IMPLEMENTED** |
| package-lock.json | P3 | NOT IMPLEMENTED |
| yarn.lock | P3 | NOT IMPLEMENTED |
| poetry.lock | P3 | NOT IMPLEMENTED |
| CycloneDX XML | P3 | NOT IMPLEMENTED |

### Parser Rules

1. Format detection via `detect_format()` — content inspection with optional hint
2. All parsers produce `list[CanonicalComponent]`
3. No security logic per parser — security engines consume canonical model only
4. Invalid/malformed input raises exceptions caught by orchestrator → FAILED
5. Empty component list → FAILED with `INVALID_SBOM` error

---

## 14. Threat Intelligence

### Provider Abstraction

```python
class VulnerabilityProvider(ABC):
    def get_vulnerabilities(self, ecosystem, name, version) -> list[VulnerabilityRecord]
    def is_available(self) -> bool
    def provider_name(self) -> str
```

### Implemented Providers

| Provider | Type | Status | Offline |
|----------|------|--------|---------|
| LocalProvider | CVE fixtures | **IMPLEMENTED** | Yes |
| OSVProvider | OSV.dev API | **IMPLEMENTED** | No (2s timeout) |
| NVDProvider | NVD API | P2 | No |
| GHSAProvider | GitHub Advisory | P2 | No |

### Intelligence Rules

1. LocalProvider is ALWAYS available — no network required
2. OSV has 2-second strict timeout; failure logged, scan continues
3. Provider failures do not cause scan failure
4. Multiple providers are deduplicated by CVE ID
5. CISA KEV is a boolean enrichment flag, not a separate provider

### VulnerabilityRecord

```python
class VulnerabilityRecord(BaseModel):
    cve_id: str
    title: str
    description: str
    severity: str       # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    cvss_score: float?
    affected_versions: list[str]
    fixed_versions: list[str]
    references: list[str]
    source: str
    is_kev: bool        # CISA Known Exploited Vulnerability
    exploitability: str  # ACTIVE/FUNCTIONAL/PROOF_OF_CONCEPT/THEORETICAL/UNKNOWN
```

---

## 15. Security Analysis

### 5 Analysis Engines

| Engine | Category | Input | Detection Logic | Status |
|--------|----------|-------|-----------------|--------|
| Vulnerability | VULNERABILITY | Components + Providers | CVE matching by ecosystem/name/version | **IMPLEMENTED** |
| Behavioral | BEHAVIORAL | Component install_scripts | Regex pattern matching (20 patterns) | **IMPLEMENTED** |
| Typosquatting | TYPOSQUATTING | Component names | Levenshtein distance ≤ 2 from protected packages | **IMPLEMENTED** |
| Reputation | REPUTATION | Component ecosystem/name | Lookup against known-bad database | **IMPLEMENTED** |
| Health | DEPENDENCY_HEALTH | Component version/pinning | Unpinned, wildcard, missing license | **IMPLEMENTED** |

### Safety Rule

Behavioral analysis is STATIC ONLY. The system NEVER:
- Executes `subprocess` or `shell=True`
- Runs `eval()` or `exec()`
- Installs arbitrary packages
- Downloads or executes remote code

---

## 16. Risk Engine

### Deterministic Weighted Scoring

```python
CATEGORY_WEIGHTS = {
    "VULNERABILITY":    0.40,
    "BEHAVIORAL":       0.20,
    "TYPOSQUATTING":    0.20,
    "REPUTATION":       0.10,
    "DEPENDENCY_HEALTH":0.10,
}
```

### Algorithm

1. Group findings by category
2. Per-category score = max(finding scores) + min(count * 5, 20), capped at 100
3. Weighted sum across categories
4. Blast radius boost: if affected > 3, add min(affected * 2, 15)
5. Clamp to [0, 100]

### Risk Levels

| Range | Level |
|-------|-------|
| 0-30 | LOW |
| 31-60 | MEDIUM |
| 61-80 | HIGH |
| 81-100 | CRITICAL |

### Outputs

```python
{
    "risk_score": float,        # 0-100
    "risk_level": str,          # LOW/MEDIUM/HIGH/CRITICAL
    "confidence": float,        # 0.0-1.0 (avg of finding confidences)
    "data_quality": str,        # COMPLETE/PARTIAL/MINIMAL/UNKNOWN
    "risk_factors": list[dict], # Top 5 contributing findings
    "metrics_breakdown": dict,  # Per-category scores
    "vulnerable_count": int,
    "suspicious_count": int,
    "outdated_count": int,
}
```

### Invariants

- `risk_score != confidence` — they are independent metrics
- No findings → score = 0, level = LOW, quality = MINIMAL
- Missing intelligence → UNKNOWN quality, NOT zero risk
- LLM NEVER modifies risk_score, risk_level, or confidence
- Same input → same output (deterministic)

---

## 17. Policy Engine

### Separation of Concerns

```
Risk Engine → score + level
    ↓
Policy Engine → ALLOW / REVIEW / BLOCK
```

### Default Policies

| Environment | CRITICAL | HIGH | MEDIUM | LOW |
|-------------|----------|------|--------|-----|
| production | BLOCK | REVIEW | ALLOW | ALLOW |
| staging | REVIEW | REVIEW | ALLOW | ALLOW |
| development | REVIEW | ALLOW | ALLOW | ALLOW |

### Custom Policies

Projects can have custom per-level override rules stored in `policies.rules` JSON:
```json
{ "HIGH": "BLOCK", "MEDIUM": "REVIEW" }
```

### Future: Policy Exceptions

```python
{
    "finding_id": "...",
    "reason": "...",
    "approver": "...",
    "created_at": "...",
    "expires_at": "..."
}
```

**Status**: Exception expiry NOT IMPLEMENTED.

---

## 18. Explainability

### Current Implementation

The `ExplainabilityPanel` frontend component displays:
- Per-category metric scores (vulnerability, behavioral, typosquatting, reputation, health)
- Category weights
- Confidence and data quality

### Evidence Model

Every finding carries structured evidence:
```json
{
    "signal_type": "KNOWN_VULNERABILITY",
    "component": "lodash",
    "version": "4.17.19",
    "cve_id": "CVE-2021-23337",
    "severity": "HIGH",
    "cvss_score": 7.2,
    "source": "local",
    "is_kev": false,
    "exploitability": "FUNCTIONAL",
    "fixed_versions": ["4.17.21"],
    "context": { "environment": "production", "criticality": "high" }
}
```

### LLM Explanation (P1)

Optional Ollama/LLM integration for:
- Natural language finding summaries
- Remediation explanations
- Scan comparison summaries

**Rule**: LLM output is READ-ONLY — cannot modify score, severity, or decision.

**Status**: LLM integration NOT IMPLEMENTED. Architecture flag exists (`ENABLE_LLM`).

---

## 19. Remediation

### Categories

| Action | When |
|--------|------|
| `upgrade` | Fixed version available |
| `replace` | Typosquatting candidate / malicious package |
| `remove` | Malicious reputation |
| `review` | Suspicious behavior needs manual review |
| `configuration_fix` | Pin versions, add licenses |

### Implementation

Two-stage remediation:
1. Analysis engines generate basic remediation per finding
2. `RemediationEngine.generate_remediation()` enriches with priority and recommended actions

### Output

```json
{
    "action": "upgrade",
    "reason": "CVE-2021-23337 affects this version",
    "target_version": "4.17.21",
    "recommended_action": "Upgrade to version 4.17.21 or later",
    "priority": "immediate",
    "verification": "Re-scan after updating to confirm vulnerability is resolved"
}
```

**Status**: **IMPLEMENTED** — basic remediation works for all categories.

---

## 20. Fix Verification

### Required Lifecycle

```
Finding → Remediation → Developer Fix → New SBOM → Re-scan → Compare → RESOLVED/STILL OPEN
```

### Current Status

- Re-scanning works (submit new SBOM to same project)
- Risk history tracks score changes between scans
- Finding comparison (resolved vs. new vs. unchanged) — **NOT IMPLEMENTED**
- Frontend displays risk delta in history — **PARTIAL**

**Status**: PARTIAL — re-scan works, explicit finding diff NOT IMPLEMENTED.

---

## 21. Continuous Monitoring

### Architecture Support

| Trigger | Status |
|---------|--------|
| Manual re-scan via UI/API | **IMPLEMENTED** |
| Scheduled scans | NOT IMPLEMENTED |
| Repository webhook | NOT IMPLEMENTED (integrations/ dir exists) |
| New advisory alerts | NOT IMPLEMENTED |

**Status**: ARCHITECTURE-READY. Orchestrator is portable. Integrations directory exists but is empty.

---

## 22. Alerts

### Current Status

- Frontend Findings page with severity filtering — **IMPLEMENTED**
- Dedicated alerts page — **NOT IMPLEMENTED**
- Email/Slack/webhook notifications — **NOT IMPLEMENTED**

**Status**: NOT IMPLEMENTED (P1).

---

## 23. Risk History

### Implementation

- `RiskHistory` model persists per-scan: score, level, confidence, severity counts
- API endpoint: `GET /api/v1/projects/{id}/risk-history`
- Frontend `RiskTimeline` component renders Recharts line chart
- Risk delta (previous vs. current) — **PARTIAL** (data exists, explicit delta not computed)

**Status**: **IMPLEMENTED** — persistence, API, and frontend visualization work.

---

## 24. CI/CD

### Supported Architecture

```
Developer Commit
    ↓
CI generates SBOM (e.g., cdxgen, syft)
    ↓
POST /api/v1/projects/{id}/scans (raw_content + source="ci")
    ↓
Poll GET /scans/{id}/status until COMPLETED
    ↓
GET /scans/{id}/report → policy_decision
    ↓
Exit 0 (ALLOW) / Exit 1 (BLOCK) / Warning (REVIEW)
```

### Current Status

- API supports `source="ci"` field
- Policy decision returned in scan report
- GitHub Actions workflow — **NOT IMPLEMENTED**
- Webhook receiver — **NOT IMPLEMENTED**

**Status**: API-READY, workflow template NOT IMPLEMENTED (P1).

---

## 25. Audit & Observability

### Audit Logging

- `AuditLog` model with action, resource_type, resource_id, details JSON
- `save_audit_event()` called on: scan start, scan complete, scan fail
- Audit query endpoint — **NOT IMPLEMENTED** (model/repo exist)

### Observability

- Structured logging: `%(asctime)s | %(levelname)-8s | %(name)s | %(message)s`
- Scan stage transitions logged
- Provider failures logged with warnings
- DB errors logged

**Status**: PARTIAL — audit writes work, query endpoint missing. Logs are structured.

---

## 26. Storage & Fallback

### Primary: SQLite

- SQLAlchemy ORM with `create_engine("sqlite:///...")`
- `check_same_thread=False` for FastAPI compatibility
- `create_all()` on startup — no migration tool
- 8 tables with foreign keys and relationships

### Fallback: JSON

- `_json_fallback_save()` writes to `data/json_fallback/{collection}/{id}.json`
- Activated on SQLAlchemy commit exceptions for: scans, components, dependencies, findings, risk_history
- Fallback is write-only — **no read-back recovery implemented**

### PostgreSQL Migration

- `DATABASE_URL` is configurable via `SCS_DATABASE_URL` env var
- `check_same_thread` conditionally applied only for SQLite
- Business logic uses repository pattern, not raw SQLAlchemy queries
- **Migration-ready** — change URL, remove SQLite-specific args

**Status**: SQLite IMPLEMENTED, JSON fallback PARTIAL (write-only), PostgreSQL ARCHITECTURE-READY.

---

## 27. Security Requirements

| Check | Status |
|-------|--------|
| No `subprocess` in application code | PASS |
| No `shell=True` | PASS |
| No `eval()` or `exec()` | PASS |
| No arbitrary package execution | PASS |
| Path traversal protection (`sanitize_filename`) | IMPLEMENTED |
| Upload size limit (50MB) | IMPLEMENTED |
| SBOM hash (SHA-256) | IMPLEMENTED |
| CORS restricted to localhost origins | IMPLEMENTED |
| API key validation (dev-mode bypass) | IMPLEMENTED |
| SQLAlchemy parameterized queries | PASS (ORM) |
| Hardcoded secret in source | `SECRET_KEY = "change-me..."` — intentional dev default |
| Secrets in logs | PASS — no secrets logged |

---

## 28. Testing Strategy

### Current Test Suite

| Test File | Type | Count | Status |
|-----------|------|-------|--------|
| `tests/test_core.py` | Unit | 17 | ALL PASS |
| `tests/test_e2e.py` | Integration/E2E | 1 | PASS |

### Test Coverage

| Area | Tested |
|------|--------|
| Format detection (CDX, SPDX, pkg.json, req.txt) | Yes |
| CycloneDX parser | Yes |
| package.json parser | Yes |
| requirements.txt parser | Yes |
| PURL generation | Yes |
| Version pinning (npm + pip) | Yes |
| CVE matching (local) | Yes |
| Typosquatting detection | Yes |
| Behavioral detection | Yes |
| Health analysis | Yes |
| Risk score boundaries (30/31/60/61/80/81/100) | Yes |
| Risk engine calculation | Yes |
| Policy decisions (prod/staging/dev + custom) | Yes |
| Signal deduplication | Yes |
| Dependency graph blast radius | Yes |
| Invalid SBOM handling | Yes |
| Unknown package (no false positive) | Yes |
| E2E: project → scan → poll → report | Yes |
| Frontend TypeScript typecheck | Yes |
| Frontend Vite build | Yes |

### Missing Tests

- SPDX parser unit test
- OSV provider timeout test
- JSON fallback activation test
- DB persistence round-trip test
- API error response tests
- Frontend component tests

### Verification Commands

```bash
# Backend unit tests
cd backend && python -X utf8 tests/test_core.py

# Backend E2E (requires running server)
cd backend && python -X utf8 tests/test_e2e.py

# Frontend typecheck
cd frontend && npx tsc --noEmit

# Frontend build
cd frontend && npx vite build
```

---

## 29. Evaluation Engine

### Purpose (P2)

Offline evaluation of risk engine accuracy:
- Compare predicted risk against known-good/known-bad datasets
- Measure precision/recall of typosquatting, behavioral detection
- Benchmark scoring consistency

**Status**: NOT IMPLEMENTED — future offline tool.

---

## 30. Formal Prediction Limitation

### Required Acknowledgment

The system provides **evidence-based risk estimation**, not guaranteed prediction.

The PRD and documentation must state:
1. Same observable signals can be compatible with multiple future outcomes
2. Unknown information remains UNKNOWN, never silently becomes SAFE
3. Confidence and data quality are always reported alongside scores
4. LLM/AI never determines final risk score, severity, or policy decisions
5. External intelligence timeout does not fail a scan
6. The system detects **known threats** — zero-day supply-chain attacks may not be detected

**Status**: README states limitations. Frontend distinguishes score/confidence/quality.

---

## 31. P0 Requirements

### P0-001: Application Startup and Health

| Field | Value |
|-------|-------|
| **ID** | P0-001 |
| **Title** | Application Startup and Health |
| **Priority** | P0 |
| **Description** | FastAPI starts, initializes SQLite, serves health endpoint |
| **User Story** | As a developer, I can start the backend and verify it's running |
| **Inputs** | None |
| **Processing** | Create engine, init_db(), mount routes |
| **Outputs** | `GET /health` returns `{"status": "healthy", "app": "...", "version": "..."}` |
| **Acceptance Criteria** | AC-STARTUP-001: Server starts in < 5s. AC-HEALTH-001: `/health` returns 200 |
| **Dependencies** | None |
| **Failure Cases** | Missing dependencies, port conflict |
| **Security** | No secrets in health response |
| **Test** | `curl http://localhost:8000/health` |
| **Status** | **IMPLEMENTED** |

### P0-002: Project Creation/Listing

| Field | Value |
|-------|-------|
| **ID** | P0-002 |
| **Priority** | P0 |
| **Description** | Create projects with name/environment/criticality; list all projects |
| **Inputs** | `{"name": "...", "environment": "production", "criticality": "high"}` |
| **Outputs** | Project with generated ID, 201 status |
| **Acceptance Criteria** | AC-PROJ-001: POST creates persisted project. AC-PROJ-002: GET lists all projects |
| **Dependencies** | P0-001, P0-003 |
| **Test** | `python -X utf8 tests/test_e2e.py` (project creation section) |
| **Status** | **IMPLEMENTED** |

### P0-003: SQLite Persistence

| Field | Value |
|-------|-------|
| **ID** | P0-003 |
| **Priority** | P0 |
| **Description** | SQLAlchemy + SQLite with 8 ORM models, repository pattern, session lifecycle |
| **Acceptance Criteria** | AC-STORAGE-001: Data persists across API requests. AC-STORAGE-002: Foreign keys enforced |
| **Dependencies** | None |
| **Test** | `python -c "from app.db.base import init_db; init_db(); print('OK')"` |
| **Status** | **IMPLEMENTED** |

### P0-004: JSON Emergency Fallback

| Field | Value |
|-------|-------|
| **ID** | P0-004 |
| **Priority** | P0 |
| **Description** | When SQLite commit fails, write JSON files to fallback directory |
| **Acceptance Criteria** | AC-FALLBACK-001: On DB error, JSON file is created. AC-FALLBACK-002: Application does not crash |
| **Dependencies** | P0-003 |
| **Test** | Inspect `_json_fallback_save()` logic; test by forcing DB error |
| **Status** | **PARTIAL** — Write-only. No read-back recovery implemented |

### P0-005: CycloneDX JSON Ingestion

| Field | Value |
|-------|-------|
| **ID** | P0-005 |
| **Priority** | P0 |
| **Description** | Parse CycloneDX JSON SBOM into CanonicalComponent list |
| **Acceptance Criteria** | AC-CDX-001: Valid CycloneDX produces components. AC-CDX-002: PURL extracted. AC-CDX-003: Licenses extracted |
| **Dependencies** | None |
| **Test** | `test_cyclonedx_parser()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-006: package.json Ingestion

| Field | Value |
|-------|-------|
| **ID** | P0-006 |
| **Priority** | P0 |
| **Description** | Parse package.json manifests; detect pinning, scope, install scripts |
| **Acceptance Criteria** | AC-PKG-001: deps, devDeps, peerDeps, optDeps parsed. AC-PKG-002: Pinning detected. AC-PKG-003: Install scripts captured |
| **Dependencies** | None |
| **Test** | `test_package_json_parser()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-007: requirements.txt Ingestion

| Field | Value |
|-------|-------|
| **ID** | P0-007 |
| **Priority** | P0 |
| **Description** | Parse Python requirements.txt; detect pinning (`==` vs `>=`) |
| **Acceptance Criteria** | AC-REQ-001: Package names + versions extracted. AC-REQ-002: Comments/flags ignored. AC-REQ-003: Pinning detected |
| **Dependencies** | None |
| **Test** | `test_requirements_txt_parser()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-008: Canonical Normalization + PURL

| Field | Value |
|-------|-------|
| **ID** | P0-008 |
| **Priority** | P0 |
| **Description** | Normalize components: generate PURLs, deduplicate by PURL, merge metadata |
| **Acceptance Criteria** | AC-PURL-001: Every component gets a PURL. AC-PURL-002: Duplicates merged. AC-PURL-003: component_id = purl |
| **Dependencies** | P0-005, P0-006, P0-007 |
| **Test** | `test_purl_generation()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-009: Scan State Machine

| Field | Value |
|-------|-------|
| **ID** | P0-009 |
| **Priority** | P0 |
| **Description** | Scan progresses through PENDING → PARSING → ... → COMPLETED/FAILED with persisted state |
| **Acceptance Criteria** | AC-SCAN-002: All states transition correctly. AC-SCAN-005: Failed scans have error code |
| **Dependencies** | P0-003 |
| **Test** | E2E test polls status; verify transitions in server logs |
| **Status** | **IMPLEMENTED** |

### P0-010: Async Scan Orchestration

| Field | Value |
|-------|-------|
| **ID** | P0-010 |
| **Priority** | P0 |
| **Description** | POST scan returns 202; orchestrator runs in BackgroundTasks with own DB session |
| **Acceptance Criteria** | AC-SCAN-001: POST returns 202 + scan_id. AC-SCAN-006: Orchestrator doesn't import FastAPI |
| **Dependencies** | P0-009 |
| **Test** | `python -X utf8 tests/test_e2e.py` |
| **Status** | **IMPLEMENTED** |

### P0-011: Local Vulnerability Intelligence

| Field | Value |
|-------|-------|
| **ID** | P0-011 |
| **Priority** | P0 |
| **Description** | LocalProvider loads CVE fixtures from JSON, matches by ecosystem/name/version |
| **Acceptance Criteria** | AC-INTEL-001: Always available. AC-INTEL-002: Matches lodash CVEs. AC-INTEL-003: Unknown packages return empty (not fake data) |
| **Dependencies** | None |
| **Test** | `test_cve_matching()`, `test_unknown_intelligence()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-012: OSV Enrichment with Timeout/Fallback

| Field | Value |
|-------|-------|
| **ID** | P0-012 |
| **Priority** | P0 |
| **Description** | OSVProvider queries OSV.dev with 2s timeout; scan continues on failure |
| **Acceptance Criteria** | AC-SCAN-004: OSV timeout → scan completes. AC-INTEL-004: OSV disabled → scan completes |
| **Dependencies** | P0-011 |
| **Test** | Set `SCS_ENABLE_OSV=false` and run scan; verify completion |
| **Status** | **IMPLEMENTED** |

### P0-013: Vulnerability Analysis

| Field | Value |
|-------|-------|
| **ID** | P0-013 |
| **Priority** | P0 |
| **Description** | Vulnerability engine queries all providers, deduplicates by CVE, generates findings with evidence |
| **Acceptance Criteria** | AC-VULN-001: Known CVEs detected. AC-VULN-002: KEV status included. AC-VULN-003: Fixed versions in remediation |
| **Dependencies** | P0-011, P0-012 |
| **Test** | E2E test detects lodash/jwt CVEs |
| **Status** | **IMPLEMENTED** |

### P0-014: Behavioral Analysis

| Field | Value |
|-------|-------|
| **ID** | P0-014 |
| **Priority** | P0 |
| **Description** | Static regex detection of suspicious install script patterns (curl, wget, eval, exec, etc.) |
| **Acceptance Criteria** | AC-BEHAV-001: Malicious scripts detected. AC-BEHAV-002: No code execution on host |
| **Dependencies** | None |
| **Test** | `test_behavioral_detection()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-015: Typosquatting Detection

| Field | Value |
|-------|-------|
| **ID** | P0-015 |
| **Priority** | P0 |
| **Description** | Levenshtein distance ≤ 2 from protected package dictionary |
| **Acceptance Criteria** | AC-TYPO-001: "expresss" flagged as typosquat of "express". AC-TYPO-002: "express" itself NOT flagged |
| **Dependencies** | None |
| **Test** | `test_typosquatting()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-016: Dependency Health Analysis

| Field | Value |
|-------|-------|
| **ID** | P0-016 |
| **Priority** | P0 |
| **Description** | Detect unpinned versions, wildcards, missing licenses |
| **Acceptance Criteria** | AC-HEALTH-001: Unpinned version flagged. AC-HEALTH-002: Wildcard flagged |
| **Dependencies** | None |
| **Test** | `test_health_analysis()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-017: Evidence Generation

| Field | Value |
|-------|-------|
| **ID** | P0-017 |
| **Priority** | P0 |
| **Description** | Every finding has structured evidence JSON with signal_type, source, confidence |
| **Acceptance Criteria** | AC-EVIDENCE-001: All findings have evidence dict. AC-EVIDENCE-002: Evidence includes source identifier |
| **Dependencies** | P0-013 through P0-016 |
| **Test** | Inspect findings in E2E report |
| **Status** | **IMPLEMENTED** |

### P0-018: Signal Processing

| Field | Value |
|-------|-------|
| **ID** | P0-018 |
| **Priority** | P0 |
| **Description** | Deduplicate by (purl, category, cve_id, title); cap confidence at 1.0; sort by score desc |
| **Acceptance Criteria** | AC-SIGNAL-001: No duplicates. AC-SIGNAL-002: Sorted descending |
| **Dependencies** | P0-017 |
| **Test** | `test_signal_processor()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-019: Deterministic Risk Engine

| Field | Value |
|-------|-------|
| **ID** | P0-019 |
| **Priority** | P0 |
| **Description** | Weighted category scoring with blast radius boost, clamped to [0, 100] |
| **Acceptance Criteria** | AC-RISK-001: Score always 0-100. AC-RISK-002: Deterministic. AC-RISK-003: No LLM dependency |
| **Dependencies** | P0-018 |
| **Test** | `test_risk_engine()`, `test_risk_score_boundaries()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-020: Risk Score + Severity + Confidence

| Field | Value |
|-------|-------|
| **ID** | P0-020 |
| **Priority** | P0 |
| **Description** | Risk score, risk level, confidence, and data quality are separate and independently reported |
| **Acceptance Criteria** | AC-RISK-004: score != confidence. AC-RISK-005: data_quality reported |
| **Dependencies** | P0-019 |
| **Test** | E2E report contains separate fields |
| **Status** | **IMPLEMENTED** |

### P0-021: Findings Persistence

| Field | Value |
|-------|-------|
| **ID** | P0-021 |
| **Priority** | P0 |
| **Description** | Findings stored in DB with full evidence, retrievable by scan_id with filtering |
| **Acceptance Criteria** | AC-FIND-001: Findings persisted. AC-FIND-002: Filterable by category/severity |
| **Dependencies** | P0-003, P0-017 |
| **Test** | E2E test retrieves findings |
| **Status** | **IMPLEMENTED** |

### P0-022: Policy Engine

| Field | Value |
|-------|-------|
| **ID** | P0-022 |
| **Priority** | P0 |
| **Description** | Separate from risk engine; consumes risk level → ALLOW/REVIEW/BLOCK |
| **Acceptance Criteria** | AC-POLICY-001: Correct decisions per environment. AC-POLICY-002: Custom rules override defaults |
| **Dependencies** | P0-019 |
| **Test** | `test_policy_decisions()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P0-023: Remediation Guidance

| Field | Value |
|-------|-------|
| **ID** | P0-023 |
| **Priority** | P0 |
| **Description** | Structured remediation per finding: action, reason, target version, priority |
| **Acceptance Criteria** | AC-REMED-001: Vulnerability findings have upgrade target. AC-REMED-002: Priority set based on severity |
| **Dependencies** | P0-017 |
| **Test** | Inspect remediation in E2E report findings |
| **Status** | **IMPLEMENTED** |

### P0-024: Risk History

| Field | Value |
|-------|-------|
| **ID** | P0-024 |
| **Priority** | P0 |
| **Description** | Persist per-scan risk scores with severity counts; API returns history ordered by date |
| **Acceptance Criteria** | AC-HIST-001: History entry created per scan. AC-HIST-002: API returns chronological data |
| **Dependencies** | P0-003, P0-019 |
| **Test** | E2E test checks `risk-history` endpoint |
| **Status** | **IMPLEMENTED** |

### P0-025: Frontend Dashboard

| Field | Value |
|-------|-------|
| **ID** | P0-025 |
| **Priority** | P0 |
| **Description** | Overview page with project list, latest scan scores, navigation |
| **Acceptance Criteria** | AC-FRONT-001: Dashboard loads and calls backend API. AC-FRONT-002: No hardcoded fake metrics |
| **Dependencies** | P0-002, P0-030 |
| **Test** | Frontend build passes; visual inspection at localhost:5173 |
| **Status** | **IMPLEMENTED** |

### P0-026: Scan Progress

| Field | Value |
|-------|-------|
| **ID** | P0-026 |
| **Priority** | P0 |
| **Description** | Real-time scan progress with stage indicators, polling status endpoint |
| **Acceptance Criteria** | AC-SCAN-007: Progress bar reflects backend stage. AC-SCAN-008: Completed shows score |
| **Dependencies** | P0-009, P0-030 |
| **Test** | Upload SBOM via UI; observe progress |
| **Status** | **IMPLEMENTED** |

### P0-027: Findings UI

| Field | Value |
|-------|-------|
| **ID** | P0-027 |
| **Priority** | P0 |
| **Description** | Findings table with severity badges, category filters, sortable columns |
| **Acceptance Criteria** | AC-FIND-003: All backend findings rendered. AC-FIND-004: Filter by severity/category works |
| **Dependencies** | P0-021, P0-030 |
| **Test** | Scan CVE demo case; verify findings display |
| **Status** | **IMPLEMENTED** |

### P0-028: Dependency Graph Visualization

| Field | Value |
|-------|-------|
| **ID** | P0-028 |
| **Priority** | P0 |
| **Description** | Cytoscape.js graph showing components as nodes, dependencies as edges, vulnerability coloring |
| **Acceptance Criteria** | AC-GRAPH-001: Graph renders from backend data. AC-GRAPH-002: Vulnerable nodes colored differently |
| **Dependencies** | P0-030 |
| **Test** | Frontend build includes Cytoscape; visual inspection on ProjectDetails |
| **Status** | **IMPLEMENTED** |

### P0-029: Error Handling

| Field | Value |
|-------|-------|
| **ID** | P0-029 |
| **Priority** | P0 |
| **Description** | Structured error responses; graceful degradation; no unhandled exceptions |
| **Acceptance Criteria** | AC-ERR-001: 404 for unknown project/scan. AC-ERR-002: 400 for invalid SBOM. AC-ERR-003: Provider failures don't crash scan |
| **Dependencies** | P0-001 |
| **Test** | E2E test with invalid input; inspect error responses |
| **Status** | **IMPLEMENTED** |

### P0-030: Backend/Frontend Integration

| Field | Value |
|-------|-------|
| **ID** | P0-030 |
| **Priority** | P0 |
| **Description** | Vite proxy → FastAPI; all frontend pages call real backend API |
| **Acceptance Criteria** | AC-INT-001: Vite proxies /api to localhost:8000. AC-INT-002: All API methods in client.ts match backend endpoints |
| **Dependencies** | P0-001 |
| **Test** | Start both servers; verify API calls in browser |
| **Status** | **IMPLEMENTED** |

---

## 32. P1 Requirements

### P1-001: SPDX Ingestion

| Field | Value |
|-------|-------|
| **ID** | P1-001 |
| **Priority** | P1 |
| **Description** | Parse SPDX JSON; extract PURLs from externalRefs; detect direct/transitive from relationships |
| **Acceptance Criteria** | AC-SPDX-001: Valid SPDX produces components. AC-SPDX-002: DEPENDS_ON relationships mapped |
| **Dependencies** | P0-008 |
| **Test** | Add SPDX parser unit test |
| **Status** | **IMPLEMENTED** — parser exists, dedicated unit test missing |

### P1-002: SBOM Integrity/Provenance

| Field | Value |
|-------|-------|
| **ID** | P1-002 |
| **Priority** | P1 |
| **Description** | Capture and persist: SHA-256, source, upload timestamp, input format, spec version |
| **Acceptance Criteria** | AC-PROV-001: sbom_hash stored. AC-PROV-002: Input format recorded |
| **Dependencies** | P0-003 |
| **Test** | E2E test: verify scan has sbom_hash and input_format |
| **Status** | **PARTIAL** — SHA-256 and input_format stored. Spec version, serial number NOT captured |

### P1-003: Blast-Radius Analysis

| Field | Value |
|-------|-------|
| **ID** | P1-003 |
| **Priority** | P1 |
| **Description** | Graph-derived blast radius: transitive dependents, affected count, boost to risk score |
| **Acceptance Criteria** | AC-BLAST-001: Not hardcoded. AC-BLAST-002: Uses dependency graph edges |
| **Dependencies** | P0-008 (dependency graph) |
| **Test** | `test_dependency_graph()` in test_core.py |
| **Status** | **IMPLEMENTED** |

### P1-004: Context/Reachability Analysis

| Field | Value |
|-------|-------|
| **ID** | P1-004 |
| **Priority** | P1 |
| **Description** | Apply environment (prod/staging/dev), criticality, and scope multipliers to findings |
| **Acceptance Criteria** | AC-CTX-001: Production scores higher than development. AC-CTX-002: Context recorded in evidence |
| **Dependencies** | P0-019 |
| **Test** | Inspect context_engine.py multipliers |
| **Status** | **PARTIAL** — Environment and criticality multipliers work. Scope multiplier hardcoded to "runtime" |

### P1-005: Explainability Engine

| Field | Value |
|-------|-------|
| **ID** | P1-005 |
| **Priority** | P1 |
| **Description** | Frontend panel showing per-category scores, weights, top risk factors |
| **Acceptance Criteria** | AC-EXPLAIN-001: Metrics breakdown displayed. AC-EXPLAIN-002: Risk factors listed |
| **Dependencies** | P0-019 |
| **Test** | Visual inspection of ExplainabilityPanel |
| **Status** | **IMPLEMENTED** |

### P1-006: Ollama/LLM Explanation

| Field | Value |
|-------|-------|
| **ID** | P1-006 |
| **Priority** | P1 |
| **Description** | Optional LLM-generated natural language explanations of findings |
| **Acceptance Criteria** | AC-AI-001: LLM cannot modify risk score. AC-AI-002: Works when disabled |
| **Dependencies** | P1-005 |
| **Test** | Verify `ENABLE_LLM=false` doesn't break any scan |
| **Status** | **NOT IMPLEMENTED** — Config flag exists, no integration code |

### P1-007: CI/CD Security Gate

| Field | Value |
|-------|-------|
| **ID** | P1-007 |
| **Priority** | P1 |
| **Description** | GitHub Actions workflow template that submits SBOM, polls, and gates on policy |
| **Acceptance Criteria** | AC-CICD-001: Workflow template exists. AC-CICD-002: Exit code based on policy decision |
| **Dependencies** | P0-010, P0-022 |
| **Test** | Validate workflow YAML syntax |
| **Status** | **NOT IMPLEMENTED** |

### P1-008: GitHub Integration/Webhook

| Field | Value |
|-------|-------|
| **ID** | P1-008 |
| **Priority** | P1 |
| **Description** | Webhook endpoint to receive GitHub push events and trigger scans |
| **Acceptance Criteria** | AC-HOOK-001: POST /api/v1/webhooks/github accepted. AC-HOOK-002: Scan triggered |
| **Dependencies** | P0-010 |
| **Test** | POST webhook payload; verify scan created |
| **Status** | **NOT IMPLEMENTED** — integrations/ dir is empty |

### P1-009: Alerts

| Field | Value |
|-------|-------|
| **ID** | P1-009 |
| **Priority** | P1 |
| **Description** | Dedicated alerts page showing new critical/high findings across projects |
| **Acceptance Criteria** | AC-ALERT-001: Alerts page exists. AC-ALERT-002: Shows findings from latest scans |
| **Dependencies** | P0-021, P0-025 |
| **Test** | Navigate to /alerts; verify data displayed |
| **Status** | **NOT IMPLEMENTED** — no Alerts page |

### P1-010: Fix Verification Workflow

| Field | Value |
|-------|-------|
| **ID** | P1-010 |
| **Priority** | P1 |
| **Description** | Compare findings between scans: resolved, new, unchanged |
| **Acceptance Criteria** | AC-FIX-001: API endpoint returns finding diff. AC-FIX-002: Frontend shows resolved/new |
| **Dependencies** | P0-021, P0-024 |
| **Test** | Run two scans (CVE, then clean); verify diff |
| **Status** | **NOT IMPLEMENTED** — risk history exists but no finding comparison |

### P1-011: Reports

| Field | Value |
|-------|-------|
| **ID** | P1-011 |
| **Priority** | P1 |
| **Description** | Dedicated report page with full scan summary; JSON export |
| **Acceptance Criteria** | AC-REPORT-001: Report page exists. AC-REPORT-002: JSON download available |
| **Dependencies** | P0-021 |
| **Test** | Navigate to report; download JSON |
| **Status** | **PARTIAL** — Report API exists (`/report`), dedicated page and export NOT IMPLEMENTED |

### P1-012: Audit Logging

| Field | Value |
|-------|-------|
| **ID** | P1-012 |
| **Priority** | P1 |
| **Description** | Audit events persisted for scan lifecycle, policy decisions; queryable API endpoint |
| **Acceptance Criteria** | AC-AUDIT-001: Events written on scan/project actions. AC-AUDIT-002: GET endpoint returns logs |
| **Dependencies** | P0-003 |
| **Test** | Check audit_logs table after scan |
| **Status** | **PARTIAL** — Write-side works, GET endpoint NOT IMPLEMENTED |

### P1-013: Observability

| Field | Value |
|-------|-------|
| **ID** | P1-013 |
| **Priority** | P1 |
| **Description** | Structured logging, scan stage timing, provider error tracking |
| **Acceptance Criteria** | AC-OBS-001: Structured log format. AC-OBS-002: Stage transitions logged |
| **Dependencies** | P0-001 |
| **Test** | Inspect server logs during scan |
| **Status** | **IMPLEMENTED** — structured logging format, transitions logged, provider failures logged |

---

## 33. P2 Requirements

### P2-001: NVD Provider
| **ID** | P2-001 | **Priority** | P2 | **Status** | NOT IMPLEMENTED |
|--------|--------|--------------|-----|-----------|-----------------|

### P2-002: GitHub Advisory Provider
| **ID** | P2-002 | **Priority** | P2 | **Status** | NOT IMPLEMENTED |
|--------|--------|--------------|-----|-----------|-----------------|

### P2-003: CISA KEV Synchronization
| **ID** | P2-003 | **Priority** | P2 | **Status** | PARTIAL — `is_kev` field exists in fixtures; no live sync |
|--------|--------|--------------|-----|-----------|-----------------|

### P2-004: Advanced Dependency Reachability
| **ID** | P2-004 | **Priority** | P2 | **Status** | NOT IMPLEMENTED |
|--------|--------|--------------|-----|-----------|-----------------|

### P2-005: SHAP / ML Explainability
| **ID** | P2-005 | **Priority** | P2 | **Status** | NOT IMPLEMENTED |
|--------|--------|--------------|-----|-----------|-----------------|

### P2-006: Continuous Scheduling Infrastructure
| **ID** | P2-006 | **Priority** | P2 | **Status** | NOT IMPLEMENTED |
|--------|--------|--------------|-----|-----------|-----------------|

### P2-007: Advanced Policy Management
| **ID** | P2-007 | **Priority** | P2 | **Status** | NOT IMPLEMENTED — basic custom rules only |
|--------|--------|--------------|-----|-----------|-----------------|

---

## 34. P3 Requirements

| ID | Title | Status |
|----|-------|--------|
| P3-001 | Celery + Redis | NOT IMPLEMENTED |
| P3-002 | PostgreSQL production deployment | ARCHITECTURE-READY |
| P3-003 | S3-compatible artifact storage | NOT IMPLEMENTED |
| P3-004 | Isolated dynamic sandbox | NOT IMPLEMENTED |
| P3-005 | Distributed workers | NOT IMPLEMENTED |
| P3-006 | Enterprise SSO | NOT IMPLEMENTED |
| P3-007 | Advanced multi-tenant production | NOT IMPLEMENTED |

---

## 35. Acceptance Criteria

### Scan Lifecycle
| ID | Criterion | Status |
|----|-----------|--------|
| AC-SCAN-001 | POST valid CycloneDX → HTTP 202 + scan_id | PASS |
| AC-SCAN-002 | Scan progresses through defined states | PASS |
| AC-SCAN-003 | Scan completes without external API | PASS |
| AC-SCAN-004 | OSV timeout → scan continues | PASS |
| AC-SCAN-005 | Failed scans have structured error | PASS |

### Risk Engine
| ID | Criterion | Status |
|----|-----------|--------|
| AC-RISK-001 | Score always 0-100 | PASS |
| AC-RISK-002 | Deterministic for identical input | PASS |
| AC-RISK-003 | Boundary: 30=LOW, 31=MEDIUM, 60=MEDIUM, 61=HIGH, 80=HIGH, 81=CRITICAL | PASS |

### AI Safety
| ID | Criterion | Status |
|----|-----------|--------|
| AC-AI-001 | LLM cannot modify risk or policy | PASS (LLM not integrated) |

### Storage
| ID | Criterion | Status |
|----|-----------|--------|
| AC-STORAGE-001 | JSON fallback attempted on DB error | PARTIAL (write-only) |
| AC-STORAGE-002 | PostgreSQL migration via config change | PASS |

### Frontend
| ID | Criterion | Status |
|----|-----------|--------|
| AC-FRONT-001 | Frontend displays backend score/findings | PASS |
| AC-GRAPH-001 | Dependency graph from backend data | PASS |

### Policy
| ID | Criterion | Status |
|----|-----------|--------|
| AC-POLICY-001 | ALLOW/REVIEW/BLOCK based on policy | PASS |

### Fix Verification
| ID | Criterion | Status |
|----|-----------|--------|
| AC-FIX-001 | Previous/current findings compared | NOT IMPLEMENTED |

---

## 36. Definition of Done

A feature is DONE only when:

1. Implementation exists (not a TODO/comment/filename)
2. API or UI integration exists where required
3. Tests exist where appropriate
4. Tests pass
5. No obvious regression
6. Acceptance criteria satisfied
7. No fake/placeholder implementation remains
8. Documentation updated if public contract changed

**Do NOT count**: filenames, comments, TODOs, placeholder classes, fake API responses, unused imports, static mock data, future architecture notes.

---

## 37. Ralph Loop Execution Rules

### Agent Must

1. **Inspect before modifying** — read existing code first
2. **Read existing code** — understand current implementation
3. **Preserve working implementation** — never break working features
4. **Implement one logical task at a time** — small, focused changes
5. **Run relevant tests after each task** — verify changes
6. **Avoid unnecessary rewrites** — prefer minimal compatible changes
7. **Avoid architecture drift** — follow the approved architecture
8. **Never replace working code with simplified demo**
9. **Never add mandatory infrastructure** without explicit requirement
10. **Never claim completion without verification** — run tests
11. **Prefer smallest compatible change** — less risk
12. **Keep APIs and schemas stable** — don't break the frontend
13. **Record remaining work** — update status in PRD
14. **Prioritize P0 before P1** — always
15. **Never silently downgrade a requirement** — if something can't be done, say so

### Priority Order

When selecting work:
1. Fix any broken P0 feature first
2. Complete any PARTIAL P0 feature
3. Start NOT IMPLEMENTED P1 features in order
4. P2 and P3 only after all P1 features are at least PARTIAL

### Verification Commands

```bash
# Backend unit tests (must always pass)
cd backend && python -X utf8 tests/test_core.py

# Backend E2E (requires running server on :8000)
cd backend && python -X utf8 tests/test_e2e.py

# Frontend typecheck (must pass)
cd frontend && npx tsc --noEmit

# Frontend build (must pass)
cd frontend && npx vite build

# Start backend
cd backend && python -m uvicorn main:app --host 0.0.0.0 --port 8000

# Start frontend
cd frontend && npx vite --port 5173
```

---

## 38. Future Roadmap

### Phase 1 (Current): Core Platform
- All P0 features implemented and tested
- Basic P1 features (SPDX, blast radius, explainability, observability)

### Phase 2: Integration & Verification
- CI/CD workflow templates (P1-007)
- GitHub webhook integration (P1-008)
- Fix verification with finding diff (P1-010)
- Audit log query endpoint (P1-012)
- Alerts page (P1-009)
- Reports with JSON export (P1-011)
- LLM explanation (P1-006)

### Phase 3: Advanced Intelligence
- NVD provider (P2-001)
- GitHub Advisory provider (P2-002)
- CISA KEV live sync (P2-003)
- Advanced reachability (P2-004)
- Scheduled monitoring (P2-006)
- Advanced policy with exceptions (P2-007)

### Phase 4: Production Scale
- PostgreSQL migration (P3-002)
- Celery + Redis (P3-001)
- S3 artifact storage (P3-003)
- Distributed workers (P3-005)
- Enterprise SSO (P3-006)

---

## Appendix A: Implementation Status Summary

| Priority | Total | Implemented | Partial | Not Implemented |
|----------|-------|-------------|---------|-----------------|
| P0 | 30 | **29** | 1 | 0 |
| P1 | 13 | 3 | 4 | 6 |
| P2 | 7 | 0 | 1 | 6 |
| P3 | 7 | 0 | 0 | 7 |
| **Total** | **57** | **32** | **6** | **19** |

### Next Priority Work Items

1. **P0-004** (PARTIAL): Implement JSON fallback read-back recovery
2. **P1-010**: Fix verification — finding comparison between scans
3. **P1-009**: Alerts page
4. **P1-012**: Audit log GET endpoint
5. **P1-011**: Reports page with JSON export
6. **P1-007**: CI/CD GitHub Actions workflow template
7. **P1-006**: LLM/Ollama explanation integration

---

## Appendix B: Demo Scenarios

### Clean SBOM (`data/demo_cases/clean.json`)
- Trusted dependencies (react, express latest)
- No known vulnerabilities
- Expected: LOW risk, ALLOW policy

### CVE SBOM (`data/demo_cases/cve.json`)
- lodash@4.17.19, jsonwebtoken@8.5.1, express@4.17.1
- Expected: MEDIUM-HIGH risk, multiple CVE findings, REVIEW/ALLOW policy

### Poisoned SBOM (`data/demo_cases/poisoned.json`)
- "expresss" (typosquat), "lodasch" (typosquat)
- Malicious install scripts (curl|bash, wget)
- Expected: HIGH-CRITICAL risk, behavioral + typosquatting findings

All scenarios are backed by real backend analysis, not frontend mocks.
