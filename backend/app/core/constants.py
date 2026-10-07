"""Application-wide constants."""
from enum import Enum


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    PARSING = "PARSING"
    NORMALIZING = "NORMALIZING"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    ENRICHING = "ENRICHING"
    ANALYZING = "ANALYZING"
    SCORING = "SCORING"
    APPLYING_POLICY = "APPLYING_POLICY"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class FindingCategory(str, Enum):
    VULNERABILITY = "VULNERABILITY"
    BEHAVIORAL = "BEHAVIORAL"
    TYPOSQUATTING = "TYPOSQUATTING"
    REPUTATION = "REPUTATION"
    DEPENDENCY_HEALTH = "DEPENDENCY_HEALTH"


class DataQuality(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MINIMAL = "MINIMAL"
    UNKNOWN = "UNKNOWN"


class InputFormat(str, Enum):
    CYCLONEDX_JSON = "cyclonedx_json"
    SPDX_JSON = "spdx_json"
    PACKAGE_JSON = "package_json"
    REQUIREMENTS_TXT = "requirements_txt"
    PACKAGE_LOCK_JSON = "package_lock_json"
    POETRY_LOCK = "poetry_lock"
    UNKNOWN_JSON = "unknown_json"
    MALFORMED_JSON = "malformed_json"
    UNKNOWN = "unknown"



# Risk score thresholds
RISK_THRESHOLDS = {
    RiskLevel.LOW: (0, 30),
    RiskLevel.MEDIUM: (31, 60),
    RiskLevel.HIGH: (61, 80),
    RiskLevel.CRITICAL: (81, 100),
}


def score_to_risk_level(score: float) -> RiskLevel:
    """Convert a numeric risk score to a risk level."""
    if score <= 30:
        return RiskLevel.LOW
    elif score <= 60:
        return RiskLevel.MEDIUM
    elif score <= 80:
        return RiskLevel.HIGH
    elif score <= 100:
        return RiskLevel.CRITICAL
    return RiskLevel.UNKNOWN


# Scan progress percentages for each stage
SCAN_PROGRESS = {
    ScanStatus.PENDING: 0,
    ScanStatus.PARSING: 10,
    ScanStatus.NORMALIZING: 20,
    ScanStatus.BUILDING_GRAPH: 30,
    ScanStatus.ENRICHING: 45,
    ScanStatus.ANALYZING: 60,
    ScanStatus.SCORING: 80,
    ScanStatus.APPLYING_POLICY: 90,
    ScanStatus.COMPLETED: 100,
    ScanStatus.FAILED: -1,
}

SCAN_MESSAGES = {
    ScanStatus.PENDING: "Scan queued",
    ScanStatus.PARSING: "Parsing SBOM/manifest",
    ScanStatus.NORMALIZING: "Normalizing components",
    ScanStatus.BUILDING_GRAPH: "Building dependency graph",
    ScanStatus.ENRICHING: "Checking vulnerability intelligence",
    ScanStatus.ANALYZING: "Running security analysis",
    ScanStatus.SCORING: "Calculating risk score",
    ScanStatus.APPLYING_POLICY: "Applying organization policies",
    ScanStatus.COMPLETED: "Scan complete",
    ScanStatus.FAILED: "Scan failed",
}

# Suspicious patterns for behavioral analysis
SUSPICIOUS_PATTERNS = [
    r"curl\s+", r"wget\s+", r"bash\s+", r"/bin/sh",
    r"powershell", r"eval\(", r"exec\(", r"base64",
    r"child_process", r"\.exec\(", r"\.spawn\(",
    r"process\.env", r"require\(['\"]child_process",
    r"import\s+subprocess", r"os\.system\(",
    r"os\.popen\(", r"subprocess\.call",
    r"subprocess\.Popen", r"__import__",
]
