"""
Core data models for CVE-2025-29927 Detection System.

Defines all evidence types, results, and verdict enums used throughout the scanner.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any


class Confidence(Enum):
    """Confidence levels for assertions."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Verdict(Enum):
    """Final verdict for vulnerability assessment."""
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"  # Very likely vulnerable, recommend immediate action
    LIKELY = "LIKELY"  # Probably vulnerable, needs manual verification
    POSSIBLE = "POSSIBLE"  # Some signals, needs investigation
    INCONCLUSIVE = "INCONCLUSIVE"  # Can't determine, manual review required
    INCONCLUSIVE_INCONSISTENT = "INCONCLUSIVE_INCONSISTENT"  # Inconsistent bypass results
    NOT_VULNERABLE = "NOT_VULNERABLE"  # Bypass doesn't work
    FALSE_POSITIVE_LOGIN_PAGE = "FALSE_POSITIVE_LOGIN_PAGE"  # Bypass returns login page
    SKIP_NOT_NEXTJS = "SKIP_NOT_NEXTJS"  # Target is not Next.js
    SKIP_NOT_PROTECTED = "SKIP_NOT_PROTECTED"  # No protected routes found
    ERROR = "ERROR"  # Error during scanning


@dataclass
class Evidence:
    """Single piece of evidence for an assertion."""
    type: str  # header, body, asset, etc.
    name: str  # Evidence name
    value: str  # What was found
    weight: int  # Evidence weight (1-4)
    found: bool  # Whether evidence was present

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "name": self.name,
            "value": self.value,
            "weight": self.weight,
            "found": self.found
        }


@dataclass
class FingerprintResult:
    """Result of Phase 1: Next.js fingerprinting."""
    is_nextjs: bool
    confidence: Confidence
    evidences: List[Evidence] = field(default_factory=list)
    total_weight: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assertion": "Target is Next.js",
            "is_nextjs": self.is_nextjs,
            "confidence": self.confidence.value,
            "total_weight": self.total_weight,
            "signals": [e.to_dict() for e in self.evidences if e.found],
            "error": self.error
        }


@dataclass
class AuthRedirectResult:
    """Result of auth redirect analysis."""
    is_auth: bool
    confidence: Confidence
    reason: str
    location: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_auth_redirect": self.is_auth,
            "confidence": self.confidence.value,
            "reason": self.reason,
            "location": self.location
        }


@dataclass
class BaselineResult:
    """Result of Phase 2: Baseline behavior for a route."""
    route: str
    status_code: int
    is_auth_protected: bool
    auth_confidence: Confidence
    auth_indicators: List[str] = field(default_factory=list)
    redirect_location: Optional[str] = None
    content_length: int = 0
    content_sample: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        behavior = f"{self.status_code}"
        if self.redirect_location:
            behavior += f" -> {self.redirect_location}"

        return {
            "assertion": f"Route {self.route} is protected by middleware",
            "route": self.route,
            "confidence": self.auth_confidence.value,
            "behavior": behavior,
            "auth_indicators": self.auth_indicators,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "error": self.error
        }


@dataclass
class DifferenceResult:
    """Analysis of behavior difference between normal and bypass requests."""
    is_significant: bool
    type: str  # AUTH_TO_SUCCESS, REDIRECT_CHANGE, REDIRECT_REMOVED, CONTENT_DIFF
    description: str
    normal_status: int = 0
    bypass_status: int = 0
    normal_location: str = ""
    bypass_location: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_significant": self.is_significant,
            "type": self.type,
            "description": self.description,
            "normal_status": self.normal_status,
            "bypass_status": self.bypass_status
        }


@dataclass
class BypassResult:
    """Result of Phase 3: Bypass testing."""
    works: bool
    payload_name: Optional[str] = None
    payload_value: Optional[str] = None
    difference: Optional[DifferenceResult] = None
    consistency_verified: bool = False
    consistency_details: str = ""
    all_payloads_tested: List[str] = field(default_factory=list)
    bypass_status: int = 0
    bypass_location: Optional[str] = None
    bypass_content_length: int = 0
    bypass_content_sample: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "assertion": "Middleware skipped with bypass header",
            "works": self.works,
            "payload": self.payload_name,
            "consistency": self.consistency_details,
            "payloads_tested": self.all_payloads_tested,
            "error": self.error
        }

        if self.difference:
            result["difference"] = self.difference.description
            result["difference_type"] = self.difference.type

        return result


@dataclass
class MarkerMatch:
    """A matched stable marker."""
    category: str
    marker: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "marker": self.marker
        }


@dataclass
class ImpactResult:
    """Result of Phase 4: Impact validation."""
    is_real: bool
    confidence: Confidence
    reason: str
    is_login_page: bool = False
    markers_found: List[MarkerMatch] = field(default_factory=list)
    structural_diff_count: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assertion": "Protected content accessible",
            "is_real": self.is_real,
            "confidence": self.confidence.value,
            "reason": self.reason,
            "login_page": self.is_login_page,
            "markers_found": [m.to_dict() for m in self.markers_found],
            "structural_diff_elements": self.structural_diff_count,
            "error": self.error
        }


@dataclass
class ScanResult:
    """Complete scan result with evidence chain."""
    url: str
    verdict: Verdict
    confidence_score: int = 0

    # Phase results
    fingerprint: Optional[FingerprintResult] = None
    baseline: Optional[BaselineResult] = None
    bypass: Optional[BypassResult] = None
    impact: Optional[ImpactResult] = None

    # Metadata
    scan_time_ms: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # CVE info
    cve_id: str = "CVE-2025-29927"
    cvss_score: str = "9.1 (Critical)"
    recommendation: str = "Upgrade to Next.js 15.2.3+ or 14.2.25+"

    def to_dict(self) -> Dict[str, Any]:
        evidence_chain = {}

        if self.fingerprint:
            evidence_chain["phase1_fingerprint"] = self.fingerprint.to_dict()
        if self.baseline:
            evidence_chain["phase2_baseline"] = self.baseline.to_dict()
        if self.bypass:
            evidence_chain["phase3_bypass"] = self.bypass.to_dict()
        if self.impact:
            evidence_chain["phase4_impact"] = self.impact.to_dict()

        return {
            "url": self.url,
            "verdict": self.verdict.value,
            "confidence_score": self.confidence_score,
            "evidence_chain": evidence_chain,
            "scan_time_ms": self.scan_time_ms,
            "errors": self.errors,
            "warnings": self.warnings,
            "cve": self.cve_id,
            "cvss": self.cvss_score,
            "recommendation": self.recommendation
        }
