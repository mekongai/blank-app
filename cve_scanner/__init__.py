"""
CVE-2025-29927 Detection System

A security scanner for detecting Next.js middleware bypass vulnerability.
This tool is intended for authorized security testing, defensive security,
and security audits only.
"""

from .models import (
    Confidence,
    Verdict,
    Evidence,
    FingerprintResult,
    AuthRedirectResult,
    BaselineResult,
    DifferenceResult,
    BypassResult,
    ImpactResult,
    ScanResult,
)
from .scanner import CVE202529927Scanner

__version__ = "1.0.0"
__all__ = [
    "CVE202529927Scanner",
    "Confidence",
    "Verdict",
    "Evidence",
    "FingerprintResult",
    "AuthRedirectResult",
    "BaselineResult",
    "DifferenceResult",
    "BypassResult",
    "ImpactResult",
    "ScanResult",
]
