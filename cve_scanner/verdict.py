"""
Verdict Calculation

Combines results from all phases to produce a final verdict with
confidence scoring.
"""

from typing import Optional, Tuple

from .models import (
    Confidence,
    Verdict,
    FingerprintResult,
    BaselineResult,
    BypassResult,
    ImpactResult,
)


# Confidence to score mapping
CONFIDENCE_SCORES = {
    Confidence.NONE: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}


def calculate_confidence_score(
    fingerprint: Optional[FingerprintResult],
    baseline: Optional[BaselineResult],
    bypass: Optional[BypassResult],
    impact: Optional[ImpactResult]
) -> int:
    """
    Calculate total confidence score from all phase results.

    Maximum score is 12 (3 + 3 + 3 + 3).

    Returns:
        Total confidence score (0-12)
    """
    score = 0

    if fingerprint:
        score += CONFIDENCE_SCORES.get(fingerprint.confidence, 0)

    if baseline:
        score += CONFIDENCE_SCORES.get(baseline.auth_confidence, 0)

    if bypass:
        # Bypass gets full points if consistent, half if not
        if bypass.works:
            score += 3 if bypass.consistency_verified else 1

    if impact:
        score += CONFIDENCE_SCORES.get(impact.confidence, 0)

    return score


def calculate_verdict(
    fingerprint: Optional[FingerprintResult],
    baseline: Optional[BaselineResult],
    bypass: Optional[BypassResult],
    impact: Optional[ImpactResult]
) -> Tuple[Verdict, int]:
    """
    Calculate final verdict based on all phase results.

    Args:
        fingerprint: Phase 1 result
        baseline: Phase 2 result
        bypass: Phase 3 result
        impact: Phase 4 result

    Returns:
        Tuple of (Verdict, confidence_score)
    """
    # Gate check 1: Not Next.js
    if fingerprint is None or fingerprint.confidence == Confidence.NONE:
        return Verdict.SKIP_NOT_NEXTJS, 0

    # Gate check 2: No protected routes
    if baseline is None or not baseline.is_auth_protected:
        return Verdict.SKIP_NOT_PROTECTED, CONFIDENCE_SCORES.get(fingerprint.confidence, 0)

    # Gate check 3: Bypass doesn't work
    if bypass is None or not bypass.works:
        score = (
            CONFIDENCE_SCORES.get(fingerprint.confidence, 0) +
            CONFIDENCE_SCORES.get(baseline.auth_confidence, 0)
        )
        return Verdict.NOT_VULNERABLE, score

    # Gate check 4: Inconsistent results
    if not bypass.consistency_verified:
        score = (
            CONFIDENCE_SCORES.get(fingerprint.confidence, 0) +
            CONFIDENCE_SCORES.get(baseline.auth_confidence, 0) + 1
        )
        return Verdict.INCONCLUSIVE_INCONSISTENT, score

    # Gate check 5: Impact is login page (false positive)
    if impact and impact.is_login_page:
        score = (
            CONFIDENCE_SCORES.get(fingerprint.confidence, 0) +
            CONFIDENCE_SCORES.get(baseline.auth_confidence, 0) + 3
        )
        return Verdict.FALSE_POSITIVE_LOGIN_PAGE, score

    # Calculate confidence score
    total_score = calculate_confidence_score(fingerprint, baseline, bypass, impact)

    # Determine verdict based on score
    if total_score >= 10:
        return Verdict.HIGH_CONFIDENCE, total_score
    elif total_score >= 7:
        return Verdict.LIKELY, total_score
    elif total_score >= 4:
        return Verdict.POSSIBLE, total_score
    else:
        return Verdict.INCONCLUSIVE, total_score


def get_verdict_description(verdict: Verdict) -> str:
    """Get human-readable description for a verdict."""
    descriptions = {
        Verdict.HIGH_CONFIDENCE: "Very likely vulnerable. Multiple strong signals confirm the bypass works. Recommend immediate action.",
        Verdict.LIKELY: "Probably vulnerable. Strong signals detected but needs manual verification for full confirmation.",
        Verdict.POSSIBLE: "Some vulnerability signals detected. Requires further investigation.",
        Verdict.INCONCLUSIVE: "Cannot determine vulnerability status. Manual review required.",
        Verdict.INCONCLUSIVE_INCONSISTENT: "Bypass results were inconsistent (possibly due to caching or rate limiting). Cannot confirm.",
        Verdict.NOT_VULNERABLE: "Bypass does not appear to work. Middleware protection is effective.",
        Verdict.FALSE_POSITIVE_LOGIN_PAGE: "Bypass returns login page, not protected content. Likely a soft 404 or redirect handling.",
        Verdict.SKIP_NOT_NEXTJS: "Target does not appear to be running Next.js.",
        Verdict.SKIP_NOT_PROTECTED: "No middleware-protected routes detected.",
        Verdict.ERROR: "An error occurred during scanning.",
    }
    return descriptions.get(verdict, "Unknown verdict")


def get_verdict_severity(verdict: Verdict) -> str:
    """Get severity level for a verdict."""
    if verdict in [Verdict.HIGH_CONFIDENCE, Verdict.LIKELY]:
        return "CRITICAL"
    elif verdict == Verdict.POSSIBLE:
        return "HIGH"
    elif verdict in [Verdict.INCONCLUSIVE, Verdict.INCONCLUSIVE_INCONSISTENT]:
        return "MEDIUM"
    else:
        return "INFO"


def get_recommendation(verdict: Verdict) -> str:
    """Get recommended action for a verdict."""
    if verdict in [Verdict.HIGH_CONFIDENCE, Verdict.LIKELY]:
        return (
            "1. Upgrade Next.js immediately to version 15.2.3+ or 14.2.25+\n"
            "2. Review all middleware-protected routes for authorization bypass\n"
            "3. Consider adding additional authorization checks at the route level\n"
            "4. Audit access logs for potential exploitation"
        )
    elif verdict == Verdict.POSSIBLE:
        return (
            "1. Manually verify the bypass behavior\n"
            "2. Consider upgrading Next.js as a precaution\n"
            "3. Review middleware authorization logic"
        )
    elif verdict in [Verdict.INCONCLUSIVE, Verdict.INCONCLUSIVE_INCONSISTENT]:
        return (
            "1. Run the scan again to verify results\n"
            "2. Check for caching or rate limiting that may affect results\n"
            "3. Manually test the identified routes"
        )
    elif verdict == Verdict.NOT_VULNERABLE:
        return (
            "No immediate action required. Consider staying up to date with Next.js patches."
        )
    else:
        return "No specific recommendation."
