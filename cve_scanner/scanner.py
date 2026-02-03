"""
CVE-2025-29927 Scanner Orchestrator

Main scanner class that coordinates all phases and produces
final scan results with evidence chain.
"""

import time
from typing import List, Optional, Callable
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import (
    Confidence,
    Verdict,
    ScanResult,
    FingerprintResult,
    BaselineResult,
    BypassResult,
    ImpactResult,
)
from .fingerprint import fingerprint_nextjs
from .baseline import find_protected_routes, test_route_baseline, DEFAULT_PROTECTED_ROUTES
from .bypass import test_bypass
from .impact import validate_impact, validate_api_impact
from .verdict import calculate_verdict, get_verdict_description, get_recommendation


class CVE202529927Scanner:
    """
    Scanner for CVE-2025-29927 (Next.js middleware bypass).

    This scanner performs a 4-phase detection:
    1. Fingerprint: Verify target is Next.js
    2. Baseline: Find middleware-protected routes
    3. Bypass: Test bypass with consistency verification
    4. Impact: Validate access to protected content

    Usage:
        scanner = CVE202529927Scanner()
        result = scanner.scan("https://target.com")
        print(result.verdict)
    """

    def __init__(
        self,
        timeout: int = 10,
        max_retries: int = 3,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int], None]] = None
    ):
        """
        Initialize scanner.

        Args:
            timeout: Request timeout in seconds
            max_retries: Max retries for failed requests
            verify_ssl: Whether to verify SSL certificates
            user_agent: Custom user agent string
            progress_callback: Optional callback for progress updates (message, percentage)
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.progress_callback = progress_callback

        # Create session with retry logic
        self.session = requests.Session()

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set headers
        self.session.headers.update({
            "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

        self.session.verify = verify_ssl

    def _report_progress(self, message: str, percentage: int):
        """Report progress to callback if set."""
        if self.progress_callback:
            self.progress_callback(message, percentage)

    def _normalize_url(self, url: str) -> str:
        """Normalize URL format."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Remove trailing slash for consistency
        return url.rstrip("/")

    def scan(
        self,
        url: str,
        routes: Optional[List[str]] = None,
        skip_fingerprint: bool = False,
        specific_route: Optional[str] = None
    ) -> ScanResult:
        """
        Perform complete CVE-2025-29927 scan.

        Args:
            url: Target URL to scan
            routes: Optional list of routes to test (uses defaults if None)
            skip_fingerprint: Skip fingerprinting (assume Next.js)
            specific_route: Only test this specific route

        Returns:
            ScanResult with complete evidence chain
        """
        start_time = time.time()
        url = self._normalize_url(url)

        result = ScanResult(url=url, verdict=Verdict.ERROR)
        errors: List[str] = []
        warnings: List[str] = []

        try:
            # === PHASE 1: FINGERPRINT ===
            self._report_progress("Phase 1: Fingerprinting Next.js...", 10)

            if skip_fingerprint:
                fingerprint = FingerprintResult(
                    is_nextjs=True,
                    confidence=Confidence.MEDIUM,
                    total_weight=5
                )
                warnings.append("Fingerprinting skipped, assuming Next.js")
            else:
                fingerprint = fingerprint_nextjs(
                    url=url,
                    session=self.session,
                    timeout=self.timeout
                )

            result.fingerprint = fingerprint

            # Gate: Not Next.js
            if fingerprint.confidence == Confidence.NONE:
                result.verdict = Verdict.SKIP_NOT_NEXTJS
                result.confidence_score = 0
                result.scan_time_ms = int((time.time() - start_time) * 1000)
                return result

            self._report_progress(
                f"Phase 1 complete: Next.js detected ({fingerprint.confidence.value} confidence)",
                25
            )

            # === PHASE 2: FIND PROTECTED ROUTES ===
            self._report_progress("Phase 2: Finding protected routes...", 30)

            if specific_route:
                # Test only the specific route
                baseline = test_route_baseline(
                    base_url=url,
                    route=specific_route,
                    session=self.session,
                    timeout=self.timeout
                )
                protected_routes = [baseline] if baseline.is_auth_protected else []
            else:
                # Find all protected routes
                test_routes = routes or DEFAULT_PROTECTED_ROUTES
                protected_routes = find_protected_routes(
                    base_url=url,
                    routes=test_routes,
                    session=self.session,
                    timeout=self.timeout
                )

            # Gate: No protected routes
            if not protected_routes:
                result.verdict = Verdict.SKIP_NOT_PROTECTED
                result.confidence_score = CONFIDENCE_SCORES.get(fingerprint.confidence, 0)
                result.scan_time_ms = int((time.time() - start_time) * 1000)
                return result

            # Use first protected route for testing
            baseline = protected_routes[0]
            result.baseline = baseline

            if len(protected_routes) > 1:
                warnings.append(f"Found {len(protected_routes)} protected routes, testing: {baseline.route}")

            self._report_progress(
                f"Phase 2 complete: Found protected route {baseline.route}",
                50
            )

            # === PHASE 3: TEST BYPASS ===
            self._report_progress("Phase 3: Testing bypass...", 55)

            bypass = test_bypass(
                base_url=url,
                route=baseline.route,
                baseline=baseline,
                session=self.session,
                timeout=self.timeout
            )
            result.bypass = bypass

            # Gate: Bypass doesn't work
            if not bypass.works:
                verdict, score = calculate_verdict(fingerprint, baseline, bypass, None)
                result.verdict = verdict
                result.confidence_score = score
                result.scan_time_ms = int((time.time() - start_time) * 1000)
                return result

            self._report_progress(
                f"Phase 3 complete: Bypass works with payload {bypass.payload_name}",
                75
            )

            # === PHASE 4: VALIDATE IMPACT ===
            self._report_progress("Phase 4: Validating impact...", 80)

            # Determine if this is an API route
            is_api_route = "/api/" in baseline.route

            if is_api_route:
                impact = validate_api_impact(
                    bypass_content=bypass.bypass_content_sample,
                    baseline_content=baseline.content_sample,
                    bypass_status=bypass.bypass_status
                )
            else:
                impact = validate_impact(
                    bypass_content=bypass.bypass_content_sample,
                    baseline_content=baseline.content_sample,
                    bypass_status=bypass.bypass_status
                )

            result.impact = impact

            self._report_progress("Phase 4 complete: Impact validated", 90)

            # === CALCULATE FINAL VERDICT ===
            verdict, score = calculate_verdict(fingerprint, baseline, bypass, impact)
            result.verdict = verdict
            result.confidence_score = score

        except requests.exceptions.SSLError as e:
            errors.append(f"SSL Error: {str(e)}")
            warnings.append("Consider using verify_ssl=False for self-signed certificates")
            result.verdict = Verdict.ERROR

        except requests.exceptions.ConnectionError as e:
            errors.append(f"Connection Error: {str(e)}")
            result.verdict = Verdict.ERROR

        except requests.exceptions.Timeout as e:
            errors.append(f"Timeout: {str(e)}")
            result.verdict = Verdict.ERROR

        except Exception as e:
            errors.append(f"Unexpected error: {str(e)}")
            result.verdict = Verdict.ERROR

        finally:
            result.errors = errors
            result.warnings = warnings
            result.scan_time_ms = int((time.time() - start_time) * 1000)
            self._report_progress("Scan complete", 100)

        return result

    def scan_route(
        self,
        url: str,
        route: str
    ) -> ScanResult:
        """
        Scan a specific route.

        Convenience method for testing a single known protected route.
        """
        return self.scan(url=url, specific_route=route)

    def quick_scan(self, url: str) -> ScanResult:
        """
        Perform a quick scan with reduced checks.

        Useful for initial triage.
        """
        # Use shorter timeout and fewer routes
        old_timeout = self.timeout
        self.timeout = 5

        result = self.scan(
            url=url,
            routes=["/admin", "/dashboard", "/api/admin"],
        )

        self.timeout = old_timeout
        return result


# Confidence score mapping (duplicated here to avoid circular import)
CONFIDENCE_SCORES = {
    Confidence.NONE: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}


def scan_url(url: str, **kwargs) -> ScanResult:
    """
    Convenience function for single URL scan.

    Args:
        url: Target URL
        **kwargs: Additional arguments passed to scanner

    Returns:
        ScanResult
    """
    scanner = CVE202529927Scanner(**kwargs)
    return scanner.scan(url)
