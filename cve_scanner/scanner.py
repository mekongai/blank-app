"""
CVE-2025-29927 Scanner Orchestrator

Main scanner class that coordinates all phases and produces
final scan results with evidence chain.
"""

import ipaddress
import logging
import re
import socket
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


# Configure logging
logger = logging.getLogger(__name__)

# Confidence score mapping
CONFIDENCE_SCORES = {
    Confidence.NONE: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}

# URL validation constants
MAX_URL_LENGTH = 2048
BLOCKED_HOSTS = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
]

# Private IP ranges for SSRF prevention
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("127.0.0.0/8"),     # Loopback
]


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
        progress_callback: Optional[Callable[[str, int], None]] = None,
        allow_private_ips: bool = False
    ):
        """
        Initialize scanner.

        Args:
            timeout: Request timeout in seconds
            max_retries: Max retries for failed requests
            verify_ssl: Whether to verify SSL certificates
            user_agent: Custom user agent string
            progress_callback: Optional callback for progress updates (message, percentage)
            allow_private_ips: Allow scanning private/internal IPs (default: False for SSRF prevention)
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.progress_callback = progress_callback
        self.allow_private_ips = allow_private_ips
        self._session: Optional[requests.Session] = None

    @property
    def session(self) -> requests.Session:
        """Lazy initialization of session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def _create_session(self) -> requests.Session:
        """Create and configure requests session."""
        session = requests.Session()

        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Updated User-Agent (Chrome 122, Feb 2024)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

        session.verify = self.verify_ssl
        return session

    def close(self):
        """Close the session and release resources."""
        if self._session is not None:
            self._session.close()
            self._session = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        self.close()
        return False

    def __del__(self):
        """Destructor - ensure session is closed."""
        self.close()

    def _report_progress(self, message: str, percentage: int):
        """Report progress to callback if set."""
        if self.progress_callback:
            self.progress_callback(message, percentage)

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if an IP address is private/internal."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in network for network in PRIVATE_IP_RANGES)
        except ValueError:
            return False

    def _validate_url(self, url: str) -> tuple:
        """
        Validate URL for security and correctness.

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check length
        if len(url) > MAX_URL_LENGTH:
            return False, f"URL exceeds maximum length ({MAX_URL_LENGTH})"

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "Invalid URL format"

        # Check scheme
        if parsed.scheme not in ("http", "https"):
            return False, f"Invalid scheme: {parsed.scheme}"

        # Check host
        if not parsed.netloc:
            return False, "Missing host in URL"

        # Extract hostname (remove port if present)
        hostname = parsed.hostname or parsed.netloc.split(":")[0]

        # Check blocked hosts
        if hostname.lower() in BLOCKED_HOSTS:
            return False, f"Blocked host: {hostname}"

        # SSRF prevention: check for private IPs
        if not self.allow_private_ips:
            # Try to resolve hostname to check for private IPs
            try:
                ip = socket.gethostbyname(hostname)
                if self._is_private_ip(ip):
                    return False, f"Private IP not allowed: {ip}"
            except socket.gaierror:
                # Can't resolve - might be invalid or DNS issue
                pass

            # Also check if hostname itself is an IP
            if self._is_private_ip(hostname):
                return False, f"Private IP not allowed: {hostname}"

        return True, None

    def _normalize_url(self, url: str) -> str:
        """
        Normalize and validate URL format.

        Raises:
            ValueError: If URL is invalid or blocked
        """
        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Validate URL
        is_valid, error = self._validate_url(url)
        if not is_valid:
            raise ValueError(f"Invalid URL: {error}")

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

        result = ScanResult(url=url, verdict=Verdict.ERROR)
        errors: List[str] = []
        warnings: List[str] = []

        # Validate and normalize URL
        try:
            url = self._normalize_url(url)
            result.url = url
        except ValueError as e:
            errors.append(str(e))
            result.errors = errors
            result.scan_time_ms = int((time.time() - start_time) * 1000)
            return result

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
            # Sanitize SSL error - don't expose internal certificate details
            errors.append("SSL certificate verification failed")
            warnings.append("Consider using verify_ssl=False for self-signed certificates")
            logger.debug(f"SSL Error details: {e}")
            result.verdict = Verdict.ERROR

        except requests.exceptions.ConnectionError as e:
            # Sanitize connection error - don't expose internal network info
            errors.append("Connection failed - target may be unreachable")
            logger.debug(f"Connection Error details: {e}")
            result.verdict = Verdict.ERROR

        except requests.exceptions.Timeout:
            errors.append(f"Request timed out after {self.timeout} seconds")
            result.verdict = Verdict.ERROR

        except Exception as e:
            # Log full error for debugging, but sanitize for user
            logger.exception("Unexpected error during scan")
            errors.append("An unexpected error occurred during scanning")
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


def scan_url(url: str, **kwargs) -> ScanResult:
    """
    Convenience function for single URL scan.

    Uses context manager to ensure proper cleanup.

    Args:
        url: Target URL
        **kwargs: Additional arguments passed to scanner

    Returns:
        ScanResult
    """
    with CVE202529927Scanner(**kwargs) as scanner:
        return scanner.scan(url)
