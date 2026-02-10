"""
Phase 1: Next.js Fingerprinting

Detects whether a target is running Next.js by analyzing response headers,
HTML body content, and static asset patterns.
"""

import re
from typing import List, Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException

from .models import Evidence, FingerprintResult, Confidence


# Evidence definitions with weights
FINGERPRINT_CHECKS = [
    {
        "name": "x-powered-by",
        "type": "header",
        "weight": 3,
        "check": lambda headers, body: "next.js" in headers.get("x-powered-by", "").lower()
    },
    {
        "name": "x-nextjs-cache",
        "type": "header",
        "weight": 4,
        "check": lambda headers, body: "x-nextjs-cache" in [h.lower() for h in headers.keys()]
    },
    {
        "name": "x-nextjs-matched-path",
        "type": "header",
        "weight": 4,
        "check": lambda headers, body: "x-nextjs-matched-path" in [h.lower() for h in headers.keys()]
    },
    {
        "name": "__NEXT_DATA__",
        "type": "body",
        "weight": 4,
        "check": lambda headers, body: "__NEXT_DATA__" in body
    },
    {
        "name": "_next/static",
        "type": "body",
        "weight": 3,
        "check": lambda headers, body: "/_next/static/" in body
    },
    {
        "name": "self.__next_f",
        "type": "body",
        "weight": 3,
        "check": lambda headers, body: "self.__next_f" in body
    },
    {
        "name": "RSC payload (0:)",
        "type": "body",
        "weight": 4,
        "check": lambda headers, body: bool(re.search(r'^0:', body, re.MULTILINE))
    },
    {
        "name": "next/head",
        "type": "body",
        "weight": 2,
        "check": lambda headers, body: "next/head" in body.lower() or "next-head" in body.lower()
    },
    {
        "name": "buildId pattern",
        "type": "body",
        "weight": 3,
        "check": lambda headers, body: bool(re.search(r'"buildId"\s*:\s*"[a-zA-Z0-9_-]+"', body))
    },
]


def calculate_confidence(total_weight: int) -> Confidence:
    """
    Calculate confidence level based on total evidence weight.

    Returns:
        HIGH if weight >= 8 (multiple strong signals)
        MEDIUM if weight >= 4 (some signals)
        LOW if weight >= 2 (weak signals)
        NONE otherwise (not Next.js)
    """
    if total_weight >= 8:
        return Confidence.HIGH
    elif total_weight >= 4:
        return Confidence.MEDIUM
    elif total_weight >= 2:
        return Confidence.LOW
    else:
        return Confidence.NONE


def check_static_assets(base_url: str, session: requests.Session, timeout: int) -> List[Evidence]:
    """
    Check for Next.js static asset endpoints.

    Returns list of Evidence objects for asset checks.
    """
    evidences = []

    # Check /_next/image endpoint
    try:
        image_url = urljoin(base_url, "/_next/image")
        resp = session.head(image_url, timeout=timeout, allow_redirects=False)
        # Next.js image endpoint returns 400 when no params provided
        found = resp.status_code in [200, 400]
        evidences.append(Evidence(
            type="asset",
            name="_next/image endpoint",
            value=f"Status: {resp.status_code}",
            weight=2,
            found=found
        ))
    except RequestException:
        evidences.append(Evidence(
            type="asset",
            name="_next/image endpoint",
            value="Request failed",
            weight=2,
            found=False
        ))

    # Check for common Next.js static paths
    static_paths = [
        "/_next/static/chunks/main.js",
        "/_next/static/chunks/webpack.js",
        "/_next/static/chunks/framework.js",
    ]

    for path in static_paths:
        try:
            url = urljoin(base_url, path)
            resp = session.head(url, timeout=timeout, allow_redirects=False)
            found = resp.status_code == 200
            if found:
                evidences.append(Evidence(
                    type="asset",
                    name=f"Static chunk: {path}",
                    value=f"Status: {resp.status_code}",
                    weight=3,
                    found=True
                ))
                break  # One found is enough
        except RequestException:
            continue

    return evidences


def fingerprint_nextjs(
    url: str,
    session: Optional[requests.Session] = None,
    timeout: int = 10,
    check_assets: bool = True
) -> FingerprintResult:
    """
    Phase 1: Fingerprint target to determine if it's running Next.js.

    Args:
        url: Target URL to fingerprint
        session: Optional requests session to use
        timeout: Request timeout in seconds
        check_assets: Whether to check static asset endpoints

    Returns:
        FingerprintResult with confidence level and evidence chain
    """
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    evidences: List[Evidence] = []

    try:
        # Make initial request to target
        response = session.get(url, timeout=timeout, allow_redirects=True)
        headers = response.headers
        body = response.text

        # Run all fingerprint checks
        for check in FINGERPRINT_CHECKS:
            try:
                found = check["check"](headers, body)
                evidences.append(Evidence(
                    type=check["type"],
                    name=check["name"],
                    value=f"Found in {check['type']}" if found else "Not found",
                    weight=check["weight"],
                    found=found
                ))
            except Exception:
                evidences.append(Evidence(
                    type=check["type"],
                    name=check["name"],
                    value="Check failed",
                    weight=check["weight"],
                    found=False
                ))

        # Check static assets if enabled
        if check_assets:
            asset_evidences = check_static_assets(url, session, timeout)
            evidences.extend(asset_evidences)

        # Calculate total weight and confidence
        total_weight = sum(e.weight for e in evidences if e.found)
        confidence = calculate_confidence(total_weight)

        return FingerprintResult(
            is_nextjs=confidence != Confidence.NONE,
            confidence=confidence,
            evidences=evidences,
            total_weight=total_weight
        )

    except RequestException as e:
        return FingerprintResult(
            is_nextjs=False,
            confidence=Confidence.NONE,
            evidences=evidences,
            total_weight=0,
            error=f"Request failed: {str(e)}"
        )
    except Exception as e:
        return FingerprintResult(
            is_nextjs=False,
            confidence=Confidence.NONE,
            evidences=evidences,
            total_weight=0,
            error=f"Fingerprint error: {str(e)}"
        )
