"""
Phase 2: Identify Middleware-Protected Routes

Detects routes that are protected by middleware authorization logic.
Distinguishes between auth redirects and routing redirects (locale, trailing slash, etc.)
"""

from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urljoin

import requests
from requests.exceptions import RequestException

from .models import AuthRedirectResult, BaselineResult, Confidence


# Login page patterns
LOGIN_PATTERNS = [
    "/login", "/signin", "/sign-in", "/auth",
    "/sso", "/oauth", "/authenticate", "/session",
    "/account/login", "/user/login", "/users/sign_in",
    "/api/auth", "/connect", "/authorize"
]

# Return URL parameter names
RETURN_PARAMS = [
    "next", "redirect", "return", "returnUrl", "returnTo",
    "callback", "callbackUrl", "redirect_uri", "continue",
    "destination", "goto", "target", "url", "from", "ref"
]

# Locale prefixes
LOCALE_PATTERNS = [
    "/en/", "/en-us/", "/en-gb/",
    "/de/", "/de-de/",
    "/fr/", "/fr-fr/",
    "/es/", "/es-es/",
    "/jp/", "/ja/",
    "/zh/", "/zh-cn/", "/zh-tw/",
    "/ko/", "/ko-kr/",
    "/pt/", "/pt-br/",
    "/it/", "/ru/", "/nl/", "/pl/", "/tr/", "/ar/",
]

# Common protected route patterns to test
DEFAULT_PROTECTED_ROUTES = [
    "/admin",
    "/dashboard",
    "/api/admin",
    "/api/user",
    "/api/users",
    "/settings",
    "/account",
    "/profile",
    "/panel",
    "/console",
    "/manage",
    "/internal",
    "/private",
    "/protected",
]


def is_login_page(path: str) -> bool:
    """Check if a path looks like a login page."""
    path_lower = path.lower()
    return any(pattern in path_lower for pattern in LOGIN_PATTERNS)


def has_return_param(query_string: str) -> bool:
    """Check if query string contains a return/redirect parameter."""
    try:
        params = parse_qs(query_string)
        return any(param.lower() in [p.lower() for p in params.keys()] for param in RETURN_PARAMS)
    except Exception:
        return False


def is_path_normalization(request_path: str, location: str) -> bool:
    """Check if redirect is just path normalization (trailing slash)."""
    try:
        loc_parsed = urlparse(location)
        loc_path = loc_parsed.path

        # Trailing slash normalization
        if loc_path == request_path + "/":
            return True
        if loc_path.rstrip("/") == request_path.rstrip("/"):
            return True

        return False
    except Exception:
        return False


def is_locale_redirect(request_path: str, location: str) -> bool:
    """Check if redirect adds a locale prefix."""
    try:
        loc_parsed = urlparse(location)
        loc_path = loc_parsed.path.lower()

        for locale in LOCALE_PATTERNS:
            if loc_path.startswith(locale):
                # Check if rest of path matches original
                remaining = loc_path[len(locale) - 1:]  # Keep leading /
                if remaining == request_path or remaining.rstrip("/") == request_path.rstrip("/"):
                    return True

        return False
    except Exception:
        return False


def analyze_auth_redirect(
    request_path: str,
    status_code: int,
    location: Optional[str]
) -> AuthRedirectResult:
    """
    Analyze if a redirect is an auth redirect vs routing redirect.

    Returns:
        AuthRedirectResult with is_auth flag, confidence, and reason
    """
    # Direct auth status codes
    if status_code in [401, 403]:
        return AuthRedirectResult(
            is_auth=True,
            confidence=Confidence.HIGH,
            reason="Direct auth status code",
            location=location
        )

    # Not a redirect
    if status_code not in [301, 302, 303, 307, 308]:
        return AuthRedirectResult(
            is_auth=False,
            confidence=Confidence.HIGH,
            reason="Not a redirect",
            location=location
        )

    if not location:
        return AuthRedirectResult(
            is_auth=False,
            confidence=Confidence.MEDIUM,
            reason="Redirect without location header",
            location=None
        )

    try:
        loc_parsed = urlparse(location)
        loc_path = loc_parsed.path.lower()
        loc_query = loc_parsed.query

        # Check 1: Path normalization (trailing slash)
        if is_path_normalization(request_path, location):
            return AuthRedirectResult(
                is_auth=False,
                confidence=Confidence.HIGH,
                reason="Path normalization (trailing slash)",
                location=location
            )

        # Check 2: Locale redirect
        if is_locale_redirect(request_path, location):
            return AuthRedirectResult(
                is_auth=False,
                confidence=Confidence.HIGH,
                reason="Locale redirect",
                location=location
            )

        # Check 3: Login destination with return param
        is_login_dest = is_login_page(loc_path)
        has_return = has_return_param(loc_query)

        if is_login_dest and has_return:
            return AuthRedirectResult(
                is_auth=True,
                confidence=Confidence.HIGH,
                reason="Login page with return parameter",
                location=location
            )

        if is_login_dest:
            return AuthRedirectResult(
                is_auth=True,
                confidence=Confidence.MEDIUM,
                reason="Login page destination",
                location=location
            )

        # Check 4: Temporary redirects are more likely auth
        if status_code in [302, 307]:
            return AuthRedirectResult(
                is_auth=False,
                confidence=Confidence.LOW,
                reason="Unknown temporary redirect, might be auth",
                location=location
            )

        # Permanent redirects less likely to be auth
        return AuthRedirectResult(
            is_auth=False,
            confidence=Confidence.MEDIUM,
            reason="Permanent redirect, likely not auth",
            location=location
        )

    except Exception as e:
        return AuthRedirectResult(
            is_auth=False,
            confidence=Confidence.LOW,
            reason=f"Analysis error: {str(e)}",
            location=location
        )


def test_route_baseline(
    base_url: str,
    route: str,
    session: Optional[requests.Session] = None,
    timeout: int = 10
) -> BaselineResult:
    """
    Test a single route to establish baseline behavior.

    Args:
        base_url: Target base URL
        route: Route path to test (e.g., "/admin")
        session: Optional requests session
        timeout: Request timeout in seconds

    Returns:
        BaselineResult with auth protection analysis
    """
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    url = urljoin(base_url, route)

    try:
        # Request without cookies (unauthenticated)
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            cookies={}
        )

        status_code = response.status_code
        location = response.headers.get("location", response.headers.get("Location"))
        content = response.text
        content_length = len(content)

        # Analyze if this is an auth redirect
        auth_result = analyze_auth_redirect(route, status_code, location)

        # Build auth indicators list
        auth_indicators = []
        if auth_result.is_auth:
            auth_indicators.append(auth_result.reason)
            if location and is_login_page(location):
                auth_indicators.append("login destination")
            if location and has_return_param(urlparse(location).query):
                auth_indicators.append("return param present")

        return BaselineResult(
            route=route,
            status_code=status_code,
            is_auth_protected=auth_result.is_auth,
            auth_confidence=auth_result.confidence,
            auth_indicators=auth_indicators,
            redirect_location=location,
            content_length=content_length,
            content_sample=content[:2000] if content else "",
            headers=dict(response.headers)
        )

    except RequestException as e:
        return BaselineResult(
            route=route,
            status_code=0,
            is_auth_protected=False,
            auth_confidence=Confidence.NONE,
            error=f"Request failed: {str(e)}"
        )
    except Exception as e:
        return BaselineResult(
            route=route,
            status_code=0,
            is_auth_protected=False,
            auth_confidence=Confidence.NONE,
            error=f"Baseline error: {str(e)}"
        )


def find_protected_routes(
    base_url: str,
    routes: Optional[List[str]] = None,
    session: Optional[requests.Session] = None,
    timeout: int = 10
) -> List[BaselineResult]:
    """
    Find routes that appear to be protected by middleware.

    Args:
        base_url: Target base URL
        routes: List of routes to test (uses defaults if None)
        session: Optional requests session
        timeout: Request timeout in seconds

    Returns:
        List of BaselineResult for routes that appear protected
    """
    if routes is None:
        routes = DEFAULT_PROTECTED_ROUTES

    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    protected: List[BaselineResult] = []

    for route in routes:
        result = test_route_baseline(base_url, route, session, timeout)
        if result.is_auth_protected:
            protected.append(result)

    return protected


def validate_auth_consistency(
    base_url: str,
    route: str,
    session: Optional[requests.Session] = None,
    timeout: int = 10
) -> Tuple[bool, str]:
    """
    Validate auth protection by comparing behavior with/without cookies.

    True auth protection should redirect consistently regardless of
    invalid/fake cookies.

    Returns:
        Tuple of (is_consistent, reason)
    """
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    url = urljoin(base_url, route)

    try:
        # Request 1: No cookies
        resp_no_cookie = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            cookies={}
        )

        # Request 2: With fake cookie
        resp_fake_cookie = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            cookies={"session": "fake_invalid_session_value"}
        )

        # Compare behavior
        no_cookie_loc = resp_no_cookie.headers.get("location", "")
        fake_cookie_loc = resp_fake_cookie.headers.get("location", "")

        if resp_no_cookie.status_code == resp_fake_cookie.status_code:
            if no_cookie_loc == fake_cookie_loc:
                return True, "Consistent behavior with/without cookies"
            else:
                return False, f"Location differs: {no_cookie_loc} vs {fake_cookie_loc}"
        else:
            return False, f"Status differs: {resp_no_cookie.status_code} vs {resp_fake_cookie.status_code}"

    except RequestException as e:
        return False, f"Request error: {str(e)}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"
