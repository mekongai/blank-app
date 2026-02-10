"""
Phase 4: Validate Impact with Stable Markers

Validates that the bypass actually provides access to protected content
by looking for stable markers that indicate authenticated content.
"""

import logging
from typing import Dict, List, Tuple
from html.parser import HTMLParser

from .models import ImpactResult, MarkerMatch, Confidence


# Configure logging
logger = logging.getLogger(__name__)

# Threshold constants for impact validation
MIN_MARKERS_HIGH_CONFIDENCE = 2      # Minimum markers for HIGH confidence
MIN_STRUCTURAL_DIFF_MEDIUM = 10      # Structural diff for MEDIUM confidence
MIN_STRUCTURAL_DIFF_LOW = 5          # Structural diff for LOW confidence
MIN_CONTENT_LENGTH_DIFF = 5000       # Minimum content length diff (bytes)
MIN_LOGIN_PAGE_SIGNALS = 2           # Minimum signals to detect login page
MIN_ERROR_PAGE_SIGNALS = 2           # Minimum signals to detect error page
API_RESPONSE_SIZE_MULTIPLIER = 2     # API response must be 2x larger


# Stable markers that indicate authenticated/protected content
STABLE_MARKERS: Dict[str, List[str]] = {
    # DOM elements only present when authenticated
    "dom_markers": [
        'data-testid="admin-',
        'data-testid="dashboard-',
        'data-testid="user-',
        'class="admin-',
        'class="dashboard-',
        'id="admin-',
        'id="dashboard-',
        '<nav class="authenticated',
        '<nav class="admin',
        'data-user=',
        'data-role=',
        'data-authenticated=',
        'data-admin=',
        'class="user-menu',
        'class="account-menu',
        'class="settings-menu',
    ],

    # API response fields only present when authenticated
    "api_markers": [
        '"users":',
        '"admin":',
        '"permissions":',
        '"role":',
        '"settings":',
        '"config":',
        '"profile":',
        '"account":',
        '"email":',
        '"username":',
        '"accessToken":',
        '"refreshToken":',
        '"isAdmin":',
        '"isAuthenticated":',
        '"userData":',
        '"userInfo":',
    ],

    # Routes/links only visible when authenticated
    "route_markers": [
        'href="/admin/',
        'href="/dashboard/',
        'href="/settings/',
        'href="/users/',
        'href="/api/admin',
        'href="/api/users',
        'href="/account/',
        'href="/profile/',
        'href="/manage/',
        'href="/console/',
        'href="/panel/',
        'href="/internal/',
        'to="/admin/',
        'to="/dashboard/',
        'to="/settings/',
    ],

    # Text content indicating protected area
    "text_markers": [
        'welcome back,',
        'logged in as',
        'signed in as',
        'my account',
        'my dashboard',
        'admin panel',
        'admin dashboard',
        'user management',
        'system settings',
        'account settings',
        'profile settings',
        'logout',
        'sign out',
        'log out',
    ],
}

# Markers indicating a login page (false positive detection)
LOGIN_PAGE_MARKERS = [
    'type="password"',
    'name="password"',
    'id="password"',
    '<form',
    'action="/login',
    'action="/signin',
    'action="/auth',
    'forgot-password',
    'forgot password',
    'reset password',
    'sign up',
    'sign-up',
    'signup',
    'create account',
    'create an account',
    'register',
    'don\'t have an account',
    "don't have an account",
    'remember me',
    'keep me signed in',
]

# Markers indicating error pages
ERROR_PAGE_MARKERS = [
    '404',
    'not found',
    'page not found',
    'access denied',
    'forbidden',
    'unauthorized',
    'error',
    '500',
    'internal server error',
    'something went wrong',
]


class DOMStructureParser(HTMLParser):
    """Simple HTML parser to extract DOM structure."""

    def __init__(self):
        super().__init__()
        self.elements: List[str] = []
        self.depth = 0

    def handle_starttag(self, tag, attrs):
        # Create a normalized representation of the element
        attr_keys = sorted([a[0] for a in attrs if a[0] not in ['style', 'data-nonce', 'nonce']])
        element_sig = f"{self.depth}:{tag}[{','.join(attr_keys[:5])}]"
        self.elements.append(element_sig)
        self.depth += 1

    def handle_endtag(self, tag):
        self.depth = max(0, self.depth - 1)

    def get_structure(self) -> List[str]:
        return self.elements


def extract_dom_structure(html: str) -> List[str]:
    """
    Extract simplified DOM structure from HTML.

    Args:
        html: HTML content to parse

    Returns:
        List of element signatures representing DOM structure
    """
    if not html or not html.strip():
        return []

    try:
        parser = DOMStructureParser()
        parser.feed(html)
        return parser.get_structure()
    except Exception as e:
        # Log the error for debugging but don't fail
        logger.debug(f"Failed to parse HTML structure: {type(e).__name__}: {e}")
        return []


def is_login_page(content: str) -> Tuple[bool, int]:
    """
    Check if content appears to be a login page.

    Args:
        content: Page content to analyze

    Returns:
        Tuple of (is_login, signal_count)
    """
    if not content:
        return False, 0

    content_lower = content.lower()
    signals = sum(1 for m in LOGIN_PAGE_MARKERS if m in content_lower)
    return signals >= MIN_LOGIN_PAGE_SIGNALS, signals


def is_error_page(content: str) -> Tuple[bool, int]:
    """
    Check if content appears to be an error page.

    Args:
        content: Page content to analyze

    Returns:
        Tuple of (is_error, signal_count)
    """
    if not content:
        return False, 0

    content_lower = content.lower()
    signals = sum(1 for m in ERROR_PAGE_MARKERS if m in content_lower)
    return signals >= MIN_ERROR_PAGE_SIGNALS, signals


def find_new_markers(
    bypass_content: str,
    baseline_content: str
) -> List[MarkerMatch]:
    """
    Find auth-only markers in bypass content that aren't in baseline.

    Returns:
        List of MarkerMatch objects for found markers
    """
    bypass_lower = bypass_content.lower()
    baseline_lower = baseline_content.lower()

    new_markers: List[MarkerMatch] = []

    for category, markers in STABLE_MARKERS.items():
        for marker in markers:
            marker_lower = marker.lower()
            if marker_lower in bypass_lower and marker_lower not in baseline_lower:
                new_markers.append(MarkerMatch(
                    category=category,
                    marker=marker
                ))

    return new_markers


def calculate_structural_diff(
    bypass_content: str,
    baseline_content: str
) -> int:
    """
    Calculate the number of significant structural differences.

    Returns:
        Number of structural elements that differ
    """
    bypass_structure = extract_dom_structure(bypass_content)
    baseline_structure = extract_dom_structure(baseline_content)

    # Convert to sets for comparison
    bypass_set = set(bypass_structure)
    baseline_set = set(baseline_structure)

    # Elements in bypass but not in baseline
    new_elements = bypass_set - baseline_set

    return len(new_elements)


def validate_impact(
    bypass_content: str,
    baseline_content: str,
    bypass_status: int = 200
) -> ImpactResult:
    """
    Phase 4: Validate that bypass provides real access to protected content.

    Args:
        bypass_content: Content received with bypass header
        baseline_content: Content received without bypass (normal behavior)
        bypass_status: HTTP status code of bypass response

    Returns:
        ImpactResult with validation details
    """
    # Check 1: Is bypass content a login page?
    login_check, login_signals = is_login_page(bypass_content)
    if login_check:
        return ImpactResult(
            is_real=False,
            confidence=Confidence.HIGH,
            reason=f"Bypass content is login page ({login_signals} signals)",
            is_login_page=True
        )

    # Check 2: Is bypass content an error page?
    error_check, error_signals = is_error_page(bypass_content)
    if error_check:
        return ImpactResult(
            is_real=False,
            confidence=Confidence.MEDIUM,
            reason=f"Bypass content appears to be error page ({error_signals} signals)"
        )

    # Check 3: Find auth-only markers in bypass that aren't in baseline
    new_markers = find_new_markers(bypass_content, baseline_content)

    if len(new_markers) >= MIN_MARKERS_HIGH_CONFIDENCE:
        # 2+ markers = HIGH confidence
        return ImpactResult(
            is_real=True,
            confidence=Confidence.HIGH,
            reason=f"Found {len(new_markers)} auth-only markers",
            markers_found=new_markers
        )

    if len(new_markers) == 1:
        # Single marker = MEDIUM confidence
        return ImpactResult(
            is_real=True,
            confidence=Confidence.MEDIUM,
            reason="Found 1 auth-only marker",
            markers_found=new_markers
        )

    # Check 4: Structural difference
    structural_diff = calculate_structural_diff(bypass_content, baseline_content)

    if structural_diff > MIN_STRUCTURAL_DIFF_MEDIUM:
        return ImpactResult(
            is_real=True,
            confidence=Confidence.MEDIUM,
            reason=f"Significant structural difference ({structural_diff} new elements)",
            structural_diff_count=structural_diff
        )

    if structural_diff > MIN_STRUCTURAL_DIFF_LOW:
        return ImpactResult(
            is_real=True,
            confidence=Confidence.LOW,
            reason=f"Some structural difference ({structural_diff} new elements)",
            structural_diff_count=structural_diff
        )

    # Check 5: Content length difference (weak signal)
    len_diff = len(bypass_content) - len(baseline_content)
    if len_diff > MIN_CONTENT_LENGTH_DIFF:
        return ImpactResult(
            is_real=True,
            confidence=Confidence.LOW,
            reason=f"Significant content length increase (+{len_diff} bytes)",
            structural_diff_count=0
        )

    # No clear evidence of real impact
    return ImpactResult(
        is_real=False,
        confidence=Confidence.MEDIUM,
        reason="No stable markers found, difference may be dynamic content"
    )


def validate_api_impact(
    bypass_content: str,
    baseline_content: str,
    bypass_status: int = 200
) -> ImpactResult:
    """
    Validate impact for API endpoints.

    API endpoints may have different markers than HTML pages.
    """
    # Check if responses are JSON
    bypass_is_json = bypass_content.strip().startswith('{') or bypass_content.strip().startswith('[')
    baseline_is_json = baseline_content.strip().startswith('{') or baseline_content.strip().startswith('[')

    if bypass_is_json:
        # Look for API-specific markers
        api_markers = STABLE_MARKERS["api_markers"]
        bypass_lower = bypass_content.lower()
        baseline_lower = baseline_content.lower()

        new_markers = []
        for marker in api_markers:
            if marker in bypass_lower and marker not in baseline_lower:
                new_markers.append(MarkerMatch(category="api", marker=marker))

        if len(new_markers) >= 2:
            return ImpactResult(
                is_real=True,
                confidence=Confidence.HIGH,
                reason=f"Found {len(new_markers)} API data markers",
                markers_found=new_markers
            )

        if len(new_markers) == 1:
            return ImpactResult(
                is_real=True,
                confidence=Confidence.MEDIUM,
                reason="Found 1 API data marker",
                markers_found=new_markers
            )

        # Check for data exposure by length
        if len(bypass_content) > len(baseline_content) * API_RESPONSE_SIZE_MULTIPLIER:
            return ImpactResult(
                is_real=True,
                confidence=Confidence.LOW,
                reason=f"API response significantly larger ({len(bypass_content)} vs {len(baseline_content)} bytes)"
            )

    # Fall back to standard validation
    return validate_impact(bypass_content, baseline_content, bypass_status)
