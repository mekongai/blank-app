"""
CVE-2025-29927 Detection System - Streamlit UI

A security scanner for detecting Next.js middleware bypass vulnerability.
This tool is intended for authorized security testing only.
"""

import streamlit as st

from cve_scanner import CVE202529927Scanner, Verdict
from cve_scanner.verdict import get_verdict_description, get_recommendation, get_verdict_severity


# Page configuration
st.set_page_config(
    page_title="CVE-2025-29927 Scanner",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS
st.markdown("""
<style>
    .verdict-high { color: #ff4b4b; font-weight: bold; }
    .verdict-likely { color: #ffa500; font-weight: bold; }
    .verdict-possible { color: #ffcc00; font-weight: bold; }
    .verdict-safe { color: #00cc00; font-weight: bold; }
    .verdict-skip { color: #888888; }
    .evidence-box {
        background-color: #f0f2f6;
        border-radius: 5px;
        padding: 10px;
        margin: 5px 0;
    }
    .phase-header {
        border-left: 4px solid #1f77b4;
        padding-left: 10px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)


def get_verdict_color(verdict: Verdict) -> str:
    """Get color class for verdict display."""
    if verdict in [Verdict.HIGH_CONFIDENCE, Verdict.LIKELY]:
        return "verdict-high"
    elif verdict == Verdict.POSSIBLE:
        return "verdict-possible"
    elif verdict in [Verdict.NOT_VULNERABLE, Verdict.SKIP_NOT_NEXTJS, Verdict.SKIP_NOT_PROTECTED]:
        return "verdict-safe"
    else:
        return "verdict-skip"


def render_evidence_chain(result):
    """Render the evidence chain from scan result."""
    evidence = result.to_dict().get("evidence_chain", {})

    # Phase 1: Fingerprint
    if "phase1_fingerprint" in evidence:
        st.markdown("### Phase 1: Next.js Fingerprinting")
        fp = evidence["phase1_fingerprint"]
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Confidence", fp.get("confidence", "N/A"))
        with col2:
            st.metric("Total Weight", fp.get("total_weight", 0))

        if fp.get("signals"):
            with st.expander("Evidence Signals", expanded=False):
                for signal in fp["signals"]:
                    st.markdown(f"- **{signal['name']}** ({signal['type']}): {signal['value']} (weight: {signal['weight']})")

    # Phase 2: Baseline
    if "phase2_baseline" in evidence:
        st.markdown("### Phase 2: Protected Route Detection")
        bl = evidence["phase2_baseline"]
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Route", bl.get("route", "N/A"))
            st.metric("Status Code", bl.get("status_code", "N/A"))
        with col2:
            st.metric("Auth Confidence", bl.get("confidence", "N/A"))
            st.write("**Behavior:**", bl.get("behavior", "N/A"))

        if bl.get("auth_indicators"):
            with st.expander("Auth Indicators", expanded=False):
                for indicator in bl["auth_indicators"]:
                    st.markdown(f"- {indicator}")

    # Phase 3: Bypass
    if "phase3_bypass" in evidence:
        st.markdown("### Phase 3: Bypass Testing")
        bp = evidence["phase3_bypass"]

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Bypass Works", "Yes" if bp.get("works") else "No")
            st.metric("Payload", bp.get("payload", "N/A"))
        with col2:
            st.metric("Consistency", bp.get("consistency", "N/A"))
            if bp.get("difference"):
                st.write("**Difference:**", bp.get("difference", "N/A"))

        if bp.get("payloads_tested"):
            with st.expander("Payloads Tested", expanded=False):
                for payload in bp["payloads_tested"]:
                    st.markdown(f"- {payload}")

    # Phase 4: Impact
    if "phase4_impact" in evidence:
        st.markdown("### Phase 4: Impact Validation")
        imp = evidence["phase4_impact"]

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Real Impact", "Yes" if imp.get("is_real") else "No")
            st.metric("Confidence", imp.get("confidence", "N/A"))
        with col2:
            st.metric("Login Page", "Yes" if imp.get("login_page") else "No")
            st.write("**Reason:**", imp.get("reason", "N/A"))

        if imp.get("markers_found"):
            with st.expander("Markers Found", expanded=False):
                for marker in imp["markers_found"]:
                    st.markdown(f"- **{marker['category']}**: `{marker['marker']}`")


def main():
    st.title("CVE-2025-29927 Detection System")
    st.markdown("""
    **Next.js Middleware Bypass Vulnerability Scanner**

    This tool detects CVE-2025-29927, a critical vulnerability in Next.js that allows
    attackers to bypass middleware authorization by sending the `x-middleware-subrequest` header.

    ---
    **Disclaimer:** This tool is for authorized security testing only. Only scan targets you have permission to test.
    """)

    # Sidebar configuration
    with st.sidebar:
        st.header("Configuration")

        timeout = st.slider("Request Timeout (seconds)", 5, 30, 10)
        verify_ssl = st.checkbox("Verify SSL", value=True)
        skip_fingerprint = st.checkbox("Skip Fingerprinting", value=False,
                                       help="Skip Next.js detection and assume target is Next.js")

        st.markdown("---")

        st.subheader("Custom Routes")
        custom_routes = st.text_area(
            "Routes to test (one per line)",
            placeholder="/admin\n/dashboard\n/api/admin",
            help="Leave empty to use default routes"
        )

        st.markdown("---")

        st.subheader("About CVE-2025-29927")
        st.markdown("""
        - **CVSS Score:** 9.1 (Critical)
        - **Affected:** Next.js < 15.2.3, < 14.2.25
        - **Type:** Authorization Bypass
        - **Vector:** `x-middleware-subrequest` header
        """)

    # Main content
    col1, col2 = st.columns([3, 1])

    with col1:
        target_url = st.text_input(
            "Target URL",
            placeholder="https://example.com",
            help="Enter the URL of the Next.js application to scan"
        )

    with col2:
        st.write("")  # Spacing
        st.write("")  # Spacing
        scan_button = st.button("Scan", type="primary", use_container_width=True)

    if scan_button and target_url:
        # Parse custom routes
        routes = None
        if custom_routes.strip():
            routes = [r.strip() for r in custom_routes.strip().split("\n") if r.strip()]

        # Progress container
        progress_container = st.empty()
        status_text = st.empty()

        def progress_callback(message: str, percentage: int):
            progress_container.progress(percentage / 100, text=message)

        # Run scan
        with st.spinner("Scanning..."):
            try:
                scanner = CVE202529927Scanner(
                    timeout=timeout,
                    verify_ssl=verify_ssl,
                    progress_callback=progress_callback
                )

                result = scanner.scan(
                    url=target_url,
                    routes=routes,
                    skip_fingerprint=skip_fingerprint
                )

                # Clear progress
                progress_container.empty()
                status_text.empty()

                # Display results
                st.markdown("---")
                st.header("Scan Results")

                # Verdict display
                verdict_class = get_verdict_color(result.verdict)
                severity = get_verdict_severity(result.verdict)

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Verdict", result.verdict.value)
                with col2:
                    st.metric("Confidence Score", f"{result.confidence_score}/12")
                with col3:
                    st.metric("Severity", severity)

                # Description
                st.markdown(f"**{get_verdict_description(result.verdict)}**")

                # Warnings and errors
                if result.warnings:
                    with st.expander("Warnings", expanded=False):
                        for warning in result.warnings:
                            st.warning(warning)

                if result.errors:
                    with st.expander("Errors", expanded=True):
                        for error in result.errors:
                            st.error(error)

                # Evidence chain
                st.markdown("---")
                st.header("Evidence Chain")
                render_evidence_chain(result)

                # Recommendations
                if result.verdict in [Verdict.HIGH_CONFIDENCE, Verdict.LIKELY, Verdict.POSSIBLE]:
                    st.markdown("---")
                    st.header("Recommendations")
                    st.markdown(get_recommendation(result.verdict))

                # Raw JSON output
                st.markdown("---")
                with st.expander("Raw JSON Output", expanded=False):
                    st.json(result.to_dict())

                # Scan metadata
                st.markdown("---")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Scan Time", f"{result.scan_time_ms}ms")
                with col2:
                    st.metric("CVE", result.cve_id)
                with col3:
                    st.metric("CVSS", result.cvss_score)

            except Exception as e:
                st.error(f"Scan failed: {str(e)}")

    elif scan_button:
        st.warning("Please enter a target URL")

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #888;">
        <small>
            CVE-2025-29927 Detection System | For authorized security testing only<br>
            <a href="https://nvd.nist.gov/vuln/detail/CVE-2025-29927" target="_blank">NVD Reference</a>
        </small>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
