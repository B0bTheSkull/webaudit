# WebAudit

> **Web application security scanner — finds misconfigs and common vulns, generates clean HTML reports.**

![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Ethical Use](https://img.shields.io/badge/authorized%20use-only-red?style=flat-square)

> ⚠️ Only use against systems you own or have explicit permission to test.

---

## What It Checks

| Category | What It Tests |
|----------|--------------|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **SSL/TLS** | Certificate validity, expiry (flags certs expiring in <30 days), TLS version |
| **Cookie Security** | Secure, HttpOnly, SameSite flags on all cookies |
| **Exposed Files** | `.env`, `.git/HEAD`, `wp-config.php`, backup files, `phpinfo.php`, robots.txt |
| **XSS Reflection** | Injects harmless test string into GET params, checks if it reflects unencoded |
| **Open Redirect** | Tests common redirect params (`?redirect=`, `?url=`, `?next=`, etc.) |

---

## Installation

```bash
git clone https://github.com/B0bTheSkull/webaudit.git
cd webaudit
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic scan with terminal output
python webaudit.py --url https://example.com

# Generate a full HTML report
python webaudit.py --url https://example.com --output report.html

# HTML + JSON output
python webaudit.py --url https://example.com --output report.html --json results.json

# Skip SSL verification (for self-signed certs)
python webaudit.py --url https://internal.example.com --no-verify

# Custom timeout
python webaudit.py --url https://slow-site.example.com --timeout 20
```

---

## Example Terminal Output

```
╔══════════════════════════════════════════╗
║  WebAudit v1.0 — Web Security Scanner   ║
║  Use only on systems you own/authorized  ║
╚══════════════════════════════════════════╝

[*] Target: https://example.com
[*] Starting scan...

[*] Checking: Security Headers...
    └─ 3 issue(s) found
  [FAIL] [HIGH] Missing header: Content-Security-Policy
         → Define a restrictive CSP policy for your application
  [FAIL] [HIGH] Missing header: Strict-Transport-Security
         → Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
  [WARN] [MEDIUM] Missing header: Permissions-Policy

[*] Checking: SSL/TLS...
    └─ 2 check(s) passed

[*] Checking: Cookie Security...
    └─ 1 issue(s) found
  [WARN] [MEDIUM] Cookie 'session' has security issues: Missing HttpOnly flag

[*] Checking: Exposed Files...
    └─ 1 issue(s) found
  [FAIL] [HIGH] Sensitive file accessible: /.env (HTTP 200)

────────────────────────────────────────────────────────────

Scan complete — 24 checks run
  FAIL: 3  WARN: 4  PASS: 17

[*] HTML report saved: report.html
```

---

## HTML Report

The HTML report is dark-themed and self-contained (no external dependencies). It includes:

- **Security score** (0–100) based on findings
- **Color-coded findings** (red=FAIL, yellow=WARN, green=PASS)
- **Remediation recommendations** for each issue
- **Grouped by check category** for easy navigation

---

## JSON Output

```json
{
  "url": "https://example.com",
  "total_findings": 24,
  "findings": [
    {
      "check": "security_headers",
      "header": "Content-Security-Policy",
      "status": "FAIL",
      "severity": "HIGH",
      "detail": "Missing header: Content-Security-Policy",
      "recommendation": "Define a restrictive CSP policy for your application"
    }
  ]
}
```

---

## Roadmap

- [ ] Directory listing detection
- [ ] Subdomain enumeration integration
- [ ] Rate limiting / WAF detection
- [ ] Authentication bypass checks
- [ ] CORS misconfiguration testing

---

## License

MIT — See [LICENSE](LICENSE). Use responsibly.
