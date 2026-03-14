---
title: "WebAudit: Building a Web Security Scanner That Actually Explains Its Findings"
date: 2024-09-14
tags: [web-security, python, appsec, tools, owasp]
excerpt: "Most security scanners throw a wall of output at you and call it a day. I wanted something that not only finds issues but explains them — so I built WebAudit."
---

# WebAudit: Building a Web Security Scanner That Actually Explains Its Findings

There's no shortage of web security scanners. Nikto, OWASP ZAP, Burp Suite — they're all powerful, and I use them regularly. But they can be overwhelming, especially when you're trying to audit something quickly or share results with someone who isn't a security specialist.

I wanted a scanner that:
1. Covered the most impactful, highest-frequency web security issues
2. Explained each finding in plain language
3. Generated a clean HTML report you could drop into an email or paste into a Jira ticket

That's WebAudit.

## What It Actually Checks

### Security Headers

HTTP security headers are low-hanging fruit that an astonishing number of production sites get wrong. They're free to add, they mitigate real attack classes, and yet:

**Content-Security-Policy** — Present on a minority of sites, and when it's there, it often contains `unsafe-inline` which guts the XSS protection it's supposed to provide. CSP tells the browser which sources are allowed to load scripts, styles, and other resources. Without it, a single XSS vulnerability can run arbitrary JavaScript in your users' browsers.

**Strict-Transport-Security (HSTS)** — Forces HTTPS connections. Without it, an attacker who can intercept HTTP traffic (think coffee shop wifi) can strip the TLS and MITM the session.

**X-Frame-Options** — Prevents clickjacking, where an attacker embeds your site in an invisible iframe and tricks users into clicking things they didn't mean to.

These aren't obscure hardening tweaks. They're standard. WebAudit checks all of them and explains what each one does if it's missing.

### Exposed Sensitive Files

This check has caught real issues in the wild more times than I care to count. Developers push code to production and leave files behind — `.env` files with database credentials, `.git` directories exposing entire commit history, `phpinfo.php` pages revealing server configuration, backup files like `db.sql` that dump the entire database.

WebAudit probes for a curated list of the most commonly exposed paths. For each one that returns HTTP 200, it flags it as a FAIL with the severity it deserves (and `.env` containing AWS keys is definitely CRITICAL territory).

The `robots.txt` check is a bonus — it doesn't just verify the file exists, it parses the `Disallow` entries and surfaces them. Developers often put sensitive paths in robots.txt to hide them from search engines. This works exactly as well as hiding your house key under the doormat.

### SSL/TLS

Certificate management is surprisingly messy in practice. WebAudit checks:
- Whether the certificate is valid and trusted
- How many days until it expires (flags anything under 30 days as HIGH)
- Whether the TLS version in use is current (TLS 1.0/1.1 should be disabled everywhere)

### XSS Reflection Testing

This is a lightweight reflection test, not a full XSS exploit — the goal is to check whether the application blindly reflects user input in HTML output without encoding it. WebAudit injects a harmless unique string into GET parameters and checks whether it appears verbatim in the response body.

It's not a replacement for a proper XSS testing workflow, but it catches the low-hanging fruit cases where there's literally no output encoding at all.

### Open Redirect

Open redirects are underrated in terms of impact. By themselves they're medium severity, but they're commonly used in phishing chains: `https://legitimate-site.com/?redirect=https://evil.com` — the user clicks the legitimate domain and gets sent somewhere malicious.

WebAudit tests a list of common redirect parameter names and checks whether the server will redirect to an external URL.

## The HTML Report

I wanted the report to look like something a professional would hand to a client — dark-themed, clean, with color-coded severity badges and remediation recommendations for every finding. It's entirely self-contained (no external CSS or JS dependencies), which means you can email it or host it anywhere.

The security score (0–100) is calculated by deducting points for each finding by severity: CRITICAL costs 25 points, HIGH costs 15, MEDIUM costs 7. It's a rough number, not a certification, but it gives a quick at-a-glance health indicator.

## Running It

```bash
# Quick scan
python webaudit.py --url https://yourtarget.com

# Full report
python webaudit.py --url https://yourtarget.com --output report.html --json results.json
```

The terminal output is color-coded and includes remediation suggestions inline. The JSON output is machine-readable for feeding into other tools or SIEMs.

## Responsible Use

Every time I work with a scanner like this, I feel obligated to say it explicitly: **only test systems you own or have written permission to test**. Running this against someone else's site without authorization is illegal in most jurisdictions, regardless of what you find. The tool is built for security engineers doing legitimate assessments, developers checking their own apps, and bug bounty hunters working within program scope.

The user-agent is set to `WebAudit/1.0 Security Scanner` — there's no attempt to hide what the tool is. I think that's the right call for a legitimate security tool.

## What's Next

A few things on my roadmap:
- CORS misconfiguration testing (a surprisingly common and impactful issue)
- Directory listing detection
- Integration with SubScope for subdomain enumeration before scanning

---

*Code: [B0bTheSkull/webaudit](https://github.com/B0bTheSkull/webaudit)*
