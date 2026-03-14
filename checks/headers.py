"""Security headers checker."""

HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "description": "Forces HTTPS connections (HSTS)",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "required": True,
        "description": "Mitigates XSS and data injection attacks",
        "recommendation": "Define a restrictive CSP policy for your application"
    },
    "X-Frame-Options": {
        "required": True,
        "description": "Prevents clickjacking attacks",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "required": True,
        "description": "Prevents MIME type sniffing",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "required": False,
        "description": "Controls referrer information in requests",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "required": False,
        "description": "Controls browser features/APIs",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "X-XSS-Protection": {
        "required": False,
        "description": "Legacy XSS filter (deprecated in modern browsers)",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (for older browser support)"
    },
}

CSP_UNSAFE = ["unsafe-inline", "unsafe-eval", "*"]


def check(response):
    findings = []
    resp_headers = {k.lower(): v for k, v in response.headers.items()}

    for header, info in HEADERS.items():
        value = response.headers.get(header)
        if not value:
            findings.append({
                "check": "security_headers",
                "header": header,
                "status": "FAIL" if info["required"] else "WARN",
                "severity": "HIGH" if info["required"] else "MEDIUM",
                "description": info["description"],
                "recommendation": info["recommendation"],
                "detail": f"Missing header: {header}"
            })
        else:
            # CSP quality check
            if header == "Content-Security-Policy":
                for unsafe in CSP_UNSAFE:
                    if unsafe in value:
                        findings.append({
                            "check": "security_headers",
                            "header": header,
                            "status": "WARN",
                            "severity": "MEDIUM",
                            "value": value,
                            "description": "CSP contains unsafe directive",
                            "detail": f"CSP contains '{unsafe}' which weakens XSS protection",
                            "recommendation": f"Remove '{unsafe}' from CSP or use nonce/hash-based approach"
                        })
            # HSTS quality check
            elif header == "Strict-Transport-Security":
                if "max-age" not in value.lower():
                    findings.append({
                        "check": "security_headers",
                        "header": header,
                        "status": "WARN",
                        "severity": "MEDIUM",
                        "value": value,
                        "detail": "HSTS header missing max-age directive",
                        "recommendation": "Set max-age to at least 31536000 (1 year)"
                    })
            else:
                findings.append({
                    "check": "security_headers",
                    "header": header,
                    "status": "PASS",
                    "severity": "INFO",
                    "value": value,
                    "detail": f"Header present: {header}"
                })

    return findings
