"""Cookie security flag checker."""


def check(response, is_https=True):
    findings = []
    cookies = response.cookies

    if not cookies:
        findings.append({
            "check": "cookies",
            "status": "INFO",
            "severity": "INFO",
            "detail": "No cookies set in response"
        })
        return findings

    for cookie in cookies:
        issues = []

        if is_https and not cookie.secure:
            issues.append("Missing Secure flag (cookie transmitted over HTTP)")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("Missing HttpOnly flag (accessible via JavaScript)")

        samesite = cookie.get_nonstandard_attr("SameSite")
        if not samesite:
            issues.append("Missing SameSite attribute (CSRF risk)")
        elif samesite.lower() == "none" and not cookie.secure:
            issues.append("SameSite=None requires Secure flag")

        if issues:
            findings.append({
                "check": "cookies",
                "status": "WARN",
                "severity": "MEDIUM",
                "cookie_name": cookie.name,
                "issues": issues,
                "detail": f"Cookie '{cookie.name}' has security issues: {'; '.join(issues)}"
            })
        else:
            findings.append({
                "check": "cookies",
                "status": "PASS",
                "severity": "INFO",
                "cookie_name": cookie.name,
                "detail": f"Cookie '{cookie.name}' has correct security flags"
            })

    return findings
