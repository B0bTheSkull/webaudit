"""XSS reflection and open redirect tests."""
import logging
import urllib.parse
import requests

logger = logging.getLogger(__name__)

XSS_PAYLOAD = "WebAudit_XSS_TEST_abc123"
REDIRECT_PAYLOAD = "https://example.com"
REDIRECT_PARAMS = ["redirect", "url", "next", "return", "return_to", "redirect_to",
                   "goto", "dest", "destination", "target", "redir", "r", "u"]


def check_xss(base_url, session, timeout=10):
    """Test if GET parameters reflect unsanitized input."""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    if not params:
        # Try injecting into a common test param
        test_params = {"q": XSS_PAYLOAD, "search": XSS_PAYLOAD, "s": XSS_PAYLOAD}
        for param, payload in test_params.items():
            test_url = f"{base_url}{'?' if '?' not in base_url else '&'}{param}={urllib.parse.quote(payload)}"
            try:
                r = session.get(test_url, timeout=timeout, allow_redirects=True)
                if XSS_PAYLOAD in r.text:
                    findings.append({
                        "check": "xss_reflection",
                        "status": "WARN",
                        "severity": "MEDIUM",
                        "url": test_url,
                        "parameter": param,
                        "detail": f"Input reflected unencoded in response for param '{param}' — possible XSS",
                        "recommendation": "Encode all user input before reflecting in HTML output"
                    })
            except requests.RequestException as exc:
                logger.debug("XSS probe request failed for %s: %s", test_url, exc)
    else:
        # Test each existing parameter
        for param in params:
            modified = params.copy()
            modified[param] = XSS_PAYLOAD
            test_url = parsed._replace(query=urllib.parse.urlencode(modified)).geturl()
            try:
                r = session.get(test_url, timeout=timeout, allow_redirects=True)
                if XSS_PAYLOAD in r.text:
                    findings.append({
                        "check": "xss_reflection",
                        "status": "WARN",
                        "severity": "MEDIUM",
                        "url": test_url,
                        "parameter": param,
                        "detail": f"Input reflected unencoded for param '{param}' — possible XSS",
                        "recommendation": "Sanitize and encode all reflected user input"
                    })
            except requests.RequestException as exc:
                logger.debug("XSS probe request failed for %s: %s", test_url, exc)

    return findings


def check_open_redirect(base_url, session, timeout=10):
    """Test common redirect parameters for open redirect."""
    findings = []
    base = base_url.split("?")[0]

    for param in REDIRECT_PARAMS:
        test_url = f"{base}?{param}={urllib.parse.quote(REDIRECT_PAYLOAD)}"
        try:
            r = session.get(test_url, timeout=timeout, allow_redirects=False)
            location = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and "example.com" in location:
                findings.append({
                    "check": "open_redirect",
                    "status": "FAIL",
                    "severity": "MEDIUM",
                    "url": test_url,
                    "parameter": param,
                    "redirect_to": location,
                    "detail": f"Open redirect via '{param}' parameter — redirects to {location}",
                    "recommendation": "Validate redirect URLs against an allowlist of trusted destinations"
                })
        except requests.RequestException as exc:
            logger.debug("Open-redirect probe request failed for %s: %s", test_url, exc)

    return findings
