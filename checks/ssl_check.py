"""SSL/TLS certificate checker."""
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def check(url):
    findings = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append({
            "check": "ssl",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": "Site is not using HTTPS",
            "recommendation": "Enable HTTPS with a valid TLS certificate"
        })
        return findings

    hostname = parsed.netloc.split(":")[0]
    port = int(parsed.port) if parsed.port else 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        # Certificate expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_dt - datetime.utcnow()).days

            if days_left < 0:
                findings.append({
                    "check": "ssl",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": f"Certificate EXPIRED {abs(days_left)} days ago",
                    "expiry": expire_str
                })
            elif days_left < 30:
                findings.append({
                    "check": "ssl",
                    "status": "WARN",
                    "severity": "HIGH",
                    "detail": f"Certificate expires in {days_left} days",
                    "expiry": expire_str,
                    "recommendation": "Renew certificate immediately"
                })
            else:
                findings.append({
                    "check": "ssl",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Certificate valid for {days_left} more days",
                    "expiry": expire_str
                })

        # Cipher suite
        if cipher:
            cipher_name, tls_version, _ = cipher
            findings.append({
                "check": "ssl",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"TLS version: {tls_version}, Cipher: {cipher_name}"
            })

            if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                findings.append({
                    "check": "ssl",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"Weak TLS version in use: {tls_version}",
                    "recommendation": "Disable TLS 1.0/1.1 and use TLS 1.2/1.3 only"
                })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "check": "ssl",
            "status": "FAIL",
            "severity": "HIGH",
            "detail": f"SSL certificate verification failed: {e}",
            "recommendation": "Use a certificate from a trusted CA"
        })
    except Exception as e:
        findings.append({
            "check": "ssl",
            "status": "ERROR",
            "severity": "MEDIUM",
            "detail": f"SSL check error: {e}"
        })

    return findings
