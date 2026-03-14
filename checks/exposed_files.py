"""Check for exposed sensitive files."""
import requests

SENSITIVE_PATHS = [
    ("/.env", "HIGH", "Environment file with credentials/config"),
    ("/.env.local", "HIGH", "Local environment file"),
    ("/.env.production", "HIGH", "Production environment file"),
    ("/.git/HEAD", "HIGH", "Exposed git repository"),
    ("/.git/config", "HIGH", "Git config with remote URLs"),
    ("/wp-config.php", "HIGH", "WordPress configuration with DB credentials"),
    ("/config.php", "HIGH", "PHP configuration file"),
    ("/phpinfo.php", "MEDIUM", "PHP info page leaks server details"),
    ("/backup.zip", "HIGH", "Backup archive"),
    ("/backup.tar.gz", "HIGH", "Backup archive"),
    ("/db.sql", "HIGH", "SQL database dump"),
    ("/database.sql", "HIGH", "SQL database dump"),
    ("/.DS_Store", "LOW", "macOS directory metadata"),
    ("/.htaccess", "MEDIUM", "Apache configuration file"),
    ("/web.config", "MEDIUM", "IIS configuration file"),
    ("/server-status", "MEDIUM", "Apache server status page"),
    ("/server-info", "MEDIUM", "Apache server info page"),
]

SEVERITY_MAP = {"HIGH": "FAIL", "MEDIUM": "WARN", "LOW": "INFO"}


def check(base_url, session, timeout=10):
    findings = []
    base_url = base_url.rstrip("/")

    for path, severity, description in SENSITIVE_PATHS:
        url = base_url + path
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 206):
                # Verify it's not a generic 200 for everything (soft 404)
                content = r.text[:200].lower()
                is_real = not any(phrase in content for phrase in [
                    "page not found", "404", "not exist", "doesn't exist"
                ])
                if is_real:
                    findings.append({
                        "check": "exposed_files",
                        "status": SEVERITY_MAP.get(severity, "WARN"),
                        "severity": severity,
                        "url": url,
                        "http_status": r.status_code,
                        "description": description,
                        "detail": f"Sensitive file accessible: {path} (HTTP {r.status_code})"
                    })
        except requests.RequestException:
            pass

    # Check robots.txt for interesting paths
    robots_url = base_url + "/robots.txt"
    try:
        r = session.get(robots_url, timeout=timeout)
        if r.status_code == 200:
            disallowed = [
                line.split(":", 1)[1].strip()
                for line in r.text.splitlines()
                if line.lower().startswith("disallow:") and len(line.split(":", 1)) > 1
            ]
            if disallowed:
                findings.append({
                    "check": "exposed_files",
                    "status": "INFO",
                    "severity": "LOW",
                    "url": robots_url,
                    "description": "robots.txt reveals path structure",
                    "disallowed_paths": disallowed[:20],
                    "detail": f"robots.txt lists {len(disallowed)} Disallow entries — may reveal sensitive paths"
                })
    except requests.RequestException:
        pass

    return findings
