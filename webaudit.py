#!/usr/bin/env python3
"""
WebAudit - Web Application Security Scanner
Checks for common misconfigurations and vulnerabilities.

⚠️  Only use against systems you own or have explicit permission to test.
"""

import argparse
import json
import sys
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from checks import headers, exposed_files, ssl_check, cookies, xss
from reporter import html_reporter

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
ORANGE = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
WHITE = "\033[37m"

SEVERITY_COLORS = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": WHITE}
STATUS_COLORS = {"FAIL": RED, "WARN": YELLOW, "PASS": GREEN, "INFO": WHITE}


def banner():
    print(f"""
{CYAN}╔══════════════════════════════════════════╗{RESET}
{CYAN}║  WebAudit v1.0 — Web Security Scanner   ║{RESET}
{CYAN}║  Use only on systems you own/authorized  ║{RESET}
{CYAN}╚══════════════════════════════════════════╝{RESET}
""")


def print_finding(f):
    status = f.get("status", "INFO")
    severity = f.get("severity", "INFO")
    detail = f.get("detail", "")
    scolor = STATUS_COLORS.get(status, WHITE)
    sevcolor = SEVERITY_COLORS.get(severity, WHITE)
    print(f"  {scolor}[{status}]{RESET} {sevcolor}[{severity}]{RESET} {detail}")
    rec = f.get("recommendation")
    if rec and status in ("FAIL", "WARN"):
        print(f"         {WHITE}→ {rec}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="WebAudit — Web application security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webaudit.py --url https://example.com
  python webaudit.py --url https://example.com --output report.html
  python webaudit.py --url https://example.com --output report.html --json results.json
  python webaudit.py --url https://example.com --no-verify
        """
    )
    parser.add_argument("--url", required=True, help="Target URL to audit")
    parser.add_argument("--output", help="Write HTML report to this file")
    parser.add_argument("--json", dest="json_output", help="Write JSON results to this file")
    parser.add_argument("--no-verify", action="store_true", help="Skip SSL certificate verification")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    banner()
    print(f"{CYAN}[*]{RESET} Target: {BOLD}{url}{RESET}")
    print(f"{CYAN}[*]{RESET} Starting scan...\n")

    parsed = urlparse(url)
    is_https = parsed.scheme == "https"

    session = requests.Session()
    session.headers["User-Agent"] = "WebAudit/1.0 Security Scanner"
    session.verify = not args.no_verify

    all_findings = []

    # Initial request
    try:
        initial_response = session.get(url, timeout=args.timeout, allow_redirects=True)
    except requests.RequestException as e:
        print(f"{RED}[!] Failed to connect to {url}: {e}{RESET}")
        sys.exit(1)

    # Run checks
    checks_to_run = [
        ("Security Headers", lambda: headers.check(initial_response)),
        ("SSL/TLS", lambda: ssl_check.check(url)),
        ("Cookie Security", lambda: cookies.check(initial_response, is_https=is_https)),
        ("Exposed Files", lambda: exposed_files.check(url, session, args.timeout)),
        ("XSS Reflection", lambda: xss.check_xss(url, session, args.timeout)),
        ("Open Redirect", lambda: xss.check_open_redirect(url, session, args.timeout)),
    ]

    for check_name, check_fn in checks_to_run:
        print(f"{CYAN}[*]{RESET} Checking: {check_name}...")
        try:
            findings = check_fn()
            all_findings.extend(findings)

            fails = sum(1 for f in findings if f.get("status") in ("FAIL", "WARN"))
            passes = sum(1 for f in findings if f.get("status") == "PASS")

            if fails > 0:
                print(f"    {YELLOW}└─ {fails} issue(s) found{RESET}")
            else:
                print(f"    {GREEN}└─ {passes} check(s) passed{RESET}")

            for f in findings:
                if f.get("status") in ("FAIL", "WARN"):
                    print_finding(f)
        except Exception as e:
            print(f"    {RED}└─ Error: {e}{RESET}")

    # Summary
    print(f"\n{'─'*60}")
    total = len(all_findings)
    fails = sum(1 for f in all_findings if f.get("status") == "FAIL")
    warns = sum(1 for f in all_findings if f.get("status") == "WARN")
    passes = sum(1 for f in all_findings if f.get("status") == "PASS")

    print(f"\n{BOLD}Scan complete — {total} checks run{RESET}")
    print(f"  {RED}FAIL: {fails}{RESET}  {YELLOW}WARN: {warns}{RESET}  {GREEN}PASS: {passes}{RESET}")

    if args.output:
        html_reporter.generate(url, all_findings, args.output)
        print(f"\n{CYAN}[*]{RESET} HTML report saved: {args.output}")

    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump({
                "url": url,
                "total_findings": total,
                "findings": all_findings
            }, f, indent=2)
        print(f"{CYAN}[*]{RESET} JSON report saved: {args.json_output}")


if __name__ == "__main__":
    main()
