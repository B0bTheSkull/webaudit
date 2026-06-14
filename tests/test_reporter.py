"""Tests for severity scoring and HTML escaping in the reporter."""
from reporter import html_reporter


def test_empty_findings_scores_100():
    assert html_reporter._severity_score([]) == 100


def test_deductions_per_severity():
    findings = [
        {"status": "FAIL", "severity": "HIGH"},     # -15
        {"status": "WARN", "severity": "MEDIUM"},   # -7
        {"status": "FAIL", "severity": "LOW"},      # -2
    ]
    assert html_reporter._severity_score(findings) == 100 - 15 - 7 - 2


def test_pass_and_info_do_not_deduct():
    findings = [
        {"status": "PASS", "severity": "INFO"},
        {"status": "INFO", "severity": "LOW"},
    ]
    assert html_reporter._severity_score(findings) == 100


def test_score_floored_at_zero():
    findings = [{"status": "FAIL", "severity": "CRITICAL"}] * 10  # -250
    assert html_reporter._severity_score(findings) == 0


def test_score_color_thresholds():
    assert html_reporter._score_color(90) == "#51cf66"
    assert html_reporter._score_color(80) == "#51cf66"
    assert html_reporter._score_color(70) == "#ffd700"
    assert html_reporter._score_color(60) == "#ffd700"
    assert html_reporter._score_color(40) == "#ff4444"


def test_html_escaping_of_url(tmp_path):
    out = tmp_path / "r.html"
    malicious_url = 'http://x.example/"><script>alert(1)</script>'
    html_reporter.generate(malicious_url, [], str(out))
    content = out.read_text()
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content


def test_html_escaping_of_finding_detail(tmp_path):
    out = tmp_path / "r.html"
    findings = [{
        "check": "xss_reflection",
        "status": "WARN",
        "severity": "MEDIUM",
        "detail": "reflected <img src=x onerror=alert(1)>",
        "parameter": "<b>q</b>",
    }]
    html_reporter.generate("http://x.example", findings, str(out))
    content = out.read_text()
    assert "<img src=x onerror=alert(1)>" not in content
    assert "&lt;img" in content
    # extra metadata row value also escaped
    assert "<b>q</b>" not in content


def test_report_includes_score_and_stats(tmp_path):
    out = tmp_path / "r.html"
    findings = [
        {"check": "headers", "status": "FAIL", "severity": "HIGH", "detail": "x"},
        {"check": "headers", "status": "PASS", "severity": "INFO", "detail": "y"},
    ]
    html_reporter.generate("http://x.example", findings, str(out))
    content = out.read_text()
    assert "/100" in content
    assert "WebAudit Security Report" in content
