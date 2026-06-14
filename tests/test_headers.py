"""Tests for security-header checks."""
from unittest.mock import MagicMock

from checks import headers


def _resp(header_dict):
    r = MagicMock()
    r.headers = header_dict
    return r


def _by_header(findings, name):
    return [f for f in findings if f.get("header") == name]


def test_all_headers_missing_flags_required_as_high():
    findings = headers.check(_resp({}))
    sts = _by_header(findings, "Strict-Transport-Security")[0]
    assert sts["status"] == "FAIL"
    assert sts["severity"] == "HIGH"


def test_optional_header_missing_is_warn_medium():
    findings = headers.check(_resp({}))
    rp = _by_header(findings, "Referrer-Policy")[0]
    assert rp["status"] == "WARN"
    assert rp["severity"] == "MEDIUM"


def test_present_optional_header_passes():
    findings = headers.check(_resp({
        "Referrer-Policy": "strict-origin-when-cross-origin"}))
    rp = _by_header(findings, "Referrer-Policy")[0]
    assert rp["status"] == "PASS"


def test_csp_unsafe_inline_flagged():
    findings = headers.check(_resp({
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}))
    csp = _by_header(findings, "Content-Security-Policy")
    assert any("unsafe-inline" in f.get("detail", "") for f in csp)
    assert all(f["status"] == "WARN" for f in csp)


def test_csp_wildcard_flagged():
    findings = headers.check(_resp({"Content-Security-Policy": "default-src *"}))
    csp = _by_header(findings, "Content-Security-Policy")
    assert any("*" in f.get("detail", "") for f in csp)


def test_hsts_without_max_age_warns():
    findings = headers.check(_resp({
        "Strict-Transport-Security": "includeSubDomains"}))
    sts = _by_header(findings, "Strict-Transport-Security")
    assert any(f["status"] == "WARN" and "max-age" in f.get("detail", "") for f in sts)


def test_hsts_with_max_age_no_warning():
    findings = headers.check(_resp({
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains"}))
    sts = _by_header(findings, "Strict-Transport-Security")
    # required header present and valid -> no FAIL/WARN entry recorded for it
    assert sts == []
