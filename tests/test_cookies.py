"""Tests for cookie security-flag checks."""
from unittest.mock import MagicMock

from checks import cookies


class FakeCookie:
    def __init__(self, name, secure=False, httponly=False, samesite=None):
        self.name = name
        self.secure = secure
        self._attrs = {}
        if httponly:
            self._attrs["HttpOnly"] = True
        if samesite is not None:
            self._attrs["SameSite"] = samesite

    def has_nonstandard_attr(self, key):
        return key in self._attrs

    def get_nonstandard_attr(self, key):
        return self._attrs.get(key)


def _resp(cookie_list):
    r = MagicMock()
    r.cookies = cookie_list
    return r


def test_no_cookies_is_info():
    findings = cookies.check(_resp([]))
    assert findings[0]["status"] == "INFO"


def test_insecure_cookie_collects_all_issues():
    c = FakeCookie("sid", secure=False, httponly=False, samesite=None)
    findings = cookies.check(_resp([c]), is_https=True)
    assert findings[0]["status"] == "WARN"
    issues = findings[0]["issues"]
    assert any("Secure" in i for i in issues)
    assert any("HttpOnly" in i for i in issues)
    assert any("SameSite" in i for i in issues)


def test_fully_secured_cookie_passes():
    c = FakeCookie("sid", secure=True, httponly=True, samesite="Strict")
    findings = cookies.check(_resp([c]), is_https=True)
    assert findings[0]["status"] == "PASS"


def test_samesite_none_requires_secure():
    c = FakeCookie("sid", secure=False, httponly=True, samesite="None")
    findings = cookies.check(_resp([c]), is_https=False)
    issues = findings[0]["issues"]
    assert any("SameSite=None requires Secure" in i for i in issues)
