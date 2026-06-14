"""Tests for exposed-files detection logic (session mocked)."""
from unittest.mock import MagicMock

from checks import exposed_files


class FakeSession:
    """Session whose responses are driven by a {path_suffix: (status, text)} map."""
    def __init__(self, responses, default=(404, "Not Found")):
        self.responses = responses
        self.default = default

    def get(self, url, **kwargs):
        status, text = self.default
        for suffix, val in self.responses.items():
            if url.endswith(suffix):
                status, text = val
                break
        r = MagicMock()
        r.status_code = status
        r.text = text
        return r


def test_exposed_env_file_is_high_fail():
    sess = FakeSession({"/.env": (200, "SECRET_KEY=fakeplaceholder123")})
    findings = exposed_files.check("http://x.example", sess)
    env = [f for f in findings if f["url"].endswith("/.env")]
    assert env and env[0]["severity"] == "HIGH"
    assert env[0]["status"] == "FAIL"


def test_soft_404_is_ignored():
    # Returns 200 but body looks like a not-found page -> should NOT be flagged
    sess = FakeSession({"/.env": (200, "404 - page not found")})
    findings = exposed_files.check("http://x.example", sess)
    assert not any(f["url"].endswith("/.env") for f in findings)


def test_medium_severity_maps_to_warn():
    sess = FakeSession({"/phpinfo.php": (200, "phpinfo() output here")})
    findings = exposed_files.check("http://x.example", sess)
    php = [f for f in findings if f["url"].endswith("/phpinfo.php")]
    assert php and php[0]["status"] == "WARN"
    assert php[0]["severity"] == "MEDIUM"


def test_low_severity_maps_to_info():
    sess = FakeSession({"/.DS_Store": (200, "\x00\x01garbage")})
    findings = exposed_files.check("http://x.example", sess)
    ds = [f for f in findings if f["url"].endswith("/.DS_Store")]
    assert ds and ds[0]["status"] == "INFO"


def test_non_200_not_flagged():
    sess = FakeSession({})  # everything 404
    findings = exposed_files.check("http://x.example", sess)
    assert findings == []


def test_robots_disallow_paths_reported():
    robots = "User-agent: *\nDisallow: /admin/\nDisallow: /secret/\n"
    sess = FakeSession({"/robots.txt": (200, robots)})
    findings = exposed_files.check("http://x.example", sess)
    robo = [f for f in findings if f["url"].endswith("/robots.txt")]
    assert robo
    assert robo[0]["disallowed_paths"] == ["/admin/", "/secret/"]


def test_base_url_trailing_slash_stripped():
    sess = FakeSession({"/.git/HEAD": (200, "ref: refs/heads/main")})
    findings = exposed_files.check("http://x.example/", sess)
    git = [f for f in findings if f["url"].endswith("/.git/HEAD")]
    assert git
    assert "//.git" not in git[0]["url"]
