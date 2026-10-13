"""Tests for reconpipe stages (mocked HTTP)."""
import responses

from reconpipe.subdomains import enumerate_crtsh
from reconpipe.wayback import interesting_urls, fetch_wayback_urls
from reconpipe.pipe import run_pipeline
from reconpipe import pipe as pipe_mod


@responses.activate
def test_enumerate_crtsh():
    responses.add(
        responses.GET, "https://crt.sh/",
        json=[{"name_value": "a.example.com"},
              {"name_value": "*.wild.example.com\nb.example.com"}],
        status=200)
    subs = enumerate_crtsh("example.com")
    assert subs == ["a.example.com", "b.example.com"]


@responses.activate
def test_enumerate_crtsh_failure_returns_empty():
    responses.add(responses.GET, "https://crt.sh/", status=500)
    assert enumerate_crtsh("example.com") == []


def test_interesting_urls_params():
    urls = [
        "https://example.com/about",
        "https://example.com/search?q=test",
        "https://example.com/item?id=42",
        "https://example.com/api/users",
    ]
    out = interesting_urls(urls)
    by_url = {i["url"]: i for i in out}
    assert "https://example.com/about" not in by_url
    assert by_url["https://example.com/search?q=test"]["params"] == ["q"]
    assert by_url["https://example.com/item?id=42"]["params"] == ["id"]
    assert by_url["https://example.com/api/users"]["path_hint"] is True


def test_interesting_urls_dedupes():
    urls = ["https://example.com/?id=1", "https://example.com/?id=1"]
    assert len(interesting_urls(urls)) == 1


@responses.activate
def test_fetch_wayback_parses_rows():
    responses.add(
        responses.GET, "http://web.archive.org/cdx/search/cdx",
        json=[["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
              ["k1", "20260101", "https://example.com/?id=1", "text/html", "200", "d", "10"]],
        status=200)
    urls = fetch_wayback_urls("example.com")
    assert urls == ["https://example.com/?id=1"]


def test_pipeline_without_jshunter(monkeypatch):
    monkeypatch.setattr(pipe_mod, "HAVE_JSHUNTER", False)
    monkeypatch.setattr(pipe_mod, "enumerate_crtsh", lambda d: ["a.example.com"])
    monkeypatch.setattr(pipe_mod, "probe_live", lambda h: "https://a.example.com")
    monkeypatch.setattr(pipe_mod, "fetch_wayback_urls",
                        lambda d, limit=10000: ["https://a.example.com/?id=1"])
    report = run_pipeline("example.com", max_hosts=5)
    assert report["summary"]["subdomains"] == 1
    assert report["summary"]["live_hosts"] == 2  # root + subdomain both mocked live
    assert report["stages"]["js_hunt"]["ran"] is False
    assert report["summary"]["wayback_interesting_urls"] == 1
    assert report["probe_targets"] == ["https://a.example.com/?id=1"]


def test_run_pipeline_importable():
    from reconpipe.pipe import run_pipeline as rp
    assert callable(rp)
