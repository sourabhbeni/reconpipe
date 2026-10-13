"""Wayback Machine URL harvesting via the CDX API (fully passive).

Collects historical URLs for a domain, then surfaces the interesting ones:
URLs with query parameters (probe targets) and sensitive-looking paths.
"""
from urllib.parse import urlparse, parse_qsl
import requests

CDX_URL = "http://web.archive.org/cdx/search/cdx"
HEADERS = {"User-Agent": "reconpipe/0.1 (bug-bounty recon; passive only)"}

# parameter names worth probing (SQLi/XSS/redirect/SSRF candidates)
INTERESTING_PARAMS = {
    "id", "q", "s", "search", "query", "keyword", "url", "uri", "redirect",
    "redir", "next", "return", "returnurl", "callback", "file", "path",
    "page", "pg", "dir", "folder", "doc", "document", "template", "theme",
    "lang", "locale", "user", "username", "email", "name", "token", "key",
    "api_key", "apikey", "debug", "test", "admin", "edit", "delete",
}

INTERESTING_PATH_HINTS = (
    "/api/", "/graphql", "/gql", "/admin", "/debug", "/test", "/dev",
    "/staging", "/internal", "/.git/", "/.env", "swagger", "openapi.json",
    "wp-json", ".php?", "?id=",
)


def fetch_wayback_urls(domain, limit=10000, timeout=30):
    """Return raw list of historical URLs from the CDX API."""
    params = {
        "url": domain + "/*",
        "output": "json",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": str(limit),
    }
    try:
        resp = requests.get(CDX_URL, params=params, headers=HEADERS, timeout=timeout)
        resp.raise_for_status()
        rows = resp.json()
    except Exception:
        return []
    # first row is the header
    urls = []
    for row in rows[1:]:
        # columns: urlkey, timestamp, original, mimetype, statuscode, digest, length
        if len(row) >= 3:
            urls.append(row[2])
    return urls


def interesting_urls(urls, max_results=500):
    """Filter to URLs with interesting params or paths. Returns list of dicts."""
    out = []
    seen = set()
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        try:
            parsed = urlparse(u)
        except Exception:
            continue
        params = {k.lower() for k, _ in parse_qsl(parsed.query)}
        hit_params = sorted(params & INTERESTING_PARAMS)
        low = u.lower()
        hit_path = any(h in low for h in INTERESTING_PATH_HINTS)
        if hit_params or hit_path:
            out.append({
                "url": u,
                "params": hit_params,
                "path_hint": hit_path,
                "reason": ("params:" + ",".join(hit_params)) if hit_params else "path",
            })
        if len(out) >= max_results:
            break
    return out
