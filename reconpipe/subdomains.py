"""Subdomain enumeration via crt.sh (passive, no scanning of the target itself)."""
import requests

CRT_URL = "https://crt.sh/"
HEADERS = {"User-Agent": "reconpipe/0.1 (bug-bounty recon; passive only)"}


def enumerate_crtsh(domain, timeout=20):
    """Return sorted unique subdomains of `domain` from crt.sh."""
    params = {"q": "%." + domain, "output": "json"}
    try:
        resp = requests.get(CRT_URL, params=params, headers=HEADERS, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []
    subs = set()
    for entry in data:
        name = entry.get("name_value", "")
        for part in name.split("\n"):
            part = part.strip().lower()
            if part.endswith(domain) and "*" not in part and "@" not in part:
                subs.add(part)
    return sorted(subs)
