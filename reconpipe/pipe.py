"""reconpipe orchestrator: subdomains -> live hosts -> JS secrets -> wayback URLs.

Passive recon only. Every stage is plain HTTP GET against public endpoints;
no exploitation, no auth bypass. Run only against authorized targets.
"""
import concurrent.futures
import requests

from .subdomains import enumerate_crtsh
from .wayback import fetch_wayback_urls, interesting_urls

HEADERS = {"User-Agent": "reconpipe/0.1 (bug-bounty recon; passive only)"}

try:
    from jshunter import hunt as jshunter_hunt
    HAVE_JSHUNTER = True
except ImportError:
    HAVE_JSHUNTER = False
    jshunter_hunt = None


def probe_live(host, timeout=10):
    """Return the working base URL for a host, or None."""
    for scheme in ("https", "http"):
        url = "{0}://{1}".format(scheme, host)
        try:
            r = requests.get(url, headers=HEADERS, timeout=timeout,
                             allow_redirects=True)
            if r.status_code < 400:
                return url
        except Exception:
            continue
    return None


def run_pipeline(domain, max_hosts=25, max_js_per_host=15, wayback_limit=10000,
                 progress=None):
    """Run all stages. progress(stage_name, detail) is an optional callback."""
    def say(stage, detail=""):
        if progress:
            progress(stage, detail)

    report = {"target": domain, "tool": "reconpipe/0.1", "stages": {}}

    # Stage 1: subdomains
    say("subdomains", "querying crt.sh")
    subs = enumerate_crtsh(domain)
    report["stages"]["subdomains"] = {"count": len(subs), "items": subs}

    # Stage 2: live probing (root domain first, then subdomains)
    say("live-probe", "checking {0} hosts".format(len(subs) + 1))
    candidates = [domain] + subs
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        future_map = {ex.submit(probe_live, h): h for h in candidates[:max_hosts * 2]}
        for fut in concurrent.futures.as_completed(future_map):
            url = fut.result()
            if url:
                live.append(url)
            if len(live) >= max_hosts:
                break
    report["stages"]["live_hosts"] = {"count": len(live), "items": sorted(live)}

    # Stage 3: JS secret hunt on live hosts
    js_results = []
    if HAVE_JSHUNTER:
        say("jshunt", "scanning JS on {0} live hosts".format(len(live)))
        for url in live:
            try:
                js_results.append(jshunter_hunt(url, max_js=max_js_per_host))
            except Exception as e:
                js_results.append({"target": url, "error": str(e)[:120],
                                   "js_files": [], "summary": {}})
    else:
        say("jshunt", "skipped (jshunter not installed)")
    total_secrets = sum(r.get("summary", {}).get("secrets_found", 0) for r in js_results)
    total_eps = sum(r.get("summary", {}).get("endpoints_found", 0) for r in js_results)
    report["stages"]["js_hunt"] = {
        "ran": HAVE_JSHUNTER,
        "hosts_scanned": len(js_results),
        "secrets_found": total_secrets,
        "endpoints_found": total_eps,
        "details": js_results,
    }

    # Stage 4: wayback URLs
    say("wayback", "harvesting historical URLs")
    raw_urls = fetch_wayback_urls(domain, limit=wayback_limit)
    interesting = interesting_urls(raw_urls)
    report["stages"]["wayback"] = {
        "urls_seen": len(raw_urls),
        "interesting_count": len(interesting),
        "items": interesting,
    }

    # Targets for deeper testing (aegis / manual): dedupe interesting hosts+paths
    probe_targets = sorted({i["url"] for i in interesting})
    report["probe_targets"] = probe_targets[:200]
    report["summary"] = {
        "subdomains": len(subs),
        "live_hosts": len(live),
        "js_secrets": total_secrets,
        "js_endpoints": total_eps,
        "wayback_interesting_urls": len(interesting),
        "probe_targets": len(report["probe_targets"]),
    }
    say("done", "")
    return report
