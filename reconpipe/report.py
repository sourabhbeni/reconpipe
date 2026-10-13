"""Unified report rendering for reconpipe."""
import json


def to_json(report):
    return json.dumps(report, indent=2)


def _secret_preview(value, length):
    if length <= 16:
        return value
    return value[:6] + "..." + value[-4:]


def to_text(report):
    L = []
    s = report["summary"]
    L.append("reconpipe report for {0}".format(report["target"]))
    L.append("=" * 60)
    L.append("Subdomains          : {0}".format(s["subdomains"]))
    L.append("Live hosts          : {0}".format(s["live_hosts"]))
    L.append("JS secrets          : {0}".format(s["js_secrets"]))
    L.append("JS endpoints        : {0}".format(s["js_endpoints"]))
    L.append("Interesting URLs    : {0}".format(s["wayback_interesting_urls"]))
    L.append("Probe targets       : {0}".format(s["probe_targets"]))
    L.append("")

    js = report["stages"]["js_hunt"]
    if js["ran"]:
        L.append("--- JS secrets (verify before reporting) ---")
        shown = 0
        for detail in js["details"]:
            for f in detail.get("js_files", []):
                for sec in f.get("secrets", []):
                    L.append("[{0}] {1} in {2}".format(
                        sec["severity"], sec["rule"], f["url"]))
                    L.append("        preview: {0} -- {1}".format(
                        _secret_preview(sec["value"], sec["length"]),
                        sec["description"][:80]))
                    shown += 1
                    if shown >= 20:
                        break
                if shown >= 20:
                    break
            if shown >= 20:
                break
        if shown == 0:
            L.append("(none)")
        L.append("")
    else:
        L.append("--- JS hunt skipped: pip install jshunter ---\n")

    wb = report["stages"]["wayback"]["items"]
    L.append("--- Top interesting URLs (probe targets) ---")
    for item in wb[:30]:
        L.append("* {0}  [{1}]".format(item["url"][:110], item["reason"]))
    if len(wb) > 30:
        L.append("... +{0} more (see JSON)".format(len(wb) - 30))
    L.append("")
    L.append("Next step: feed probe_targets into aegis (SQLi/XSS) or test manually.")
    L.append("NOTE: passive recon only. Verify scope before any active testing.")
    return "\n".join(L)
