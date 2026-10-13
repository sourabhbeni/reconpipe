#!/usr/bin/env python3
"""reconpipe CLI: full passive recon pipeline for web bug-bounty targets.

Stages: crt.sh subdomains -> live probing -> jshunter JS scan ->
wayback URL harvest -> unified report + probe-target list.

Usage:
    python -m reconpipe.cli example.com --i-am-authorized
"""
import argparse
import sys

from .pipe import run_pipeline
from .report import to_json, to_text


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Passive recon pipeline: subdomains, JS secrets, wayback URLs.")
    ap.add_argument("domain", help="Target domain (e.g. example.com)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-o", "--output")
    ap.add_argument("--max-hosts", type=int, default=25)
    ap.add_argument("--max-js", type=int, default=15)
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="Confirm you are authorized to recon this target")
    args = ap.parse_args(argv)

    if not args.i_am_authorized:
        print("Refusing to run: pass --i-am-authorized to confirm scope.",
              file=sys.stderr)
        return 2

    def progress(stage, detail):
        print("[{0}] {1}".format(stage, detail), file=sys.stderr)

    report = run_pipeline(args.domain, max_hosts=args.max_hosts,
                          max_js_per_host=args.max_js, progress=progress)
    out = to_json(report) if args.json else to_text(report)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(out)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
