#!/usr/bin/env python3
"""Fail the build if any sensitive identifier reached the published output.

This is the backstop for the whole design. The aggregate stage is supposed
to drop every host name, address, and per-host value. This check proves it
did, by scanning the published artifacts for every identifier the raw
telemetry contained. It also scans for address-shaped patterns in general,
so a future change that introduces a new identifier still gets caught.

Exit code is non-zero if anything leaks, so it can gate a CI pipeline.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# generic IPv4 pattern, used as a belt-and-suspenders check beyond the
# known identifier list
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def published_blobs(paths):
    for p in paths:
        with open(p, encoding="utf-8") as f:
            yield p, f.read()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--identifiers", default="data/identifiers.json")
    ap.add_argument("--published", nargs="+",
                    default=["data/aggregates.json", "site/index.html"])
    args = ap.parse_args()

    with open(args.identifiers) as f:
        ids = json.load(f)["identifiers"]

    leaks = []
    for path, text in published_blobs(args.published):
        for ident in ids:
            if ident in text:
                leaks.append((path, "known-identifier", ident))
        for m in IPV4.findall(text):
            leaks.append((path, "address-shaped", m))

    if leaks:
        print(f"PRIVACY CHECK FAILED: {len(leaks)} leak(s)")
        for path, kind, val in leaks[:50]:
            print(f"  {path}: {kind}: {val}")
        return 1

    print(f"PRIVACY CHECK PASSED: scanned {len(args.published)} artifact(s), "
          f"{len(ids)} known identifiers, no leaks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
