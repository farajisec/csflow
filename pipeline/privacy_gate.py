#!/usr/bin/env python3
"""Publication gate: the pipeline fails closed.

Before anything is published, every output file is scanned against the
private inventory and against structural identifier patterns. If a single
hostname, address, or owner from the private side appears in the output
bundle, publication is refused with a nonzero exit.

The aggregator is trusted to do the right thing; this gate exists so that
a future bug in the aggregator (or a new field someone adds) cannot leak
quietly. Defense in depth for a status page.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

IP_PATTERN = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
FQDN_PATTERN = re.compile(
    r"[a-z0-9][a-z0-9-]*\.(?:internal|corp|lan|local|example)\b",
    re.IGNORECASE)


def load_private_identifiers(inventory_path: str) -> set[str]:
    with open(inventory_path) as f:
        inv = json.load(f)
    idents: set[str] = set()
    for h in inv:
        idents.add(h["hostname"].lower())
        idents.add(h["hostname"].split(".")[0].lower())  # short hostname
        idents.add(h["ip"])
        idents.add(h["owner"].lower())
    return idents


def scan_text(text: str, idents: set[str]) -> list[str]:
    findings = []
    low = text.lower()
    for ident in sorted(idents):
        if ident and ident in low:
            findings.append(f"private identifier present: {ident!r}")
    for m in IP_PATTERN.finditer(text):
        findings.append(f"IPv4-shaped string present: {m.group(0)!r}")
    for m in FQDN_PATTERN.finditer(text):
        findings.append(f"internal-FQDN-shaped string: {m.group(0)!r}")
    return findings


def check_files(paths: list[str], inventory_path: str) -> list[str]:
    idents = load_private_identifiers(inventory_path)
    findings = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            text = f.read()
        for item in scan_text(text, idents):
            findings.append(f"{p}: {item}")
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inventory", default="data/inventory.json")
    ap.add_argument("files", nargs="+",
                    help="output files that are about to be published")
    args = ap.parse_args()

    findings = check_files(args.files, args.inventory)
    if findings:
        print("PUBLICATION REFUSED:")
        for f in findings:
            print(f"  {f}")
        sys.exit(1)
    print(f"privacy gate: PASS ({len(args.files)} file(s) clean)")


if __name__ == "__main__":
    main()
