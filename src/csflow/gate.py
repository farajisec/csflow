"""The publication gate. Fails closed.

Before anything ships, every artifact about to be published is checked
four ways, and a single finding refuses publication with a non-zero exit:

1. **Known identifiers.** Every value of every identifying field in the
   private inventory (hostnames, short hostnames, addresses, MACs, serials,
   asset ids, owners, emails, rack positions) is searched for in the
   artifacts, as text and in common encodings (base64, URL-encoding, hex)
   so an "innocent" transformation does not slip past.
2. **Structural patterns.** IPv4, IPv6, MAC, FQDN-with-private-suffix,
   e-mail, serial-like and UUID-shaped strings are refused wherever they
   appear, so an identifier the inventory does not know about is caught.
3. **Schema allowlist.** Published JSON may contain only the fields the
   policy lists, at the places it lists them. A new field is a refusal
   until the policy says otherwise.
4. **Policy invariants.** Every published group has at least *k* hosts,
   the as-of time is at least the policy delay before the generation
   time, and the fleet row is absent whenever exactly one group was
   hidden (complementary suppression).

Findings say what was found and where, never the sensitive value in
full: the gate's own output is something people paste into tickets.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from .policy import Policy

PATTERNS = {
    "ipv4": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "ipv6": re.compile(r"(?<![0-9a-zA-Z:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{1,4}(?![0-9a-zA-Z:])"),
    "mac": re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b"),
    "fqdn": re.compile(r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"
                       r"\.(?:internal|corp|lan|local|example|edu|intra)\b", re.IGNORECASE),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "serial": re.compile(r"\bSN\d{6,}[A-Z]?\b"),
    "uuid": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE),
}
IDENTIFYING_FIELDS = ("hostname", "ip", "ipv6", "mac", "serial", "asset_id", "owner", "owner_email", "rack")
# false-positive guards for the ipv6 pattern on ISO timestamps like 12:00:00
_TIME = re.compile(r"^\d{1,2}:\d{2}(?::\d{2})?$")


@dataclass
class Finding:
    artifact: str
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"{self.artifact}: {self.kind}: {self.detail}"


def _redact(v: str) -> str:
    return v if len(v) <= 4 else v[:2] + "…" + v[-2:]


def _encodings(value: str) -> dict[str, str]:
    b = value.encode()
    return {"plain": value, "base64": base64.b64encode(b).decode(), "urlsafe": urllib.parse.quote(value, safe=""),
            "hex": b.hex(), "upper": value.upper(), "lower": value.lower()}


def load_identifiers(inventory_path: Path) -> dict[str, set[str]]:
    with open(inventory_path, encoding="utf-8") as f:
        inv = json.load(f)
    idents: dict[str, set[str]] = {k: set() for k in IDENTIFYING_FIELDS}
    for h in inv:
        for k in IDENTIFYING_FIELDS:
            v = str(h.get(k, ""))
            if v:
                idents[k].add(v)
                if k == "hostname":
                    idents[k].add(v.split(".")[0])          # short hostname
    return idents


def scan_text(artifact: str, text: str, idents: dict[str, set[str]], policy: Policy) -> list[Finding]:
    found: list[Finding] = []
    hay = {"plain": text, "lower": text.lower()}
    for kind, values in idents.items():
        for v in values:
            if len(v) < 3:
                continue
            for enc_name, enc in _encodings(v).items():
                target = hay["lower"] if enc_name in ("lower", "upper") else hay["plain"]
                if enc.lower() in target if enc_name in ("lower", "upper") else enc in target:
                    found.append(Finding(artifact, f"known {kind}", f"{_redact(v)} present ({enc_name})"))
                    break
    for name in policy.forbidden_patterns:
        rx = PATTERNS[name]
        for m in rx.finditer(text):
            s = m.group(0)
            if name == "ipv6" and (_TIME.match(s) or (not any(ch.isalpha() for ch in s) and "::" not in s)):
                continue                      # a clock time, not an address
            found.append(Finding(artifact, f"{name}-shaped", _redact(s)))
    return found


def check_schema(artifact: str, doc: dict, policy: Policy) -> list[Finding]:
    pf = policy.published_fields
    out: list[Finding] = []

    def only(obj: dict, allowed: list[str], where: str) -> None:
        for k in obj:
            if k not in allowed:
                out.append(Finding(artifact, "schema", f"unexpected field {k!r} in {where}"))
    only(doc, pf["summary"], "summary")
    if isinstance(doc.get("fleet"), dict):
        only(doc["fleet"], pf["fleet"], "fleet")
    for i, g in enumerate(doc.get("groups", [])):
        only(g, pf["group"], f"groups[{i}]")
    for i, h in enumerate(doc.get("history", [])):
        only(h, pf["history_point"], f"history[{i}]")
    if isinstance(doc.get("policy"), dict):
        only(doc["policy"], pf["policy"], "policy")
    return out


def check_invariants(artifact: str, doc: dict, policy: Policy, generated_at: datetime | None,
                     groups_in_private: int | None) -> list[Finding]:
    out: list[Finding] = []
    for g in doc.get("groups", []):
        if g.get("total", 0) < policy.k_min_group_size:
            out.append(Finding(artifact, "k-anonymity", f"group {g.get('label')!r} has {g.get('total')} < k"))
        if sum(g.get(s, 0) for s in ("up", "degraded", "down")) != g.get("total"):
            out.append(Finding(artifact, "consistency", f"group {g.get('label')!r} counts do not sum"))
    if generated_at is not None and "as_of" in doc:
        as_of = datetime.fromisoformat(doc["as_of"])
        if generated_at - as_of < timedelta(minutes=policy.publish_delay_minutes):
            out.append(Finding(artifact, "delay", f"as_of is only {generated_at - as_of} before generation"))
    if groups_in_private is not None:
        shown = [g for g in doc.get("groups", []) if g.get("label") != policy.small_group_label]
        merged = any(g.get("label") == policy.small_group_label for g in doc.get("groups", []))
        hidden = groups_in_private - len(shown) - (1 if merged else 0)
        if hidden == 1 and doc.get("fleet") is not None and not merged:
            out.append(Finding(artifact, "complementary", "fleet total published with exactly one group hidden"))
    return out


def run_gate(artifacts: list[Path], inventory: Path, policy: Policy, generated_at: datetime | None = None
             ) -> list[Finding]:
    idents = load_identifiers(inventory)
    with open(inventory, encoding="utf-8") as f:
        private_groups = len({h["group"] for h in json.load(f)})
    findings: list[Finding] = []
    for p in artifacts:
        text = Path(p).read_text(encoding="utf-8")
        findings += scan_text(p.name, text, idents, policy)
        if p.suffix == ".json":
            doc = json.loads(text)
            findings += check_schema(p.name, doc, policy)
            findings += check_invariants(p.name, doc, policy, generated_at, private_groups)
    return findings
