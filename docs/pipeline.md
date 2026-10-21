# Pipeline

```
PRIVATE                                   PUBLIC
inventory.json ─┐                         aggregates.json ──► site/index.html
samples.jsonl ──┴──► aggregate ──────────►   │                     │
                     delay                    └──────── gate ───────┘
                     latest-per-host                     │ pass → publish
                     k-anonymity + merge                 │ fail → refuse, exit 1
                     complementary suppression
                     optional Laplace noise
                     schema allowlist
policy.json ────────► every stage
```

## Stages

**simulate** (private) builds an inventory with every identifier a real
collector would hold and five-minute status samples over a window, with
an outage, a degraded group, flapping hosts and a maintenance window.
Synthetic throughout; the identifiers are shaped like real ones on
purpose so the gate has something to catch.

**aggregate** is the only stage that reads raw data. See the module
docstring for the six controls, in order. Its output is built by
projecting onto the policy's allowlist, so a field that is not in
`policy.json` cannot exist in the output.

**render** takes the summary dictionary and nothing else.

**gate** scans the artifacts about to be published: known identifiers in
plain, upper, lower, base64, URL-safe and hex encodings; identifier
shapes; the schema allowlist; and the policy invariants (k, delay,
complementary suppression). One finding refuses publication. Findings
redact the value they report, because gate output ends up in tickets.

**report** measures privacy (identifiers in vs out, smallest group,
injection drill) and utility (how closely the delayed page tracks live
truth, and the lag).

## Policy

`policy.json` is the single place a decision lives:

```json
{
  "k_min_group_size": 5,
  "publish_delay_minutes": 60,
  "history_hours": 24,
  "small_group_label": "other",
  "noise": {"enabled": false, "epsilon": 2.0},
  "forbidden_patterns": ["ipv4", "ipv6", "mac", "fqdn", "email", "serial", "uuid"]
}
```

The published-field allowlist has defaults and may be overridden, but
the policy loader refuses an allowlist that names an identifying field,
and refuses *k* < 2.

## Running it

```bash
csflow all --strict                 # simulate -> aggregate -> render -> gate -> report
csflow gate                         # re-check artifacts; exit 1 on any finding
csflow --policy strict.json all     # a different policy
```
