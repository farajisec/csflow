# csflow — a privacy-first fleet status pipeline

[![ci](https://github.com/farajisec/csflow/actions/workflows/ci.yml/badge.svg)](https://github.com/farajisec/csflow/actions/workflows/ci.yml)

A pipeline that turns sensitive per-host telemetry into a public status
page that is safe to hang in a lobby or put on the open web: whether the
fleet is healthy, without revealing what the fleet *is*. Counts only,
delayed by policy, k-anonymous by group, built from an allowlisted
schema, and checked by a **fail-closed gate** that refuses to publish if
a single identifier, in any common encoding, reaches the output.

Everything here is synthetic and reproducible. The hostnames, addresses,
MACs, serials and owners on the private side are invented (documentation
ranges, locally-administered MACs, `example` domains) and shaped like the
real thing on purpose: the gate's job is to prove none of them get out,
and the report plants thirteen kinds of leak on every run to prove the
gate is doing work. Standard library only, Python 3.10+.

```bash
pip install -e ".[dev]"
csflow all --strict                 # simulate -> aggregate -> render -> gate -> report
open build/site/index.html
```

## The design

A live dashboard of named hosts is useful inside and a liability outside:
a photo or a scrape hands an outsider a map of the environment and a
list of what is broken right now. csflow treats that as the design
problem and solves it before publication, not after:

| Control | What it does |
|---|---|
| **Publish delay** | only samples older than the policy delay (60 min) are eligible; real-time status is operational intelligence |
| **k-anonymity** | a group smaller than *k* (5) is merged into "other"; if still smaller, folded into the total and omitted |
| **Complementary suppression** | with exactly one group hidden, fleet-minus-groups would reveal it, so the fleet row is withheld |
| **Schema allowlist** | output is projected onto the fields `policy.json` lists; a new field cannot appear by accident |
| **Render isolation** | the page builder receives the summary dictionary and nothing else |
| **The gate** | scans every artifact for known identifiers (plain, upper, lower, base64, URL-safe, hex) and identifier *shapes* (IPv4/6, MAC, FQDN, e-mail, serial, UUID), checks the schema and the invariants, and refuses with a non-zero exit |
| **Injection drill** | on every run, thirteen leak types are planted in copies of the output and each must be caught |

Laplace noise on counts is implemented and switched off by default; the
threat model explains why. See [docs/threat-model.md](docs/threat-model.md)
and [docs/pipeline.md](docs/pipeline.md).

<!-- results:start -->
## Measured results

Fleet of 50 hosts in 8 groups (3 smaller than k = 5), 18,050 samples over 30 hours.

### Privacy

| | Value |
|---|---:|
| Identifying values on the private side | 411 |
| Identifiers found in published artifacts by the gate | 0 |
| Groups published / in private | 6 / 8 |
| Smallest published group | 5 (k = 5) |
| Fleet row published | yes |
| Publish delay | 60 min |
| Injected leaks caught by the gate | 13 / 13 |

Injection drill:

- plain hostname: caught
- short hostname: caught
- ipv4: caught
- ipv6: caught
- mac: caught
- serial: caught
- owner: caught
- email: caught
- base64 hostname: caught
- url-encoded email: caught
- unknown address: caught
- unknown fqdn: caught
- new field: caught

### Utility

| | Value |
|---|---:|
| Mean abs. error of published health vs live truth | 0.027 |
| Mean abs. error once the 60-min delay is accounted for | 0.0 |
| Largest real change reflected after | 60 min |
| Moments the fleet row was withheld | 0 / 145 |
<!-- results:end -->

## Why an allowlist and a gate, not just a careful aggregator

The aggregator is correct today. The question is what happens the day
someone adds a "top offenders" list to help the on-call engineer. With a
blocklist scanner, that leaks until the pattern is added. With an
allowlisted schema, the new field refuses to publish until the policy
says it may, and the policy loader will not accept a field named like an
identifier. The gate is the backstop that proves it, and the drill is the
backstop that proves the gate.

## Layout

```
src/csflow/policy.py     the publication policy: k, delay, allowlisted fields, forbidden shapes
src/csflow/simulate.py   the private side: a synthetic fleet with every identifier a collector holds
src/csflow/aggregate.py  delay, latest-per-host, k-anonymity, complementary suppression, noise, allowlist projection
src/csflow/render.py     static page from the summary only (inline SVG lamps and 24 h history)
src/csflow/gate.py       known-identifier scan in six encodings, shape scan, schema and invariant checks
src/csflow/report.py     privacy and utility measurements; injection drill
tests/                   unit tests and a Hypothesis property: any fleet, any policy, nothing leaks
docs/                    threat model, pipeline
```

## Honest limits

Counts change when one host changes state, so an observer diffing pages
over time learns that *something* in a group changed at a given hour;
that is the residual disclosure the delay and *k* are set against, not
a guarantee of zero. Group labels are published by design. The gate
cannot catch an identifier encoded in a way it does not scan for, which
is why the allowlisted schema, not the scanner, is the primary control.

## Provenance

Built with AI assistance under explicit requirements. The controls, their
limits and the validation are documented here and in `docs/`, and
enforced by the tests, the gate and the drill in this repository.

## License

MIT. See `LICENSE`.
