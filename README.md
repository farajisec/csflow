# csflow: a privacy-first fleet status board

A small pipeline that turns noisy, sensitive fleet telemetry into a public
status page that is safe to hang on a wall or publish on the open web. It
shows whether the fleet is healthy without revealing anything about the
fleet: no hostnames, no addresses, no per-host data, and nothing in real
time.

Everything here is synthetic and reproducible. The hostnames and addresses
in the generator are invented and generic. They exist only so the privacy
checks have something real to catch.

## The idea

A live dashboard of named hosts is useful internally and a liability in
public. A photo of it, or a scrape of it, hands an outsider a map of your
environment: what exists, what is called what, and what is currently
broken. csflow treats that as the design problem and solves it before
anything is published, not after.

Two controls do the work, by construction:

1. **Aggregation.** The published summary carries counts per group and
   state only. Host names, addresses, and per-host load are dropped at the
   aggregate stage and never enter anything downstream.
2. **Delay.** Only telemetry older than a fixed delay (default one hour) is
   eligible for publishing. Real-time status is itself operational
   intelligence, so the board is deliberately an hour behind.

A third control proves the first two worked:

3. **A privacy gate.** Before anything ships, a check scans the published
   artifacts for every identifier the raw telemetry contained, plus any
   address-shaped text in general, and fails the build if it finds one.

## Pipeline

```
raw_telemetry.jsonl        per-host samples with names + addresses (sensitive)
        |  aggregate.py     drop identifiers, apply delay, roll up to counts
        v
aggregates.json            counts per group + state only (safe)
        |  render.py        build the static "tree of light" page
        v
site/index.html            public status page: lamps, no names
        |  privacy_check.py scan published artifacts; non-zero exit on any leak
        v
publish
```

The render stage can only read the aggregates, never the raw telemetry, so
there is no code path by which a name could reach the page. The privacy
gate is the backstop that proves it.

## Run it

No third-party dependencies. Python 3.11+.

```bash
python3 pipeline/generate_fleet.py   # -> data/raw_telemetry.jsonl, identifiers.json
python3 pipeline/aggregate.py        # -> data/aggregates.json
python3 pipeline/render.py           # -> site/index.html
python3 pipeline/privacy_check.py    # exits non-zero if anything leaked
```

Or:

```bash
./run.sh
```

Tests, including a negative test that injects a leak and asserts the gate
catches it:

```bash
python3 -m unittest discover -s tests -v
```

## What the privacy gate guarantees, and what it does not

- It guarantees the published artifacts contain none of the known
  identifiers and no address-shaped strings. If a future change
  reintroduces one, the build fails.
- It does not reason about statistical disclosure. Counts per group are
  low-sensitivity, but on a very small group even a count can be telling.
  For a real deployment you would set a minimum group size before
  publishing a count. That is noted here rather than hidden.

## Provenance

Built with AI assistance under explicit requirements. The design controls,
their limits, and the validation are documented here and enforced by the
tests and the privacy gate in this repository.

## License

MIT. See `LICENSE`.
