# Threat model

**Asset.** The private side: which machines exist, what they are called,
where they are, who owns them, and which of them are broken right now.

**Adversary.** Anyone who can read the public status page, scrape it over
time, or photograph it on a lobby screen. They are assumed to be patient
(they can diff successive pages), moderately skilled (they know base64
and URL-encoding), and interested in exactly the things a status page is
tempted to show: names, addresses, and which specific box is down.

**What the pipeline promises.**

| Threat | Control | Where |
|---|---|---|
| A hostname, address, owner or serial appears in output | allowlisted output schema; known-identifier scan in six encodings; shape scan for addresses, MACs, FQDNs, e-mails, serials, UUIDs | `policy.py`, `gate.py` |
| A new field added by a future change carries an identifier | schema allowlist refuses any unlisted field | `gate.check_schema` |
| A group of one or two hosts identifies a machine by its state | k-anonymity: groups under *k* are merged, and withheld if still under *k* | `aggregate.k_anonymise` |
| Fleet total minus published groups recovers a hidden group | complementary suppression: fleet row withheld when exactly one group is hidden | `aggregate.aggregate`, `gate.check_invariants` |
| Real-time status is used to time an attack | fixed publish delay; the gate checks `as_of` against generation time | `aggregate`, `gate.check_invariants` |
| The renderer is handed raw data by mistake | the render stage's only input is the summary dictionary | `render.render` |
| The gate itself is broken and passes everything | injection drill on every run: thirteen leak types are planted and must each be refused; CI also plants a hostname and requires a non-zero exit | `report.privacy`, `ci.yml` |

**What it does not promise.**

- *Statistical disclosure over time.* Counts per group change when one
  machine changes state; an observer diffing pages every hour learns
  that *some* host in a group went down at a given hour. With *k* = 5
  and a one-hour delay that is low value, but it is not zero. Laplace
  noise on counts is implemented and off by default, because at these
  group sizes it costs more utility than the risk warrants; the policy
  file is where that decision lives.
- *Group names.* Labels like "gpu-compute" are published. They describe
  function, not identity, and are allowed by policy; if a label would
  itself be sensitive, rename it on the private side.
- *Availability of the page.* Out of scope.
- *A compromised private side.* If an attacker can read the samples,
  the status page is the least of the problems.
