"""Tests for the csflow privacy-first status pipeline.

Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from pipeline import aggregate, generate_fleet, privacy_check  # noqa: E402


def make_raw(tmp):
    raw = os.path.join(tmp, "raw.jsonl")
    ids = os.path.join(tmp, "ids.json")
    cwd = os.getcwd()
    os.chdir(tmp)
    try:
        os.makedirs("data", exist_ok=True)
        subprocess.run([sys.executable,
                        os.path.join(ROOT, "pipeline", "generate_fleet.py"),
                        "--out", raw], check=True, capture_output=True)
        # generate_fleet writes identifiers.json into ./data
        os.replace("data/identifiers.json", ids)
    finally:
        os.chdir(cwd)
    return raw, ids


NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)


class TestAggregate(unittest.TestCase):
    def test_counts_match_delayed_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw, _ = make_raw(tmp)
            rows = list(aggregate.load_raw(raw))
            summary = aggregate.aggregate(rows, NOW)
            # recompute expected latest-per-host under the cutoff independently
            cutoff = NOW - aggregate.PUBLISH_DELAY
            latest = {}
            for r in rows:
                ts = datetime.fromisoformat(r["ts"])
                if ts > cutoff:
                    continue
                if r["host"] not in latest or ts > latest[r["host"]][0]:
                    latest[r["host"]] = (ts, r)
            expected_total = len(latest)
            self.assertEqual(summary["fleet"]["total"], expected_total)
            self.assertEqual(
                summary["fleet"]["up"],
                sum(1 for _, r in latest.values() if r["state"] == "up"))

    def test_delay_excludes_recent(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw, _ = make_raw(tmp)
            rows = list(aggregate.load_raw(raw))
            cutoff = NOW - aggregate.PUBLISH_DELAY
            # the aggregate must never reflect a sample newer than cutoff
            summary = aggregate.aggregate(rows, NOW)
            self.assertLessEqual(
                datetime.fromisoformat(summary["as_of"]), cutoff)

    def test_output_has_no_identifier_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw, _ = make_raw(tmp)
            summary = aggregate.aggregate(list(aggregate.load_raw(raw)), NOW)
            blob = json.dumps(summary)
            for banned in ("host", "addr", "node-", "load"):
                self.assertNotIn(banned, blob,
                                 f"identifier field {banned!r} leaked")


class TestPrivacyCheck(unittest.TestCase):
    def _published(self, tmp):
        raw, ids = make_raw(tmp)
        rows = list(aggregate.load_raw(raw))
        summary = aggregate.aggregate(rows, NOW)
        agg = os.path.join(tmp, "aggregates.json")
        with open(agg, "w") as f:
            json.dump(summary, f)
        from pipeline import render
        site = os.path.join(tmp, "index.html")
        with open(site, "w") as f:
            f.write(render.render(summary))
        return ids, [agg, site]

    def test_clean_output_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            ids, pub = self._published(tmp)
            with open(ids) as f:
                identifiers = json.load(f)["identifiers"]
            leaks = []
            for _, text in privacy_check.published_blobs(pub):
                leaks += [i for i in identifiers if i in text]
                leaks += privacy_check.IPV4.findall(text)
            self.assertEqual(leaks, [])

    def test_injected_leak_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            ids, pub = self._published(tmp)
            with open(ids) as f:
                identifiers = json.load(f)["identifiers"]
            # inject one real identifier into a published artifact
            with open(pub[1], "a") as f:
                f.write(f"\n<!-- leaked {identifiers[0]} -->\n")
            caught = any(
                i in text
                for _, text in privacy_check.published_blobs([pub[1]])
                for i in identifiers)
            self.assertTrue(caught, "privacy check failed to catch a leak")


class TestDeterminism(unittest.TestCase):
    def test_same_seed_same_aggregate(self):
        with tempfile.TemporaryDirectory() as t1, \
             tempfile.TemporaryDirectory() as t2:
            r1, _ = make_raw(t1)
            r2, _ = make_raw(t2)
            s1 = aggregate.aggregate(list(aggregate.load_raw(r1)), NOW)
            s2 = aggregate.aggregate(list(aggregate.load_raw(r2)), NOW)
            self.assertEqual(json.dumps(s1, sort_keys=True),
                             json.dumps(s2, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
