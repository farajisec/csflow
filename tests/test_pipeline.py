import json
import random
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from csflow.aggregate import aggregate, k_anonymise
from csflow.gate import check_invariants, check_schema, load_identifiers, run_gate, scan_text
from csflow.policy import Policy
from csflow.render import render
from csflow.simulate import build_inventory, generate, simulate

NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def build(tmp_path_factory):
    b = tmp_path_factory.mktemp("build")
    generate(42, b, hours=30, now=NOW)
    policy = Policy.load(None)
    samples = [json.loads(line) for line in (b / "samples.jsonl").read_text(encoding="utf-8").splitlines()]
    summ = aggregate(samples, NOW, policy)
    (b / "aggregates.json").write_text(json.dumps(summ, indent=1), encoding="utf-8")
    (b / "site").mkdir()
    (b / "site" / "index.html").write_text(render(summ), encoding="utf-8")
    return b, policy, samples, summ


def test_gate_passes_on_real_output(build):
    b, policy, _, _ = build
    assert run_gate([b / "aggregates.json", b / "site" / "index.html"], b / "inventory.json", policy, NOW) == []


def test_private_side_is_actually_sensitive(build):
    b, _, _, _ = build
    idents = load_identifiers(b / "inventory.json")
    assert len(idents["hostname"]) >= 50 and idents["ip"] and idents["mac"] and idents["owner_email"]


def test_delay_and_latest_per_host(build):
    _, policy, _, summ = build
    assert datetime.fromisoformat(summ["as_of"]) == NOW - timedelta(minutes=policy.publish_delay_minutes)
    assert summ["fleet"]["total"] == 50


def test_small_groups_are_merged_or_withheld(build):
    _, policy, _, summ = build
    labels = [g["label"] for g in summ["groups"]]
    assert "sensors" not in labels and "legacy" not in labels and "storage" not in labels
    assert "other" in labels
    assert min(g["total"] for g in summ["groups"]) >= policy.k_min_group_size


def test_k_anonymise_withholds_a_single_tiny_remainder():
    counts = {"big": {"up": 9, "degraded": 0, "down": 1}, "tiny": {"up": 1, "degraded": 0, "down": 0}}
    groups, folded, hidden = k_anonymise(counts, 5, "other")
    assert [g for g, _ in groups] == ["big"] and folded == 1 and hidden == 1


def test_complementary_suppression_withholds_fleet_row():
    inv = [{"hostname": f"big{i}", "group": "big"} for i in range(9)] + [{"hostname": "lone", "group": "tiny"}]
    samples = [{"hostname": h["hostname"], "group": h["group"], "status": "up" if h["group"] == "big" else "down",
                "sampled_at": (NOW - timedelta(hours=2)).isoformat()} for h in inv]
    summ = aggregate(samples, NOW, Policy.load(None))
    assert summ["fleet"] is None, "fleet minus groups would reveal the lone host's state"
    assert [g["label"] for g in summ["groups"]] == ["big"]


def test_schema_allowlist_refuses_new_fields(build):
    _, policy, _, summ = build
    doc = json.loads(json.dumps(summ))
    doc["debug_hosts"] = ["x"]
    doc["groups"][0]["owner"] = "someone"
    kinds = {f.kind for f in check_schema("a.json", doc, policy)}
    assert kinds == {"schema"}
    assert len(check_schema("a.json", doc, policy)) == 2


def test_invariants_catch_small_group_and_short_delay(build):
    _, policy, _, summ = build
    doc = json.loads(json.dumps(summ))
    doc["groups"][0]["total"] = 2
    doc["groups"][0]["up"] = 2
    doc["groups"][0]["degraded"] = doc["groups"][0]["down"] = 0
    doc["as_of"] = (NOW - timedelta(minutes=5)).isoformat()
    kinds = {f.kind for f in check_invariants("a.json", doc, policy, NOW, 8)}
    assert {"k-anonymity", "delay"} <= kinds


@pytest.mark.parametrize("encode", [lambda v: v, lambda v: __import__("base64").b64encode(v.encode()).decode(),
                                    lambda v: __import__("urllib.parse").parse.quote(v, safe=""), lambda v: v.upper()])
def test_scan_catches_known_identifiers_in_any_encoding(build, encode):
    b, policy, _, _ = build
    idents = load_identifiers(b / "inventory.json")
    host = sorted(idents["hostname"], key=len)[-1]
    assert scan_text("x", f"<!-- {encode(host)} -->", idents, policy)


@pytest.mark.parametrize("text,kind", [
    ("addr 198.51.100.9 here", "ipv4-shaped"), ("2001:db8::7", "ipv6-shaped"),
    ("02:00:5e:aa:bb:cc", "mac-shaped"), ("node9.cs.internal.example", "fqdn-shaped"),
    ("x@example.edu", "email-shaped"), ("SN12345678X", "serial-shaped"),
    ("123e4567-e89b-12d3-a456-426614174000", "uuid-shaped")])
def test_scan_catches_unknown_identifiers_by_shape(build, text, kind):
    b, policy, _, _ = build
    kinds = {f.kind for f in scan_text("x", text, load_identifiers(b / "inventory.json"), policy)}
    assert kind in kinds


def test_scan_does_not_flag_timestamps_and_counts(build):
    b, policy, _, _ = build
    text = '{"as_of": "2026-03-02T11:00:00+00:00", "up": 42, "health": 0.84, "bucket_start": "2026-03-01T12:00:00+00:00"}'
    assert scan_text("x", text, load_identifiers(b / "inventory.json"), policy) == []


def test_render_sees_only_the_summary(build):
    _, _, _, summ = build
    page = render(summ)
    assert "lamp" in page and "cs.internal.example" not in page and "@example.edu" not in page


def test_policy_rejects_identifying_fields_and_bad_k():
    with pytest.raises(ValueError):
        Policy.from_dict({"k_min_group_size": 1})
    with pytest.raises(ValueError):
        Policy.from_dict({"published_fields": {"group": ["label", "hostname"]}})


@given(st.integers(min_value=1, max_value=10_000), st.integers(min_value=2, max_value=12),
       st.integers(min_value=0, max_value=240))
@settings(max_examples=25, deadline=None)
def test_any_fleet_any_policy_leaks_nothing(seed, k, delay):
    """Property: for any seed, k and delay, the published output contains no identifier and respects k."""
    rng = random.Random(seed)
    inv = build_inventory(rng)
    samples = simulate(inv, rng, 4, NOW)
    policy = Policy.from_dict({"k_min_group_size": k, "publish_delay_minutes": delay})
    summ = aggregate(samples, NOW, policy)
    text = json.dumps(summ) + render(summ)
    for h in inv:
        assert h["hostname"] not in text and h["ip"] not in text and h["owner"] not in text
    for g in summ["groups"]:
        assert g["total"] >= k
    assert datetime.fromisoformat(summ["as_of"]) == NOW - timedelta(minutes=delay)
