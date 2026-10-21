"""The publication policy: what may leave the private side, and in what shape.

Everything the pipeline enforces is written down here once, loaded from
``policy.json``, and validated. The published schema is an *allowlist*:
a field that is not listed cannot appear in any published artifact, no
matter which stage produced it. Blocklists (scan for hostnames, scan for
addresses) are still applied as a backstop, but the allowlist is the
control that survives a new field being added by accident.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_POLICY = {
    "k_min_group_size": 5,
    "publish_delay_minutes": 60,
    "history_hours": 24,
    "history_bucket_minutes": 60,
    "small_group_label": "other",
    "noise": {"enabled": False, "epsilon": 2.0},
    "published_fields": {
        "summary": ["as_of", "delay_minutes", "generated_from_samples_before", "fleet", "groups", "history", "policy"],
        "fleet": ["total", "up", "degraded", "down", "health"],
        "group": ["label", "total", "up", "degraded", "down", "health"],
        "history_point": ["bucket_start", "up", "degraded", "down", "total"],
        "policy": ["k_min_group_size", "publish_delay_minutes", "history_hours", "noise"],
    },
    "forbidden_patterns": ["ipv4", "ipv6", "mac", "fqdn", "email", "serial", "uuid"],
}


@dataclass
class Policy:
    k_min_group_size: int
    publish_delay_minutes: int
    history_hours: int
    history_bucket_minutes: int
    small_group_label: str
    noise_enabled: bool
    noise_epsilon: float
    published_fields: dict[str, list[str]]
    forbidden_patterns: list[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict) -> Policy:
        merged = json.loads(json.dumps(DEFAULT_POLICY))
        merged.update({k: v for k, v in d.items() if k != "noise" and k != "published_fields"})
        merged["noise"].update(d.get("noise", {}))
        merged["published_fields"].update(d.get("published_fields", {}))
        p = Policy(
            int(merged["k_min_group_size"]), int(merged["publish_delay_minutes"]), int(merged["history_hours"]),
            int(merged["history_bucket_minutes"]), str(merged["small_group_label"]),
            bool(merged["noise"]["enabled"]), float(merged["noise"]["epsilon"]),
            {k: list(v) for k, v in merged["published_fields"].items()}, list(merged["forbidden_patterns"]))
        p.validate()
        return p

    @staticmethod
    def load(path: Path | None) -> Policy:
        if path is None or not Path(path).exists():
            return Policy.from_dict({})
        with open(path, encoding="utf-8") as f:
            return Policy.from_dict(json.load(f))

    def validate(self) -> None:
        if self.k_min_group_size < 2:
            raise ValueError("k_min_group_size must be at least 2: a group of one is a named machine")
        if self.publish_delay_minutes < 0:
            raise ValueError("publish_delay_minutes cannot be negative")
        if self.history_bucket_minutes <= 0 or self.history_hours <= 0:
            raise ValueError("history settings must be positive")
        if self.noise_enabled and self.noise_epsilon <= 0:
            raise ValueError("epsilon must be positive when noise is enabled")
        for kind in ("summary", "fleet", "group", "history_point", "policy"):
            if kind not in self.published_fields:
                raise ValueError(f"published_fields.{kind} missing")
        for name in ("hostname", "host", "ip", "addr", "owner", "mac", "serial", "name"):
            for kind, fields in self.published_fields.items():
                if name in fields:
                    raise ValueError(f"published_fields.{kind} lists identifying field {name!r}")

    def to_public_dict(self) -> dict:
        return {"k_min_group_size": self.k_min_group_size, "publish_delay_minutes": self.publish_delay_minutes,
                "history_hours": self.history_hours,
                "noise": {"enabled": self.noise_enabled, "epsilon": self.noise_epsilon if self.noise_enabled else None}}
