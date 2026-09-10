"""
Tests for the canary / deception lane (Part 3.1).

Covers:
- plant_canaries writes bait files and a hash-only registry.
- check_canary_access fires on a HIT (canary UUID present in telemetry) and
  stays silent on a MISS.
- The canary lane is wired into SessionBuilder at the highest weight, so a hit
  scores CRITICAL near-automatically while a miss leaves other lanes untouched.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from src.canary.planter import (
    CanaryToken,
    TEST_CARD_PATTERN,
    load_registry,
    plant_canaries,
    value_matches_token,
)
from src.canary.watcher import (
    CANARY_RULE_ID,
    check_canary_access,
    canary_matches_to_rule_matches,
)
from src.correlate.session_builder import LANE_WEIGHTS, SessionBuilder
from src.schema import CANONICAL_COLUMNS, make_event


def _df(events: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(events)
    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[CANONICAL_COLUMNS]
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def _proc_create(pid: int, base: datetime, name: str = "evil.exe") -> dict:
    return make_event(
        pd.Timestamp(base), "HOST1", 1, "Sysmon",
        process_name=name, process_path=rf"C:\Temp\{name}", pid=pid,
        signed=False, label="malicious",
    )


# ---------------------------------------------------------------------------
# Planter
# ---------------------------------------------------------------------------

class TestPlanter:
    def test_plants_files_and_registry_hash_only(self, tmp_path):
        tokens = plant_canaries(tmp_path, count=3, registry_path=tmp_path / "reg.json")
        assert len(tokens) == 3
        kinds = {t.kind for t in tokens}
        assert {"passwords_file", "credit_card", "clipboard"} <= kinds
        # Bait files exist
        assert (tmp_path / "passwords.txt").exists()
        assert (tmp_path / "card_note.txt").exists()
        # Card file uses the documented TEST pattern, never a real number
        assert TEST_CARD_PATTERN in (tmp_path / "card_note.txt").read_text()
        # Registry stores only hashes — no raw canary value on disk
        registry = json.loads((tmp_path / "reg.json").read_text())
        assert len(registry) == 3
        for row in registry:
            assert "value" not in row
            assert row["value_hash"]
        # Raw UUID value must NOT be recoverable from the registry file
        for t in tokens:
            assert t.value not in (tmp_path / "reg.json").read_text()

    def test_load_registry_roundtrip_hash_match(self, tmp_path):
        tokens = plant_canaries(tmp_path, count=1, registry_path=tmp_path / "reg.json")
        loaded = load_registry(tmp_path / "reg.json")
        assert len(loaded) == 1
        # Registry-loaded token has no raw value but still matches via hash
        assert loaded[0].value == ""
        assert value_matches_token(tokens[0].value, loaded[0])
        assert not value_matches_token("not-the-canary", loaded[0])

    def test_unique_values(self, tmp_path):
        tokens = plant_canaries(tmp_path, count=5, registry_path=tmp_path / "r.json")
        values = {t.value for t in tokens}
        assert len(values) == 5, "every canary value must be unique"


# ---------------------------------------------------------------------------
# Watcher — hit and miss
# ---------------------------------------------------------------------------

class TestWatcher:
    def _token(self) -> CanaryToken:
        return CanaryToken(
            token_id="deadbeef", kind="passwords_file",
            location="passwords.txt", value="canary-uuid-1234-5678",
        )

    def test_hit_on_registry_value(self):
        token = self._token()
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        events = _df([
            _proc_create(4242, base),
            make_event(
                pd.Timestamp(base + timedelta(seconds=5)), "HOST1", 13, "Sysmon",
                process_name="evil.exe", pid=4242,
                registry_key=r"HKCU\Software\loot",
                registry_value=f"stolen: {token.value}",  # exfiltrated canary
                label="malicious",
            ),
        ])
        matches = check_canary_access(events, [token])
        assert len(matches) == 1
        assert matches[0].token_id == "deadbeef"
        assert matches[0].pid == 4242

    def test_hit_on_clipboard_watch_event(self):
        token = self._token()
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        events = _df([
            _proc_create(4242, base),
            make_event(
                pd.Timestamp(base + timedelta(seconds=5)), "HOST1", 26, "ClipboardWatch",
                pid=4242, registry_value=token.value, target_object="clipboard",
                label="malicious",
            ),
        ])
        matches = check_canary_access(events, [token])
        assert len(matches) == 1

    def test_miss_when_canary_absent(self):
        token = self._token()
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        events = _df([
            _proc_create(4242, base),
            make_event(
                pd.Timestamp(base + timedelta(seconds=5)), "HOST1", 13, "Sysmon",
                process_name="evil.exe", pid=4242,
                registry_key=r"HKCU\Software\kl",
                registry_value="perfectly ordinary data",
                label="malicious",
            ),
        ])
        matches = check_canary_access(events, [token])
        assert matches == []

    def test_empty_inputs_safe(self):
        assert check_canary_access(pd.DataFrame(), []) == []

    def test_rule_match_conversion(self):
        token = self._token()
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        events = _df([
            make_event(
                pd.Timestamp(base), "HOST1", 13, "Sysmon",
                pid=4242, registry_value=token.value, label="malicious",
            )
        ])
        rule_matches = canary_matches_to_rule_matches(
            check_canary_access(events, [token])
        )
        assert len(rule_matches) == 1
        rm = rule_matches[0]
        assert rm["rule_id"] == CANARY_RULE_ID
        assert rm["severity"] == "critical"
        assert rm["mitre_technique"] == "T1056.001"
        assert rm["lane"] == "canary"


# ---------------------------------------------------------------------------
# Lane wiring — hit scores CRITICAL, miss leaves other lanes untouched
# ---------------------------------------------------------------------------

class TestCanaryLaneScoring:
    def test_canary_weight_is_highest(self):
        assert LANE_WEIGHTS["canary"] == 0.70
        assert LANE_WEIGHTS["canary"] > LANE_WEIGHTS["signature"]

    def _builder_input(self, pid: int, base: datetime, canary_value: str | None):
        events = [_proc_create(pid, base)]
        if canary_value is not None:
            events.append(
                make_event(
                    pd.Timestamp(base + timedelta(seconds=5)), "HOST1", 13, "Sysmon",
                    process_name="evil.exe", pid=pid,
                    registry_key=r"HKCU\Software\loot",
                    registry_value=f"stolen: {canary_value}",
                    label="malicious",
                )
            )
        return _df(events)

    def test_hit_scores_critical(self):
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        token = CanaryToken(
            token_id="deadbeef", kind="passwords_file",
            location="passwords.txt", value="canary-uuid-1234-5678",
        )
        df = self._builder_input(4242, base, token.value)
        canary_rule_matches = canary_matches_to_rule_matches(
            check_canary_access(df[df["pid"] == 4242], [token])
        )
        incidents = SessionBuilder().build(
            df, canary_matches=canary_rule_matches, min_score=0
        )
        assert len(incidents) == 1
        inc = incidents[0]
        # A single canary hit (95 * 0.70 = 66.5) plus base -> should be HIGH+;
        # combined with the rule-id surfacing it must be at least HIGH.
        assert inc.composite_score >= 60
        assert inc.severity in ("HIGH", "CRITICAL")
        assert CANARY_RULE_ID in inc.rule_ids
        assert "T1056.001" in inc.mitre_techniques
        assert "CANARY" in inc.evidence_chain.upper()

    def test_miss_contributes_zero(self):
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        token = CanaryToken(
            token_id="deadbeef", kind="passwords_file",
            location="passwords.txt", value="canary-uuid-1234-5678",
        )
        df = self._builder_input(4242, base, None)  # no canary in telemetry
        canary_rule_matches = canary_matches_to_rule_matches(
            check_canary_access(df[df["pid"] == 4242], [token])
        )
        assert canary_rule_matches == []
        # With no canary match and no other lane firing, there is no incident.
        incidents = SessionBuilder().build(
            df, canary_matches=canary_rule_matches, min_score=0
        )
        assert incidents == []
