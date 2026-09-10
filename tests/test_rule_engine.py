"""
Tests for src/detect/rule_engine.py — signature rule detection lane.
"""

import pytest
import pandas as pd
from pathlib import Path
from src.detect.rule_engine import RuleEngine, AllowList, make_engine
from src.schema import make_event, CANONICAL_COLUMNS


def _ts():
    return pd.Timestamp("2026-01-01T08:00:00", tz="UTC")


def _event(**kwargs) -> dict:
    """Build a minimal canonical event dict."""
    defaults = dict(
        timestamp=_ts(),
        host="LABVM",
        event_id=7,
        event_source="Sysmon",
        process_name="test.exe",
        process_path="C:\\Temp\\test.exe",
        signed=False,
        label="unknown",
        technique_tag="",
        raw_fields={},
    )
    defaults.update(kwargs)
    return make_event(
        defaults.pop("timestamp"),
        defaults.pop("host"),
        defaults.pop("event_id"),
        defaults.pop("event_source"),
        **defaults,
    )


PACKS_DIR = Path("rules/packs")
ALLOWLIST  = Path("rules/allowlist.yaml")


@pytest.fixture
def engine():
    e = RuleEngine()
    if PACKS_DIR.exists():
        e.load_packs(PACKS_DIR)
    if ALLOWLIST.exists():
        e.load_allowlist(ALLOWLIST)
    return e


class TestAllowList:
    def test_known_process_is_allowed(self):
        al = AllowList()
        if ALLOWLIST.exists():
            al.load(ALLOWLIST)
            event = _event(process_name="autohotkey.exe",
                           process_path="C:\\Program Files\\AutoHotkey\\autohotkey.exe")
            assert al.is_allowed(event)

    def test_unknown_process_not_allowed(self):
        al = AllowList()
        if ALLOWLIST.exists():
            al.load(ALLOWLIST)
            event = _event(process_name="keylogger.exe",
                           process_path="C:\\Temp\\keylogger.exe")
            assert not al.is_allowed(event)

    def test_system32_path_is_allowed(self):
        al = AllowList()
        if ALLOWLIST.exists():
            al.load(ALLOWLIST)
            event = _event(process_name="svchost.exe",
                           process_path="C:\\Windows\\System32\\svchost.exe")
            assert al.is_allowed(event)


class TestRuleEngine:
    def test_loads_packs(self, engine):
        if PACKS_DIR.exists():
            assert len(engine._packs) > 0

    def test_kl001_fires_on_unsigned_user32_load(self, engine):
        if not PACKS_DIR.exists():
            pytest.skip("rules/packs not found")
        event = _event(
            event_id=7,
            process_name="suspicious.exe",
            process_path="C:\\Temp\\suspicious.exe",
            image_loaded="C:\\Windows\\System32\\user32.dll",
            signed=False,
        )
        matches = engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        assert "KL-001" in rule_ids

    def test_kl001_does_not_fire_on_signed_process(self, engine):
        if not PACKS_DIR.exists():
            pytest.skip("rules/packs not found")
        event = _event(
            event_id=7,
            process_name="legit.exe",
            process_path="C:\\Windows\\System32\\legit.exe",
            image_loaded="C:\\Windows\\System32\\user32.dll",
            signed=True,
            signature="Microsoft Windows",
        )
        matches = engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        assert "KL-001" not in rule_ids

    def test_kl002_fires_on_temp_path(self, engine):
        if not PACKS_DIR.exists():
            pytest.skip("rules/packs not found")
        event = _event(
            event_id=7,
            process_name="dropper.exe",
            process_path="C:\\Users\\User\\AppData\\Local\\Temp\\dropper.exe",
            image_loaded="C:\\Windows\\System32\\user32.dll",
            signed=False,
        )
        matches = engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        assert "KL-002" in rule_ids

    def test_kl009_fires_on_browser_injection(self, engine):
        if not PACKS_DIR.exists():
            pytest.skip("rules/packs not found")
        event = _event(
            event_id=8,
            process_name="injector.exe",
            process_path="C:\\Temp\\injector.exe",
            target_object="C:\\Program Files\\Google\\Chrome\\chrome.exe",
            signed=False,
        )
        matches = engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        assert "KL-009" in rule_ids

    def test_kl013_fires_on_keyboard_raw_access(self, engine):
        if not PACKS_DIR.exists():
            pytest.skip("rules/packs not found")
        event = _event(
            event_id=9,
            process_name="driver_loader.exe",
            process_path="C:\\Temp\\driver_loader.exe",
            target_object="\\Device\\KeyboardClass0",
            signed=False,
        )
        matches = engine.evaluate(event)
        rule_ids = [m.rule_id for m in matches]
        assert "KL-013" in rule_ids

    def test_match_has_evidence(self, engine):
        if not PACKS_DIR.exists():
            pytest.skip("rules/packs not found")
        event = _event(
            event_id=7,
            process_name="suspicious.exe",
            process_path="C:\\Temp\\suspicious.exe",
            image_loaded="C:\\Windows\\System32\\user32.dll",
            signed=False,
        )
        matches = engine.evaluate(event)
        for m in matches:
            assert m.evidence, f"Rule {m.rule_id} has empty evidence"
            assert m.score > 0

    def test_allowlisted_process_gets_downgraded_score(self, engine):
        if not PACKS_DIR.exists() or not ALLOWLIST.exists():
            pytest.skip("rules/packs or allowlist not found")
        event = _event(
            event_id=7,
            process_name="autohotkey.exe",
            process_path="C:\\Program Files\\AutoHotkey\\autohotkey.exe",
            image_loaded="C:\\Windows\\System32\\user32.dll",
            signed=False,
        )
        matches = engine.evaluate(event)
        for m in matches:
            assert m.severity == "low", f"Expected downgraded severity for allowlisted process"