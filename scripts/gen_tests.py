"""
Generator: writes tests/test_aggressive.py in full.
Run from glyph/:  python scripts/gen_tests.py
"""
import pathlib

HEADER = '''\
"""
Aggressive Debug & Security Audit Test Suite
============================================
BUG-1  PeriodicWriteDetector: tz_localize(None) on tz-naive ts raises TypeError
BUG-3  PollingDetector: all-NaN image_loaded column crashes str accessor
BUG-5  PeriodicWriteDetector: CV division by zero when mean==0
BUG-6  rule_engine: duplicate YAML NOT keys drop first NOT block
BUG-7  RuleEngine: {pid} missing from evidence_template format kwargs
BUG-8  AllowList.load: malformed YAML silently produces empty lists
BUG-9  normalize: empty timestamp string silently returns utcnow()
BUG-10 normalize: EventID=-1 stored without validation
BUG-11 schema: technique_tag not validated against VALID_TECHNIQUE_TAGS
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pandas as pd
import pytest
from src.detect.heuristics import (
    HeuristicEngine, HeuristicMatch, HeadlessHookDetector,
    PeriodicWriteDetector, PollingDetector,
)
from src.detect.rule_engine import (
    AllowList, RuleEngine, RuleMatch, _eval_condition, _str_lower, make_engine,
)
from src.ingest.normalize import (
    _extract_hash, _extract_process_name, _parse_bool, _parse_pid,
    _parse_timestamp, events_to_df, normalize_event, normalize_events,
)
from src.schema import (
    CANONICAL_COLUMNS, VALID_LABELS, SchemaValidationError,
    make_empty_df, make_event, validate_df,
)

PACKS_DIR = Path("rules/packs")
ALLOWLIST = Path("rules/allowlist.yaml")


def _ts(offset_s=0.0):
    base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
    return pd.Timestamp(base + timedelta(seconds=offset_s))

def _make_df(events):
    return pd.DataFrame(events, columns=CANONICAL_COLUMNS)

def _dll_event(pid, dll, offset=0.1, signed=True,
               proc_name="test.exe", proc_path=r"C:\\Temp\\test.exe"):
    return make_event(_ts(offset), "LABVM", 7, "Sysmon",
        process_name=proc_name, process_path=proc_path, pid=pid,
        image_loaded=r"C:\\Windows\\System32\\" + dll,
        signed=signed, raw_fields={})

def _proc_create(pid, name, path, parent, signed=False):
    return make_event(_ts(0.0), "LABVM", 1, "Sysmon",
        process_name=name, process_path=path, pid=pid, ppid=pid-1,
        parent_process_name=parent, signed=signed, raw_fields={})

def _reg_write(pid, key, offset):
    return make_event(_ts(offset), "LABVM", 13, "Sysmon",
        process_name="test.exe", pid=pid, registry_key=key, raw_fields={})

def _raw_event(event_id, **kwargs):
    return {"EventID": event_id, "TimeCreated": "2026-01-01T08:00:00.000000Z",
            "Computer": "LABVM", "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Provider": "Microsoft-Windows-Sysmon", "EventData": kwargs, "_raw_xml": ""}

def _periodic_ts(n, interval_s, tz_aware=True):
    tz = timezone.utc if tz_aware else None
    base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=tz)
    return [pd.Timestamp(base + timedelta(seconds=interval_s * i)) for i in range(1, n+1)]
'''

SCHEMA_TESTS = '''\

# ===========================================================================
# 1. schema.py
# ===========================================================================

class TestMakeEvent:
    def test_all_canonical_columns_present(self):
        assert set(make_event(_ts(), "H", 1, "S").keys()) == set(CANONICAL_COLUMNS)

    def test_process_hash_lowercased(self):
        ev = make_event(_ts(), "H", 1, "S", process_hash="DEAD" + "0" * 60)
        assert ev["process_hash"] == ev["process_hash"].lower()

    def test_invalid_label_raises(self):
        with pytest.raises(ValueError):
            make_event(_ts(), "H", 1, "S", label="INVALID")

    def test_empty_label_raises(self):
        with pytest.raises(ValueError):
            make_event(_ts(), "H", 1, "S", label="")

    def test_none_raw_fields_becomes_empty_dict(self):
        assert make_event(_ts(), "H", 1, "S", raw_fields=None)["raw_fields"] == {}

    def test_all_valid_labels_accepted(self):
        for lbl in VALID_LABELS:
            assert make_event(_ts(), "H", 1, "S", label=lbl)["label"] == lbl

    def test_signed_values_stored(self):
        for val in (True, False, None):
            assert make_event(_ts(), "H", 1, "S", signed=val)["signed"] is val


class TestMakeEmptyDf:
    def test_has_all_columns(self):
        assert set(make_empty_df().columns) == set(CANONICAL_COLUMNS)

    def test_zero_rows(self):
        assert len(make_empty_df()) == 0

    def test_pid_nullable_int(self):
        assert str(make_empty_df()["pid"].dtype) == "Int64"

    def test_signed_nullable_bool(self):
        assert str(make_empty_df()["signed"].dtype) == "boolean"


class TestValidateDf:
    def _good(self, n=3):
        return pd.DataFrame(
            [make_event(_ts(float(i)), "H", 1, "S") for i in range(n)],
            columns=CANONICAL_COLUMNS)

    def test_valid_no_violations(self):
        assert validate_df(self._good()) == []

    def test_missing_column(self):
        assert any("timestamp" in v for v in validate_df(self._good().drop(columns=["timestamp"])))

    def test_null_in_non_nullable(self):
        df = self._good(); df.loc[0, "host"] = None
        assert any("host" in v for v in validate_df(df))

    def test_invalid_label(self):
        df = self._good(); df.loc[0, "label"] = "HACKED"
        assert any("label" in v for v in validate_df(df))

    def test_uppercase_hash(self):
        df = self._good(); df.loc[0, "process_hash"] = "ABCDEF" + "0" * 58
        assert any("process_hash" in v for v in validate_df(df))

    def test_non_dict_raw_fields(self):
        df = self._good(); df.loc[0, "raw_fields"] = "bad"
        assert any("raw_fields" in v for v in validate_df(df))

    def test_strict_raises(self):
        with pytest.raises(SchemaValidationError):
            validate_df(self._good().drop(columns=["timestamp"]), strict=True)

    def test_strict_valid_no_raise(self):
        assert validate_df(self._good(), strict=True) == []

    def test_empty_df_no_violations(self):
        assert validate_df(make_empty_df()) == []

    def test_multiple_violations(self):
        assert len(validate_df(self._good().drop(columns=["timestamp", "host"]))) >= 2

    def test_bug11_technique_tag_not_validated(self):
        """BUG-11: technique_tag not validated against VALID_TECHNIQUE_TAGS."""
        df = self._good(); df.loc[0, "technique_tag"] = "INVALID_XYZ"
        assert not any("technique_tag" in v for v in validate_df(df))
'''

NORMALIZE_TESTS = '''\

# ===========================================================================
# 2. normalize helpers
# ===========================================================================

class TestParsePid:
    @pytest.mark.parametrize("val,expected", [
        ("1234", 1234), (5678, 5678), (None, None), ("", None),
        ("abc", None), ("1234.5", None), ("  999  ", 999), ("0", 0), ("-1", -1),
    ])
    def test_variants(self, val, expected):
        assert _parse_pid(val) == expected


class TestParseBool:
    @pytest.mark.parametrize("val,expected", [
        ("true", True), ("True", True), ("1", True), ("yes", True),
        ("false", False), ("False", False), ("0", False), ("no", False),
        (None, None), ("maybe", None), ("", None),
    ])
    def test_variants(self, val, expected):
        assert _parse_bool(val) == expected


class TestExtractHash:
    def test_sha256_extracted_lowercased(self):
        assert _extract_hash("MD5=x,SHA256=" + "A"*64) == "a"*64

    def test_no_sha256_none(self):
        assert _extract_hash("MD5=abc") is None

    def test_none_none(self):
        assert _extract_hash(None) is None

    def test_empty_none(self):
        assert _extract_hash("") is None


class TestParseTimestamp:
    def test_iso_z(self):
        ts = _parse_timestamp("2026-01-01T08:00:00Z")
        assert ts.tzinfo is not None and ts.year == 2026

    def test_microseconds(self):
        assert _parse_timestamp("2026-01-01T08:00:00.123456Z").microsecond == 123456

    def test_bug9_empty_returns_now(self):
        """BUG-9: empty string silently returns utcnow()."""
        before = pd.Timestamp.utcnow()
        ts = _parse_timestamp("")
        assert abs((ts - before).total_seconds()) < 5

    def test_garbage_returns_now(self):
        before = pd.Timestamp.utcnow()
        assert abs((_parse_timestamp("NOT_A_DATE") - before).total_seconds()) < 5

    def test_none_raises(self):
        with pytest.raises((AttributeError, TypeError)):
            _parse_timestamp(None)  # type: ignore


# ===========================================================================
# 3. normalize_event / normalize_events / events_to_df
# ===========================================================================

class TestNormalizeEvent:
    def test_id1_all_fields(self):
        raw = _raw_event(1, Image=r"C:\\Windows\\System32\\notepad.exe",
                         Hashes="SHA256="+"a"*64, ProcessId="1234",
                         ParentProcessId="5678",
                         ParentImage=r"C:\\Windows\\explorer.exe",
                         Signed="true", Signature="Microsoft Windows")
        ev = normalize_event(raw)
        assert ev["process_name"] == "notepad.exe"
        assert ev["pid"] == 1234 and ev["ppid"] == 5678
        assert ev["signed"] is True
        assert ev["process_hash"] == "a"*64

    def test_id7_image_load(self):
        raw = _raw_event(7, Image=r"C:\\Temp\\kl.exe",
                         ImageLoaded=r"C:\\Windows\\System32\\user32.dll",
                         ProcessId="9999", Signed="false")
        ev = normalize_event(raw)
        assert "user32.dll" in ev["image_loaded"]
        assert ev["signed"] is False

    def test_id8_remote_thread(self):
        raw = _raw_event(8, Image=r"C:\\Temp\\injector.exe",
                         TargetImage=r"C:\\Program Files\\Google\\Chrome\\chrome.exe",
                         ProcessId="1111")
        assert "chrome.exe" in normalize_event(raw)["target_object"]

    def test_id9_raw_access(self):
        raw = _raw_event(9, Image=r"C:\\Temp\\driver.exe",
                         Device=r"\\Device\\KeyboardClass0", ProcessId="2222")
        assert "KeyboardClass0" in normalize_event(raw)["target_object"]

    def test_id13_registry_write(self):
        raw = _raw_event(13, Image=r"C:\\Temp\\persist.exe",
                         TargetObject=r"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         Details=r"C:\\Temp\\persist.exe", ProcessId="3333")
        ev = normalize_event(raw)
        assert "Run" in ev["registry_key"]

    def test_all_canonical_columns_present(self):
        ev = normalize_event(_raw_event(1, Image="notepad.exe"))
        for col in CANONICAL_COLUMNS:
            assert col in ev

    def test_raw_fields_preserved(self):
        ev = normalize_event(_raw_event(1, Image="notepad.exe", Extra="val"))
        assert "Extra" in ev["raw_fields"]

    def test_unknown_event_id_best_effort(self):
        ev = normalize_event(_raw_event(999, Image=r"C:\\Temp\\x.exe", ProcessId="4444"))
        assert ev["event_id"] == 999 and ev["process_name"] == "x.exe"

    def test_bug10_negative_event_id_stored(self):
        """BUG-10: EventID=-1 stored without validation."""
        raw = {"EventID": -1, "TimeCreated": "2026-01-01T08:00:00Z",
               "Computer": "H", "Channel": "Sysmon", "EventData": {}, "_raw_xml": ""}
        assert normalize_event(raw)["event_id"] == -1

    def test_missing_event_data_key(self):
        raw = {"EventID": 1, "TimeCreated": "2026-01-01T08:00:00Z",
               "Computer": "H", "Channel": "Sysmon", "_raw_xml": ""}
        assert normalize_event(raw)["event_id"] == 1

    def test_sysmon_channel(self):
        assert normalize_event(_raw_event(1, Image="n.exe"))["event_source"] == "Sysmon"

    def test_security_channel(self):
        raw = _raw_event(4688, Image="cmd.exe"); raw["Channel"] = "Security"
        assert normalize_event(raw)["event_source"] == "Security"

    def test_pid_none_when_missing(self):
        assert normalize_event(_raw_event(1, Image="n.exe"))["pid"] is None

    def test_empty_event_data(self):
        ev = normalize_event(_raw_event(1))
        assert ev["process_name"] is None and ev["pid"] is None


class TestNormalizeEvents:
    def test_label_applied(self):
        evs = list(normalize_events([_raw_event(1, Image="n.exe")],
                                    label="malicious", technique_tag="hook"))
        assert evs[0]["label"] == "malicious" and evs[0]["technique_tag"] == "hook"

    def test_invalid_label_raises(self):
        with pytest.raises(ValueError):
            list(normalize_events([_raw_event(1)], label="INVALID"))

    def test_bad_events_skipped(self):
        evs = list(normalize_events([{"BAD": True}, _raw_event(1, Image="n.exe")],
                                    label="unknown"))
        assert len(evs) >= 1

    def test_empty_iterable(self):
        assert list(normalize_events([], label="benign")) == []

    def test_large_batch(self):
        raws = [_raw_event(7, Image=f"p{i}.exe", ImageLoaded="user32.dll") for i in range(500)]
        assert len(list(normalize_events(raws, label="unknown"))) == 500


class TestEventsToDF:
    def test_returns_dataframe(self):
        df = events_to_df([_raw_event(1, Image="n.exe") for _ in range(5)])
        assert isinstance(df, pd.DataFrame) and len(df) == 5

    def test_has_canonical_columns(self):
        df = events_to_df([_raw_event(7, Image="p.exe", ImageLoaded="user32.dll")])
        for col in CANONICAL_COLUMNS:
            assert col in df.columns

    def test_empty_returns_empty_df(self):
        df = events_to_df([])
        assert len(df) == 0
        for col in CANONICAL_COLUMNS:
            assert col in df.columns

    def test_timestamp_utc_aware(self):
        df = events_to_df([_raw_event(1, Image="n.exe")])
        assert df["timestamp"].dt.tz is not None

    def test_pid_nullable_int(self):
        df = events_to_df([_raw_event(1, Image="n.exe", ProcessId="1234")])
        assert str(df["pid"].dtype) == "Int64"
'''

POLLING_TESTS = '''\

# ===========================================================================
# 4. PollingDetector
# ===========================================================================

class TestPollingDetector:
    def _m(self, name="kl.exe", path=r"C:\\Temp\\kl.exe",
           parent="cmd.exe", signed=False, pid=1234):
        return {"process_name": name, "process_path": path,
                "parent_process_name": parent, "signed": signed, "pid": pid}

    def test_full_keylogger_fires(self):
        pid = 1234
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m())
        assert match is not None and match.score >= 30
        assert match.detector == "PollingDetector"

    def test_signed_system_process_low_score(self):
        pid = 5678
        events = [
            _proc_create(pid, "notepad.exe", r"C:\\Windows\\System32\\notepad.exe",
                         "explorer.exe", signed=True),
            _dll_event(pid, "user32.dll", signed=True,
                       proc_path=r"C:\\Windows\\System32\\notepad.exe"),
        ]
        meta = self._m("notepad.exe", r"C:\\Windows\\System32\\notepad.exe",
                       "explorer.exe", signed=True)
        match = PollingDetector().analyze(_make_df(events), meta)
        if match:
            assert match.score < 30

    @pytest.mark.parametrize("parent", [
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "schtasks.exe",
    ])
    def test_headless_parent_adds_score(self, parent):
        pid = 100
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", parent, signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m(parent=parent))
        assert match is not None and match.features["headless_parent"] is True

    def test_staging_path_appdata_fires(self):
        pid = 200
        path = r"C:\\Users\\User\\AppData\\Roaming\\kl.exe"
        events = [
            _proc_create(pid, "kl.exe", path, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll", proc_path=path),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m(path=path))
        assert match is not None and match.features["staging_path"] is True

    def test_staging_path_downloads_fires(self):
        pid = 201
        path = r"C:\\Users\\User\\Downloads\\kl.exe"
        events = [
            _proc_create(pid, "kl.exe", path, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll", proc_path=path),
        ]
        meta = {"process_name": "kl.exe", "process_path": path,
                "parent_process_name": "cmd.exe", "signed": False, "pid": pid}
        match = PollingDetector().analyze(_make_df(events), meta)
        assert match is not None and match.features["staging_path"] is True

    def test_no_user32_no_match(self):
        pid = 300
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "kernel32.dll"),
        ]
        assert PollingDetector().analyze(_make_df(events), self._m()) is None

    def test_hook_registry_clears_no_hook_flag(self):
        pid = 400
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
            _reg_write(pid, r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppInit_DLLs", 1.0),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m())
        if match:
            assert match.features["no_hook_registry"] is False

    def test_bug3_all_nan_image_loaded_no_crash(self):
        """BUG-3: all-NaN image_loaded should not crash str accessor."""
        pid = 500
        events = [_proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe")]
        df = pd.DataFrame(events, columns=CANONICAL_COLUMNS)
        df["image_loaded"] = None
        try:
            PollingDetector().analyze(df, self._m())
        except Exception as e:
            pytest.fail(f"BUG-3: {e}")

    def test_empty_df_returns_none(self):
        assert PollingDetector().analyze(make_empty_df(), self._m()) is None

    def test_score_capped_at_80(self):
        pid = 600
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m())
        if match:
            assert match.score <= 80

    def test_confidence_0_to_1(self):
        pid = 700
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m())
        if match:
            assert 0.0 <= match.confidence <= 1.0

    def test_all_none_meta_no_crash(self):
        meta = {"process_name": None, "process_path": None,
                "parent_process_name": None, "signed": None, "pid": None}
        try:
            PollingDetector().analyze(make_empty_df(), meta)
        except Exception as e:
            pytest.fail(f"all-None meta: {e}")

    def test_empty_meta_no_crash(self):
        try:
            PollingDetector().analyze(make_empty_df(), {})
        except Exception as e:
            pytest.fail(f"empty meta: {e}")

    def test_signed_none_treated_as_unsigned(self):
        pid = 800
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m(signed=None))
        if match:
            assert match.features["unsigned"] is True

    def test_evidence_contains_pid(self):
        pid = 9001
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m(pid=pid))
        if match:
            assert str(pid) in match.evidence

    def test_match_types(self):
        pid = 9002
        events = [
            _proc_create(pid, "kl.exe", r"C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._m(pid=pid))
        if match:
            assert isinstance(match, HeuristicMatch)
            assert isinstance(match.features, dict)
            assert isinstance(match.score, int)
            assert isinstance(match.confidence, float)

    def test_adversarial_unicode_process_name(self):
        pid = 9003
        name = "k\\u0435ylogger.exe"  # Cyrillic e
        events = [
            _proc_create(pid, name, r"C:\\Temp\\" + name, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        meta = {"process_name": name, "process_path": r"C:\\Temp\\" + name,
                "parent_process_name": "cmd.exe", "signed": False, "pid": pid}
        try:
            PollingDetector().analyze(_make_df(events), meta)
        except Exception as e:
            pytest.fail(f"Unicode name: {e}")

    def test_adversarial_null_bytes_in_name(self):
        pid = 9004
        name = "kl\\x00.exe"
        events = [
            _proc_create(pid, name, r"C:\\Temp\\" + name, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        meta = {"process_name": name, "process_path": r"C:\\Temp\\" + name,
                "parent_process_name": "cmd.exe", "signed": False, "pid": pid}
        try:
            PollingDetector().analyze(_make_df(events), meta)
        except Exception as e:
            pytest.fail(f"Null bytes: {e}")
'''

PERIODIC_TESTS = '''\

# ===========================================================================
# 5. PeriodicWriteDetector
# ===========================================================================

class TestPeriodicWriteDetector:
    META = {"process_name": "kl.exe", "pid": 9999}

    def test_30s_fires(self):
        match = PeriodicWriteDetector().analyze(_periodic_ts(12, 30.0), self.META)
        assert match is not None and match.score > 0
        assert match.detector == "PeriodicWriteDetector"

    def test_60s_fires(self):
        assert PeriodicWriteDetector().analyze(_periodic_ts(10, 60.0), self.META) is not None

    def test_5s_boundary_fires(self):
        assert PeriodicWriteDetector().analyze(_periodic_ts(10, 5.0), self.META) is not None

    def test_sub_second_filtered_none(self):
        base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        ts = [pd.Timestamp(base + timedelta(milliseconds=100*i)) for i in range(1, 20)]
        assert PeriodicWriteDetector().analyze(ts, self.META) is None

    def test_too_few_writes_none(self):
        assert PeriodicWriteDetector().analyze(_periodic_ts(3, 30.0), self.META) is None

    def test_empty_list_none(self):
        assert PeriodicWriteDetector().analyze([], self.META) is None

    def test_single_ts_none(self):
        base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        assert PeriodicWriteDetector().analyze([pd.Timestamp(base)], self.META) is None

    def test_score_capped_at_75(self):
        match = PeriodicWriteDetector().analyze(_periodic_ts(20, 30.0), self.META)
        if match:
            assert match.score <= 75

    def test_confidence_0_to_1(self):
        match = PeriodicWriteDetector().analyze(_periodic_ts(12, 30.0), self.META)
        if match:
            assert 0.0 <= match.confidence <= 1.0

    def test_bug1_tz_naive_no_crash(self):
        """BUG-1: tz-naive timestamps should not raise TypeError."""
        ts = _periodic_ts(12, 30.0, tz_aware=False)
        assert all(t.tzinfo is None for t in ts)
        try:
            PeriodicWriteDetector().analyze(ts, self.META)
        except TypeError as e:
            pytest.fail(f"BUG-1: {e}")

    def test_mixed_tz_no_crash(self):
        base_a = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        base_n = datetime(2026, 1, 1, 8, 0, 0)
        ts = []
        for i in range(1, 7):
            if i % 2 == 0:
                ts.append(pd.Timestamp(base_a + timedelta(seconds=i*30)))
            else:
                ts.append(pd.Timestamp(base_n + timedelta(seconds=i*30)))
        try:
            PeriodicWriteDetector().analyze(ts, self.META)
        except Exception as e:
            pytest.fail(f'Mixed TZ raised: {e}')

    def test_adversarial_shuffled_timestamps(self):
        base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        ts = [
            pd.Timestamp(base + timedelta(seconds=30 * i))
            for i in [5, 1, 3, 2, 4, 6, 8, 7, 9, 10, 12, 11]
        ]
        try:
            PeriodicWriteDetector().analyze(ts, {'process_name': 'kl.exe', 'pid': 1})
        except Exception as e:
            pytest.fail(f'Out-of-order timestamps raised: {e}')

    def test_adversarial_all_nan_dataframe(self):
        df = make_empty_df()
        for col in df.columns:
            df[col] = None
        try:
            HeuristicEngine().analyze_df(df)
            PollingDetector().analyze(df, {})
            HeadlessHookDetector().analyze(df, {})
        except Exception as e:
            pytest.fail(f'All-NaN DataFrame raised: {e}')
'''

if __name__ == '__main__':
    with open('tests/test_aggressive.py', 'w', encoding='utf-8') as f:
        f.write(HEADER + SCHEMA_TESTS + NORMALIZE_TESTS + POLLING_TESTS + PERIODIC_TESTS)
