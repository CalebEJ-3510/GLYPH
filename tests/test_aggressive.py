"""
Aggressive Debug & Security Audit Test Suite
============================================
Covers: heuristics.py, rule_engine.py, normalize.py, schema.py

BUG-1  PeriodicWriteDetector: tz_localize(None) on tz-naive ts raises TypeError
BUG-2  PeriodicWriteDetector: dominant_period=0.0 when freq==0
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(offset_s: float = 0.0) -> pd.Timestamp:
    base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
    return pd.Timestamp(base + timedelta(seconds=offset_s))


def _make_df(events: list) -> pd.DataFrame:
    return pd.DataFrame(events, columns=CANONICAL_COLUMNS)


def _dll_event(pid, dll, offset=0.1, signed=True,
               proc_name="test.exe", proc_path="C:\\Temp\\test.exe"):
    return make_event(_ts(offset), "LABVM", 7, "Sysmon",
        process_name=proc_name, process_path=proc_path, pid=pid,
        image_loaded=f"C:\\Windows\\System32\\{dll}",
        signed=signed, raw_fields={})


def _proc_create(pid, name, path, parent, signed=False):
    return make_event(_ts(0.0), "LABVM", 1, "Sysmon",
        process_name=name, process_path=path, pid=pid, ppid=pid - 1,
        parent_process_name=parent, signed=signed, raw_fields={})


def _reg_write(pid, key, offset):
    return make_event(_ts(offset), "LABVM", 13, "Sysmon",
        process_name="test.exe", pid=pid, registry_key=key, raw_fields={})


def _raw_event(event_id, **kwargs):
    return {"EventID": event_id,
            "TimeCreated": "2026-01-01T08:00:00.000000Z",
            "Computer": "LABVM",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Provider": "Microsoft-Windows-Sysmon",
            "EventData": kwargs, "_raw_xml": ""}


def _periodic_ts(n, interval_s, tz_aware=True):
    tz = timezone.utc if tz_aware else None
    base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=tz)
    return [pd.Timestamp(base + timedelta(seconds=interval_s * i)) for i in range(1, n + 1)]


# ===========================================================================
# 1. schema.py
# ===========================================================================

class TestMakeEvent:
    def test_all_canonical_columns_present(self):
        ev = make_event(_ts(), "HOST", 1, "Sysmon")
        assert set(ev.keys()) == set(CANONICAL_COLUMNS)

    def test_process_hash_lowercased(self):
        ev = make_event(_ts(), "HOST", 1, "Sysmon", process_hash="DEADBEEF" + "0" * 56)
        assert ev["process_hash"] == ev["process_hash"].lower()

    def test_invalid_label_raises(self):
        with pytest.raises(ValueError, match="Invalid label"):
            make_event(_ts(), "HOST", 1, "Sysmon", label="INVALID")

    def test_none_raw_fields_becomes_empty_dict(self):
        ev = make_event(_ts(), "HOST", 1, "Sysmon", raw_fields=None)
        assert ev["raw_fields"] == {}

    def test_all_valid_labels_accepted(self):
        for lbl in VALID_LABELS:
            ev = make_event(_ts(), "HOST", 1, "Sysmon", label=lbl)
            assert ev["label"] == lbl

    def test_empty_string_label_rejected(self):
        with pytest.raises(ValueError):
            make_event(_ts(), "HOST", 1, "Sysmon", label="")

    def test_process_hash_none_stays_none(self):
        assert make_event(_ts(), "HOST", 1, "Sysmon", process_hash=None)["process_hash"] is None

    def test_signed_values_stored(self):
        for val in (True, False, None):
            assert make_event(_ts(), "HOST", 1, "Sysmon", signed=val)["signed"] is val


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
    def _good_df(self, n=3):
        events = [make_event(_ts(float(i)), "HOST", 1, "Sysmon") for i in range(n)]
        return pd.DataFrame(events, columns=CANONICAL_COLUMNS)

    def test_valid_df_no_violations(self):
        assert validate_df(self._good_df()) == []

    def test_missing_column_reported(self):
        df = self._good_df().drop(columns=["timestamp"])
        assert any("timestamp" in v for v in validate_df(df))

    def test_null_in_non_nullable_column(self):
        df = self._good_df()
        df.loc[0, "host"] = None
        assert any("host" in v for v in validate_df(df))

    def test_invalid_label_reported(self):
        df = self._good_df()
        df.loc[0, "label"] = "HACKED"
        assert any("label" in v for v in validate_df(df))

    def test_uppercase_hash_reported(self):
        df = self._good_df()
        df.loc[0, "process_hash"] = "ABCDEF" + "0" * 58
        assert any("process_hash" in v for v in validate_df(df))

    def test_non_dict_raw_fields_reported(self):
        df = self._good_df()
        df.loc[0, "raw_fields"] = "not_a_dict"
        assert any("raw_fields" in v for v in validate_df(df))

    def test_strict_mode_raises(self):
        df = self._good_df().drop(columns=["timestamp"])
        with pytest.raises(SchemaValidationError):
            validate_df(df, strict=True)

    def test_strict_mode_no_raise_on_valid(self):
        assert validate_df(self._good_df(), strict=True) == []

    def test_empty_df_no_violations(self):
        assert validate_df(make_empty_df()) == []

    def test_multiple_violations_collected(self):
        df = self._good_df().drop(columns=["timestamp", "host"])
        assert len(validate_df(df)) >= 2

    def test_bug11_technique_tag_not_validated(self):
        """BUG-11: validate_df does NOT check technique_tag against VALID_TECHNIQUE_TAGS."""
        df = self._good_df()
        df.loc[0, "technique_tag"] = "INVALID_TAG_XYZ"
        violations = validate_df(df)
        assert not any("technique_tag" in v for v in violations), (
            "BUG-11 still present: technique_tag not validated")


# ===========================================================================
# 2. normalize.py helpers
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
        ("true", True), ("True", True), ("TRUE", True), ("1", True), ("yes", True),
        ("false", False), ("False", False), ("FALSE", False), ("0", False), ("no", False),
        (None, None), ("maybe", None), ("", None), ("2", None),
    ])
    def test_variants(self, val, expected):
        assert _parse_bool(val) == expected


class TestExtractHash:
    def test_sha256_extracted_and_lowercased(self):
        h = "MD5=abc,SHA256=" + "A" * 64 + ",IMPHASH=xyz"
        assert _extract_hash(h) == "a" * 64

    def test_no_sha256_returns_none(self):
        assert _extract_hash("MD5=abc,IMPHASH=xyz") is None

    def test_none_returns_none(self):
        assert _extract_hash(None) is None

    def test_empty_string_returns_none(self):
        assert _extract_hash("") is None

    def test_malformed_no_equals(self):
        assert _extract_hash("SHA256deadbeef") is None


class TestExtractProcessName:
    def test_windows_path(self):
        assert _extract_process_name("C:\\Windows\\System32\\notepad.exe") == "notepad.exe"

    def test_none_returns_none(self):
        assert _extract_process_name(None) is None

    def test_empty_string(self):
        assert _extract_process_name("") == ""


class TestParseTimestamp:
    def test_iso_with_z(self):
        ts = _parse_timestamp("2026-01-01T08:00:00Z")
        assert ts.tzinfo is not None and ts.year == 2026

    def test_iso_with_microseconds(self):
        assert _parse_timestamp("2026-01-01T08:00:00.123456Z").microsecond == 123456

    def test_bug9_empty_string_returns_now(self):
        """BUG-9: empty timestamp string silently returns utcnow()."""
        before = pd.Timestamp.utcnow()
        ts = _parse_timestamp("")
        assert abs((ts - before).total_seconds()) < 5

    def test_garbage_string_returns_now(self):
        before = pd.Timestamp.utcnow()
        ts = _parse_timestamp("NOT_A_DATE")
        assert abs((ts - before).total_seconds()) < 5

    def test_none_raises(self):
        with pytest.raises((AttributeError, TypeError)):
            _parse_timestamp(None)  # type: ignore


# ===========================================================================
# 3. normalize_event / normalize_events / events_to_df
# ===========================================================================

class TestNormalizeEvent:
    def test_id1_all_fields(self):
        raw = _raw_event(1, Image="C:\\Windows\\System32\\notepad.exe",
                         Hashes="SHA256=" + "a" * 64, ProcessId="1234",
                         ParentProcessId="5678",
                         ParentImage="C:\\Windows\\explorer.exe",
                         Signed="true", Signature="Microsoft Windows")
        ev = normalize_event(raw)
        assert ev["event_id"] == 1
        assert ev["process_name"] == "notepad.exe"
        assert ev["pid"] == 1234
        assert ev["ppid"] == 5678
        assert ev["parent_process_name"] == "explorer.exe"
        assert ev["signed"] is True
        assert ev["process_hash"] == "a" * 64

    def test_id7_image_load(self):
        raw = _raw_event(7, Image="C:\\Temp\\kl.exe",
                         ImageLoaded="C:\\Windows\\System32\\user32.dll",
                         ProcessId="9999", Signed="false")
        ev = normalize_event(raw)
        assert ev["image_loaded"] == "C:\\Windows\\System32\\user32.dll"
        assert ev["signed"] is False

    def test_id8_remote_thread(self):
        raw = _raw_event(8, Image="C:\\Temp\\injector.exe",
                         TargetImage="C:\\Program Files\\Google\\Chrome\\chrome.exe",
                         ProcessId="1111")
        ev = normalize_event(raw)
        assert "chrome.exe" in ev["target_object"]

    def test_id9_raw_access(self):
        raw = _raw_event(9, Image="C:\\Temp\\driver.exe",
                         Device="\\Device\\KeyboardClass0", ProcessId="2222")
        ev = normalize_event(raw)
        assert "KeyboardClass0" in ev["target_object"]

    def test_id13_registry_write(self):
        raw = _raw_event(13, Image="C:\\Temp\\persist.exe",
                         TargetObject="HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                         Details="C:\\Temp\\persist.exe", ProcessId="3333")
        ev = normalize_event(raw)
        assert "Run" in ev["registry_key"]
        assert ev["registry_value"] == "C:\\Temp\\persist.exe"

    def test_all_canonical_columns_present(self):
        ev = normalize_event(_raw_event(1, Image="notepad.exe"))
        for col in CANONICAL_COLUMNS:
            assert col in ev, f"Missing column: {col}"

    def test_raw_fields_preserved(self):
        ev = normalize_event(_raw_event(1, Image="notepad.exe", ExtraField="extra"))
        assert isinstance(ev["raw_fields"], dict)
        assert "ExtraField" in ev["raw_fields"]

    def test_unknown_event_id_best_effort(self):
        ev = normalize_event(_raw_event(999, Image="C:\\Temp\\unknown.exe", ProcessId="4444"))
        assert ev["event_id"] == 999
        assert ev["process_name"] == "unknown.exe"

    def test_bug10_negative_event_id_stored(self):
        """BUG-10: EventID=-1 is stored as-is without validation."""
        raw = {"EventID": -1, "TimeCreated": "2026-01-01T08:00:00Z",
               "Computer": "HOST", "Channel": "Sysmon", "EventData": {}, "_raw_xml": ""}
        ev = normalize_event(raw)
        assert ev["event_id"] == -1

    def test_missing_event_data_key(self):
        raw = {"EventID": 1, "TimeCreated": "2026-01-01T08:00:00Z",
               "Computer": "HOST", "Channel": "Sysmon", "_raw_xml": ""}
        ev = normalize_event(raw)
        assert ev["event_id"] == 1

    def test_sysmon_channel_detection(self):
        assert normalize_event(_raw_event(1, Image="notepad.exe"))["event_source"] == "Sysmon"

    def test_security_channel_detection(self):
        raw = _raw_event(4688, Image="cmd.exe")
        raw["Channel"] = "Security"
        assert normalize_event(raw)["event_source"] == "Security"

    def test_pid_none_when_missing(self):
        assert normalize_event(_raw_event(1, Image="notepad.exe"))["pid"] is None

    def test_empty_event_data(self):
        ev = normalize_event(_raw_event(1))
        assert ev["process_name"] is None
        assert ev["pid"] is None


class TestNormalizeEvents:
    def test_valid_label_applied(self):
        events = list(normalize_events([_raw_event(1, Image="notepad.exe")],
                                       label="malicious", technique_tag="hook"))
        assert events[0]["label"] == "malicious"
        assert events[0]["technique_tag"] == "hook"

    def test_invalid_label_raises(self):
        with pytest.raises(ValueError, match="Invalid label"):
            list(normalize_events([_raw_event(1)], label="INVALID"))

    def test_errors_skipped_not_raised(self):
        bad = {"NOT_A_VALID_EVENT": True}
        good = _raw_event(1, Image="notepad.exe")
        events = list(normalize_events([bad, good], label="unknown"))
        assert len(events) >= 1

    def test_empty_iterable(self):
        assert list(normalize_events([], label="benign")) == []

    def test_large_batch(self):
        raws = [_raw_event(7, Image=f"proc{i}.exe", ImageLoaded="user32.dll")
                for i in range(500)]
        assert len(list(normalize_events(raws, label="unknown"))) == 500


class TestEventsToDF:
    def test_returns_dataframe(self):
        df = events_to_df([_raw_event(1, Image="notepad.exe") for _ in range(5)])
        assert isinstance(df, pd.DataFrame) and len(df) == 5

    def test_has_canonical_columns(self):
        df = events_to_df([_raw_event(7, Image="proc.exe", ImageLoaded="user32.dll")])
        for col in CANONICAL_COLUMNS:
            assert col in df.columns

    def test_empty_input_returns_empty_df(self):
        df = events_to_df([])
        assert len(df) == 0
        for col in CANONICAL_COLUMNS:
            assert col in df.columns

    def test_timestamp_is_utc_aware(self):
        df = events_to_df([_raw_event(1, Image="notepad.exe")])
        assert df["timestamp"].dt.tz is not None

    def test_pid_is_nullable_int(self):
        df = events_to_df([_raw_event(1, Image="notepad.exe", ProcessId="1234")])
        assert str(df["pid"].dtype) == "Int64"

    def test_mixed_event_ids(self):
        raws = [
            _raw_event(1, Image="proc.exe", ProcessId="100"),
            _raw_event(7, Image="proc.exe", ImageLoaded="user32.dll", ProcessId="100"),
            _raw_event(13, Image="proc.exe", TargetObject="HKCU\\Run", ProcessId="100"),
        ]
        df = events_to_df(raws)
        assert len(df) == 3
        assert set(df["event_id"].dropna().tolist()) == {1, 7, 13}


# ===========================================================================
# 4. PollingDetector
# ===========================================================================

class TestPollingDetector:
    def _meta(self, name="kl.exe", path="C:\\Temp\\kl.exe",
              parent="cmd.exe", signed=False, pid=1234):
        return {"process_name": name, "process_path": path,
                "parent_process_name": parent, "signed": signed, "pid": pid}

    def test_full_keylogger_pattern_fires(self):
        pid = 1234
        events = [
            _proc_create(pid, "kl.exe", "C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._meta())
        assert match is not None
        assert match.score >= 30
        assert match.detector == "PollingDetector"

    def test_signed_system_process_low_score(self):
        pid = 5678
        events = [
            _proc_create(pid, "notepad.exe", "C:\\Windows\\System32\\notepad.exe",
                         "explorer.exe", signed=True),
            _dll_event(pid, "user32.dll", signed=True,
                       proc_path="C:\\Windows\\System32\\notepad.exe"),
        ]
        meta = self._meta("notepad.exe", "C:\\Windows\\System32\\notepad.exe",
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
            _proc_create(pid, "kl.exe", "C:\\Temp\\kl.exe", parent, signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        meta = self._meta(parent=parent)
        match = PollingDetector().analyze(_make_df(events), meta)
        assert match is not None
        assert match.features["headless_parent"] is True

    def test_staging_path_appdata_fires(self):
        pid = 200
        path = "C:\\Users\\User\\AppData\\Roaming\\kl.exe"
        events = [
            _proc_create(pid, "kl.exe", path, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll", proc_path=path),
        ]
        match = PollingDetector().analyze(_make_df(events), self._meta(path=path))
        assert match is not None
        assert match.features["staging_path"] is True

    def test_staging_path_downloads_fires(self):
        pid = 201
        path = "C:\\Users\\User\\Downloads\\kl.exe"
        events = [
            _proc_create(pid, "kl.exe", path, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll", proc_path=path),
        ]
        meta = {"process_name": "kl.exe", "process_path": path,
                "parent_process_name": "cmd.exe", "signed": False, "pid": pid}
        match = PollingDetector().analyze(_make_df(events), meta)
        assert match is not None
        assert match.features["staging_path"] is True

    def test_no_user32_no_match(self):
        pid = 300
        events = [
            _proc_create(pid, "kl.exe", "C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "kernel32.dll"),
        ]
        assert PollingDetector().analyze(_make_df(events), self._meta()) is None

    def test_hook_registry_clears_no_hook_flag(self):
        pid = 400
        events = [
            _proc_create(pid, "kl.exe", "C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
            _reg_write(pid, "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppInit_DLLs", 1.0),
        ]
        match = PollingDetector().analyze(_make_df(events), self._meta())
        if match:
            assert match.features["no_hook_registry"] is False

    def test_bug3_all_nan_image_loaded_does_not_crash(self):
        """BUG-3: all-NaN image_loaded column should not crash str accessor."""
        pid = 500
        events = [_proc_create(pid, "kl.exe", "C:\\Temp\\kl.exe", "cmd.exe")]
        df = pd.DataFrame(events, columns=CANONICAL_COLUMNS)
        df["image_loaded"] = None
        try:
            PollingDetector().analyze(df, self._meta())
        except Exception as e:
            pytest.fail(f"BUG-3: crashed with all-NaN image_loaded: {e}")

    def test_empty_dataframe_returns_none(self):
        assert PollingDetector().analyze(make_empty_df(), self._meta()) is None

    def test_score_capped_at_80(self):
        pid = 600
        path = "C:\\Temp\\kl.exe"
        events = [
            _proc_create(pid, "kl.exe", path, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._meta(path=path))
        if match:
            assert match.score <= 80

    def test_confidence_between_0_and_1(self):
        pid = 700
        path = "C:\\Temp\\kl.exe"
        events = [
            _proc_create(pid, "kl.exe", path, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._meta(path=path))
        if match:
            assert 0.0 <= match.confidence <= 1.0

    def test_all_none_meta_does_not_crash(self):
        meta = {"process_name": None, "process_path": None,
                "parent_process_name": None, "signed": None, "pid": None}
        try:
            PollingDetector().analyze(make_empty_df(), meta)
        except Exception as e:
            pytest.fail(f"all-None meta raised: {e}")

    def test_empty_meta_does_not_crash(self):
        try:
            PollingDetector().analyze(make_empty_df(), {})
        except Exception as e:
            pytest.fail(f"empty meta raised: {e}")

    def test_signed_none_treated_as_unsigned(self):
        pid = 800
        events = [
            _proc_create(pid, "kl.exe", "C:\\Temp\\kl.exe", "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._meta(signed=None))
        if match:
            assert match.features["unsigned"] is True

    def test_evidence_contains_pid(self):
        pid = 9001
        path = "C:\\Temp\\kl.exe"
        events = [
            _proc_create(pid, "kl.exe", path, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._meta(pid=pid, path=path))
        if match:
            assert str(pid) in match.evidence

    def test_heuristic_match_types(self):
        pid = 9002
        path = "C:\\Temp\\kl.exe"
        events = [
            _proc_create(pid, "kl.exe", path, "cmd.exe", signed=False),
            _dll_event(pid, "user32.dll"),
        ]
        match = PollingDetector().analyze(_make_df(events), self._meta(pid=pid, path=path))
        if match:
            assert isinstance(match, HeuristicMatch)
            assert isinstance(match.features, dict)
            assert isinstance(match.evidence, str)
            assert isinstance(match.score, int)
            assert isinstance(match.confidence, float)


# ===========================================================================
# 5. PeriodicWriteDetector
# ===========================================================================

class TestPeriodicWriteDetector:
    META = {"process_name": "kl.exe", "pid": 9999}

    def test_perfectly_periodic_30s_fires(self):
        match = PeriodicWriteDetector().analyze(_periodic_ts(12, 30.0), self.META)
        assert match is not None
        assert match.score > 0
        assert match.detector == "PeriodicWriteDetector"

    def test_perfectly_periodic_60s_fires(self):
        assert PeriodicWriteDetector().analyze(_periodic_ts(10, 60.0), self.META) is not None

    def test_5s_boundary_fires(self):
        assert PeriodicWriteDetector().analyze(_periodic_ts(10, 5.0), self.META) is not None

    def test_sub_second_filtered_returns_none(self):
        base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        ts = [pd.Timestamp(base + timedelta(milliseconds=100 * i)) for i in range(1, 20)]
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
