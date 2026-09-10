"""
Tests for src/schema.py — canonical event schema validation.
"""

import pytest
import pandas as pd
from src.schema import (
    make_empty_df,
    make_event,
    validate_df,
    SchemaValidationError,
    CANONICAL_COLUMNS,
    VALID_LABELS,
)


class TestMakeEmptyDf:
    def test_has_all_columns(self):
        df = make_empty_df()
        assert set(df.columns) == set(CANONICAL_COLUMNS)

    def test_is_empty(self):
        df = make_empty_df()
        assert len(df) == 0


class TestMakeEvent:
    def test_required_fields(self):
        ts = pd.Timestamp("2026-01-01T00:00:00", tz="UTC")
        event = make_event(ts, "LABVM", 1, "Sysmon")
        assert event["timestamp"] == ts
        assert event["host"] == "LABVM"
        assert event["event_id"] == 1
        assert event["event_source"] == "Sysmon"

    def test_raw_fields_defaults_to_empty_dict(self):
        ts = pd.Timestamp("2026-01-01T00:00:00", tz="UTC")
        event = make_event(ts, "LABVM", 1, "Sysmon")
        assert event["raw_fields"] == {}

    def test_label_defaults_to_unknown(self):
        ts = pd.Timestamp("2026-01-01T00:00:00", tz="UTC")
        event = make_event(ts, "LABVM", 1, "Sysmon")
        assert event["label"] == "unknown"

    def test_invalid_label_raises(self):
        ts = pd.Timestamp("2026-01-01T00:00:00", tz="UTC")
        with pytest.raises(ValueError, match="Invalid label"):
            make_event(ts, "LABVM", 1, "Sysmon", label="bad_label")

    def test_process_hash_lowercased(self):
        ts = pd.Timestamp("2026-01-01T00:00:00", tz="UTC")
        event = make_event(ts, "LABVM", 1, "Sysmon",
                           process_hash="ABCDEF1234567890" * 4)
        assert event["process_hash"] == event["process_hash"].lower()

    def test_all_canonical_keys_present(self):
        ts = pd.Timestamp("2026-01-01T00:00:00", tz="UTC")
        event = make_event(ts, "LABVM", 1, "Sysmon")
        assert set(event.keys()) == set(CANONICAL_COLUMNS)


class TestValidateDf:
    def _make_valid_df(self) -> pd.DataFrame:
        ts = pd.Timestamp("2026-01-01T00:00:00", tz="UTC")
        events = [
            make_event(ts, "LABVM", 1, "Sysmon",
                       process_name="notepad.exe", pid=1234),
            make_event(ts, "LABVM", 7, "Sysmon",
                       process_name="notepad.exe", pid=1234,
                       image_loaded="C:\\Windows\\System32\\user32.dll"),
        ]
        return pd.DataFrame(events, columns=CANONICAL_COLUMNS)

    def test_valid_df_returns_no_violations(self):
        df = self._make_valid_df()
        violations = validate_df(df)
        assert violations == []

    def test_missing_column_detected(self):
        df = self._make_valid_df()
        df = df.drop(columns=["timestamp"])
        violations = validate_df(df)
        assert any("timestamp" in v for v in violations)

    def test_null_host_detected(self):
        df = self._make_valid_df()
        df.loc[0, "host"] = None
        violations = validate_df(df)
        assert any("host" in v for v in violations)

    def test_non_dict_raw_fields_detected(self):
        df = self._make_valid_df()
        df.loc[0, "raw_fields"] = None
        violations = validate_df(df)
        assert any("raw_fields" in v for v in violations)

    def test_invalid_label_detected(self):
        df = self._make_valid_df()
        df.loc[0, "label"] = "suspicious"
        violations = validate_df(df)
        assert any("label" in v for v in violations)

    def test_uppercase_hash_detected(self):
        df = self._make_valid_df()
        df.loc[0, "process_hash"] = "ABCDEF" * 10 + "12345678"
        violations = validate_df(df)
        assert any("process_hash" in v for v in violations)

    def test_strict_mode_raises(self):
        df = self._make_valid_df()
        df.loc[0, "host"] = None
        with pytest.raises(SchemaValidationError):
            validate_df(df, strict=True)