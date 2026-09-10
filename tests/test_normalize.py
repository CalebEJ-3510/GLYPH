"""
Tests for src/ingest/normalize.py — event normalization layer.
"""

import pytest
import pandas as pd
from src.ingest.normalize import normalize_event, normalize_events, events_to_df
from src.schema import CANONICAL_COLUMNS


def _raw_event(event_id: int, **kwargs) -> dict:
    """Build a minimal raw event dict as evtx_loader would produce."""
    return {
        "EventID": event_id,
        "TimeCreated": "2026-01-01T08:00:00.000000Z",
        "Computer": "LABVM",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Provider": "Microsoft-Windows-Sysmon",
        "EventData": kwargs,
        "_raw_xml": "",
    }


class TestNormalizeEvent:
    def test_id1_process_create(self):
        raw = _raw_event(
            1,
            Image="C:\\Windows\\System32\\notepad.exe",
            Hashes="MD5=abc,SHA256=deadbeef" + "0" * 56,
            ProcessId="1234",
            ParentProcessId="5678",
            ParentImage="C:\\Windows\\explorer.exe",
            Signed="true",
            Signature="Microsoft Windows",
        )
        event = normalize_event(raw)
        assert event["event_id"] == 1
        assert event["process_name"] == "notepad.exe"
        assert event["process_path"] == "C:\\Windows\\System32\\notepad.exe"
        assert event["pid"] == 1234
        assert event["ppid"] == 5678
        assert event["parent_process_name"] == "explorer.exe"
        assert event["signed"] is True
        assert event["signature"] == "Microsoft Windows"
        assert event["event_source"] == "Sysmon"

    def test_id7_image_load(self):
        raw = _raw_event(
            7,
            Image="C:\\Temp\\keylogger.exe",
            ImageLoaded="C:\\Windows\\System32\\user32.dll",
            ProcessId="9999",
            Signed="false",
        )
        event = normalize_event(raw)
        assert event["event_id"] == 7
        assert event["process_name"] == "keylogger.exe"
        assert event["image_loaded"] == "C:\\Windows\\System32\\user32.dll"
        assert event["pid"] == 9999
        assert event["signed"] is False

    def test_id8_remote_thread(self):
        raw = _raw_event(
            8,
            Image="C:\\Temp\\injector.exe",
            TargetImage="C:\\Program Files\\Google\\Chrome\\chrome.exe",
            ProcessId="1111",
        )
        event = normalize_event(raw)
        assert event["event_id"] == 8
        assert event["target_object"] == "C:\\Program Files\\Google\\Chrome\\chrome.exe"

    def test_id13_registry_write(self):
        raw = _raw_event(
            13,
            Image="C:\\Temp\\persist.exe",
            TargetObject="HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            Details="C:\\Temp\\persist.exe",
            ProcessId="2222",
        )
        event = normalize_event(raw)
        assert event["event_id"] == 13
        assert "Run" in event["registry_key"]
        assert event["registry_value"] == "C:\\Temp\\persist.exe"

    def test_raw_fields_preserved(self):
        raw = _raw_event(1, Image="notepad.exe", ExtraField="extra_value")
        event = normalize_event(raw)
        assert isinstance(event["raw_fields"], dict)
        assert "ExtraField" in event["raw_fields"]

    def test_label_applied(self):
        raw = _raw_event(1, Image="notepad.exe")
        events = list(normalize_events([raw], label="malicious", technique_tag="hook"))
        assert events[0]["label"] == "malicious"
        assert events[0]["technique_tag"] == "hook"

    def test_all_canonical_columns_present(self):
        raw = _raw_event(1, Image="notepad.exe")
        event = normalize_event(raw)
        for col in CANONICAL_COLUMNS:
            assert col in event, f"Missing column: {col}"


class TestEventsToDF:
    def test_returns_dataframe(self):
        raws = [_raw_event(1, Image="notepad.exe") for _ in range(5)]
        df = events_to_df(raws)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 5

    def test_has_canonical_columns(self):
        raws = [_raw_event(7, Image="proc.exe", ImageLoaded="user32.dll")]
        df = events_to_df(raws)
        for col in CANONICAL_COLUMNS:
            assert col in df.columns

    def test_empty_input_returns_empty_df(self):
        df = events_to_df([])
        assert len(df) == 0
        for col in CANONICAL_COLUMNS:
            assert col in df.columns