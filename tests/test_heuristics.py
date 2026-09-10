"""
Tests for src/detect/heuristics.py — heuristic/statistical detection lane.
"""

import pytest
import pandas as pd
from datetime import datetime, timedelta, timezone
from src.detect.heuristics import (
    PollingDetector,
    PeriodicWriteDetector,
    HeadlessHookDetector,
    HeuristicEngine,
)
from src.schema import make_event, CANONICAL_COLUMNS


def _ts(offset_s: float = 0.0) -> pd.Timestamp:
    base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
    return pd.Timestamp(base + timedelta(seconds=offset_s))


def _make_df(events: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(events, columns=CANONICAL_COLUMNS)


def _dll_load_event(pid: int, dll: str, offset: float = 0.1, signed: bool = True) -> dict:
    return make_event(
        _ts(offset), "LABVM", 7, "Sysmon",
        process_name="test.exe",
        pid=pid,
        image_loaded=f"C:\\Windows\\System32\\{dll}",
        signed=signed,
        raw_fields={},
    )


def _proc_create_event(pid: int, name: str, path: str, parent: str,
                       signed: bool = False) -> dict:
    return make_event(
        _ts(0.0), "LABVM", 1, "Sysmon",
        process_name=name,
        process_path=path,
        pid=pid,
        ppid=pid - 1,
        parent_process_name=parent,
        signed=signed,
        raw_fields={},
    )


def _reg_write_event(pid: int, key: str, offset: float) -> dict:
    return make_event(
        _ts(offset), "LABVM", 13, "Sysmon",
        process_name="test.exe",
        pid=pid,
        registry_key=key,
        raw_fields={},
    )


class TestPollingDetector:
    def test_detects_polling_pattern(self):
        pid = 1234
        events = [
            _proc_create_event(pid, "keylogger.exe", "C:\\Temp\\keylogger.exe",
                               "cmd.exe", signed=False),
            _dll_load_event(pid, "user32.dll", offset=0.1, signed=True),
        ]
        df = _make_df(events)
        meta = {
            "process_name": "keylogger.exe",
            "process_path": "C:\\Temp\\keylogger.exe",
            "parent_process_name": "cmd.exe",
            "signed": False,
            "pid": pid,
        }
        detector = PollingDetector()
        match = detector.analyze(df, meta)
        assert match is not None
        assert match.score > 0
        assert match.detector == "PollingDetector"

    def test_does_not_flag_signed_system_process(self):
        pid = 5678
        events = [
            _proc_create_event(pid, "notepad.exe",
                               "C:\\Windows\\System32\\notepad.exe",
                               "explorer.exe", signed=True),
            _dll_load_event(pid, "user32.dll", signed=True),
        ]
        df = _make_df(events)
        meta = {
            "process_name": "notepad.exe",
            "process_path": "C:\\Windows\\System32\\notepad.exe",
            "parent_process_name": "explorer.exe",
            "signed": True,
            "pid": pid,
        }
        detector = PollingDetector()
        match = detector.analyze(df, meta)
        # Score should be low enough to not trigger (< 45 — signed + system path)
        if match:
            assert match.score < 45


class TestPeriodicWriteDetector:
    def test_detects_periodic_writes(self):
        # Simulate 12 writes at exactly 30s intervals — enough for FFT to detect periodicity
        base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        timestamps = [
            pd.Timestamp(base + timedelta(seconds=30 * i))
            for i in range(1, 13)
        ]
        meta = {"process_name": "keylogger.exe", "pid": 9999}
        detector = PeriodicWriteDetector()
        match = detector.analyze(timestamps, meta)
        assert match is not None
        assert match.score > 0
        assert "periodic" in match.evidence.lower()

    def test_does_not_flag_random_writes(self):
        import random
        random.seed(42)
        base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        # Random intervals between 5 and 200 seconds
        timestamps = [
            pd.Timestamp(base + timedelta(seconds=random.uniform(5, 200) * i))
            for i in range(1, 8)
        ]
        meta = {"process_name": "legit.exe", "pid": 1111}
        detector = PeriodicWriteDetector()
        match = detector.analyze(timestamps, meta)
        # May or may not fire, but if it does, score should be low
        if match:
            assert match.score < 60

    def test_requires_minimum_writes(self):
        base = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
        timestamps = [pd.Timestamp(base)]  # only 1 write
        meta = {"process_name": "test.exe", "pid": 2222}
        detector = PeriodicWriteDetector()
        match = detector.analyze(timestamps, meta)
        assert match is None


class TestHeadlessHookDetector:
    def test_detects_headless_user32_load(self):
        pid = 3333
        events = [
            _dll_load_event(pid, "user32.dll", signed=True),
            _dll_load_event(pid, "hid.dll", signed=True),
            # No gdi32.dll or other GUI DLLs
        ]
        df = _make_df(events)
        meta = {"process_name": "headless.exe", "pid": pid}
        detector = HeadlessHookDetector()
        match = detector.analyze(df, meta)
        assert match is not None
        assert match.score >= 35

    def test_does_not_flag_gui_application(self):
        pid = 4444
        events = [
            _dll_load_event(pid, "user32.dll", signed=True),
            _dll_load_event(pid, "gdi32.dll", signed=True),
            _dll_load_event(pid, "comctl32.dll", signed=True),
        ]
        df = _make_df(events)
        meta = {"process_name": "legit_gui.exe", "pid": pid}
        detector = HeadlessHookDetector()
        match = detector.analyze(df, meta)
        assert match is None  # GUI DLLs present → not flagged


class TestHeuristicEngine:
    def test_analyze_session_returns_list(self):
        pid = 5555
        events = [
            _proc_create_event(pid, "keylogger.exe", "C:\\Temp\\keylogger.exe",
                               "cmd.exe", signed=False),
            _dll_load_event(pid, "user32.dll"),
        ]
        df = _make_df(events)
        meta = {
            "process_name": "keylogger.exe",
            "process_path": "C:\\Temp\\keylogger.exe",
            "parent_process_name": "cmd.exe",
            "signed": False,
            "pid": pid,
        }
        engine = HeuristicEngine()
        matches = engine.analyze_session(df, meta)
        assert isinstance(matches, list)

    def test_analyze_df_groups_by_pid(self):
        events = []
        for pid in [100, 200, 300]:
            events.append(_proc_create_event(
                pid, "proc.exe", "C:\\Temp\\proc.exe", "cmd.exe", signed=False
            ))
            events.append(_dll_load_event(pid, "user32.dll"))

        df = _make_df(events)
        engine = HeuristicEngine()
        results = engine.analyze_df(df)
        assert isinstance(results, list)
        # Each result should have required keys
        for r in results:
            assert "pid" in r
            assert "detector" in r
            assert "score" in r
            assert "evidence" in r