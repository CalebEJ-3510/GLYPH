"""
Regression tests for Part 1 bug fixes (items 1.2 and 1.3).

1.2 — PeriodicWriteDetector must not mislabel registry writes as "disk writes".
      These tests assert the detector's evidence string and its declared input
      event_ids agree with each other (the original defect claimed "disk writes"
      while consuming EID 13 registry events).

1.3 — SessionBuilder must split a recycled PID into separate sessions on each
      new Process Create (EID 1) event, instead of merging unrelated lifetimes
      into one incident.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from src.correlate.session_builder import SessionBuilder
from src.detect.heuristics import (
    HeuristicEngine,
    PeriodicWriteDetector,
)
from src.schema import CANONICAL_COLUMNS, make_empty_df, make_event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _df_from_events(events: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(events)
    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[CANONICAL_COLUMNS]
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


# ---------------------------------------------------------------------------
# 1.2 — PeriodicWriteDetector honesty tests
# ---------------------------------------------------------------------------

class TestPeriodicWriteDetectorHonesty:
    """Guard against regression of the docstring-vs-implementation mismatch."""

    def _regular_registry_timestamps(self, n: int = 8, period_s: float = 30.0):
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        return [
            pd.Timestamp(base + timedelta(seconds=i * period_s)) for i in range(n)
        ]

    def test_registry_source_evidence_never_says_disk(self):
        """Registry-fed alerts must describe registry writes, not disk writes."""
        det = PeriodicWriteDetector()
        meta = {"process_name": "kl.exe", "pid": 4242}
        match = det.analyze(
            self._regular_registry_timestamps(), meta, source="registry_write"
        )
        assert match is not None, "regularly-spaced writes should be detected"
        evidence = match.evidence.lower()
        assert "registry" in evidence
        assert "disk" not in evidence
        assert "file-create" not in evidence

    def test_file_create_source_evidence_says_file_create(self):
        det = PeriodicWriteDetector()
        meta = {"process_name": "kl.exe", "pid": 4242}
        match = det.analyze(
            self._regular_registry_timestamps(), meta, source="file_create"
        )
        assert match is not None
        assert "file-create" in match.evidence.lower()

    def test_docstring_declares_real_input_event_ids(self):
        """
        Mismatch-catching test: the docstring must accurately name the Sysmon
        event IDs the detector consumes (11 FileCreate / 13 RegistryValueSet)
        and must NOT claim to measure a generic disk-write event that Sysmon
        does not emit.
        """
        doc = PeriodicWriteDetector.__doc__ or ""
        # Must mention both real event IDs it consumes
        assert "11" in doc and "13" in doc
        assert "FileCreate" in doc
        assert "RegistryValueSet" in doc
        # Must explicitly acknowledge there is no generic file-write event
        assert re.search(r"no generic .file write. event", doc, re.IGNORECASE)

    def test_analyze_df_marks_write_source_provenance(self):
        """analyze_df must propagate which event feed produced each alert."""
        engine = HeuristicEngine()
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        events = [
            make_event(
                pd.Timestamp(base),
                "HOST1",
                1,
                "Sysmon",
                process_name="kl.exe",
                process_path=r"C:\Temp\kl.exe",
                pid=4242,
                signed=False,
                label="malicious",
            )
        ]
        # 8 registry writes (EID 13) at perfectly regular 30 s intervals
        for i in range(8):
            events.append(
                make_event(
                    pd.Timestamp(base + timedelta(seconds=(i + 1) * 30)),
                    "HOST1",
                    13,
                    "Sysmon",
                    process_name="kl.exe",
                    pid=4242,
                    registry_key=r"HKCU\Software\kl",
                    registry_value="data",
                    label="malicious",
                )
            )
        df = _df_from_events(events)
        results = engine.analyze_df(df)
        periodic = [r for r in results if r.get("detector") == "PeriodicWriteDetector"]
        assert periodic, "expected a periodic-write match from regular registry writes"
        for r in periodic:
            # provenance recorded in features and evidence must agree
            src = (r.get("features") or {}).get("write_source")
            assert src == "registry_write"
            assert "registry" in r["evidence"].lower()
            assert "disk" not in r["evidence"].lower()


# ---------------------------------------------------------------------------
# 1.3 — PID-reuse session splitting tests
# ---------------------------------------------------------------------------

class TestSessionBuilderPidReuse:
    def _make_reused_pid_df(self) -> pd.DataFrame:
        """
        Two unrelated processes share PID 4242 at different times.
        Each lifetime begins with its own Process Create (EID 1) event.
        Lifetime A gets a rule-match-worthy event early; lifetime B later.
        """
        base = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            # Lifetime A: notepad-ish, starts at t=0
            make_event(
                pd.Timestamp(base),
                "HOST1",
                1,
                "Sysmon",
                process_name="alpha.exe",
                process_path=r"C:\Temp\alpha.exe",
                pid=4242,
                label="malicious",
                technique_tag="hook",
            ),
            make_event(
                pd.Timestamp(base + timedelta(seconds=5)),
                "HOST1",
                7,
                "Sysmon",
                process_name="alpha.exe",
                pid=4242,
                image_loaded=r"C:\Windows\System32\user32.dll",
                label="malicious",
                technique_tag="hook",
            ),
            # Lifetime B: different process, reuses PID 4242 one hour later
            make_event(
                pd.Timestamp(base + timedelta(hours=1)),
                "HOST1",
                1,
                "Sysmon",
                process_name="beta.exe",
                process_path=r"C:\Temp\beta.exe",
                pid=4242,
                label="malicious",
                technique_tag="poll",
            ),
            make_event(
                pd.Timestamp(base + timedelta(hours=1, seconds=5)),
                "HOST1",
                7,
                "Sysmon",
                process_name="beta.exe",
                pid=4242,
                image_loaded=r"C:\Windows\System32\hid.dll",
                label="malicious",
                technique_tag="poll",
            ),
        ]
        return _df_from_events(events)

    def test_recycled_pid_produces_two_sessions(self):
        """Two process lifetimes sharing a PID must not be merged."""
        df = self._make_reused_pid_df()
        sessions = list(
            SessionBuilder._iter_sessions(4242, df[df["pid"] == 4242])
        )
        assert len(sessions) == 2, "recycled PID must split into two sessions"
        names = {s[1]["process_name"].iloc[0] for s in sessions}
        assert names == {"alpha.exe", "beta.exe"}

    def test_recycled_pid_produces_two_incidents(self):
        """End-to-end: each lifetime must yield its own incident, not one merged one."""
        df = self._make_reused_pid_df()
        base = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        # One fake rule match per lifetime (keyed by pid + timestamp window)
        rule_matches = [
            {
                "rule_id": "KL-TEST-001",
                "rule_name": "Test Rule A",
                "pid": 4242,
                "score": 90,
                "severity": "high",
                "mitre_technique": "T1056.001",
                "evidence": "lifetime A match",
                "timestamp": pd.Timestamp(base + timedelta(seconds=5)),
            },
            {
                "rule_id": "KL-TEST-002",
                "rule_name": "Test Rule B",
                "pid": 4242,
                "score": 90,
                "severity": "high",
                "mitre_technique": "T1056.001",
                "evidence": "lifetime B match",
                "timestamp": pd.Timestamp(base + timedelta(hours=1, seconds=5)),
            },
        ]

        builder = SessionBuilder()
        incidents = builder.build(df, rule_matches=rule_matches, min_score=0)

        assert len(incidents) == 2, (
            f"expected 2 incidents for recycled PID, got {len(incidents)}: "
            f"{[(i.process_name, i.rule_ids) for i in incidents]}"
        )
        proc_names = {i.process_name for i in incidents}
        assert proc_names == {"alpha.exe", "beta.exe"}
        # Each incident must carry exactly its own lifetime's rule match
        for inc in incidents:
            assert len(inc.rule_ids) == 1
            if inc.process_name == "alpha.exe":
                assert inc.rule_ids == ["KL-TEST-001"]
            else:
                assert inc.rule_ids == ["KL-TEST-002"]

    def test_no_process_create_warns_and_single_session(self, caplog):
        """Truncated log (no EID 1) → single session + a logged warning."""
        base = datetime(2024, 1, 1, tzinfo=timezone.utc)
        events = [
            make_event(
                pd.Timestamp(base + timedelta(seconds=i)),
                "HOST1",
                7,
                "Sysmon",
                process_name="orphan.exe",
                pid=9999,
                image_loaded=r"C:\Windows\System32\kernel32.dll",
            )
            for i in range(3)
        ]
        df = _df_from_events(events)
        with caplog.at_level(logging.WARNING):
            sessions = list(
                SessionBuilder._iter_sessions(9999, df[df["pid"] == 9999])
            )
        assert len(sessions) == 1
        assert any(
            "no Process Create" in rec.message or "PID" in rec.message
            for rec in caplog.records
            if rec.levelno == logging.WARNING
        ), "expected a warning about the missing Process Create event"
