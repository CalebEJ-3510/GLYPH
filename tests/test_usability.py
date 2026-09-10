"""Loader / ingest usability checks (no CLI — the dashboard is the only
entry point, so these exercise the shared library functions it calls)."""

from __future__ import annotations

from src.canary.clipboard_probe import main as clipboard_main
from src.ingest.csv_loader import load_csv_events
from src.ingest.normalize import last_normalize_stats, normalize_events


def _raw(**extra):
    return {
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "HOST1",
        "TimeCreated": "2024-01-01T00:00:00Z",
        "EventData": {"Image": r"C:\Windows\System32\notepad.exe", **extra},
    }


def test_clipboard_probe_requires_lab_flag():
    try:
        clipboard_main([])
    except SystemExit as exc:
        assert exc.code != 0
        return
    raise AssertionError("clipboard probe must abort without the lab flag")


def test_iso_microsecond_timestamps_are_not_skipped(tmp_path):
    """Valid ISO-8601 timestamps with fractional seconds must not count as malformed."""
    csv_path = tmp_path / "events.csv"
    csv_path.write_text(
        "timestamp,host,event_id,event_source,pid\n"
        "2026-01-01 08:00:00+00:00,HOST,1,Sysmon,1\n"
        "2026-01-01 08:00:00.100000+00:00,HOST,1,Sysmon,1\n",
        encoding="utf-8",
    )
    df, stats = load_csv_events(csv_path)
    assert stats["loaded"] == 2
    assert stats["skipped"] == 0
    assert len(df) == 2


def test_malformed_timestamp_is_counted_as_skipped(tmp_path):
    """A row with an unparseable timestamp should be dropped and counted."""
    csv_path = tmp_path / "events.csv"
    csv_path.write_text(
        "timestamp,host,event_id,event_source,pid\n"
        "2026-01-01 08:00:00+00:00,HOST,1,Sysmon,1\n"
        "not-a-timestamp,HOST,1,Sysmon,1\n",
        encoding="utf-8",
    )
    df, stats = load_csv_events(csv_path)
    assert stats["loaded"] == 1
    assert stats["skipped"] == 1
    assert len(df) == 1


def test_normalize_stats_exposed():
    list(normalize_events([_raw()], label="unknown"))
    stats = last_normalize_stats()
    assert stats["count"] >= 1
    assert "errors" in stats
