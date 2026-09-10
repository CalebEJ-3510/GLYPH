"""Tests for LLM-narrated summaries (Part 3.2)."""

from __future__ import annotations

from src.correlate.session_builder import Incident, ProcessSession
from src.report.narrative import _build_prompt, generate_narrative


def _incident() -> Incident:
    session = ProcessSession(
        pid=4242,
        process_name="kl.exe",
        process_path=r"C:\Temp\kl.exe",
        parent_process_name="explorer.exe",
        signed=False,
        host="HOST1",
        start_time=None,
        end_time=None,
        event_count=2,
        label="malicious",
        technique_tag="hook",
        timeline=[
            {
                "event_id": 1,
                "event_source": "Sysmon",
                "raw_fields": {"captured_input": "MUST-NOT-APPEAR"},
            }
        ],
    )
    return Incident(
        incident_id="INC-TEST-1",
        pid=4242,
        process_name="kl.exe",
        process_path=r"C:\Temp\kl.exe",
        host="HOST1",
        start_time=None,
        end_time=None,
        composite_score=82.0,
        severity="CRITICAL",
        label="malicious",
        technique_tag="hook",
        rule_ids=["KL-001"],
        mitre_techniques=["T1056.001"],
        evidence_chain="SetWindowsHookEx observed",
        raw_session=session,
    )


class TestNarrativeFallback:
    def test_no_api_key_returns_template(self, tmp_path, monkeypatch):
        for key in (
            "KDS_LLM_API_KEY",
            "ANTHROPIC_API_KEY",
            "KDS_OPENAI_API_KEY",
            "OPENAI_API_KEY",
        ):
            monkeypatch.delenv(key, raising=False)
        inc = _incident()
        text = generate_narrative(inc, cache_path=tmp_path / "cache.json")
        assert "kl.exe" in text
        assert "CRITICAL" in text
        assert "KL-001" in text
        assert "T1056.001" in text
        assert "Isolate" in text

    def test_prompt_excludes_raw_fields(self):
        prompt = _build_prompt(_incident())
        assert "MUST-NOT-APPEAR" not in prompt
        assert "KL-001" in prompt
        assert "T1056.001" in prompt
        assert "Sysmon:1" in prompt

    def test_cache_avoids_second_call(self, tmp_path, monkeypatch):
        for key in (
            "KDS_LLM_API_KEY",
            "ANTHROPIC_API_KEY",
            "KDS_OPENAI_API_KEY",
            "OPENAI_API_KEY",
        ):
            monkeypatch.delenv(key, raising=False)
        inc = _incident()
        cache = tmp_path / "cache.json"
        first = generate_narrative(inc, cache_path=cache)
        second = generate_narrative(inc, cache_path=cache)
        assert first == second
        assert cache.exists()
