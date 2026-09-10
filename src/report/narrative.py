"""
LLM-Narrated Incident Summaries
===============================
Turns a structured :class:`~src.correlate.session_builder.Incident` into a
short, plain-English analyst summary.

Design & privacy contract
--------------------------
* **Opt-in only.**  Narrative generation is triggered by the ``--narrate`` CLI
  flag and is OFF by default.  No network call happens unless enabled.
* **Structured data only.**  The prompt sent to the LLM contains ONLY the
  incident's structured fields (rule IDs, scores, MITRE techniques, timeline
  event types, evidence strings).  It NEVER contains raw file contents or any
  captured user input.  ``_build_prompt`` deliberately constructs its payload
  from a fixed whitelist of fields.
* **Graceful degradation.**  If no API key is configured, the provider is
  unreachable, or the call exceeds the timeout, a deterministic template-based
  summary is returned instead — no crash, no block.
* **Caching.**  Narratives are cached in ``output/.narrative_cache.json`` keyed
  by ``incident_id`` + a hash of the evidence chain, so re-running on unchanged
  data never re-calls the API.

Providers
---------
Primary: Anthropic (``https://api.anthropic.com/v1/messages``, model
``claude-sonnet-4-6``).  Fallback: OpenAI-compatible chat-completions endpoint
when ``KDS_OPENAI_API_KEY`` is set.  Both read keys from environment variables;
neither is required for the template fallback.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import urllib.request
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-4-6"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OPENAI_MODEL = "gpt-4o-mini"

#: Hard network timeout (seconds) — a slow LLM must never block a report.
TIMEOUT_SECONDS = 10

DEFAULT_CACHE_PATH = Path("output/.narrative_cache.json")

_SYSTEM_PROMPT = (
    "You are a senior DFIR analyst writing a concise incident summary for a "
    "security operations team.  Given ONLY the structured detection data "
    "provided, write 3-5 plain-English sentences covering: what happened, why "
    "it is suspicious, the most likely MITRE ATT&CK technique, and a concrete "
    "recommended next action (e.g. isolate the host, inspect the process tree, "
    "acquire memory).  Do not invent facts not present in the data.  Do not "
    "repeat raw field dumps; synthesize them."
)


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_key(incident: Any) -> str:
    """Stable cache key: incident_id + content hash of the evidence chain."""
    content = f"{incident.incident_id}|{incident.evidence_chain}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _load_cache(path: Path) -> dict[str, str]:
    if path.exists():
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(path: Path, cache: dict[str, str]) -> None:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError as exc:
        log.warning("Could not write narrative cache: %s", exc)


# ---------------------------------------------------------------------------
# Prompt construction — structured fields ONLY
# ---------------------------------------------------------------------------

def _build_prompt(incident: Any) -> str:
    """
    Build the LLM prompt from a fixed whitelist of structured incident fields.

    Only detection metadata is included.  Raw file contents, captured input,
    and arbitrary ``raw_fields`` are deliberately excluded so nothing sensitive
    is ever sent to a third-party API.
    """
    timeline = getattr(incident, "raw_session", None)
    event_types: list[str] = []
    if timeline is not None:
        for ev in (timeline.timeline or [])[:50]:
            if isinstance(ev, dict):
                eid = ev.get("event_id", ev.get("event_source", "?"))
                src = ev.get("event_source", "")
                event_types.append(f"{src}:{eid}" if src else str(eid))
            else:
                event_types.append(type(ev).__name__)
    timeline_types = sorted(set(event_types)) or ["(no timeline events)"]
    return (
        "Structured incident data (no raw user content):\n"
        f"- Incident ID: {incident.incident_id}\n"
        f"- Process: {incident.process_name} (PID {incident.pid})\n"
        f"- Path: {incident.process_path}\n"
        f"- Host: {incident.host}\n"
        f"- Composite score: {incident.composite_score} (severity {incident.severity})\n"
        f"- Rule IDs fired: {', '.join(incident.rule_ids) or 'none'}\n"
        f"- MITRE techniques: {', '.join(incident.mitre_techniques) or 'none'}\n"
        f"- Technique tag: {incident.technique_tag or 'unknown'}\n"
        f"- Detection evidence (pre-digested, no raw input):\n"
        f"{incident.evidence_chain}\n"
        f"- Timeline event types: {', '.join(timeline_types)}\n\n"
        "Write the 3-5 sentence analyst summary now."
    )


# ---------------------------------------------------------------------------
# Provider calls (both optional; failure -> caller falls back to template)
# ---------------------------------------------------------------------------

def _call_anthropic(prompt: str, api_key: str) -> str:
    body = json.dumps({
        "model": ANTHROPIC_MODEL,
        "max_tokens": 300,
        "system": _SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        ANTHROPIC_URL,
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return "".join(
        block.get("text", "") for block in data.get("content", [])
    ).strip()


def _call_openai(prompt: str, api_key: str) -> str:
    body = json.dumps({
        "model": OPENAI_MODEL,
        "max_tokens": 300,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    }).encode("utf-8")
    req = urllib.request.Request(
        OPENAI_URL,
        data=body,
        headers={
            "content-type": "application/json",
            "authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"].strip()


# ---------------------------------------------------------------------------
# Template fallback (no network, no dependency)
# ---------------------------------------------------------------------------

def _template_summary(incident: Any) -> str:
    """Deterministic summary built from the evidence chain fields."""
    sev = incident.severity
    proc = incident.process_name or "an unknown process"
    techniques = ", ".join(incident.mitre_techniques) or "no mapped MITRE technique"
    rules = ", ".join(incident.rule_ids) or "no signature rules"
    action = {
        "CRITICAL": "Isolate the host immediately and acquire a memory image.",
        "HIGH":     "Isolate the host and inspect the full process tree.",
        "MEDIUM":   "Triage promptly; pull the process tree and parent lineage.",
        "LOW":      "Review at next triage pass; correlate with related alerts.",
    }.get(sev, "Log and monitor.")

    return (
        f"{proc} (PID {incident.pid}) on host {incident.host} triggered a "
        f"{sev} detection with a composite score of {incident.composite_score}. "
        f"It matched {rules}, consistent with {techniques}. "
        f"The observed behavior is characteristic of keylogging activity "
        f"({incident.technique_tag or 'unknown technique'}). "
        f"Recommended next step: {action}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_narrative(
    incident: Any,
    *,
    cache_path: Path = DEFAULT_CACHE_PATH,
    use_cache: bool = True,
) -> str:
    """
    Return a plain-English summary for ``incident``.

    Resolution order:
      1. cache hit (if ``use_cache``),
      2. Anthropic API (if ``KDS_LLM_API_KEY``/``ANTHROPIC_API_KEY`` set),
      3. OpenAI API   (if ``KDS_OPENAI_API_KEY``/``OPENAI_API_KEY`` set),
      4. deterministic template fallback.

    Never raises for lack of a key or a network failure — always returns text.
    """
    cache_path = Path(cache_path)
    cache = _load_cache(cache_path) if use_cache else {}
    key = _cache_key(incident)
    if use_cache and key in cache:
        log.debug("Narrative cache hit for %s", incident.incident_id)
        return cache[key]

    prompt = _build_prompt(incident)

    narrative: str | None = None

    # Primary: Anthropic
    anthropic_key = os.environ.get("KDS_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        try:
            narrative = _call_anthropic(prompt, anthropic_key)
        except Exception as exc:
            log.warning("Anthropic narrative call failed (%s); trying fallback.", exc)

    # Fallback: OpenAI
    if not narrative:
        openai_key = os.environ.get("KDS_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if openai_key:
            try:
                narrative = _call_openai(prompt, openai_key)
            except Exception as exc:
                log.warning("OpenAI narrative call failed (%s).", exc)

    # Final fallback: template (no network, no dependency)
    if not narrative:
        log.info("No LLM available for %s; using template summary.", incident.incident_id)
        narrative = _template_summary(incident)

    if use_cache:
        cache[key] = narrative
        _save_cache(cache_path, cache)

    return narrative
