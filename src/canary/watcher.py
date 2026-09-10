"""
Canary Watcher
==============
Scans a process session's events for the presence of a planted canary's unique
value and, on a hit, emits a match dict that renders exactly like a signature
rule match (``KL-CANARY-001``).

This is a NEW event source, not something Sysmon captures by default.  In
addition to the standard Sysmon fields (``registry_value``, ``target_object``,
``raw_fields``), it understands ``event_source == "ClipboardWatch"`` events
emitted by the lab-only :mod:`src.canary.clipboard_probe`.

A canary hit is near-zero-false-positive by construction: the matched value is
a unique UUID that no legitimate process should ever contain, so seeing it in
telemetry means the bait was accessed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import pandas as pd

from src.canary.planter import CanaryToken, value_matches_token

log = logging.getLogger(__name__)

#: Pseudo-rule identifier so canary hits render consistently with rule matches.
CANARY_RULE_ID = "KL-CANARY-001"
CANARY_RULE_NAME = "Canary credential access (deception)"
#: MITRE ATT&CK mapping.  T1056.001 (Input Capture: Keylogging) is used when the
#: bait is input/credential-shaped; document-only bait could map to T1213.
CANARY_MITRE = "T1056.001"

#: Event fields whose string content is scanned for a canary value.
_SCANNED_FIELDS = (
    "registry_value",
    "target_object",
    "image_loaded",
    "process_path",
)


@dataclass
class CanaryMatch:
    """A confirmed canary access by a process session."""
    token_id: str
    kind: str
    location: str
    pid: Any
    matched_field: str
    timestamp: Any


def _iter_candidate_strings(row: pd.Series) -> tuple[list[str], str]:
    """
    Collect every string field of an event row that could carry a canary.

    Returns the list of candidate strings plus the name of the field the first
    candidate came from (refined by the caller per-match).
    """
    candidates: list[str] = []
    for field_name in _SCANNED_FIELDS:
        v = row.get(field_name)
        if isinstance(v, str) and v:
            candidates.append(v)
    raw = row.get("raw_fields")
    if isinstance(raw, dict):
        for v in raw.values():
            if isinstance(v, str) and v:
                candidates.append(v)
    return candidates, ""


def check_canary_access(
    session_events: pd.DataFrame,
    registry: list[CanaryToken],
) -> list[CanaryMatch]:
    """
    Scan ``session_events`` for any planted canary's unique value.

    Parameters
    ----------
    session_events:
        Canonical DataFrame of events for ONE process session.
    registry:
        Live canary tokens (raw value available) or registry-loaded tokens
        (hash only) — either is accepted by ``value_matches_token``.

    Returns
    -------
    list[CanaryMatch] — one per (token, first matching event).  Empty when no
    canary was touched (the expected case for benign traffic).
    """
    matches: list[CanaryMatch] = []
    if not registry or session_events.empty:
        return matches

    pid = session_events["pid"].dropna().iloc[0] if "pid" in session_events else None

    for _, row in session_events.iterrows():
        candidates, _ = _iter_candidate_strings(row)
        if not candidates:
            continue
        for token in registry:
            for cand in candidates:
                # The unique canary UUID may be a *substring* of a larger blob
                # (e.g. an exfiltrated file body) — but it must be the exact
                # UUID, never a fuzzy/partial match.
                needle = token.value or None
                hit = False
                if needle and needle in cand:
                    hit = True
                elif not needle and any(
                    value_matches_token(part, token) for part in cand.split()
                ):
                    hit = True
                if hit:
                    matched_field = next(
                        (f for f in _SCANNED_FIELDS
                         if isinstance(row.get(f), str) and
                         (needle and needle in row.get(f, ""))),
                        "raw_fields",
                    )
                    matches.append(
                        CanaryMatch(
                            token_id=token.token_id,
                            kind=token.kind,
                            location=token.location,
                            pid=row.get("pid", pid),
                            matched_field=matched_field,
                            timestamp=row.get("timestamp"),
                        )
                    )
                    log.info(
                        "CANARY HIT: token %s (%s) accessed by PID %s",
                        token.token_id, token.kind, row.get("pid", pid),
                    )
                    break  # one match per token per event is enough
    return matches


def canary_matches_to_rule_matches(matches: list[CanaryMatch]) -> list[dict]:
    """
    Convert :class:`CanaryMatch` objects into rule-match dicts compatible with
    :meth:`SessionBuilder.build`'s ``rule_matches`` argument, so canary hits
    flow through the existing scoring/evidence-chain pipeline as
    ``KL-CANARY-001``.
    """
    out: list[dict] = []
    for m in matches:
        out.append(
            {
                "rule_id": CANARY_RULE_ID,
                "rule_name": CANARY_RULE_NAME,
                "pid": m.pid,
                "score": 95,
                "severity": "critical",
                "mitre_technique": CANARY_MITRE,
                "lane": "canary",
                "evidence": (
                    f"Planted canary '{m.token_id}' ({m.kind}) accessed; "
                    f"its unique value appeared in field '{m.matched_field}' "
                    f"of this process's telemetry.  A random process should "
                    f"never contain this UUID, so this is near-certain "
                    f"evidence of bait access (bait location: {m.location})."
                ),
                "timestamp": m.timestamp,
            }
        )
    return out
