"""
Session Builder & Correlation Engine (Phase 6)
================================================
Groups all events by ``(pid, process_start_time)`` into "process session"
objects, then computes a composite risk score across four detection lanes.

Composite Scoring
-----------------
Score = weighted sum with diminishing returns:
  - Canary lane     : weight 0.70 (highest — planted-bait hit is near-ground-truth)
  - Signature lane  : weight 0.50
  - Heuristic lane  : weight 0.35
  - ML lane         : weight 0.15 (lowest — most uncertain)

Diminishing returns: each additional hit from the same lane contributes
half the weight of the previous one, preventing a single noisy rule from
dominating the score.

Severity Thresholds
-------------------
  - CRITICAL : composite score >= 80
  - HIGH      : composite score >= 60
  - MEDIUM    : composite score >= 35
  - LOW       : composite score >= 10
  - INFO      : composite score < 10

Usage
-----
    from src.correlate.session_builder import SessionBuilder

    builder = SessionBuilder()
    incidents = builder.build(
        df,
        rule_matches=rule_results,
        heuristic_matches=heuristic_results,
        ml_matches=ml_results,
    )
    for inc in incidents:
        print(inc.severity, inc.composite_score, inc.process_name)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import pandas as pd

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------

SEVERITY_THRESHOLDS = {
    "CRITICAL": 80,
    "HIGH":     60,
    "MEDIUM":   35,
    "LOW":      10,
}

# Lane weights
LANE_WEIGHTS = {
    "canary":     0.70,   # highest — a canary hit is near-ground-truth
    "signature":  0.50,
    "heuristic":  0.35,
    "ml":         0.15,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProcessSession:
    """All events and detection results for a single process lifetime."""
    pid: Any
    process_name: str | None
    process_path: str | None
    parent_process_name: str | None
    signed: bool | None
    host: str | None
    start_time: pd.Timestamp | None
    end_time: pd.Timestamp | None
    event_count: int
    label: str
    technique_tag: str

    # Per-lane matches
    rule_matches: list[dict] = field(default_factory=list)
    heuristic_matches: list[dict] = field(default_factory=list)
    ml_matches: list[dict] = field(default_factory=list)
    canary_matches: list[dict] = field(default_factory=list)

    # Computed
    composite_score: float = 0.0
    severity: str = "INFO"
    timeline: list[dict] = field(default_factory=list)


@dataclass
class Incident:
    """A correlated, scored detection incident."""
    incident_id: str
    pid: Any
    process_name: str | None
    process_path: str | None
    host: str | None
    start_time: pd.Timestamp | None
    end_time: pd.Timestamp | None
    composite_score: float
    severity: str
    label: str
    technique_tag: str
    rule_ids: list[str]
    mitre_techniques: list[str]
    evidence_chain: str          # human-readable timeline
    raw_session: ProcessSession
    narrative: str | None = None  # optional LLM/template analyst summary


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _diminishing_sum(scores: list[float], weight: float) -> float:
    """
    Sum scores with diminishing returns: each successive score contributes
    half the weight of the previous one.

    Example: scores=[90, 60, 30], weight=0.5
      → 0.5*90 + 0.25*60 + 0.125*30 = 45 + 15 + 3.75 = 63.75
    """
    total = 0.0
    w = weight
    for s in sorted(scores, reverse=True):
        total += w * s
        w *= 0.5
    return total


def _score_to_severity(score: float) -> str:
    for sev, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return sev
    return "INFO"


# ---------------------------------------------------------------------------
# Session Builder
# ---------------------------------------------------------------------------

class SessionBuilder:
    """
    Builds :class:`ProcessSession` objects from a canonical DataFrame and
    per-lane match lists, then computes composite risk scores.
    """

    def build(
        self,
        df: pd.DataFrame,
        rule_matches: list[dict] | None = None,
        heuristic_matches: list[dict] | None = None,
        ml_matches: list[dict] | None = None,
        canary_matches: list[dict] | None = None,
        min_score: float = 5.0,
    ) -> list[Incident]:
        """
        Build and score all process sessions.

        Parameters
        ----------
        df:
            Canonical events DataFrame.
        rule_matches:
            Output of :meth:`~src.detect.rule_engine.RuleEngine.evaluate_df`.
        heuristic_matches:
            Output of :meth:`~src.detect.heuristics.HeuristicEngine.analyze_df`.
        ml_matches:
            Output of :meth:`~src.detect.ml_lane.MLLane.predict_df`.
        min_score:
            Minimum composite score to include in output.

        Returns
        -------
        list[Incident]
            Sorted by composite_score descending.
        """
        rule_matches      = rule_matches or []
        heuristic_matches = heuristic_matches or []
        ml_matches        = ml_matches or []
        canary_matches    = canary_matches or []

        # Index matches by PID
        rule_by_pid:      dict[Any, list[dict]] = {}
        heuristic_by_pid: dict[Any, list[dict]] = {}
        ml_by_pid:        dict[Any, list[dict]] = {}
        canary_by_pid:    dict[Any, list[dict]] = {}

        for m in rule_matches:
            rule_by_pid.setdefault(m.get("pid"), []).append(m)
        for m in heuristic_matches:
            heuristic_by_pid.setdefault(m.get("pid"), []).append(m)
        for m in ml_matches:
            ml_by_pid.setdefault(m.get("pid"), []).append(m)
        for m in canary_matches:
            canary_by_pid.setdefault(m.get("pid"), []).append(m)

        incidents: list[Incident] = []
        incident_counter = 0

        for pid, pid_group in df.groupby("pid", dropna=True):
            # A PID is not a unique session identifier — Windows recycles PIDs
            # constantly.  Split the PID's events into one session per process
            # lifetime, keyed on (pid, process_start_time) as documented.
            for session_key, group in self._iter_sessions(pid, pid_group):
                session = self._build_session(pid, group)

                # Per-lane matches are keyed by PID only (lanes do not know
                # about session boundaries).  Restrict them to events that
                # actually fall inside this session's time window so a recycled
                # PID does not inherit matches from an unrelated lifetime.
                session.rule_matches      = self._matches_in_window(
                    rule_by_pid.get(pid, []), session)
                session.heuristic_matches = self._matches_in_window(
                    heuristic_by_pid.get(pid, []), session)
                session.ml_matches        = self._matches_in_window(
                    ml_by_pid.get(pid, []), session)
                session.canary_matches    = self._matches_in_window(
                    canary_by_pid.get(pid, []), session)

                # Skip sessions with no matches at all
                if not (session.rule_matches or session.heuristic_matches
                        or session.ml_matches or session.canary_matches):
                    continue

                # Compute composite score
                session.composite_score = self._compute_score(session)
                session.severity = _score_to_severity(session.composite_score)

                if session.composite_score < min_score:
                    continue

                # Build evidence chain
                chain = self._build_evidence_chain(session, group)

                incident_counter += 1
                incident = Incident(
                    incident_id=f"INC-{incident_counter:04d}",
                    pid=pid,
                    process_name=session.process_name,
                    process_path=session.process_path,
                    host=session.host,
                    start_time=session.start_time,
                    end_time=session.end_time,
                    composite_score=session.composite_score,
                    severity=session.severity,
                    label=session.label,
                    technique_tag=session.technique_tag,
                    rule_ids=(
                        [m["rule_id"] for m in session.rule_matches]
                        + [m.get("rule_id", "KL-CANARY-001") for m in session.canary_matches]
                    ),
                    mitre_techniques=list({
                        m.get("mitre_technique", "")
                        for m in (session.rule_matches + session.canary_matches)
                        if m.get("mitre_technique")
                    }),
                    evidence_chain=chain,
                    raw_session=session,
                )
                incidents.append(incident)

        incidents.sort(key=lambda i: i.composite_score, reverse=True)
        log.info("Built %d incidents from %d process sessions", len(incidents), df["pid"].nunique())
        return incidents

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_sessions(pid: Any, pid_group: pd.DataFrame):
        """
        Partition all events for one PID into per-lifetime sessions.

        Windows recycles PIDs, so a single PID may correspond to several
        unrelated process lifetimes within one capture window.  A new
        lifetime begins at each Process Create (Event ID 1) event for the
        PID.  Events are grouped into the lifetime whose start boundary they
        fall under, honouring the documented ``(pid, process_start_time)``
        session key.

        Yields
        ------
        (session_key, group_df)
            ``session_key`` is the process-start timestamp (or ``None`` when
            no Process Create event exists and the PID cannot be split).
        """
        proc_creates = (
            pid_group[pid_group["event_id"] == 1]
            .sort_values("timestamp")
        )

        # No Process Create event → cannot split; yield the whole PID group.
        # Warn: without an EID-1 boundary we cannot detect PID reuse, so a
        # truncated log could silently merge unrelated lifetimes into one.
        if proc_creates.empty:
            log.warning(
                "PID %r has no Process Create (EID 1) event — treating all %d "
                "events as a single session; PID-reuse splitting is not possible "
                "(truncated log?).",
                pid, len(pid_group),
            )
            yield None, pid_group
            return

        starts = proc_creates["timestamp"].dropna().tolist()
        if not starts:
            log.warning(
                "PID %r has Process Create events with no usable timestamps — "
                "treating all %d events as a single session; PID-reuse splitting "
                "is not possible.",
                pid, len(pid_group),
            )
            yield None, pid_group
            return

        # Assign every event to the most recent process-start boundary at or
        # before its own timestamp.  Events predating the first Process Create
        # (clock skew, out-of-order ingestion) join the first lifetime.
        sorted_group = pid_group.sort_values("timestamp")
        session_index: list[int] = []
        for ts in sorted_group["timestamp"]:
            idx = 0
            for i, start in enumerate(starts):
                if pd.notna(ts) and ts >= start:
                    idx = i
                else:
                    break
            session_index.append(idx)

        sorted_group = sorted_group.assign(_session_idx=session_index)
        for idx, group in sorted_group.groupby("_session_idx"):
            yield starts[idx], group.drop(columns=["_session_idx"])

    @staticmethod
    def _matches_in_window(matches: list[dict], session: ProcessSession) -> list[dict]:
        """
        Keep only matches that fall inside the session's [start, end] window.

        Lanes key their matches by PID only; when a PID is recycled we must not
        let a later/earlier lifetime inherit detections from an unrelated one.
        Matches without a usable timestamp are kept (fail-open) to avoid
        silently dropping evidence.
        """
        if session.start_time is None or session.end_time is None:
            return matches

        kept: list[dict] = []
        for m in matches:
            ts = m.get("timestamp") or m.get("start_time") or m.get("end_time")
            if ts is None:
                kept.append(m)  # fail-open: no timing info to disambiguate
                continue
            try:
                ts = pd.Timestamp(ts)
                if session.start_time <= ts <= session.end_time:
                    kept.append(m)
            except Exception:
                kept.append(m)  # unparseable timestamp → fail-open
        return kept

    def _build_session(self, pid: Any, group: pd.DataFrame) -> ProcessSession:
        proc_create = group[group["event_id"] == 1]
        if not proc_create.empty:
            row = proc_create.iloc[0]
        else:
            row = group.iloc[0]

        ts_sorted = group["timestamp"].dropna().sort_values()
        start_time = ts_sorted.iloc[0] if not ts_sorted.empty else None
        end_time   = ts_sorted.iloc[-1] if not ts_sorted.empty else None

        return ProcessSession(
            pid=pid,
            process_name=row.get("process_name"),
            process_path=row.get("process_path"),
            parent_process_name=row.get("parent_process_name"),
            signed=row.get("signed"),
            host=row.get("host"),
            start_time=start_time,
            end_time=end_time,
            event_count=len(group),
            label=group["label"].iloc[0] if "label" in group.columns else "unknown",
            technique_tag=group["technique_tag"].iloc[0] if "technique_tag" in group.columns else "",
        )

    def _compute_score(self, session: ProcessSession) -> float:
        """Compute composite score with diminishing returns per lane."""
        canary_scores = [m.get("score", 0) for m in session.canary_matches]
        sig_scores    = [m.get("score", 0) for m in session.rule_matches]
        heur_scores   = [m.get("score", 0) for m in session.heuristic_matches]
        ml_scores     = [m.get("final_score", 0) for m in session.ml_matches]

        canary_contrib = _diminishing_sum(canary_scores, LANE_WEIGHTS["canary"])
        sig_contrib    = _diminishing_sum(sig_scores,  LANE_WEIGHTS["signature"])
        heur_contrib   = _diminishing_sum(heur_scores, LANE_WEIGHTS["heuristic"])
        ml_contrib     = _diminishing_sum(ml_scores,   LANE_WEIGHTS["ml"])

        raw = canary_contrib + sig_contrib + heur_contrib + ml_contrib
        return min(round(raw, 1), 100.0)

    def _build_evidence_chain(
        self,
        session: ProcessSession,
        group: pd.DataFrame,
    ) -> str:
        """
        Build a human-readable timeline of events and detections.

        Format:
            [HH:MM:SS] <event description>
            ...
            RULE MATCHES:
              [KL-001] ...
            HEURISTIC MATCHES:
              [PollingDetector] ...
            ML MATCHES:
              [MLLane] ...
        """
        lines: list[str] = []

        # Timeline of raw events
        lines.append(f"=== Evidence Chain for PID {session.pid} "
                     f"({session.process_name}) ===")
        lines.append(f"Host: {session.host}")
        lines.append(f"Path: {session.process_path}")
        lines.append(f"Parent: {session.parent_process_name}")
        lines.append(f"Signed: {session.signed}")
        lines.append(f"Start: {session.start_time}  End: {session.end_time}")
        lines.append(f"Events: {session.event_count}")
        lines.append("")

        # Key events in chronological order
        lines.append("--- Event Timeline ---")
        event_id_names = {
            1: "Process Create",
            7: "Image/DLL Load",
            8: "CreateRemoteThread",
            9: "RawAccessRead",
            12: "Registry Create",
            13: "Registry Write",
            14: "Registry Rename",
        }
        for _, row in group.sort_values("timestamp").iterrows():
            eid = row.get("event_id")
            ts  = row.get("timestamp")
            ts_str = str(ts)[:19] if ts is not None else "??:??:??"
            name = event_id_names.get(eid, f"Event {eid}")

            detail = ""
            if eid == 7:
                detail = f"loaded {row.get('image_loaded', '')}"
            elif eid == 8:
                detail = f"→ target {row.get('target_object', '')}"
            elif eid == 9:
                detail = f"device {row.get('target_object', '')}"
            elif eid in (12, 13, 14):
                detail = f"key {row.get('registry_key', '')}"

            lines.append(f"  [{ts_str}] {name}: {detail}".rstrip(": "))

        lines.append("")

        # Canary matches (highest-priority lane — shown first)
        if session.canary_matches:
            lines.append("--- CANARY / DECEPTION MATCHES (KL-CANARY-001) ---")
            for m in session.canary_matches:
                lines.append(f"  [{m.get('rule_id', 'KL-CANARY-001')}] "
                              f"{m.get('rule_name', 'Canary credential access')} "
                              f"(severity={m.get('severity', 'critical')}, "
                              f"score={m.get('score', 95)}, "
                              f"MITRE={m.get('mitre_technique', 'T1056.001')})")
                lines.append(f"    {m.get('evidence', '')}")

        # Rule matches
        if session.rule_matches:
            lines.append("--- Signature Rule Matches ---")
            for m in session.rule_matches:
                lines.append(f"  [{m['rule_id']}] {m['rule_name']} "
                              f"(severity={m['severity']}, score={m['score']}, "
                              f"MITRE={m.get('mitre_technique', '')})")
                lines.append(f"    {m.get('evidence', '')}")

        # Heuristic matches
        if session.heuristic_matches:
            lines.append("")
            lines.append("--- Heuristic Matches ---")
            for m in session.heuristic_matches:
                lines.append(f"  [{m['detector']}] score={m['score']}, "
                              f"confidence={m.get('confidence', 0):.2f}")
                lines.append(f"    {m.get('evidence', '')}")

        # ML matches
        if session.ml_matches:
            lines.append("")
            lines.append("--- ML Anomaly Matches ---")
            for m in session.ml_matches:
                lines.append(f"  [MLLane] anomaly_score={m.get('anomaly_score', 0):.3f}, "
                              f"malicious_prob={m.get('malicious_prob', -1):.3f}, "
                              f"final_score={m.get('final_score', 0)}")
                lines.append(f"    {m.get('evidence', '')}")

        lines.append("")
        lines.append(f"COMPOSITE SCORE: {session.composite_score:.1f} / 100  "
                     f"[{session.severity}]")

        return "\n".join(lines)