"""
Heuristic & Statistical Detection Lane (Phase 4)
=================================================
Catches keylogging techniques that leave no hook artifact — especially
polling-based loggers (GetAsyncKeyState) and periodic-flush loggers.

Three detectors are implemented:

1. **PollingDetector**
   Identifies processes with high-frequency, regular API call cadence
   consistent with a GetAsyncKeyState polling loop.  Since Sysmon doesn't
   log individual API calls, this is approximated from process-level
   behavioral features extracted during log collection.

2. **PeriodicWriteDetector**
   Applies an FFT-based periodicity test over a process's write-like
   event timestamps.  Sysmon has no generic "file write" event, so the
   detector consumes Event ID 11 (FileCreate, a genuine disk-write proxy)
   and/or Event ID 13 (RegistryValueSet, a weaker registry-write signal)
   and labels which signal produced the alert.  Many keyloggers flush
   their buffer on a fixed interval (e.g. every 30s), producing a
   detectable periodic signal distinct from normal application I/O.

3. **HeadlessHookDetector**
   Flags processes that loaded user32.dll but have no visible window
   handle and no known-legitimate reason to use keyboard APIs.

Each detector returns :class:`HeuristicMatch` objects with a score and
human-readable evidence string.

Usage
-----
    from src.detect.heuristics import HeuristicEngine

    engine = HeuristicEngine()
    matches = engine.analyze_session(session_events, process_meta)
    for m in matches:
        print(m.detector, m.score, m.evidence)
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HeuristicMatch:
    """A heuristic detector that fired against a process session."""
    detector: str           # detector name
    score: int              # 0–100
    confidence: float       # 0.0–1.0
    evidence: str           # human-readable explanation
    features: dict          # raw feature values that triggered the match


# ---------------------------------------------------------------------------
# 1. Polling Detector
# ---------------------------------------------------------------------------

class PollingDetector:
    """
    Detects GetAsyncKeyState / GetKeyState polling-based keyloggers.

    Since Sysmon does not log individual Win32 API calls, polling is
    detected indirectly via a combination of:
      - Process has no registered hook (no user32.dll load with hook pattern)
      - Process is headless (no parent with a visible window)
      - Process has keyboard-adjacent imports (user32.dll loaded)
      - Process shows high CPU utilization relative to its I/O rate
        (tight loop with no meaningful work)

    In live mode, actual polling cadence from ETW would be used.
    In batch/EVTX mode, we use the proxy features above.

    Thresholds
    ----------
    MIN_USER32_LOADS : int
        Minimum number of user32.dll load events to consider.
    HEADLESS_PARENTS : set
        Parent process names that indicate a headless/scripted launch.
    """

    MIN_USER32_LOADS = 1
    HEADLESS_PARENTS = frozenset({
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "schtasks.exe",
    })

    def analyze(
        self,
        session_events: pd.DataFrame,
        process_meta: dict,
    ) -> HeuristicMatch | None:
        """
        Analyze a process session for polling-based keylogger indicators.

        Parameters
        ----------
        session_events:
            All canonical events for this process session.
        process_meta:
            Dict with keys: ``process_name``, ``process_path``,
            ``parent_process_name``, ``signed``, ``pid``.

        Returns
        -------
        HeuristicMatch or None
        """
        process_name = (process_meta.get("process_name") or "").lower()
        parent_name  = (process_meta.get("parent_process_name") or "").lower()
        signed       = process_meta.get("signed")
        pid          = process_meta.get("pid")

        features: dict = {}
        score = 0

        # Feature 1: loaded user32.dll
        dll_loads = session_events[session_events["event_id"] == 7]
        user32_loads = dll_loads[
            dll_loads["image_loaded"].str.lower().str.endswith("user32.dll", na=False)
        ]
        features["user32_loaded"] = len(user32_loads) > 0

        # Hard gate: this detector's entire premise is *userland* polling via
        # user32.dll (GetAsyncKeyState / GetKeyState).  A process that never
        # loaded user32.dll cannot be polling through that API — firing anyway
        # would produce self-contradictory evidence (``user32_loaded=False``)
        # and conflate driver/raw-input techniques with userland polling.
        if not features["user32_loaded"]:
            return None
        score += 15

        # Feature 2: no hook-related registry writes (distinguishes poll from hook)
        reg_events = session_events[session_events["event_id"].isin([12, 13, 14])]
        hook_reg = reg_events[
            reg_events["registry_key"].str.lower().str.contains(
                "appinit|winlogon|run", na=False
            )
        ]
        features["no_hook_registry"] = len(hook_reg) == 0
        if features["no_hook_registry"] and features["user32_loaded"]:
            score += 20  # user32 loaded but no hook persistence = polling pattern

        # Feature 3: headless launch (scripted/no-GUI parent)
        features["headless_parent"] = parent_name in self.HEADLESS_PARENTS
        if features["headless_parent"]:
            score += 15

        # Feature 4: unsigned process
        features["unsigned"] = signed is False or signed is None
        if features["unsigned"]:
            score += 10
        elif signed is True:
            score -= 10

        # Feature 5: no CreateRemoteThread (not an injector)
        crt_events = session_events[session_events["event_id"] == 8]
        features["no_injection"] = len(crt_events) == 0

        # Feature 6: process has disk writes (keylogger flushes to file)
        # Approximated by checking if process_path is in a writable location
        proc_path = (process_meta.get("process_path") or "").lower()
        features["staging_path"] = any(
            p in proc_path for p in ["\\temp\\", "\\appdata\\", "\\downloads\\"]
        )
        if features["staging_path"]:
            score += 20

        # Only flag if score is meaningful
        if score < 30:
            return None

        confidence = min(score / 80.0, 1.0)
        evidence = (
            f"Process '{process_meta.get('process_name')}' (PID {pid}) "
            f"shows polling-based keylogger indicators: "
            f"user32_loaded={features['user32_loaded']}, "
            f"no_hook_registry={features['no_hook_registry']}, "
            f"headless_parent={features['headless_parent']}, "
            f"unsigned={features['unsigned']}, "
            f"staging_path={features['staging_path']}. "
            f"Heuristic score: {score}/80."
        )

        return HeuristicMatch(
            detector="PollingDetector",
            score=min(score, 80),
            confidence=confidence,
            evidence=evidence,
            features=features,
        )


# ---------------------------------------------------------------------------
# 2. Periodic Write Detector (FFT-based)
# ---------------------------------------------------------------------------

class PeriodicWriteDetector:
    """
    Detects keyloggers that flush their buffer to persistent storage on a
    fixed interval.

    IMPORTANT — what is actually measured
    --------------------------------------
    Sysmon has **no generic "file write" event**.  This pipeline surfaces
    two write-adjacent signals:

    * **Event ID 11 — FileCreate**: a file being created/overwritten.
      This is the closest genuine *disk-write* proxy Sysmon offers.
    * **Event ID 13 — RegistryValueSet**: a registry write.  Some
      keyloggers persist captured data via the registry on a fixed cadence,
      but this is a *weaker* signal than a true file-flush and is **not**
      the same thing as writing a log file to disk.

    The caller (``HeuristicEngine.analyze_df``) may feed either or both.
    The ``source`` field in the emitted match records which signal(s)
    produced the alert so reports do not mislabel registry writes as
    "disk writes."

    Method
    ------
    1. Collect write-event timestamps for the process session.
    2. Compute inter-write intervals.
    3. Apply FFT to the interval time series.
    4. If a dominant frequency exists with power > threshold, the process
       has periodic write-like I/O — characteristic of a keylogger flush loop.

    Parameters
    ----------
    MIN_WRITES : int
        Minimum number of write events needed for analysis.
    PERIODICITY_THRESHOLD : float
        Ratio of dominant-frequency power to total power.  Values above
        this indicate strong periodicity.
    MIN_PERIOD_SECONDS : float
        Minimum flush interval to consider (ignore sub-second noise).
    MAX_PERIOD_SECONDS : float
        Maximum flush interval to consider.
    """

    MIN_WRITES = 4
    PERIODICITY_THRESHOLD = 0.35   # dominant freq must hold >35% of total power
    MIN_PERIOD_SECONDS = 5.0
    MAX_PERIOD_SECONDS = 300.0     # 5 minutes max

    def analyze(
        self,
        write_timestamps: list[pd.Timestamp],
        process_meta: dict,
        source: str = "registry_write",
    ) -> HeuristicMatch | None:
        """
        Analyze write-event timestamps for periodic flush behavior.

        Parameters
        ----------
        write_timestamps:
            List of UTC-aware Timestamps for each write-like event.
        process_meta:
            Dict with process metadata.
        source:
            What the timestamps actually represent.  One of
            ``"file_create"`` (Sysmon EID 11 — genuine file writes),
            ``"registry_write"`` (Sysmon EID 13 — registry value sets), or
            ``"mixed"``.  This is recorded in the evidence string so reports
            do not mislabel registry writes as disk writes.

        Returns
        -------
        HeuristicMatch or None
        """
        if len(write_timestamps) < self.MIN_WRITES:
            return None

        # Human-readable label for the evidence string
        source_label = {
            "file_create": "file-create",
            "registry_write": "registry-write",
            "mixed": "file-create+registry-write",
        }.get(source, source)

        # Sort and compute inter-write intervals in seconds
        # Normalize to tz-naive UTC for consistent arithmetic
        def _to_naive(t):
            t = pd.Timestamp(t)  # coerce str / datetime / Timestamp
            if t.tzinfo is not None:
                t = t.tz_convert("UTC")
            return t.tz_localize(None)

        ts_sorted = sorted(_to_naive(t) for t in write_timestamps)
        intervals = np.array([
            (ts_sorted[i+1] - ts_sorted[i]).total_seconds()
            for i in range(len(ts_sorted) - 1)
        ])

        # Filter out sub-second noise and very long gaps
        intervals = intervals[
            (intervals >= self.MIN_PERIOD_SECONDS) &
            (intervals <= self.MAX_PERIOD_SECONDS)
        ]

        if len(intervals) < self.MIN_WRITES - 1:
            return None

        # FFT-based periodicity test
        fft_vals = np.abs(np.fft.rfft(intervals))
        total_power = np.sum(fft_vals ** 2)
        if total_power == 0:
            return None

        dominant_idx = np.argmax(fft_vals[1:]) + 1  # skip DC component
        dominant_power = fft_vals[dominant_idx] ** 2
        periodicity_ratio = dominant_power / total_power

        # Dominant period in seconds
        n = len(intervals)
        freqs = np.fft.rfftfreq(n, d=1.0)  # normalized frequencies
        if freqs[dominant_idx] > 0:
            dominant_period = 1.0 / freqs[dominant_idx]
        else:
            dominant_period = 0.0

        features = {
            "write_count": len(write_timestamps),
            "write_source": source,
            "mean_interval_s": float(np.mean(intervals)),
            "std_interval_s": float(np.std(intervals)),
            "periodicity_ratio": float(periodicity_ratio),
            "dominant_period_s": float(dominant_period),
        }

        # Fallback: if intervals are very regular (low CV), that IS the signal
        # even if FFT doesn't cross the threshold (e.g. perfectly uniform intervals)
        cv = float(np.std(intervals) / np.mean(intervals)) if np.mean(intervals) > 0 else 1.0
        if periodicity_ratio < self.PERIODICITY_THRESHOLD:
            if cv > 0.25:
                return None
            # Low CV = highly regular = strong periodicity signal
            # Score inversely proportional to CV (lower CV = more periodic)
            effective_ratio = max(1.0 - cv * 4, self.PERIODICITY_THRESHOLD)
        else:
            effective_ratio = periodicity_ratio

        # Score based on how strong the periodicity is
        score = int(min(effective_ratio * 100, 75))
        confidence = min(effective_ratio, 1.0)

        evidence = (
            f"Process '{process_meta.get('process_name')}' "
            f"(PID {process_meta.get('pid')}) has periodic {source_label} activity: "
            f"{len(write_timestamps)} {source_label} events, dominant period "
            f"~{dominant_period:.1f}s, periodicity ratio "
            f"{periodicity_ratio:.2f} (threshold {self.PERIODICITY_THRESHOLD}). "
            f"Mean interval: {np.mean(intervals):.1f}s ± {np.std(intervals):.1f}s."
        )

        return HeuristicMatch(
            detector="PeriodicWriteDetector",
            score=score,
            confidence=confidence,
            evidence=evidence,
            features=features,
        )


# ---------------------------------------------------------------------------
# 3. Headless Hook Detector
# ---------------------------------------------------------------------------

class HeadlessHookDetector:
    """
    Flags processes that loaded user32.dll but appear to be headless
    (no GUI, no legitimate reason to use keyboard APIs).

    This catches hook-based keyloggers that the signature lane may miss
    if they are signed or have a non-suspicious path.
    """

    GUI_PROCESS_INDICATORS = frozenset({
        "explorer.exe", "notepad.exe", "wordpad.exe", "mspaint.exe",
        "calc.exe", "taskmgr.exe", "regedit.exe", "mmc.exe",
    })

    def analyze(
        self,
        session_events: pd.DataFrame,
        process_meta: dict,
    ) -> HeuristicMatch | None:
        process_name = (process_meta.get("process_name") or "").lower()
        pid = process_meta.get("pid")

        # Skip known GUI processes
        if process_name in self.GUI_PROCESS_INDICATORS:
            return None

        dll_loads = session_events[session_events["event_id"] == 7]
        loaded_dlls = set(
            dll_loads["image_loaded"].str.lower().dropna().tolist()
        )

        has_user32 = any("user32.dll" in d for d in loaded_dlls)
        has_hid    = any("hid.dll" in d for d in loaded_dlls)

        if not has_user32:
            return None

        # Check for GUI indicators: if process loaded gdi32.dll or d3d, it's likely GUI
        has_gui_dlls = any(
            any(g in d for g in ["gdi32.dll", "d3d", "opengl32.dll", "comctl32.dll"])
            for d in loaded_dlls
        )

        if has_gui_dlls:
            return None  # Likely a legitimate GUI application

        score = 35
        features = {
            "has_user32": has_user32,
            "has_hid": has_hid,
            "has_gui_dlls": has_gui_dlls,
            "loaded_dlls": list(loaded_dlls)[:10],
        }

        if has_hid:
            score += 20  # Both user32 + hid without GUI = strong indicator

        evidence = (
            f"Process '{process_meta.get('process_name')}' (PID {pid}) "
            f"loaded keyboard-adjacent DLLs (user32={has_user32}, hid={has_hid}) "
            f"but shows no GUI DLL indicators. "
            f"Possible headless hook or raw-input keylogger."
        )

        return HeuristicMatch(
            detector="HeadlessHookDetector",
            score=score,
            confidence=score / 55.0,
            evidence=evidence,
            features=features,
        )


# ---------------------------------------------------------------------------
# Heuristic Engine (combines all detectors)
# ---------------------------------------------------------------------------

class HeuristicEngine:
    """
    Runs all heuristic detectors against a process session and returns
    a combined list of :class:`HeuristicMatch` objects.
    """

    def __init__(self) -> None:
        self.polling_detector       = PollingDetector()
        self.periodic_write_detector = PeriodicWriteDetector()
        self.headless_hook_detector  = HeadlessHookDetector()

    def analyze_session(
        self,
        session_events: pd.DataFrame,
        process_meta: dict,
        write_timestamps: list[pd.Timestamp] | None = None,
        write_source: str = "registry_write",
    ) -> list[HeuristicMatch]:
        """
        Run all detectors against a process session.

        Parameters
        ----------
        session_events:
            All canonical events for this process session (same PID).
        process_meta:
            Dict with process metadata (process_name, pid, etc.).
        write_timestamps:
            Optional list of write-like event timestamps for the periodic
            detector (see ``write_source`` for what they represent).
        write_source:
            What ``write_timestamps`` actually represent — ``"file_create"``
            (Sysmon EID 11), ``"registry_write"`` (Sysmon EID 13), or
            ``"mixed"``.  Passed through to the periodic detector so its
            evidence string accurately describes the measured signal.

        Returns
        -------
        list[HeuristicMatch]
            All matches from all detectors (may be empty).
        """
        matches: list[HeuristicMatch] = []

        # 1. Polling detector
        m = self.polling_detector.analyze(session_events, process_meta)
        if m:
            matches.append(m)

        # 2. Periodic write detector
        if write_timestamps and len(write_timestamps) >= PeriodicWriteDetector.MIN_WRITES:
            m = self.periodic_write_detector.analyze(
                write_timestamps, process_meta, source=write_source
            )
            if m:
                matches.append(m)

        # 3. Headless hook detector
        m = self.headless_hook_detector.analyze(session_events, process_meta)
        if m:
            matches.append(m)

        return matches

    def analyze_df(self, df: pd.DataFrame) -> list[dict]:
        """
        Analyze all process sessions in a canonical DataFrame.

        Groups events by PID, runs all detectors per session, and returns
        a flat list of match dicts.
        """
        results = []

        for pid, group in df.groupby("pid", dropna=True):
            # Build process_meta from the first Process Create event (ID 1)
            proc_create = group[group["event_id"] == 1]
            if not proc_create.empty:
                row = proc_create.iloc[0]
                meta = {
                    "process_name": row.get("process_name"),
                    "process_path": row.get("process_path"),
                    "parent_process_name": row.get("parent_process_name"),
                    "signed": row.get("signed"),
                    "pid": pid,
                }
            else:
                # Infer from any event in the group
                row = group.iloc[0]
                meta = {
                    "process_name": row.get("process_name"),
                    "process_path": row.get("process_path"),
                    "parent_process_name": row.get("parent_process_name"),
                    "signed": row.get("signed"),
                    "pid": pid,
                }

            # Collect write-like event timestamps.
            #
            # Sysmon has no generic "file write" event.  The two write-adjacent
            # signals available are:
            #   * Event ID 11 (FileCreate)  -> genuine disk-write proxy
            #   * Event ID 13 (RegistryValueSet) -> registry write (weaker signal)
            #
            # We prefer FileCreate when present and fall back to registry writes.
            # The ``write_source`` value is propagated so the detector's evidence
            # string accurately describes which signal produced the alert.
            file_creates = group[group["event_id"] == 11]
            reg_writes = group[group["event_id"] == 13]
            fc_ts = file_creates["timestamp"].dropna().tolist()
            rw_ts = reg_writes["timestamp"].dropna().tolist()

            if fc_ts and rw_ts:
                write_ts = fc_ts + rw_ts
                write_source = "mixed"
            elif fc_ts:
                write_ts = fc_ts
                write_source = "file_create"
            else:
                write_ts = rw_ts
                write_source = "registry_write"

            matches = self.analyze_session(
                group, meta, write_timestamps=write_ts, write_source=write_source
            )

            for m in matches:
                results.append({
                    "pid": pid,
                    "process_name": meta.get("process_name"),
                    "detector": m.detector,
                    "score": m.score,
                    "confidence": m.confidence,
                    "evidence": m.evidence,
                    "features": m.features,
                    "label": group["label"].iloc[0] if "label" in group.columns else "unknown",
                    "technique_tag": group["technique_tag"].iloc[0] if "technique_tag" in group.columns else "",
                })

        return results