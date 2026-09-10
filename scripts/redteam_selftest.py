"""
Red Team Self-Test (Phase 7)
=============================
Evasion test suite that runs each keylogging technique with common evasion
tricks and reports the resulting detection rate per technique/evasion pair.

This is the "does it actually work?" measurement — turning detection coverage
into a quantified, repeatable answer rather than a demo.

Evasion techniques tested
--------------------------
Cosmetic (rename/persistence-only; these test rule *completeness*, not
evasion resistance, because they leave detector-visible artifacts intact):
- binary_rename    : Rename the keylogger binary to a benign-sounding name
- delayed_hook     : Install hook after a random delay (defeats time-based rules)
- signed_masquerade: Simulate a signed binary (tests allow-list bypass)
- system_path      : Place binary in System32 path (tests path-based rules)

Signal-removal (adversarial; these *delete or degrade the telemetry the
detectors consume* and therefore give a lower-bound estimate of true
evasion resistance):
- low_slow_poll    : Jitter registry-write cadence to defeat periodicity detection
- randomized_flush : Randomize write timing completely to defeat the FFT check
- suppress_user32  : Drop user32.dll ImageLoad events (attacker maps the DLL
                     without standard loader telemetry, or uses raw input
                     instead) — defeats user32-gated heuristics entirely
- mimic_benign     : Combined masquerade — explorer.exe parent, signed binary,
                     System32 path, benign name, no hook-persistence registry
                     writes, and heavy write-timing jitter.  This is the
                     strongest composite evasion in the suite.

IMPORTANT — independence caveat
--------------------------------
The evasion samples are produced by mutating the same synthetic generator
the rules and heuristics were developed against.  A 1.00 recall under a
cosmetic evasion means "the rule still sees the artifact it was written
for," NOT "a real adaptive adversary cannot evade."  Only the
signal-removal evasions provide meaningful evidence about evasion
resistance, and even those are synthetic.  Treat all numbers in the report
as upper bounds; independent red-team validation with hand-authored
samples remains necessary.

Output
------
Prints a table of detection rates per technique × evasion combination,
and saves results to ``docs/evaluation_report.md``.

Usage
-----
    python scripts/redteam_selftest.py
    python scripts/redteam_selftest.py --technique hook --evasion binary_rename
    python scripts/redteam_selftest.py --output docs/evaluation_report.md
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np

from scripts.generate_synthetic_dataset import (
    generate_benign_session,
    generate_hook_session,
    generate_poll_session,
    generate_rawinput_session,
    generate_injection_session,
    generate_driver_session,
    TECHNIQUE_GENERATORS,
    BASE_PID,
    save_dataset,
)
from src.schema import CANONICAL_COLUMNS
from src.detect.rule_engine import make_engine
from src.detect.heuristics import HeuristicEngine
from src.detect.ml_lane import MLLane
from src.correlate.session_builder import SessionBuilder

from datetime import datetime, timedelta, timezone
import random

# ---------------------------------------------------------------------------
# Evasion registry
# ---------------------------------------------------------------------------

#: Canonical ordered list of every evasion strategy evaluated.  "none" is the
#: unmodified baseline and must stay first.
ALL_EVASIONS: list[str] = [
    "none",
    # Cosmetic — identity/persistence disguise; artifacts stay intact.
    "binary_rename",
    "delayed_hook",
    "signed_masquerade",
    "system_path",
    "signature_spoof",      # NEW (1.5b): lookalike signer not in allow-list
    # Signal-removal — delete/degrade the telemetry detectors consume.
    "low_slow_poll",
    "randomized_flush",
    "suppress_user32",
    "mimic_benign",
    "lane_spread",          # NEW (1.5a): alternate hook/poll to split signal
    "fft_defeat",           # NEW (1.5c): irregular cadence vs. periodicity
]

#: Human judgment of how hard each evasion was to construct (per 3.3).  Stated
#: plainly, not inflated.  Used in the evaluation report's difficulty column.
EVASION_DIFFICULTY: dict[str, str] = {
    "none":              "—",
    "binary_rename":     "trivial",
    "delayed_hook":      "trivial",
    "signed_masquerade": "trivial",
    "system_path":       "trivial",
    "signature_spoof":   "moderate",   # needs a lookalike not in the allow-list
    "low_slow_poll":     "trivial",
    "randomized_flush":  "trivial",
    "suppress_user32":   "moderate",   # needs manual DLL mapping / raw input
    "mimic_benign":      "sophisticated",  # multi-signal composite masquerade
    "lane_spread":       "sophisticated",  # coordinates two techniques in-session
    "fft_defeat":        "moderate",   # attacker-randomized write spacing
}

# ---------------------------------------------------------------------------
# Evasion modifiers
# ---------------------------------------------------------------------------

def apply_evasion(events: list[dict], evasion: str) -> list[dict]:
    """
    Apply an evasion modifier to a list of events.

    Parameters
    ----------
    events:
        List of canonical event dicts for a malicious session.
    evasion:
        Evasion technique name.

    Returns
    -------
    Modified list of event dicts.
    """
    if evasion == "binary_rename":
        # Rename process to something benign-sounding
        benign_names = ["svchost32.exe", "updater.exe", "helper.exe", "runtime.exe"]
        new_name = random.choice(benign_names)
        for e in events:
            if e.get("process_name") and e["process_name"] not in ("notepad.exe",):
                e["process_name"] = new_name
                if e.get("process_path"):
                    path = e["process_path"].rsplit("\\", 1)[0] + "\\"
                    e["process_path"] = path + new_name

    elif evasion == "delayed_hook":
        # Add a large time delay before hook-related events
        delay = timedelta(seconds=random.uniform(60, 300))
        for e in events:
            if e.get("event_id") in (7, 13) and e.get("technique_tag") == "hook":
                if e.get("timestamp"):
                    e["timestamp"] = e["timestamp"] + delay

    elif evasion == "low_slow_poll":
        # Jitter registry write timestamps to defeat periodicity detection
        for e in events:
            if e.get("event_id") == 13:
                jitter = timedelta(seconds=random.uniform(-15, 15))
                if e.get("timestamp"):
                    e["timestamp"] = e["timestamp"] + jitter

    elif evasion == "randomized_flush":
        # Randomize disk-write intervals completely
        for e in events:
            if e.get("event_id") == 13:
                random_offset = timedelta(seconds=random.uniform(0, 200))
                base = events[0].get("timestamp")
                if base and e.get("timestamp"):
                    e["timestamp"] = base + random_offset

    elif evasion == "signed_masquerade":
        # Mark process as signed (tests whether allow-list is too permissive)
        for e in events:
            e["signed"] = True
            e["signature"] = "Microsoft Corporation"

    elif evasion == "system_path":
        # Move binary to System32 path
        for e in events:
            if e.get("process_path"):
                name = e["process_path"].rsplit("\\", 1)[-1]
                e["process_path"] = f"C:\\Windows\\System32\\{name}"

    elif evasion == "suppress_user32":
        # SIGNAL-REMOVAL evasion: attacker sidesteps the userland-polling
        # heuristic by never generating user32.dll ImageLoad telemetry
        # (manual mapping, raw input device reads, or kernel-level capture).
        # This *removes the signal the detector keys on* rather than merely
        # disguising it, so it is a genuine test of evasion resistance.
        events = [
            e for e in events
            if not (
                e.get("event_id") == 7
                and isinstance(e.get("image_loaded"), str)
                and e["image_loaded"].lower().endswith("user32.dll")
            )
        ]

    elif evasion == "mimic_benign":
        # SIGNAL-REMOVAL composite: strongest synthetic evasion.  Strips or
        # degrades every artifact the signature/heuristic lanes consume.
        for e in events:
            # 1. Benign-looking, signed binary at a trusted path
            if e.get("process_name") and e["process_name"] != "notepad.exe":
                e["process_name"] = "SearchIndexer.exe"
                if e.get("process_path"):
                    e["process_path"] = (
                        "C:\\Windows\\System32\\SearchIndexer.exe"
                    )
            e["signed"] = True
            e["signature"] = "Microsoft Windows Publisher"
            # 2. Re-parent to a GUI process so headless_parent never fires
            if e.get("event_id") == 1:
                e["parent_process_name"] = "explorer.exe"
            # 3. Heavy write-timing jitter defeats the FFT periodicity check
            if e.get("event_id") == 13 and e.get("timestamp"):
                jitter = timedelta(seconds=random.uniform(-120, 120))
                e["timestamp"] = e["timestamp"] + jitter
        # 4. Drop hook-persistence registry writes so no_hook_registry=False
        events = [
            e for e in events
            if not (
                e.get("event_id") == 13
                and isinstance(e.get("registry_key"), str)
                and any(
                    k in e["registry_key"].lower()
                    for k in ("appinit", "winlogon", "\\run")
                )
            )
        ]

    elif evasion == "lane_spread":
        # NEW (1.5a) — SIGNAL-REMOVAL, sophisticated.  A single implant
        # alternates between the hook and polling techniques *within the same
        # session*, splitting its signal across detection lanes so no single
        # lane accumulates a decisive score.  Concretely: roughly half of the
        # user32.dll ImageLoad events (hook signal) are dropped, and the
        # registry-write cadence (polling/periodicity signal) is jittered.
        # Both lanes see a weakened, ambiguous trace rather than a clean one.
        dll_seen = 0
        for e in events:
            # Drop ~50% of user32 loads (deterministic alternate) to dilute
            # the hook-lane signal without fully suppressing it.
            if (
                e.get("event_id") == 7
                and isinstance(e.get("image_loaded"), str)
                and e["image_loaded"].lower().endswith("user32.dll")
            ):
                dll_seen += 1
                if dll_seen % 2 == 0:
                    e["_drop"] = True
            # Jitter write cadence so the periodicity lane's FFT sees noise.
            if e.get("event_id") == 13 and e.get("timestamp"):
                jitter = timedelta(seconds=random.uniform(-45, 45))
                e["timestamp"] = e["timestamp"] + jitter
        events = [e for e in events if not e.pop("_drop", False)]

    elif evasion == "signature_spoof":
        # NEW (1.5b) — cosmetic/identity, moderate.  The implant forges a
        # *plausible but structurally different* signer string than anything in
        # the allow-list, testing whether the allow-list matches exact strings
        # only (and would be fooled by a near-miss) or is robust to lookalikes.
        # We deliberately use a homoglyph/typo variant NOT present in
        # rules/allowlist.yaml so a naive substring allow-list will miss it.
        spoofed_signers = [
            "Micr0soft Corporation",          # zero for 'o'
            "Microsoft Corporatioп",          # Cyrillic 'п' lookalike
            "Microsoft Windows Publisher ",   # trailing space
            "Microsoft  Corporation",         # double space
        ]
        signer = random.choice(spoofed_signers)
        for e in events:
            e["signed"] = True
            e["signature"] = signer

    elif evasion == "fft_defeat":
        # NEW (1.5c) — SIGNAL-REMOVAL, targets the periodicity threshold
        # directly.  Registry writes are re-spaced at *attacker-randomized*,
        # deliberately irregular intervals drawn from a wide non-uniform
        # mixture (bursts + long gaps).  This maximises the coefficient of
        # variation of the inter-write intervals so BOTH the FFT dominant-
        # frequency ratio AND the low-CV fallback in PeriodicWriteDetector
        # fail.  This is a direct stress test of PERIODICITY_THRESHOLD — if
        # recall collapses here, that threshold is a known limitation.
        reg_events = [e for e in events if e.get("event_id") == 13]
        if reg_events:
            base = min(
                (e.get("timestamp") for e in reg_events if e.get("timestamp")),
                default=None,
            )
            if base is not None:
                t = base
                for e in sorted(reg_events, key=lambda x: x.get("timestamp") or x["timestamp"]):
                    # Alternate between tight bursts (2-8 s) and long silences
                    # (90-280 s) so there is no stable period to detect.
                    if random.random() < 0.5:
                        gap = random.uniform(2, 8)
                    else:
                        gap = random.uniform(90, 280)
                    t = t + timedelta(seconds=gap)
                    e["timestamp"] = t

    return events


# ---------------------------------------------------------------------------
# Detection pipeline runner
# ---------------------------------------------------------------------------

def run_detection(
    df: pd.DataFrame,
    engine: Any,
    heuristic_engine: HeuristicEngine,
    ml_lane: MLLane,
    builder: SessionBuilder,
    min_score: float = 10.0,
) -> list[Any]:
    """Run the full detection pipeline and return incidents."""
    rule_matches      = engine.evaluate_df(df)
    heuristic_matches = heuristic_engine.analyze_df(df)
    ml_matches        = ml_lane.predict_df(df) if ml_lane._trained_if else []

    incidents = builder.build(
        df,
        rule_matches=rule_matches,
        heuristic_matches=heuristic_matches,
        ml_matches=ml_matches,
        min_score=min_score,
    )
    return incidents


# ---------------------------------------------------------------------------
# Evaluation metrics
# ---------------------------------------------------------------------------

def compute_metrics(
    incidents: list[Any],
    df: pd.DataFrame,
    min_score: float = 10.0,
) -> dict[str, float]:
    """
    Compute precision, recall, F1, and FPR.

    A session is "detected" if it has at least one incident with score >= min_score.
    """
    detected_pids = {inc.pid for inc in incidents}

    # Ground truth
    malicious_pids = set(df[df["label"] == "malicious"]["pid"].dropna().unique())
    benign_pids    = set(df[df["label"] == "benign"]["pid"].dropna().unique())

    tp = len(detected_pids & malicious_pids)
    fp = len(detected_pids & benign_pids)
    fn = len(malicious_pids - detected_pids)
    tn = len(benign_pids - detected_pids)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # Per-lane attribution: which detection lane(s) contributed to each
    # *detected* malicious session.  Used by the honest-eval report (3.3) so a
    # reader can see whether detection was corroborated or hung on one lane.
    lane_names = ["signature", "heuristic", "ml"]
    lane_hits: dict[str, set] = {k: set() for k in lane_names}
    for inc in incidents:
        if inc.pid not in malicious_pids:
            continue
        s = inc.raw_session
        if getattr(s, "rule_matches", None):
            lane_hits["signature"].add(inc.pid)
        if getattr(s, "heuristic_matches", None):
            lane_hits["heuristic"].add(inc.pid)
        if getattr(s, "ml_matches", None):
            lane_hits["ml"].add(inc.pid)

    # Fraction of *detected malicious* sessions each lane fired on.
    detected_mal = tp
    lane_recall = {
        k: (len(v) / detected_mal if detected_mal else 0.0)
        for k, v in lane_hits.items()
    }
    lanes_detected = sorted(k for k, v in lane_hits.items() if v)

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "n_malicious": len(malicious_pids),
        "n_benign": len(benign_pids),
        "n_detected": len(detected_pids),
        "lanes_detected": lanes_detected,
        "lane_recall": lane_recall,
    }


# ---------------------------------------------------------------------------
# Main self-test runner
# ---------------------------------------------------------------------------

def run_selftest(
    techniques: list[str] | None = None,
    evasions: list[str] | None = None,
    n_benign: int = 50,
    n_malicious: int = 20,
    seed: int = 42,
    output_path: str | Path = "docs/evaluation_report.md",
) -> dict[str, dict[str, dict]]:
    """
    Run the full red team self-test.

    Returns
    -------
    dict mapping technique → evasion → metrics dict
    """
    random.seed(seed)

    if techniques is None:
        techniques = list(TECHNIQUE_GENERATORS.keys())
    if evasions is None:
        evasions = ALL_EVASIONS

    # Build detection pipeline
    print("[*] Loading detection engine ...")
    engine = make_engine("rules/packs", "rules/allowlist.yaml")
    heuristic_engine = HeuristicEngine()
    ml_lane = MLLane()
    builder = SessionBuilder()

    # Generate benign baseline for ML training
    print("[*] Generating benign baseline for ML training ...")
    base_time = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)
    benign_events: list[dict] = []
    for i in range(n_benign * 2):
        session_base = base_time + timedelta(minutes=i * 2)
        benign_events.extend(generate_benign_session(BASE_PID + i, session_base))

    benign_df = pd.DataFrame(benign_events, columns=CANONICAL_COLUMNS)

    # Generate malicious sessions for ML training
    print("[*] Generating malicious sessions for ML training ...")
    mal_events: list[dict] = []
    pid = BASE_PID + n_benign * 2 + 1000
    for tech in techniques:
        gen_fn = TECHNIQUE_GENERATORS[tech]
        for i in range(n_malicious):
            session_base = base_time + timedelta(hours=3, minutes=i * 3)
            mal_events.extend(gen_fn(pid, session_base, stealth=i % 3))
            pid += 1

    mal_df = pd.DataFrame(mal_events, columns=CANONICAL_COLUMNS)

    # Train ML lane
    print("[*] Training ML lane ...")
    ml_lane.train(benign_df, mal_df)

    # Run tests
    results: dict[str, dict[str, dict]] = {}
    pid_counter = BASE_PID + 5000

    for technique in techniques:
        results[technique] = {}
        gen_fn = TECHNIQUE_GENERATORS[technique]

        for evasion in evasions:
            print(f"[>] Testing {technique} × {evasion} ...")

            # Generate test sessions
            test_events: list[dict] = []

            # Benign sessions
            for i in range(n_benign):
                session_base = base_time + timedelta(hours=6, minutes=i * 2)
                test_events.extend(generate_benign_session(pid_counter, session_base))
                pid_counter += 1

            # Malicious sessions with evasion applied
            for i in range(n_malicious):
                session_base = base_time + timedelta(hours=8, minutes=i * 3)
                stealth = 1 if evasion != "none" else 0
                events = gen_fn(pid_counter, session_base, stealth=stealth)
                if evasion != "none":
                    events = apply_evasion(events, evasion)
                test_events.extend(events)
                pid_counter += 1

            test_df = pd.DataFrame(test_events, columns=CANONICAL_COLUMNS)

            # Run detection
            incidents = run_detection(
                test_df, engine, heuristic_engine, ml_lane, builder
            )

            # Compute metrics
            metrics = compute_metrics(incidents, test_df)
            results[technique][evasion] = metrics

            print(
                f"    recall={metrics['recall']:.2f}  "
                f"precision={metrics['precision']:.2f}  "
                f"f1={metrics['f1']:.2f}  "
                f"fpr={metrics['fpr']:.2f}"
            )

    # Save report
    _save_report(results, output_path)
    return results


def _save_report(
    results: dict[str, dict[str, dict]],
    output_path: str | Path,
) -> None:
    """Save evaluation results to a Markdown report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Classify evasions by what they actually test.  Cosmetic evasions only
    # disguise identity/persistence metadata while leaving detector-visible
    # artifacts intact — a high recall there is NOT evidence of evasion
    # resistance.  Signal-removal evasions delete or degrade the telemetry the
    # detectors consume and are the only meaningful lower bound.
    COSMETIC = {
        "binary_rename", "delayed_hook", "signed_masquerade", "system_path",
        "signature_spoof",
    }
    SIGNAL_REMOVAL = {
        "low_slow_poll", "randomized_flush", "suppress_user32", "mimic_benign",
        "lane_spread", "fft_defeat",
    }

    def _evasion_class(ev: str) -> str:
        if ev == "none":
            return "baseline"
        if ev in SIGNAL_REMOVAL:
            return "signal-removal"
        if ev in COSMETIC:
            return "cosmetic"
        return "unknown"

    def _lanes_cell(m: dict) -> str:
        lanes = m.get("lanes_detected") or []
        return ", ".join(lanes) if lanes else "—"

    # Flatten all (technique, evasion) combos for weakest-first analysis.
    combos: list[tuple[str, str, dict]] = [
        (t, ev, m)
        for t, evs in results.items()
        for ev, m in evs.items()
    ]

    # ------------------------------------------------------------------
    # Summary — weakest result FIRST (per honest-reporting requirement).
    # ------------------------------------------------------------------
    non_baseline = [(t, ev, m) for t, ev, m in combos if ev != "none"]
    weakest = min(non_baseline, key=lambda c: c[2]["recall"], default=None)
    strongest = max(non_baseline, key=lambda c: c[2]["recall"], default=None)
    worst_fpr = max(combos, key=lambda c: c[2]["fpr"], default=None)

    no_evasion_recalls = [results[t].get("none", {}).get("recall", 0.0) for t in results]
    no_evasion_fprs = [results[t].get("none", {}).get("fpr", 0.0) for t in results]
    evasion_recalls = [m["recall"] for _, ev, m in non_baseline]

    lines = [
        "# Glyph — Evaluation Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Summary",
        "",
        "The **weakest** result is listed first, so the honest limitation is the",
        "first thing a reader sees — not buried at the bottom.",
        "",
    ]
    if weakest is not None:
        t, ev, m = weakest
        lines.append(
            f"- **Lowest recall: {m['recall']:.2f}** against `{ev}` evasion "
            f"targeting `{t}` (caught by lanes: {_lanes_cell(m)}; "
            f"difficulty: {EVASION_DIFFICULTY.get(ev, 'unknown')})."
        )
    lines.append("")
    if strongest is not None:
        t, ev, m = strongest
        lines.append(
            f"- Highest recall (under evasion): {m['recall']:.2f} against "
            f"`{ev}` evasion targeting `{t}`."
        )
    if worst_fpr is not None and worst_fpr[2]["fpr"] > 0:
        t, ev, m = worst_fpr
        lines.append(
            f"- Worst false-positive rate: {m['fpr']:.2f} on `{t}` × `{ev}`."
        )
    if no_evasion_recalls:
        lines.append(f"- Mean recall (no evasion): **{np.mean(no_evasion_recalls):.2f}**")
        lines.append(f"- Mean FPR (no evasion): **{np.mean(no_evasion_fprs):.2f}**")
    if evasion_recalls:
        lines.append(f"- Mean recall (with evasion): **{np.mean(evasion_recalls):.2f}**")

    lines += [
        "",
        "## Detection Rate by Technique × Evasion",
        "",
        "`Lanes` lists which detection lane(s) fired on the detected malicious",
        "sessions.  Detection resting on a single lane is more fragile than",
        "corroborated detection.  `Difficulty` is a plain-language judgment of",
        "how hard the evasion is for a real attacker to pull off.",
        "",
        "| Technique | Evasion | Class | Difficulty | Recall | Precision | F1 | FPR | Lanes | TP | FP | FN |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for technique, evasion_results in results.items():
        for evasion, m in evasion_results.items():
            lines.append(
                f"| {technique} | {evasion} | {_evasion_class(evasion)} | "
                f"{EVASION_DIFFICULTY.get(evasion, 'unknown')} | "
                f"{m['recall']:.2f} | {m['precision']:.2f} | "
                f"{m['f1']:.2f} | {m['fpr']:.2f} | {_lanes_cell(m)} | "
                f"{m['tp']} | {m['fp']} | {m['fn']} |"
            )

    # ------------------------------------------------------------------
    # Known Limitations — every evasion that dropped recall below 80%.
    # ------------------------------------------------------------------
    low_recall = sorted(
        [(t, ev, m) for t, ev, m in non_baseline if m["recall"] < 0.80],
        key=lambda c: c[2]["recall"],
    )
    lines += [
        "",
        "## Known Limitations",
        "",
    ]
    if low_recall:
        lines += [
            "The following evasion strategies reduced recall below 80%.  Each is",
            "a real, reproducible weakness in the current detection lanes.",
            "",
        ]
        for t, ev, m in low_recall:
            reason = {
                "fft_defeat": (
                    "Attacker-randomized write spacing raises the coefficient of "
                    "variation enough that BOTH the FFT dominant-frequency test "
                    "AND the low-CV fallback in `PeriodicWriteDetector` fail.  "
                    "The periodicity lane has no signal left to key on."
                ),
                "lane_spread": (
                    "Splitting hook and polling signals across lanes keeps every "
                    "individual lane below its firing threshold; no single lane "
                    "accumulates a decisive score."
                ),
                "suppress_user32": (
                    "Removing user32.dll ImageLoad telemetry disarms the "
                    "userland-polling heuristic entirely (its hard gate).  Only "
                    "signature/ML lanes can still catch it."
                ),
                "mimic_benign": (
                    "Composite masquerade strips signature, headless-parent, and "
                    "periodicity signals simultaneously."
                ),
                "randomized_flush": (
                    "Fully randomized write timing defeats the periodicity "
                    "detector."
                ),
                "low_slow_poll": (
                    "Heavy cadence jitter defeats the periodicity detector."
                ),
            }.get(ev, "This evasion degrades the signal the lane consumes.")
            lines.append(
                f"- **`{ev}` x `{t}` -- recall {m['recall']:.2f}.** {reason}"
            )
    else:
        lines.append(
            "No tested evasion reduced recall below 80%.  See the Independence "
            "Caveat below before reading too much into that — these are "
            "synthetic, self-generated samples, not independent red-team data."
        )

    # ------------------------------------------------------------------
    # Methodology — exactly how samples were made + independence statement.
    # ------------------------------------------------------------------
    lines += [
        "",
        "## Methodology",
        "",
        "- **Sample generation.** Both benign and malicious events are produced by",
        "  `scripts/generate_synthetic_dataset.py`.  Evasion variants are produced",
        "  by `apply_evasion()` in `scripts/redteam_selftest.py`, which mutates the",
        "  synthetic events (rename, re-time, or delete telemetry).",
        "- **Detection pipeline.** Each mutated dataset is run through the full",
        "  pipeline: YAML signature rules (`rules/packs/*.yaml`) + heuristic lane",
        "  (`src/detect/heuristics.py`) + ML lane (`src/detect/ml_lane.py`), then",
        "  correlated/scored by `SessionBuilder`.",
        "- **Metrics.** Recall/precision/F1/FPR computed at composite score >= 10,",
        "  where a session counts as detected if any incident fires for its PID.",
        "- **Independence statement.** The evasion generator is parameterized by",
        "  *what a real attacker would tune* (jitter distribution, delay ranges,",
        "  renamed binaries, alternate paths) and does NOT read detector",
        "  thresholds or rule contents.  However, it still *mutates output of the",
        "  same upstream generator* the detectors were developed against, so the",
        "  underlying event structure is shared.  This is a partial, not full,",
        "  decoupling -- see the caveat below.",
        "",
        "## Notes",
        "",
        "- Recall = fraction of malicious sessions correctly detected",
        "- Precision = fraction of detections that are truly malicious",
        "- FPR = false positive rate (benign sessions incorrectly flagged)",
        "- All metrics computed at composite score threshold >= 10",
        "",
        "## Limitations & Independence Caveat",
        "",
        "This self-test does **not** constitute independent adversarial validation:",
        "",
        "1. **Shared provenance.** Both the benign baseline and the malicious",
        "   samples are emitted by `scripts/generate_synthetic_dataset.py` — the",
        "   same generator the rules, heuristics, and ML features were developed",
        "   and tuned against.  The detector is therefore being scored on data",
        "   whose structure it already models.",
        "2. **Cosmetic evasions are not evasions.** Renaming the binary, moving",
        "   it to `System32`, or forging a signature does not remove the artifact",
        "   (hook registry key, user32 load, injection thread, driver device read)",
        "   that the corresponding rule matches.  A perfect recall under these",
        "   evasions demonstrates rule *completeness*, not *evasion resistance*.",
        "3. **Signal-removal evasions are the meaningful lower bound.** Only",
        "   `low_slow_poll`, `randomized_flush`, `suppress_user32`, `mimic_benign`,",
        "   `lane_spread`, and `fft_defeat` delete or degrade the telemetry the",
        "   detectors actually consume.  Degraded recall under *these* is the",
        "   honest signal; consult the `Class` column and weight those rows most",
        "   heavily.",
        "4. **Synthetic ≠ real.** None of these samples capture an adaptive",
        "   adversary's full freedom (living-off-the-land binaries, in-memory",
        "   only payloads, kernel tampering, ETW/Sysmon blinding).  Real-world",
        "   performance will be lower.  Independent red-team testing with",
        "   hand-authored samples remains necessary before trusting these numbers.",
    ]

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"\n[+] Evaluation report saved to {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Red team self-test: measure detection rate against evasion"
    )
    parser.add_argument("--technique", default="all",
                        choices=list(TECHNIQUE_GENERATORS.keys()) + ["all"])
    parser.add_argument("--evasion", default="all",
                        help="Evasion technique (default: all)")
    parser.add_argument("--benign", type=int, default=50,
                        help="Number of benign test sessions (default: 50)")
    parser.add_argument("--malicious", type=int, default=20,
                        help="Number of malicious test sessions per technique (default: 20)")
    parser.add_argument("--output", default="docs/evaluation_report.md")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    techniques = (
        list(TECHNIQUE_GENERATORS.keys()) if args.technique == "all"
        else [args.technique]
    )
    evasions = (
        list(ALL_EVASIONS) if args.evasion == "all" else [args.evasion]
    )

    run_selftest(
        techniques=techniques,
        evasions=evasions,
        n_benign=args.benign,
        n_malicious=args.malicious,
        seed=args.seed,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()