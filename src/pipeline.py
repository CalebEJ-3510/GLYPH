"""
Detection Pipeline
====================
End-to-end pipeline: ingest → normalize → detect (4 lanes) → correlate → report.

This is the single shared entry point used by the Streamlit dashboard
(``src/dashboard.py``) and by scripts (``scripts/train_models.py``,
``scripts/redteam_selftest.py``). There is no command-line wrapper around
it — the dashboard is the interactive entry point for this project.

Usage
-----
    from src.pipeline import run_pipeline

    incidents = run_pipeline(
        df,
        model_dir="models" if Path("models").exists() else None,
        min_severity="LOW",
    )
"""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from src.schema import validate_df
from src.detect.rule_engine import make_engine
from src.detect.heuristics import HeuristicEngine
from src.detect.ml_lane import MLLane
from src.correlate.session_builder import SessionBuilder
from src.report.evidence_chain import Reporter

log = logging.getLogger(__name__)


def run_pipeline(
    df: pd.DataFrame,
    *,
    packs_dir: str = "rules/packs",
    allowlist_path: str = "rules/allowlist.yaml",
    model_dir: str | None = None,
    min_severity: str = "LOW",
    json_output: str | None = None,
    summary_output: str | None = None,
    quiet: bool = False,
) -> list:
    """
    Run the full detection pipeline on a canonical DataFrame.

    Parameters
    ----------
    df:
        Canonical events DataFrame.
    packs_dir:
        Path to YAML detection pack directory.
    allowlist_path:
        Path to allowlist YAML.
    model_dir:
        Path to trained ML models directory. If None, the ML lane is
        skipped (the other three lanes still run).
    min_severity:
        Minimum severity to display/save (only affects printed/saved
        output, not what gets detected).
    json_output:
        Optional path to save JSON alerts.
    summary_output:
        Optional path to save a plain-text summary.
    quiet:
        If True, suppress console output (the dashboard always passes
        ``quiet=True`` since it renders incidents itself).

    Returns
    -------
    list of Incident objects
    """
    # Validate schema
    violations = validate_df(df)
    if violations:
        log.warning("Schema violations: %s", violations)

    # Lane 1: Signature rules
    log.info("Running signature rule lane ...")
    engine = make_engine(packs_dir, allowlist_path)
    rule_matches = engine.evaluate_df(df)
    log.info("Rule lane: %d matches", len(rule_matches))

    # Lane 2: Heuristics
    log.info("Running heuristic lane ...")
    heuristic_engine = HeuristicEngine()
    heuristic_matches = heuristic_engine.analyze_df(df)
    log.info("Heuristic lane: %d matches", len(heuristic_matches))

    # Lane 3: ML (optional)
    ml_matches: list = []
    ml_lane = MLLane()
    if model_dir and Path(model_dir).exists():
        try:
            ml_lane.load(model_dir)
            ml_matches = ml_lane.predict_df(df)
            log.info("ML lane: %d anomalous sessions", len(ml_matches))
        except Exception as exc:
            log.warning("ML lane failed to load: %s", exc)
    else:
        log.info("ML lane skipped (no model_dir provided or models not found)")

    # Lane 4: Canary / deception (optional — only when canaries are registered)
    canary_matches: list = []
    try:
        from src.canary.planter import load_registry
        from src.canary.watcher import check_canary_access, canary_matches_to_rule_matches

        registry = load_registry()
        if registry:
            for pid, group in df.groupby("pid", dropna=True):
                hits = check_canary_access(group, registry)
                canary_matches.extend(canary_matches_to_rule_matches(hits))
            if canary_matches:
                log.info("Canary lane: %d bait-access matches", len(canary_matches))
    except Exception as exc:  # canary lane must never break the main pipeline
        log.warning("Canary lane skipped: %s", exc)

    # Correlation & scoring
    log.info("Correlating sessions ...")
    builder = SessionBuilder()
    incidents = builder.build(
        df,
        rule_matches=rule_matches,
        heuristic_matches=heuristic_matches,
        ml_matches=ml_matches,
        canary_matches=canary_matches,
    )
    log.info("Correlation: %d incidents", len(incidents))

    # Reporting
    reporter = Reporter()

    if not quiet:
        reporter.print_incidents(incidents, min_severity=min_severity)

    if json_output:
        reporter.save_json(incidents, json_output)

    if summary_output:
        reporter.save_summary(incidents, summary_output)

    return incidents
