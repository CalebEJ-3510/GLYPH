"""
KDS Local Dashboard
===================
The only interface for the Glyph. Launch via::

    streamlit run src/dashboard.py

Features
--------
* Upload a CSV or EVTX event log, or load demo data (synthetic, generated
  on the fly).
* Schema-violation warning if an uploaded file doesn't match the canonical
  columns cleanly.
* Minimum-severity filter.
* Incident table sorted by composite score with severity color-coding.
* Click a row to expand the full evidence chain (monospace).
* Optional LLM narrative (opt-in, template fallback when no key).
* Bar chart of incident counts by severity.
* Download buttons for JSON alerts (SIEM ingestion) and a plain-text
  summary report.

This is a local demo tool only — no authentication, multi-user support, or
persistence beyond the current browser session.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

# Ensure project root is importable when launched via `streamlit run`.
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pipeline import run_pipeline  # noqa: E402
from src.schema import CANONICAL_COLUMNS, validate_df  # noqa: E402
from src.ingest.csv_loader import load_csv_events  # noqa: E402
from src.report.evidence_chain import Reporter  # noqa: E402

st.set_page_config(page_title="KDS Dashboard", layout="wide")

SEVERITY_COLORS = {
    "CRITICAL": "#d62728",
    "HIGH": "#ff7f0e",
    "MEDIUM": "#e6c619",
    "LOW": "#1f77b4",
    "INFO": "#7f7f7f",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@st.cache_data(show_spinner=False)
def _load_csv(uploaded) -> tuple[pd.DataFrame, dict]:
    return load_csv_events(uploaded)


@st.cache_data(show_spinner=False)
def _load_evtx(uploaded_bytes: bytes) -> tuple[pd.DataFrame, dict]:
    from src.ingest.evtx_loader import last_evtx_stats, stream_evtx
    from src.ingest.normalize import events_to_df, last_normalize_stats

    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(uploaded_bytes)
        tmp_path = Path(tmp.name)
    try:
        df = events_to_df(stream_evtx(tmp_path), label="unknown")
    finally:
        tmp_path.unlink(missing_ok=True)

    skipped = (last_evtx_stats().get("skipped", 0)
               + last_normalize_stats().get("errors", 0))
    return df, {"loaded": len(df), "skipped": skipped}


@st.cache_data(show_spinner=True)
def _demo_data() -> pd.DataFrame:
    from scripts.generate_synthetic_dataset import generate_dataset
    return generate_dataset(n_benign=40, n_malicious_per_technique=4, seed=42)


def _style_severity(row: pd.Series) -> list[str]:
    color = SEVERITY_COLORS.get(row["severity"], "#000000")
    return [f"color: {color}; font-weight: bold" if c == "severity" else "" for c in row.index]


def main() -> None:
    st.title("Glyph — Dashboard")
    st.caption("Local single-session demo. No data leaves this machine unless "
               "narratives are explicitly enabled (structured fields only).")

    narrate = st.sidebar.checkbox(
        "LLM narratives (opt-in)",
        value=False,
        help="Calls an external LLM API per unique incident when an API key is "
             "configured; otherwise uses a local template. Only structured "
             "detection data is sent.",
    )
    min_severity = st.sidebar.selectbox(
        "Minimum severity to show", SEVERITY_ORDER[::-1], index=0,
    )

    source = st.sidebar.radio("Data source", ["Demo data", "Upload CSV", "Upload EVTX"])
    stats: dict | None = None
    if source == "Upload CSV":
        uploaded = st.sidebar.file_uploader("CSV event log", type=["csv"])
        if uploaded is None:
            st.info("Upload a CSV file or switch to Demo data.")
            return
        df, stats = _load_csv(uploaded)
    elif source == "Upload EVTX":
        uploaded = st.sidebar.file_uploader("Sysmon EVTX log", type=["evtx"])
        if uploaded is None:
            st.info("Upload an EVTX file or switch to Demo data.")
            return
        df, stats = _load_evtx(uploaded.getvalue())
    else:
        df = _demo_data()

    if stats and stats.get("skipped"):
        st.warning(f"{stats['skipped']} record(s) skipped due to malformed "
                   f"data — {stats['loaded']} loaded successfully.")

    violations = validate_df(df)
    if violations:
        with st.expander(f"⚠ {len(violations)} schema violation(s) — click to view", expanded=False):
            for v in violations:
                st.text(v)

    st.write(f"**Loaded {len(df)} events** across "
             f"{df['pid'].nunique() if 'pid' in df.columns else '?'} sessions")

    with st.spinner("Running detection pipeline ..."):
        incidents = run_pipeline(
            df,
            packs_dir="rules/packs",
            allowlist_path="rules/allowlist.yaml",
            model_dir="models" if Path("models").exists() else None,
            min_severity="INFO",  # filter for display happens below instead
            quiet=True,
        )

    if narrate:
        from src.report.narrative import generate_narrative
        with st.spinner("Generating narratives ..."):
            for inc in incidents:
                if not getattr(inc, "narrative", None):
                    inc.narrative = generate_narrative(inc)

    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    min_rank = severity_rank[min_severity]
    incidents = [i for i in incidents if severity_rank.get(i.severity, 99) <= min_rank]

    if not incidents:
        st.success("No incidents at or above the selected severity.")
        return

    # --- Download buttons ---------------------------------------------------
    reporter = Reporter()
    col1, col2 = st.sidebar.columns(2)
    col1.download_button(
        "⬇ JSON alerts",
        data=json.dumps(reporter.to_json(incidents), indent=2, default=str),
        file_name="alerts.json",
        mime="application/json",
    )
    summary_lines = [f"{i.incident_id} | {i.severity} | {i.composite_score:.1f} | "
                     f"{i.process_name} (PID {i.pid})" for i in incidents]
    col2.download_button(
        "⬇ Summary",
        data="\n".join(summary_lines),
        file_name="summary.txt",
        mime="text/plain",
    )

    # --- Summary bar chart -------------------------------------------------
    counts = {s: 0 for s in SEVERITY_ORDER}
    for inc in incidents:
        counts[inc.severity] = counts.get(inc.severity, 0) + 1
    chart_df = pd.DataFrame({"severity": list(counts), "count": list(counts.values())})
    chart_df = chart_df[chart_df["count"] > 0]
    st.subheader("Incidents by severity")
    st.bar_chart(chart_df.set_index("severity"))

    # --- Incident table ----------------------------------------------------
    rows = [
        {
            "incident_id": inc.incident_id,
            "severity": inc.severity,
            "score": round(inc.composite_score, 1),
            "process": inc.process_name,
            "pid": inc.pid,
            "techniques": ", ".join(inc.mitre_techniques),
        }
        for inc in sorted(incidents, key=lambda i: i.composite_score, reverse=True)
    ]
    table = pd.DataFrame(rows)
    st.subheader("Incidents")
    st.dataframe(table.style.apply(_style_severity, axis=1), use_container_width=True)

    # --- Expandable evidence chains ----------------------------------------
    st.subheader("Evidence chains")
    for inc in sorted(incidents, key=lambda i: i.composite_score, reverse=True):
        label = (f"[{inc.severity}] {inc.process_name} (PID {inc.pid}) — "
                 f"score {inc.composite_score:.1f}")
        with st.expander(label):
            narrative = getattr(inc, "narrative", None)
            if narrative:
                st.markdown(f"**Analyst summary:** {narrative}")
                st.divider()
            st.code(inc.evidence_chain, language="text")


if __name__ == "__main__":
    main()
