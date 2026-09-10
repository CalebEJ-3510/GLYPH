"""
Shared CSV Event Loader
========================
Loads a canonical-schema events CSV (from disk or an in-memory buffer, e.g.
a Streamlit ``UploadedFile``) into a normalized DataFrame.

This used to live inline in the old CLI's ``analyze`` command.  It is now a
standalone module so the dashboard (and tests) can load CSVs the same way
without depending on a command-line entry point.

Handles the two things naive ``pd.read_csv`` calls get wrong for this
project's data:

* ISO-8601 timestamps with fractional seconds + a UTC offset (the default
  pandas parser silently turns these into ``NaT`` on recent pandas unless
  told ``format="ISO8601"``).
* ``raw_fields`` is stored as a Python-dict-literal string in CSV and needs
  ``ast.literal_eval`` to become a real dict again.

Usage
-----
    from src.ingest.csv_loader import load_csv_events

    df, stats = load_csv_events("data/samples/combined_synthetic.csv")
    # or, for an uploaded file-like object:
    df, stats = load_csv_events(uploaded_file)
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from src.schema import CANONICAL_COLUMNS

log = logging.getLogger(__name__)


def load_csv_events(source: str | Path | Any) -> tuple[pd.DataFrame, dict]:
    """
    Load a canonical-schema events CSV from a path or file-like object.

    Parameters
    ----------
    source:
        A filesystem path, or any file-like object ``pandas.read_csv``
        accepts (e.g. a Streamlit ``UploadedFile``).

    Returns
    -------
    (df, stats)
        ``df`` is the normalized events DataFrame.  ``stats`` is a dict with
        ``loaded`` (rows kept) and ``skipped`` (rows dropped for malformed
        CSV lines or unparseable timestamps) counts, so callers can report
        data loss instead of silently swallowing it.
    """
    try:
        df = pd.read_csv(source, on_bad_lines="warn")
        skipped = getattr(df, "_bad_line_count", 0)
    except TypeError:
        # Older pandas without on_bad_lines support.
        df = pd.read_csv(source)
        skipped = 0

    if "timestamp" in df.columns:
        raw_ts = df["timestamp"]
        parsed = pd.to_datetime(raw_ts, utc=True, format="ISO8601", errors="coerce")
        still_bad = parsed.isna()
        if still_bad.any():
            parsed = parsed.fillna(
                pd.to_datetime(raw_ts[still_bad], utc=True, errors="coerce")
            )
        df["timestamp"] = parsed
        bad_ts = int(df["timestamp"].isna().sum())
        if bad_ts:
            df = df.dropna(subset=["timestamp"])
        skipped += bad_ts

    if "raw_fields" in df.columns:
        df["raw_fields"] = df["raw_fields"].apply(
            lambda v: ast.literal_eval(v) if isinstance(v, str) and v.startswith("{") else {}
        )
    else:
        df["raw_fields"] = [{}] * len(df)

    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            df[col] = None

    stats = {"loaded": len(df), "skipped": skipped}
    if skipped:
        log.warning("Loaded %d events (%d skipped due to malformed records)",
                     stats["loaded"], skipped)
    else:
        log.info("Loaded %d events (0 skipped)", stats["loaded"])

    return df, stats
