"""
Canonical event schema definition and DataFrame factory.

Every ingestion adapter must produce a DataFrame whose columns match
CANONICAL_COLUMNS exactly.  Use ``make_empty_df()`` to get a correctly-typed
empty frame, and ``validate_df()`` to assert conformance.
"""

from __future__ import annotations

import pandas as pd
from typing import Any


# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

#: Ordered list of all canonical column names.
CANONICAL_COLUMNS: list[str] = [
    "timestamp",
    "host",
    "event_id",
    "event_source",
    "process_name",
    "process_path",
    "process_hash",
    "pid",
    "ppid",
    "parent_process_name",
    "image_loaded",
    "registry_key",
    "registry_value",
    "target_object",
    "signed",
    "signature",
    "label",
    "technique_tag",
    "raw_fields",
]

#: Pandas dtype for each column (used when constructing empty frames).
COLUMN_DTYPES: dict[str, Any] = {
    "timestamp": "datetime64[ns, UTC]",
    "host": "object",
    "event_id": "Int64",        # nullable integer
    "event_source": "object",
    "process_name": "object",
    "process_path": "object",
    "process_hash": "object",
    "pid": "Int64",
    "ppid": "Int64",
    "parent_process_name": "object",
    "image_loaded": "object",
    "registry_key": "object",
    "registry_value": "object",
    "target_object": "object",
    "signed": "boolean",        # nullable bool
    "signature": "object",
    "label": "object",
    "technique_tag": "object",
    "raw_fields": "object",     # stores Python dicts
}

#: Columns that must never be null.
NON_NULLABLE: frozenset[str] = frozenset({"timestamp", "host", "event_id", "event_source"})

#: Valid label values.
VALID_LABELS: frozenset[str] = frozenset({"benign", "malicious", "unknown"})

#: Valid technique tags (empty string = not applicable).
VALID_TECHNIQUE_TAGS: frozenset[str] = frozenset(
    {"hook", "poll", "rawinput", "injection", "driver", ""}
)


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def make_empty_df() -> pd.DataFrame:
    """Return an empty DataFrame with the canonical schema applied."""
    df = pd.DataFrame(columns=CANONICAL_COLUMNS)
    for col, dtype in COLUMN_DTYPES.items():
        if dtype == "datetime64[ns, UTC]":
            df[col] = pd.Series(dtype="datetime64[ns, UTC]")
        elif dtype == "Int64":
            df[col] = pd.array([], dtype="Int64")
        elif dtype == "boolean":
            df[col] = pd.array([], dtype="boolean")
        else:
            df[col] = pd.Series(dtype="object")
    return df


def make_event(
    timestamp: pd.Timestamp,
    host: str,
    event_id: int,
    event_source: str,
    *,
    process_name: str | None = None,
    process_path: str | None = None,
    process_hash: str | None = None,
    pid: int | None = None,
    ppid: int | None = None,
    parent_process_name: str | None = None,
    image_loaded: str | None = None,
    registry_key: str | None = None,
    registry_value: str | None = None,
    target_object: str | None = None,
    signed: bool | None = None,
    signature: str | None = None,
    label: str = "unknown",
    technique_tag: str = "",
    raw_fields: dict | None = None,
) -> dict:
    """
    Build a single canonical event dict.

    Parameters
    ----------
    timestamp:
        UTC-aware pandas Timestamp.
    host:
        Hostname string.
    event_id:
        Windows Event ID integer.
    event_source:
        Log channel name (``"Sysmon"``, ``"Security"``, etc.).
    **kwargs:
        Optional fields; see :data:`CANONICAL_COLUMNS`.

    Returns
    -------
    dict
        A dict whose keys are exactly :data:`CANONICAL_COLUMNS`.
    """
    if label not in VALID_LABELS:
        raise ValueError(f"Invalid label {label!r}; must be one of {VALID_LABELS}")
    if process_hash is not None:
        process_hash = process_hash.lower()

    return {
        "timestamp": timestamp,
        "host": host,
        "event_id": event_id,
        "event_source": event_source,
        "process_name": process_name,
        "process_path": process_path,
        "process_hash": process_hash,
        "pid": pid,
        "ppid": ppid,
        "parent_process_name": parent_process_name,
        "image_loaded": image_loaded,
        "registry_key": registry_key,
        "registry_value": registry_value,
        "target_object": target_object,
        "signed": signed,
        "signature": signature,
        "label": label,
        "technique_tag": technique_tag,
        "raw_fields": raw_fields if raw_fields is not None else {},
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class SchemaValidationError(ValueError):
    """Raised when a DataFrame does not conform to the canonical schema."""


def validate_df(df: pd.DataFrame, *, strict: bool = False) -> list[str]:
    """
    Validate *df* against the canonical schema.

    Parameters
    ----------
    df:
        DataFrame to validate.
    strict:
        If ``True``, raise :class:`SchemaValidationError` on the first
        violation; otherwise collect all violations and return them.

    Returns
    -------
    list[str]
        List of human-readable violation messages (empty = valid).

    Raises
    ------
    SchemaValidationError
        Only when *strict* is ``True`` and violations are found.
    """
    violations: list[str] = []

    # 1. Required columns present
    missing = set(CANONICAL_COLUMNS) - set(df.columns)
    if missing:
        for m in sorted(missing):
            violations.append(f"Missing column: {m}")

    # 2. Non-nullable columns have no nulls
    for col in NON_NULLABLE:
        if col in df.columns and df[col].isna().any():
            violations.append(f"Column '{col}' contains null values (must be non-null)")

    # 3. raw_fields is always a dict (not NaN/None)
    if "raw_fields" in df.columns:
        bad = df["raw_fields"].apply(lambda v: not isinstance(v, dict))
        if bad.any():
            violations.append(
                f"Column 'raw_fields' has {bad.sum()} non-dict values; use {{}} for empty"
            )

    # 4. label values are valid
    if "label" in df.columns:
        bad_labels = df["label"].dropna()
        bad_labels = bad_labels[~bad_labels.isin(VALID_LABELS)]
        if not bad_labels.empty:
            violations.append(
                f"Column 'label' has invalid values: {bad_labels.unique().tolist()}"
            )

    # 5. process_hash is lowercase when present
    if "process_hash" in df.columns:
        hashes = df["process_hash"].dropna()
        if len(hashes) > 0 and (hashes != hashes.str.lower()).any():
            violations.append(
                "Column 'process_hash' contains uppercase characters; must be lowercase hex"
            )

    if strict and violations:
        raise SchemaValidationError("\n".join(violations))

    return violations