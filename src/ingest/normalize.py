"""
Normalization Layer
===================
Maps raw event dicts (from :mod:`src.ingest.evtx_loader`) onto the canonical
DataFrame schema defined in :mod:`src.schema`.

Each Sysmon Event ID has its own field mapping.  Unknown/extra fields are
preserved in ``raw_fields`` for forensic use.

Usage
-----
    from src.ingest.evtx_loader import stream_evtx
    from src.ingest.normalize import normalize_events
    import pandas as pd

    records = list(normalize_events(stream_evtx("sysmon.evtx")))
    df = pd.DataFrame(records)
"""

from __future__ import annotations

import logging
import os
from datetime import timezone
from typing import Any, Generator, Iterable

import pandas as pd

from src.schema import (
    CANONICAL_COLUMNS,
    make_event,
    VALID_LABELS,
)

log = logging.getLogger(__name__)

# Last completed normalize_events() stats — surfaced by the CLI.
_LAST_NORMALIZE_STATS: dict[str, int] = {"count": 0, "errors": 0}


def last_normalize_stats() -> dict[str, int]:
    """Return ``{"count": int, "errors": int}`` from the last ``normalize_events`` run."""
    return dict(_LAST_NORMALIZE_STATS)

# ---------------------------------------------------------------------------
# Sysmon field-name aliases
# (Sysmon uses different casing/names across schema versions)
# ---------------------------------------------------------------------------

_PROCESS_NAME_KEYS = ("Image", "image", "ProcessName")
_PROCESS_HASH_KEYS = ("Hashes", "hashes", "Hash")
_PID_KEYS          = ("ProcessId", "ProcessID", "pid", "Pid")
_PPID_KEYS         = ("ParentProcessId", "ParentProcessID", "ppid")
_PARENT_IMG_KEYS   = ("ParentImage", "parentimage")
_SIGNED_KEYS       = ("Signed", "signed")
_SIGNATURE_KEYS    = ("Signature", "signature")
_IMAGE_LOAD_KEYS   = ("ImageLoaded", "imageloaded", "ImageLoad")
_REG_KEY_KEYS      = ("TargetObject", "targetobject")
_REG_VAL_KEYS      = ("Details", "details", "RegistryValue")
_TARGET_OBJ_KEYS   = ("TargetObject", "targetobject", "Device", "device")


def _first(d: dict, keys: tuple[str, ...], default: Any = None) -> Any:
    """Return the value of the first matching key in *d*, or *default*."""
    for k in keys:
        if k in d:
            return d[k]
    return default


def _parse_pid(value: Any) -> int | None:
    if value is None:
        return None
    s = str(value).strip()
    try:
        return int(s, 0)
    except (ValueError, TypeError):
        return None


def _parse_bool(value: Any) -> bool | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no"):
        return False
    return None


def _extract_hash(hashes_str: str | None) -> str | None:
    """
    Extract SHA-256 from a Sysmon Hashes field like:
        ``MD5=abc123,SHA256=def456,IMPHASH=ghi789``
    Returns lowercase hex string or None.
    """
    if not hashes_str:
        return None
    for part in hashes_str.split(","):
        part = part.strip()
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].lower()
    return None


def _extract_process_name(image_path: str | None) -> str | None:
    """
    Extract filename from a full image path.

    Sysmon/EVTX events always carry Windows paths (backslash separators),
    regardless of the OS running this analysis.  ``os.path.basename`` only
    splits on the *native* separator, so on Linux/macOS it would return the
    full ``C:\\Windows\\System32\\notepad.exe`` string unchanged.  Normalise
    both separators before splitting so the extraction is platform-independent.
    """
    if image_path is None:
        return None
    if image_path == "":
        return ""
    # Split on both Windows and POSIX separators; take the last non-empty part
    parts = [p for p in image_path.replace("\\", "/").split("/") if p]
    return parts[-1] if parts else ""


def _parse_timestamp(ts_str: str) -> pd.Timestamp:
    """
    Parse a Sysmon timestamp string to a UTC-aware pandas Timestamp.
    Handles ISO-8601 with or without trailing 'Z'.
    """
    if ts_str is None:
        raise TypeError("ts_str cannot be None")
    
    import datetime
    if isinstance(ts_str, datetime.datetime) or pd.api.types.is_datetime64_any_dtype(ts_str):
        ts = pd.Timestamp(ts_str)
        if ts.tz is None:
            ts = ts.tz_localize("UTC")
        elif ts.tz.zone != "UTC":
            ts = ts.tz_convert("UTC")
        return ts

    if not ts_str:
        return pd.Timestamp.now("UTC")
    ts_str = str(ts_str).strip().rstrip("Z")
    try:
        ts = pd.Timestamp(ts_str, tz="UTC")
    except Exception:
        try:
            ts = pd.Timestamp(ts_str).tz_localize("UTC")
        except Exception:
            log.debug("Could not parse timestamp %r; using now()", ts_str)
            ts = pd.Timestamp.now("UTC")
    return ts


# ---------------------------------------------------------------------------
# Per-event-ID normalizers
# ---------------------------------------------------------------------------

def _normalize_id1(ed: dict, base: dict) -> dict:
    """Event ID 1 — Process Create."""
    image = _first(ed, _PROCESS_NAME_KEYS)
    base.update(
        process_path=image,
        process_name=_extract_process_name(image),
        process_hash=_extract_hash(_first(ed, _PROCESS_HASH_KEYS)),
        pid=_parse_pid(_first(ed, _PID_KEYS)),
        ppid=_parse_pid(_first(ed, _PPID_KEYS)),
        parent_process_name=_extract_process_name(_first(ed, _PARENT_IMG_KEYS)),
        signed=_parse_bool(_first(ed, _SIGNED_KEYS)),
        signature=_first(ed, _SIGNATURE_KEYS),
    )
    return base


def _normalize_id7(ed: dict, base: dict) -> dict:
    """Event ID 7 — Image/DLL Load."""
    image = _first(ed, _PROCESS_NAME_KEYS)
    loaded = _first(ed, _IMAGE_LOAD_KEYS)
    base.update(
        process_path=image,
        process_name=_extract_process_name(image),
        pid=_parse_pid(_first(ed, _PID_KEYS)),
        image_loaded=loaded,
        signed=_parse_bool(_first(ed, _SIGNED_KEYS)),
        signature=_first(ed, _SIGNATURE_KEYS),
    )
    return base


def _normalize_id8(ed: dict, base: dict) -> dict:
    """Event ID 8 — CreateRemoteThread."""
    src_image = _first(ed, _PROCESS_NAME_KEYS)
    target = ed.get("TargetImage") or ed.get("targetimage")
    base.update(
        process_path=src_image,
        process_name=_extract_process_name(src_image),
        pid=_parse_pid(_first(ed, _PID_KEYS)),
        target_object=target,
    )
    return base


def _normalize_id9(ed: dict, base: dict) -> dict:
    """Event ID 9 — RawAccessRead."""
    image = _first(ed, _PROCESS_NAME_KEYS)
    device = ed.get("Device") or ed.get("device")
    base.update(
        process_path=image,
        process_name=_extract_process_name(image),
        pid=_parse_pid(_first(ed, _PID_KEYS)),
        target_object=device,
    )
    return base


def _normalize_id12_13_14(ed: dict, base: dict) -> dict:
    """Event IDs 12/13/14 — Registry events."""
    image = _first(ed, _PROCESS_NAME_KEYS)
    target = _first(ed, _REG_KEY_KEYS)
    base.update(
        process_path=image,
        process_name=_extract_process_name(image),
        pid=_parse_pid(_first(ed, _PID_KEYS)),
        registry_key=target,
        registry_value=_first(ed, _REG_VAL_KEYS),
        target_object=target,
    )
    return base


_ID_NORMALIZERS = {
    1:  _normalize_id1,
    7:  _normalize_id7,
    8:  _normalize_id8,
    9:  _normalize_id9,
    12: _normalize_id12_13_14,
    13: _normalize_id12_13_14,
    14: _normalize_id12_13_14,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize a single raw event dict into a canonical event dict.

    Parameters
    ----------
    raw:
        Raw event dict as yielded by :func:`~src.ingest.evtx_loader.stream_evtx`.

    Returns
    -------
    dict
        Canonical event dict (keys = :data:`~src.schema.CANONICAL_COLUMNS`).
    """
    event_id = raw.get("EventID", -1)
    ed: dict = raw.get("EventData", {})

    # Determine event_source from Channel
    channel = raw.get("Channel", "")
    if "Sysmon" in channel:
        source = "Sysmon"
    elif "Security" in channel:
        source = "Security"
    elif "Application" in channel:
        source = "Application"
    else:
        source = channel or "Unknown"

    ts = _parse_timestamp(raw.get("TimeCreated", ""))
    host = raw.get("Computer", "unknown")

    # Build base canonical dict with defaults
    base = make_event(
        timestamp=ts,
        host=host,
        event_id=event_id,
        event_source=source,
        raw_fields={**ed, "_raw_xml": raw.get("_raw_xml", "")},
    )

    # Apply per-event-ID field mapping
    normalizer = _ID_NORMALIZERS.get(event_id)
    if normalizer:
        base = normalizer(ed, base)
    else:
        # Unknown event ID: best-effort extraction
        image = _first(ed, _PROCESS_NAME_KEYS)
        if image:
            base["process_path"] = image
            base["process_name"] = _extract_process_name(image)
        base["pid"] = _parse_pid(_first(ed, _PID_KEYS))

    return base


def normalize_events(
    raw_events: Iterable[dict[str, Any]],
    *,
    label: str = "unknown",
    technique_tag: str = "",
) -> Generator[dict[str, Any], None, None]:
    """
    Normalize an iterable of raw event dicts.

    Parameters
    ----------
    raw_events:
        Iterable of raw event dicts (e.g. from :func:`~src.ingest.evtx_loader.stream_evtx`).
    label:
        Ground-truth label to apply to all events (``"benign"``, ``"malicious"``,
        or ``"unknown"``).  Use ``"unknown"`` for live/production data.
    technique_tag:
        Technique tag to apply (``"hook"``, ``"poll"``, etc.).  Empty string
        for unlabeled data.

    Yields
    ------
    dict
        Canonical event dict.
    """
    if label not in VALID_LABELS:
        raise ValueError(f"Invalid label {label!r}")

    count = 0
    errors = 0
    _LAST_NORMALIZE_STATS["count"] = 0
    _LAST_NORMALIZE_STATS["errors"] = 0
    try:
        for raw in raw_events:
            try:
                event = normalize_event(raw)
                event["label"] = label
                event["technique_tag"] = technique_tag
                count += 1
                yield event
            except Exception as exc:
                errors += 1
                log.debug("Normalization error: %s", exc)
                continue
    finally:
        _LAST_NORMALIZE_STATS["count"] = count
        _LAST_NORMALIZE_STATS["errors"] = errors
        log.info("Normalized %d events (%d errors)", count, errors)


def events_to_df(
    raw_events: Iterable[dict[str, Any]],
    *,
    label: str = "unknown",
    technique_tag: str = "",
) -> "pd.DataFrame":
    """
    Normalize *raw_events* and return a canonical pandas DataFrame.

    Parameters
    ----------
    raw_events:
        Iterable of raw event dicts.
    label:
        Ground-truth label (``"benign"``, ``"malicious"``, ``"unknown"``).
    technique_tag:
        Technique tag string.

    Returns
    -------
    pd.DataFrame
        DataFrame with :data:`~src.schema.CANONICAL_COLUMNS` columns.
    """
    records = list(normalize_events(raw_events, label=label, technique_tag=technique_tag))
    if not records:
        from src.schema import make_empty_df
        return make_empty_df()

    df = pd.DataFrame(records, columns=CANONICAL_COLUMNS)

    # Coerce types
    df["event_id"] = pd.array(df["event_id"].tolist(), dtype="Int64")
    df["pid"]      = pd.array(df["pid"].tolist(), dtype="Int64")
    df["ppid"]     = pd.array(df["ppid"].tolist(), dtype="Int64")

    # Ensure timestamp is UTC-aware
    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    elif df["timestamp"].dt.tz is None:
        df["timestamp"] = df["timestamp"].dt.tz_localize("UTC")

    return df