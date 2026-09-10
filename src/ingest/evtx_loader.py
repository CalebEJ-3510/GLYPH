"""
EVTX Loader
===========
Stream-parse Windows EVTX files using ``python-evtx`` and yield raw event
dicts without loading the entire file into memory.

Design goals
------------
- Generator-based: one event dict at a time, suitable for large log files.
- Fault-tolerant: malformed records are logged and skipped, not fatal.
- Schema-agnostic at this layer: raw field extraction only; normalization
  is handled by :mod:`src.ingest.normalize`.

Dependencies
------------
- ``python-evtx`` (``pip install python-evtx``) — Windows EVTX parser.
- ``lxml`` — XML parsing of event records.

Usage
-----
    from src.ingest.evtx_loader import stream_evtx

    for raw_event in stream_evtx("path/to/Microsoft-Windows-Sysmon.evtx"):
        print(raw_event["EventID"], raw_event["TimeCreated"])
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Any

log = logging.getLogger(__name__)

# Last completed stream_evtx() parse stats — read by the CLI so skipped
# malformed records are visible to the operator, not only in DEBUG logs.
_LAST_STREAM_STATS: dict[str, int] = {"yielded": 0, "skipped": 0}


def last_evtx_stats() -> dict[str, int]:
    """Return ``{"yielded": int, "skipped": int}`` from the last ``stream_evtx`` run."""
    return dict(_LAST_STREAM_STATS)

# ---------------------------------------------------------------------------
# Optional import guard for python-evtx
# ---------------------------------------------------------------------------

try:
    import Evtx.Evtx as evtx          # type: ignore[import]
    import Evtx.Views as evtx_views   # type: ignore[import]
    _EVTX_AVAILABLE = True
except ImportError:
    _EVTX_AVAILABLE = False
    log.warning(
        "python-evtx not installed.  EVTX loading disabled.  "
        "Install with: pip install python-evtx"
    )

try:
    from lxml import etree             # type: ignore[import]
    _LXML_AVAILABLE = True
except ImportError:
    _LXML_AVAILABLE = False
    log.warning("lxml not installed.  Install with: pip install lxml")


# ---------------------------------------------------------------------------
# Namespace helpers
# ---------------------------------------------------------------------------

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_NS_MAP = {"e": _NS}


def _tag(name: str) -> str:
    return f"{{{_NS}}}{name}"


def _find(element: Any, path: str) -> Any | None:
    """XPath find with the event namespace pre-applied."""
    return element.find(path, namespaces=_NS_MAP)


def _findall(element: Any, path: str) -> list:
    return element.findall(path, namespaces=_NS_MAP)


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

def _parse_record(xml_str: str) -> dict[str, Any]:
    """
    Parse a single EVTX record XML string into a flat dict.

    Returns a dict with keys:
      - ``EventID``       : int
      - ``TimeCreated``   : str (ISO-8601 UTC)
      - ``Computer``      : str
      - ``Channel``       : str
      - ``Provider``      : str
      - ``EventData``     : dict[str, str]  (Name → text pairs from EventData)
      - ``_raw_xml``      : str             (original XML for forensics)
    """
    root = etree.fromstring(xml_str.encode("utf-8"))

    system = _find(root, "e:System")
    if system is None:
        raise ValueError("No <System> element in event record")

    def sys_text(tag: str) -> str:
        el = _find(system, f"e:{tag}")
        return el.text.strip() if el is not None and el.text else ""

    def sys_attr(tag: str, attr: str) -> str:
        el = _find(system, f"e:{tag}")
        return el.get(attr, "") if el is not None else ""

    event_id_el = _find(system, "e:EventID")
    try:
        event_id = int(event_id_el.text.strip()) if event_id_el is not None else -1
    except (ValueError, AttributeError):
        event_id = -1

    time_created = sys_attr("TimeCreated", "SystemTime")
    computer = sys_text("Computer")
    channel = sys_text("Channel")
    provider = sys_attr("Provider", "Name")

    # Parse EventData / UserData key-value pairs
    event_data: dict[str, str] = {}
    ed = _find(root, "e:EventData")
    if ed is not None:
        for data_el in _findall(ed, "e:Data"):
            name = data_el.get("Name", "")
            value = data_el.text or ""
            event_data[name] = value.strip()

    return {
        "EventID": event_id,
        "TimeCreated": time_created,
        "Computer": computer,
        "Channel": channel,
        "Provider": provider,
        "EventData": event_data,
        "_raw_xml": xml_str,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def stream_evtx(
    path: str | Path,
    *,
    event_ids: list[int] | None = None,
) -> Generator[dict[str, Any], None, None]:
    """
    Stream-parse an EVTX file and yield one raw event dict per record.

    Parameters
    ----------
    path:
        Path to the ``.evtx`` file.
    event_ids:
        Optional allowlist of Event IDs to yield.  If ``None``, all events
        are yielded.

    Yields
    ------
    dict
        Raw event dict as returned by :func:`_parse_record`.

    Raises
    ------
    ImportError
        If ``python-evtx`` or ``lxml`` is not installed.
    FileNotFoundError
        If the EVTX file does not exist.
    """
    if not _EVTX_AVAILABLE:
        raise ImportError(
            "python-evtx is required for EVTX loading.  "
            "Install with: pip install python-evtx"
        )
    if not _LXML_AVAILABLE:
        raise ImportError(
            "lxml is required for EVTX loading.  "
            "Install with: pip install lxml"
        )

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"EVTX file not found: {path}")

    log.info("Opening EVTX file: %s", path)
    record_count = 0
    error_count = 0
    _LAST_STREAM_STATS["yielded"] = 0
    _LAST_STREAM_STATS["skipped"] = 0

    try:
        with evtx.Evtx(str(path)) as log_file:
            for record in log_file.records():
                try:
                    xml_str = record.xml()
                    parsed = _parse_record(xml_str)

                    if event_ids is not None and parsed["EventID"] not in event_ids:
                        continue

                    record_count += 1
                    yield parsed

                except Exception as exc:
                    error_count += 1
                    log.debug("Skipping malformed record: %s", exc)
                    continue
    finally:
        _LAST_STREAM_STATS["yielded"] = record_count
        _LAST_STREAM_STATS["skipped"] = error_count
        log.info(
            "EVTX stream complete: %d records yielded, %d errors skipped",
            record_count, error_count,
        )


def count_evtx(path: str | Path, *, event_ids: list[int] | None = None) -> int:
    """Return the number of records in an EVTX file (consumes the generator)."""
    return sum(1 for _ in stream_evtx(path, event_ids=event_ids))


# ---------------------------------------------------------------------------
# Synthetic EVTX-like loader (for testing without python-evtx)
# ---------------------------------------------------------------------------

def stream_csv_events(path: str | Path) -> Generator[dict[str, Any], None, None]:
    """
    Load a CSV file exported from Sysmon/Event Viewer and yield raw event
    dicts in the same format as :func:`stream_evtx`.

    Expected CSV columns (case-insensitive):
        EventID, TimeCreated, Computer, Channel, Provider, + any EventData columns.

    This allows the pipeline to work on non-Windows machines using pre-exported
    CSV samples from ``data/samples/``.
    """
    import csv

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {path}")

    log.info("Opening CSV event file: %s", path)
    record_count = 0

    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            # Normalize column names to title-case
            normalized = {k.strip(): v.strip() for k, v in row.items()}

            event_data = {
                k: v for k, v in normalized.items()
                if k not in {"EventID", "TimeCreated", "Computer", "Channel", "Provider"}
            }

            try:
                event_id = int(normalized.get("EventID", -1))
            except ValueError:
                event_id = -1

            record_count += 1
            yield {
                "EventID": event_id,
                "TimeCreated": normalized.get("TimeCreated", ""),
                "Computer": normalized.get("Computer", ""),
                "Channel": normalized.get("Channel", "Sysmon"),
                "Provider": normalized.get("Provider", "Microsoft-Windows-Sysmon"),
                "EventData": event_data,
                "_raw_xml": "",
            }

    log.info("CSV stream complete: %d records yielded", record_count)