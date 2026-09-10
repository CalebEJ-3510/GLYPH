# Canonical Event Schema

This document defines the **canonical event schema** — the normalized data contract
that every component in the detection pipeline reads and writes. All ingestion
adapters (EVTX loader, live-tail, synthetic generator) MUST produce rows that
conform to this schema before events reach the detection engine.

---

## Field Reference

| Field | Type | Nullable | Description |
|---|---|---|---|
| `timestamp` | `datetime64[ns, UTC]` | No | UTC timestamp of the event |
| `host` | `str` | No | Hostname / machine name where the event originated |
| `event_id` | `int` | No | Windows Event ID (e.g. 1 = Process Create, 7 = Image Load) |
| `event_source` | `str` | No | Log channel: `"Sysmon"`, `"Security"`, `"Application"`, `"Synthetic"` |
| `process_name` | `str` | Yes | Executable filename only (e.g. `"notepad.exe"`) |
| `process_path` | `str` | Yes | Full image path (e.g. `"C:\Windows\notepad.exe"`) |
| `process_hash` | `str` | Yes | SHA-256 of the image (hex string, lowercase) |
| `pid` | `int` | Yes | Process ID |
| `ppid` | `int` | Yes | Parent Process ID |
| `parent_process_name` | `str` | Yes | Parent executable filename |
| `image_loaded` | `str` | Yes | DLL/image path for Image Load events (Sysmon ID 7) |
| `registry_key` | `str` | Yes | Full registry key path for registry events (ID 12/13/14) |
| `registry_value` | `str` | Yes | Registry value name |
| `target_object` | `str` | Yes | Generic target (registry key, file path, etc.) |
| `signed` | `bool` | Yes | Whether the image is Authenticode-signed |
| `signature` | `str` | Yes | Signer name if signed |
| `label` | `str` | Yes | Ground-truth label for synthetic/test data: `"benign"`, `"malicious"`, `"unknown"` |
| `technique_tag` | `str` | Yes | Technique identifier for labeled data: `"hook"`, `"poll"`, `"rawinput"`, `"injection"`, `"driver"` |
| `raw_fields` | `dict` | No | All original event fields preserved verbatim for forensics |

---

## Sysmon Event ID → Schema Mapping

| Sysmon ID | Event Name | Key fields populated |
|---|---|---|
| 1 | Process Create | `process_name`, `process_path`, `process_hash`, `pid`, `ppid`, `parent_process_name`, `signed`, `signature` |
| 7 | Image/DLL Load | `process_name`, `pid`, `image_loaded`, `signed`, `signature` |
| 8 | CreateRemoteThread | `process_name`, `pid`, `ppid` (source), `target_object` (target PID/process) |
| 9 | RawAccessRead | `process_name`, `pid`, `target_object` (device path) |
| 12 | Registry Object Create/Delete | `process_name`, `pid`, `registry_key`, `target_object` |
| 13 | Registry Value Set | `process_name`, `pid`, `registry_key`, `registry_value`, `target_object` |
| 14 | Registry Key/Value Rename | `process_name`, `pid`, `registry_key`, `registry_value`, `target_object` |

---

## Invariants

1. Every row MUST have a non-null `timestamp`, `host`, `event_id`, and `event_source`.
2. `raw_fields` MUST be a `dict` (never `None`); use `{}` if no extra fields exist.
3. `label` defaults to `"unknown"` for live/production data; only synthetic and
   manually-labeled data sets it to `"benign"` or `"malicious"`.
4. `process_hash` MUST be lowercase hex SHA-256 when present.
5. All path strings use backslash separators on Windows (as received from the OS);
   the detection engine normalizes to lowercase for comparisons.

---

## Version History

| Version | Date | Change |
|---|---|---|
| 1.0 | 2026-09-09 | Initial schema definition |