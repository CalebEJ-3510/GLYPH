"""
Synthetic Dataset Generator (Phase 7)
=======================================
Procedurally generates labeled EVTX-like event sessions mixing benign noise
with each keylogging technique at varying stealth levels.

Output: CSV files in ``data/samples/`` that can be loaded by the pipeline
without requiring a real Windows VM or Sysmon installation.

Stealth levels
--------------
0 (obvious)   : standard technique, original binary name, immediate execution
1 (moderate)  : renamed binary, slight delay before hook install
2 (stealthy)  : renamed binary, delayed execution, jittered polling cadence,
                randomized disk-write timing

Usage
-----
    python scripts/generate_synthetic_dataset.py --sessions 200 --output data/samples/
    python scripts/generate_synthetic_dataset.py --technique hook --stealth 2 --sessions 50
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.schema import CANONICAL_COLUMNS, make_event
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BENIGN_PROCESS_NAMES = [
    "notepad.exe", "calc.exe", "mspaint.exe", "wordpad.exe",
    "explorer.exe", "chrome.exe", "firefox.exe", "code.exe",
    "python.exe", "cmd.exe", "powershell.exe", "taskmgr.exe",
]

BENIGN_PARENTS = [
    "explorer.exe", "svchost.exe", "cmd.exe", "powershell.exe",
]

SYSTEM_DLLS = [
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "msvcrt.dll",
    "combase.dll", "rpcrt4.dll", "sechost.dll", "advapi32.dll",
]

KEYLOGGER_NAMES_OBVIOUS = [
    "keylogger.exe", "kbhook.exe", "inputcap.exe",
]

KEYLOGGER_NAMES_RENAMED = [
    "svchost32.exe", "updater.exe", "helper.exe", "runtime.exe",
    "service.exe", "agent.exe", "monitor.exe", "sync.exe",
]

STAGING_PATHS = [
    "C:\\Users\\User\\AppData\\Local\\Temp\\",
    "C:\\Users\\User\\AppData\\Roaming\\",
    "C:\\Users\\User\\Downloads\\",
    "C:\\Users\\User\\Desktop\\",
]

SYSTEM_PATHS = [
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Program Files\\",
]

HOST = "LABVM"
BASE_PID = 1000


# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------

def _ts(base: datetime, offset_s: float) -> pd.Timestamp:
    ts = pd.Timestamp(base + timedelta(seconds=offset_s))
    if ts.tzinfo is not None:
        return ts.tz_convert("UTC")
    return ts.tz_localize("UTC")


def _make_proc_create(
    base: datetime,
    offset: float,
    pid: int,
    ppid: int,
    name: str,
    path: str,
    parent: str,
    signed: bool,
    label: str,
    technique_tag: str,
) -> dict:
    return make_event(
        timestamp=_ts(base, offset),
        host=HOST,
        event_id=1,
        event_source="Sysmon",
        process_name=name,
        process_path=path + name,
        process_hash=uuid.uuid4().hex,
        pid=pid,
        ppid=ppid,
        parent_process_name=parent,
        signed=signed,
        label=label,
        technique_tag=technique_tag,
        raw_fields={"CommandLine": path + name},
    )


def _make_dll_load(
    base: datetime,
    offset: float,
    pid: int,
    proc_name: str,
    dll: str,
    signed: bool,
    label: str,
    technique_tag: str,
) -> dict:
    return make_event(
        timestamp=_ts(base, offset),
        host=HOST,
        event_id=7,
        event_source="Sysmon",
        process_name=proc_name,
        pid=pid,
        image_loaded=f"C:\\Windows\\System32\\{dll}",
        signed=signed,
        label=label,
        technique_tag=technique_tag,
        raw_fields={},
    )


def _make_reg_write(
    base: datetime,
    offset: float,
    pid: int,
    proc_name: str,
    key: str,
    value: str,
    label: str,
    technique_tag: str,
) -> dict:
    return make_event(
        timestamp=_ts(base, offset),
        host=HOST,
        event_id=13,
        event_source="Sysmon",
        process_name=proc_name,
        pid=pid,
        registry_key=key,
        registry_value=value,
        target_object=key,
        label=label,
        technique_tag=technique_tag,
        raw_fields={},
    )


def _make_remote_thread(
    base: datetime,
    offset: float,
    pid: int,
    proc_name: str,
    target: str,
    label: str,
    technique_tag: str,
) -> dict:
    return make_event(
        timestamp=_ts(base, offset),
        host=HOST,
        event_id=8,
        event_source="Sysmon",
        process_name=proc_name,
        pid=pid,
        target_object=target,
        label=label,
        technique_tag=technique_tag,
        raw_fields={},
    )


def _make_raw_access(
    base: datetime,
    offset: float,
    pid: int,
    proc_name: str,
    device: str,
    label: str,
    technique_tag: str,
) -> dict:
    return make_event(
        timestamp=_ts(base, offset),
        host=HOST,
        event_id=9,
        event_source="Sysmon",
        process_name=proc_name,
        pid=pid,
        target_object=device,
        label=label,
        technique_tag=technique_tag,
        raw_fields={},
    )


# ---------------------------------------------------------------------------
# Benign session generator
# ---------------------------------------------------------------------------

def generate_benign_session(pid: int, base: datetime) -> list[dict]:
    """Generate a realistic benign process session."""
    name = random.choice(BENIGN_PROCESS_NAMES)
    path = random.choice(SYSTEM_PATHS)
    parent = random.choice(BENIGN_PARENTS)
    events = []

    # Process create
    events.append(_make_proc_create(
        base, 0.0, pid, pid - 1, name, path, parent,
        signed=True, label="benign", technique_tag="",
    ))

    # Load some system DLLs
    for i, dll in enumerate(random.sample(SYSTEM_DLLS, k=random.randint(2, 5))):
        events.append(_make_dll_load(
            base, 0.1 + i * 0.05, pid, name, dll,
            signed=True, label="benign", technique_tag="",
        ))

    # Occasional registry read (not write to Run keys)
    if random.random() < 0.3:
        events.append(_make_reg_write(
            base, 0.5, pid, name,
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "DisplayName",
            label="benign", technique_tag="",
        ))

    return events


# ---------------------------------------------------------------------------
# Malicious session generators
# ---------------------------------------------------------------------------

def generate_hook_session(pid: int, base: datetime, stealth: int = 0) -> list[dict]:
    """Generate a hook-based keylogger session."""
    if stealth == 0:
        name = random.choice(KEYLOGGER_NAMES_OBVIOUS)
        path = random.choice(STAGING_PATHS)
        delay = 0.0
        signed = False
    elif stealth == 1:
        name = random.choice(KEYLOGGER_NAMES_RENAMED)
        path = random.choice(STAGING_PATHS)
        delay = random.uniform(5.0, 30.0)
        signed = False
    else:
        name = random.choice(KEYLOGGER_NAMES_RENAMED)
        path = "C:\\Windows\\System32\\"  # masquerade as system
        delay = random.uniform(30.0, 120.0)
        signed = False  # still unsigned — hard to fake

    events = []
    events.append(_make_proc_create(
        base, 0.0, pid, pid - 1, name, path,
        random.choice(BENIGN_PARENTS),
        signed=signed, label="malicious", technique_tag="hook",
    ))

    # Load system DLLs first (camouflage)
    for i, dll in enumerate(random.sample(SYSTEM_DLLS[:4], k=2)):
        events.append(_make_dll_load(
            base, 0.1 + i * 0.05, pid, name, dll,
            signed=True, label="malicious", technique_tag="hook",
        ))

    # Load user32.dll (hook install)
    events.append(_make_dll_load(
        base, delay + 0.2, pid, name, "user32.dll",
        signed=True, label="malicious", technique_tag="hook",
    ))

    # Persist via Run key
    events.append(_make_reg_write(
        base, delay + 0.3, pid, name,
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        f"{name}={path}{name}",
        label="malicious", technique_tag="hook",
    ))

    # Periodic disk writes (flush buffer)
    flush_interval = 30.0 if stealth < 2 else random.uniform(20.0, 60.0)
    for i in range(4):
        jitter = 0.0 if stealth < 2 else random.uniform(-5.0, 5.0)
        events.append(_make_reg_write(
            base, delay + flush_interval * (i + 1) + jitter, pid, name,
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            f"update_{i}",
            label="malicious", technique_tag="hook",
        ))

    return events


def generate_poll_session(pid: int, base: datetime, stealth: int = 0) -> list[dict]:
    """Generate a polling-based keylogger session (no hook artifact)."""
    if stealth == 0:
        name = random.choice(KEYLOGGER_NAMES_OBVIOUS)
        path = random.choice(STAGING_PATHS)
    else:
        name = random.choice(KEYLOGGER_NAMES_RENAMED)
        path = random.choice(STAGING_PATHS)

    events = []
    events.append(_make_proc_create(
        base, 0.0, pid, pid - 1, name, path,
        random.choice(["cmd.exe", "powershell.exe", "wscript.exe"]),
        signed=False, label="malicious", technique_tag="poll",
    ))

    # Load user32.dll (needed for GetAsyncKeyState)
    events.append(_make_dll_load(
        base, 0.1, pid, name, "user32.dll",
        signed=True, label="malicious", technique_tag="poll",
    ))

    # No hook registry writes — this is the distinguishing feature of polling
    # Periodic disk writes
    flush_interval = 30.0 if stealth == 0 else random.uniform(15.0, 90.0)
    for i in range(5):
        jitter = 0.0 if stealth == 0 else random.uniform(-10.0, 10.0)
        events.append(_make_reg_write(
            base, flush_interval * (i + 1) + jitter, pid, name,
            "HKCU\\SOFTWARE\\AppData\\poll_log",
            f"entry_{i}",
            label="malicious", technique_tag="poll",
        ))

    return events


def generate_rawinput_session(pid: int, base: datetime, stealth: int = 0) -> list[dict]:
    """Generate a raw-input keylogger session."""
    name = random.choice(KEYLOGGER_NAMES_RENAMED if stealth > 0 else KEYLOGGER_NAMES_OBVIOUS)
    path = random.choice(STAGING_PATHS)

    events = []
    events.append(_make_proc_create(
        base, 0.0, pid, pid - 1, name, path,
        random.choice(BENIGN_PARENTS),
        signed=False, label="malicious", technique_tag="rawinput",
    ))

    # Load user32.dll AND hid.dll (raw input combo)
    events.append(_make_dll_load(
        base, 0.1, pid, name, "user32.dll",
        signed=True, label="malicious", technique_tag="rawinput",
    ))
    events.append(_make_dll_load(
        base, 0.15, pid, name, "hid.dll",
        signed=True, label="malicious", technique_tag="rawinput",
    ))

    return events


def generate_injection_session(pid: int, base: datetime, stealth: int = 0) -> list[dict]:
    """Generate an injection-based keylogger session."""
    name = random.choice(KEYLOGGER_NAMES_RENAMED if stealth > 0 else KEYLOGGER_NAMES_OBVIOUS)
    path = random.choice(STAGING_PATHS)
    target = random.choice(["chrome.exe", "firefox.exe", "explorer.exe"])

    events = []
    events.append(_make_proc_create(
        base, 0.0, pid, pid - 1, name, path,
        random.choice(["cmd.exe", "powershell.exe"]),
        signed=False, label="malicious", technique_tag="injection",
    ))

    # Load injection-related DLLs
    for dll in ["ntdll.dll", "kernel32.dll"]:
        events.append(_make_dll_load(
            base, 0.1, pid, name, dll,
            signed=True, label="malicious", technique_tag="injection",
        ))

    # CreateRemoteThread into target
    delay = 0.5 if stealth == 0 else random.uniform(5.0, 30.0)
    events.append(_make_remote_thread(
        base, delay, pid, name, target,
        label="malicious", technique_tag="injection",
    ))

    return events


def generate_driver_session(pid: int, base: datetime, stealth: int = 0) -> list[dict]:
    """Generate a driver/kernel-level keylogger session."""
    name = random.choice(KEYLOGGER_NAMES_RENAMED if stealth > 0 else KEYLOGGER_NAMES_OBVIOUS)
    path = random.choice(STAGING_PATHS)

    events = []
    events.append(_make_proc_create(
        base, 0.0, pid, pid - 1, name, path,
        "cmd.exe",
        signed=False, label="malicious", technique_tag="driver",
    ))

    # Register keyboard filter driver service
    events.append(_make_reg_write(
        base, 0.2, pid, name,
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\kbfilter",
        "ImagePath=C:\\Windows\\System32\\drivers\\kbfilter.sys",
        label="malicious", technique_tag="driver",
    ))

    # RawAccessRead on keyboard device
    events.append(_make_raw_access(
        base, 0.5, pid, name,
        "\\Device\\KeyboardClass0",
        label="malicious", technique_tag="driver",
    ))

    return events


# ---------------------------------------------------------------------------
# Dataset generator
# ---------------------------------------------------------------------------

TECHNIQUE_GENERATORS = {
    "hook":      generate_hook_session,
    "poll":      generate_poll_session,
    "rawinput":  generate_rawinput_session,
    "injection": generate_injection_session,
    "driver":    generate_driver_session,
}


def generate_dataset(
    n_benign: int = 100,
    n_malicious_per_technique: int = 20,
    techniques: list[str] | None = None,
    stealth_levels: list[int] | None = None,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Generate a labeled synthetic dataset.

    Parameters
    ----------
    n_benign:
        Number of benign sessions to generate.
    n_malicious_per_technique:
        Number of malicious sessions per technique.
    techniques:
        List of technique names to include.  Defaults to all.
    stealth_levels:
        List of stealth levels (0, 1, 2) to cycle through.
    seed:
        Random seed for reproducibility.

    Returns
    -------
    pd.DataFrame
        Canonical DataFrame with all generated events.
    """
    random.seed(seed)

    if techniques is None:
        techniques = list(TECHNIQUE_GENERATORS.keys())
    if stealth_levels is None:
        stealth_levels = [0, 1, 2]

    all_events: list[dict] = []
    pid = BASE_PID
    base_time = datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc)

    # Benign sessions
    for i in range(n_benign):
        session_base = base_time + timedelta(minutes=i * 2)
        events = generate_benign_session(pid, session_base)
        all_events.extend(events)
        pid += 1

    # Malicious sessions
    for technique in techniques:
        gen_fn = TECHNIQUE_GENERATORS[technique]
        for i in range(n_malicious_per_technique):
            stealth = stealth_levels[i % len(stealth_levels)]
            session_base = base_time + timedelta(
                hours=2, minutes=i * 3 + techniques.index(technique) * 60
            )
            events = gen_fn(pid, session_base, stealth=stealth)
            all_events.extend(events)
            pid += 1

    df = pd.DataFrame(all_events, columns=CANONICAL_COLUMNS)
    return df


def save_dataset(df: pd.DataFrame, output_dir: str | Path, name: str) -> Path:
    """Save a dataset DataFrame to CSV."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{name}.csv"
    df.to_csv(path, index=False)
    print(f"[+] Saved {len(df)} events ({df['pid'].nunique()} sessions) -> {path}")
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic labeled keylogger detection dataset"
    )
    parser.add_argument("--output", default="data/samples", help="Output directory")
    parser.add_argument("--sessions", type=int, default=200,
                        help="Number of benign sessions (default: 200)")
    parser.add_argument("--malicious", type=int, default=30,
                        help="Malicious sessions per technique (default: 30)")
    parser.add_argument("--technique", default="all",
                        choices=list(TECHNIQUE_GENERATORS.keys()) + ["all"])
    parser.add_argument("--stealth", type=int, default=None,
                        choices=[0, 1, 2],
                        help="Fixed stealth level (default: cycle 0,1,2)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    techniques = list(TECHNIQUE_GENERATORS.keys()) if args.technique == "all" else [args.technique]
    stealth_levels = [args.stealth] if args.stealth is not None else [0, 1, 2]

    print(f"[*] Generating synthetic dataset ...")
    print(f"    Benign sessions      : {args.sessions}")
    print(f"    Techniques           : {techniques}")
    print(f"    Malicious/technique  : {args.malicious}")
    print(f"    Stealth levels       : {stealth_levels}")
    print(f"    Seed                 : {args.seed}")

    df = generate_dataset(
        n_benign=args.sessions,
        n_malicious_per_technique=args.malicious,
        techniques=techniques,
        stealth_levels=stealth_levels,
        seed=args.seed,
    )

    # Split into benign and malicious for separate files
    benign_df    = df[df["label"] == "benign"]
    malicious_df = df[df["label"] == "malicious"]

    save_dataset(benign_df,    args.output, "benign_synthetic")
    save_dataset(malicious_df, args.output, "malicious_synthetic")
    save_dataset(df,           args.output, "combined_synthetic")

    print(f"\n[+] Dataset generation complete.")
    print(f"    Total events : {len(df)}")
    print(f"    Benign       : {len(benign_df)} events ({benign_df['pid'].nunique()} sessions)")
    print(f"    Malicious    : {len(malicious_df)} events ({malicious_df['pid'].nunique()} sessions)")


if __name__ == "__main__":
    main()