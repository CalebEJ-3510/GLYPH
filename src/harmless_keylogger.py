"""
Harmless Keylogger Telemetry Harness
=====================================
PURPOSE
-------
Generate realistic Windows telemetry (Sysmon events, registry writes, DLL
loads) that mimics each keylogging technique class — WITHOUT ever capturing,
storing, or exfiltrating actual keystrokes.

This module is a **detection test harness**, not a keylogger.  It exercises
the OS APIs that real keyloggers use so that the detection engine has
authentic artifacts to detect.

SAFETY GATES
------------
1. Must be invoked with ``--i-understand-this-is-for-lab-use-only`` flag.
2. Hostname must appear in the ``ALLOWED_HOSTS`` allowlist below.
3. Refuses to run if it cannot detect a hypervisor (VM check).

USAGE
-----
    python -m src.harmless_keylogger --i-understand-this-is-for-lab-use-only --technique hook
    python -m src.harmless_keylogger --i-understand-this-is-for-lab-use-only --technique poll --duration 10
    python -m src.harmless_keylogger --i-understand-this-is-for-lab-use-only --technique rawinput
    python -m src.harmless_keylogger --i-understand-this-is-for-lab-use-only --technique all

TECHNIQUES
----------
hook
    Installs a WH_KEYBOARD_LL hook via SetWindowsHookEx, then immediately
    removes it.  Generates Sysmon ID 7 (user32.dll load).

poll
    Enters a tight GetAsyncKeyState polling loop for ``--duration`` seconds
    without recording any key state.  Generates CPU/timing artifacts.

rawinput
    Calls RegisterRawInputDevices for keyboard, then immediately unregisters.

injection
    Spawns notepad.exe and uses CreateRemoteThread to inject a no-op stub
    (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread).  The stub
    does nothing except return immediately.  Generates Sysmon ID 8.

NOTE: This file is Windows-only.  On non-Windows platforms it prints a
      warning and exits cleanly.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import platform
import socket
import struct
import sys
import time
import logging
import subprocess
from typing import NoReturn

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety configuration — add your lab VM hostname here
# ---------------------------------------------------------------------------

ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "LABVM",
        "KEYLOGGER-LAB",
        "WIN10-SANDBOX",
        "DETECTION-VM",
        "TESTVM",
        "SANDBOX",
        # Add your VM hostname (case-insensitive match applied below):
        # "MY-LAB-VM",
    }
)

# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------

def _abort(msg: str) -> NoReturn:
    print(f"\n[ABORT] {msg}", file=sys.stderr)
    sys.exit(1)


def _check_safety_flag(args: argparse.Namespace) -> None:
    if not getattr(args, "i_understand_this_is_for_lab_use_only", False):
        _abort(
            "Safety flag not set.\n"
            "This harness must be run with:\n"
            "  --i-understand-this-is-for-lab-use-only\n"
            "Only run inside an isolated lab VM."
        )


def _check_hostname() -> None:
    hostname = socket.gethostname().upper()
    allowed_upper = {h.upper() for h in ALLOWED_HOSTS}
    if hostname not in allowed_upper:
        _abort(
            f"Hostname '{hostname}' is not in the allowed-hosts list.\n"
            f"Add it to ALLOWED_HOSTS in src/harmless_keylogger.py before running.\n"
            f"Allowed: {sorted(ALLOWED_HOSTS)}"
        )
    log.info("Hostname check passed: %s", hostname)


def _check_vm() -> None:
    """Refuse to run outside a VM by checking for common hypervisor indicators."""
    if platform.system() != "Windows":
        return  # non-Windows: skip (will fail later anyway)

    indicators = [
        # Registry keys present in VirtualBox / VMware / Hyper-V
        r"HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions",
        r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
        r"HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    ]
    import winreg  # type: ignore[import]
    found = False
    for key_path in indicators:
        hive_str, subkey = key_path.split("\\", 1)
        hive = winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(hive, subkey):
                found = True
                break
        except FileNotFoundError:
            continue

    if not found:
        # Also check CPUID hypervisor bit via WMI as fallback
        try:
            result = subprocess.run(
                ["wmic", "computersystem", "get", "model"],
                capture_output=True, text=True, timeout=5
            )
            model = result.stdout.lower()
            if any(v in model for v in ("virtual", "vmware", "vbox", "hyper-v", "qemu", "xen")):
                found = True
        except Exception:
            pass

    if not found:
        _abort(
            "No hypervisor detected.  This harness must only run inside a VM.\n"
            "If you are in a VM, add a registry indicator or update _check_vm()."
        )
    log.info("VM check passed.")


# ---------------------------------------------------------------------------
# Windows API helpers (ctypes)
# ---------------------------------------------------------------------------

def _require_windows() -> None:
    if platform.system() != "Windows":
        _abort("This harness requires Windows.  Run inside a Windows lab VM.")


# ---------------------------------------------------------------------------
# Technique: hook
# ---------------------------------------------------------------------------

def technique_hook() -> None:
    """
    Install a WH_KEYBOARD_LL low-level keyboard hook via SetWindowsHookEx,
    then immediately remove it with UnhookWindowsHookEx.

    This generates:
      - Sysmon Event ID 7: user32.dll image load (if not already loaded)
      - Process activity consistent with hook installation

    No keystrokes are captured — the hook callback immediately returns
    CallNextHookEx without inspecting the nCode/wParam/lParam.
    """
    _require_windows()
    import ctypes.wintypes as wt

    user32 = ctypes.WinDLL("user32", use_last_error=True)

    WH_KEYBOARD_LL = 13
    HC_ACTION = 0

    # No-op hook procedure: immediately pass to next hook
    HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_int, wt.WPARAM, wt.LPARAM)

    def _noop_hook(nCode: int, wParam: int, lParam: int) -> int:
        return user32.CallNextHookEx(None, nCode, wParam, lParam)

    hook_proc = HOOKPROC(_noop_hook)

    log.info("[hook] Installing WH_KEYBOARD_LL hook ...")
    hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, hook_proc, None, 0)
    if not hook:
        err = ctypes.get_last_error()
        log.warning("[hook] SetWindowsHookExW failed (error %d) — may need elevated privileges", err)
        return

    log.info("[hook] Hook installed (handle=0x%x).  Sleeping 1s for telemetry capture ...", hook)
    time.sleep(1)

    log.info("[hook] Removing hook ...")
    user32.UnhookWindowsHookEx(hook)
    log.info("[hook] Hook removed.  Technique complete.")


# ---------------------------------------------------------------------------
# Technique: poll
# ---------------------------------------------------------------------------

def technique_poll(duration: float = 5.0) -> None:
    """
    Enter a tight GetAsyncKeyState polling loop for ``duration`` seconds
    without recording any key state.

    This generates:
      - High-frequency Win32 API call pattern (sub-20ms cadence)
      - CPU usage spike consistent with polling-based keyloggers
      - No hook artifact (tests the heuristic/statistical detection lane)

    Key states are read but immediately discarded.
    """
    _require_windows()
    import ctypes.wintypes as wt

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetAsyncKeyState.restype = ctypes.c_short
    user32.GetAsyncKeyState.argtypes = [ctypes.c_int]

    log.info("[poll] Starting GetAsyncKeyState polling loop for %.1fs ...", duration)
    end_time = time.monotonic() + duration
    poll_count = 0

    while time.monotonic() < end_time:
        for vk in range(0x08, 0x5A):  # VK_BACK through VK_Z
            _ = user32.GetAsyncKeyState(vk)  # result intentionally discarded
        poll_count += 1
        # ~10ms sleep to simulate a real polling keylogger cadence
        time.sleep(0.010)

    log.info("[poll] Polling complete.  %d poll cycles in %.1fs.", poll_count, duration)


# ---------------------------------------------------------------------------
# Technique: rawinput
# ---------------------------------------------------------------------------

def technique_rawinput() -> None:
    """
    Call RegisterRawInputDevices to register for keyboard raw input,
    then immediately unregister.

    This generates:
      - Raw input device registration event (detectable via ETW/Sysmon)
      - No keystrokes captured — the message pump is never started
    """
    _require_windows()
    import ctypes.wintypes as wt

    user32 = ctypes.WinDLL("user32", use_last_error=True)

    # RAWINPUTDEVICE structure
    class RAWINPUTDEVICE(ctypes.Structure):
        _fields_ = [
            ("usUsagePage", ctypes.c_ushort),
            ("usUsage",     ctypes.c_ushort),
            ("dwFlags",     ctypes.c_ulong),
            ("hwndTarget",  wt.HWND),
        ]

    HID_USAGE_PAGE_GENERIC = 0x01
    HID_USAGE_GENERIC_KEYBOARD = 0x06
    RIDEV_INPUTSINK = 0x00000100
    RIDEV_REMOVE    = 0x00000001

    rid = RAWINPUTDEVICE(
        usUsagePage=HID_USAGE_PAGE_GENERIC,
        usUsage=HID_USAGE_GENERIC_KEYBOARD,
        dwFlags=RIDEV_INPUTSINK,
        hwndTarget=None,
    )

    log.info("[rawinput] Registering raw input device (keyboard) ...")
    ok = user32.RegisterRawInputDevices(
        ctypes.byref(rid), 1, ctypes.sizeof(RAWINPUTDEVICE)
    )
    if not ok:
        err = ctypes.get_last_error()
        log.warning("[rawinput] RegisterRawInputDevices failed (error %d)", err)
        return

    log.info("[rawinput] Registered.  Sleeping 1s for telemetry capture ...")
    time.sleep(1)

    # Unregister
    rid_remove = RAWINPUTDEVICE(
        usUsagePage=HID_USAGE_PAGE_GENERIC,
        usUsage=HID_USAGE_GENERIC_KEYBOARD,
        dwFlags=RIDEV_REMOVE,
        hwndTarget=None,
    )
    user32.RegisterRawInputDevices(
        ctypes.byref(rid_remove), 1, ctypes.sizeof(RAWINPUTDEVICE)
    )
    log.info("[rawinput] Unregistered.  Technique complete.")


# ---------------------------------------------------------------------------
# Technique: injection (no-op shellcode)
# ---------------------------------------------------------------------------

def technique_injection() -> None:
    """
    Spawn notepad.exe, inject a no-op shellcode stub via the classic
    VirtualAllocEx → WriteProcessMemory → CreateRemoteThread sequence,
    then terminate notepad.

    The stub is a single RET instruction (0xC3 on x86/x64) — it does
    nothing except return immediately.

    This generates:
      - Sysmon Event ID 1: notepad.exe process create
      - Sysmon Event ID 8: CreateRemoteThread into notepad.exe
    """
    _require_windows()
    import ctypes.wintypes as wt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT         = 0x1000
    MEM_RESERVE        = 0x2000
    PAGE_EXECUTE_READ  = 0x20

    # Spawn notepad as the injection target
    log.info("[injection] Spawning notepad.exe as injection target ...")
    proc = subprocess.Popen(["notepad.exe"])
    time.sleep(0.5)  # let it initialize

    pid = proc.pid
    log.info("[injection] Target PID: %d", pid)

    # Open target process
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        err = ctypes.get_last_error()
        log.warning("[injection] OpenProcess failed (error %d)", err)
        proc.terminate()
        return

    try:
        # No-op shellcode: just RET (0xC3)
        shellcode = b"\xC3"

        # Allocate memory in target
        remote_mem = kernel32.VirtualAllocEx(
            h_process, None, len(shellcode),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ
        )
        if not remote_mem:
            err = ctypes.get_last_error()
            log.warning("[injection] VirtualAllocEx failed (error %d)", err)
            return

        log.info("[injection] Allocated remote memory at 0x%x", remote_mem)

        # Write shellcode
        written = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(
            h_process, remote_mem,
            shellcode, len(shellcode),
            ctypes.byref(written)
        )
        if not ok:
            err = ctypes.get_last_error()
            log.warning("[injection] WriteProcessMemory failed (error %d)", err)
            return

        log.info("[injection] Wrote %d bytes.  Creating remote thread ...", written.value)

        # Create remote thread — this is the Sysmon ID 8 trigger
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, remote_mem, None, 0, None
        )
        if not h_thread:
            err = ctypes.get_last_error()
            log.warning("[injection] CreateRemoteThread failed (error %d)", err)
            return

        log.info("[injection] Remote thread created (handle=0x%x).  Waiting ...", h_thread)
        kernel32.WaitForSingleObject(h_thread, 2000)
        kernel32.CloseHandle(h_thread)
        log.info("[injection] Remote thread finished.  Technique complete.")

    finally:
        kernel32.CloseHandle(h_process)
        proc.terminate()
        log.info("[injection] notepad.exe terminated.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

TECHNIQUES = {
    "hook":      technique_hook,
    "poll":      technique_poll,
    "rawinput":  technique_rawinput,
    "injection": technique_injection,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Harmless keylogger telemetry harness (lab use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--i-understand-this-is-for-lab-use-only",
        dest="i_understand_this_is_for_lab_use_only",
        action="store_true",
        default=False,
        help="Required safety acknowledgement flag",
    )
    p.add_argument(
        "--technique",
        choices=list(TECHNIQUES.keys()) + ["all"],
        default="all",
        help="Which keylogging technique to simulate (default: all)",
    )
    p.add_argument(
        "--duration",
        type=float,
        default=5.0,
        help="Duration in seconds for the polling technique (default: 5.0)",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Safety gates — must pass all three before any technique runs
    _check_safety_flag(args)
    _check_hostname()
    _check_vm()

    print("\n[*] Harmless Keylogger Telemetry Harness")
    print("[*] All key states are discarded — no keystrokes are captured.\n")

    techniques_to_run = (
        list(TECHNIQUES.keys()) if args.technique == "all" else [args.technique]
    )

    for name in techniques_to_run:
        print(f"[>] Running technique: {name}")
        fn = TECHNIQUES[name]
        if name == "poll":
            fn(duration=args.duration)  # type: ignore[call-arg]
        else:
            fn()
        print(f"[+] Technique '{name}' complete.\n")

    print("[*] All techniques finished.  Check Sysmon logs for generated artifacts.")


if __name__ == "__main__":
    main()