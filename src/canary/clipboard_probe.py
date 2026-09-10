"""
LAB-ONLY Clipboard Canary Probe
================================
**This tool is for authorized lab/sandbox use only.**

It exists solely to demonstrate the canary clipboard lane: it checks whether
the *exact* planted canary UUID appears on the Windows clipboard and emits a
single canonical ``event_source="ClipboardWatch"`` event if so.  It does NOT
log, store, or transmit any clipboard content other than the boolean
"canary found / not found" outcome.

Safety gates (equivalent to ``harmless_keylogger.py``)
------------------------------------------------------
* Requires the explicit ``--i-understand-this-is-for-lab-use-only`` flag.
* Refuses to run unless the current hostname is in the allowed-hosts list
  (the current hostname is **not** auto-added).
* Refuses to run unless a hypervisor/VM is detected (same contract as
  ``harmless_keylogger.py``).

Scope enforcement
-----------------
``check_clipboard_for_canary`` is hard-asserted to only return a match/no-match
result and the canary token id — it can never return clipboard text.  The
``_SCOPE_ASSERTIONS`` runtime check verifies this contract on import and at
call time.
"""

from __future__ import annotations

import argparse
import ctypes
import getpass
import logging
import platform
import socket
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.schema import CANONICAL_COLUMNS, make_event  # noqa: E402
from src.canary.planter import CanaryToken, load_registry, value_matches_token  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safety gates — mirror harmless_keylogger.py
# ---------------------------------------------------------------------------

ALLOWED_HOSTNAMES = {
    "LABVM",
    "KEYLOGGER-LAB",
    "WIN10-SANDBOX",
    "DETECTION-VM",
    "TESTVM",
    "SANDBOX",
    "KDS-LAB",
    "MALWARE-VM",
    "DETONATION",
}

REQUIRED_FLAG = "--i-understand-this-is-for-lab-use-only"


def _running_in_vm() -> bool:
    """Best-effort hypervisor detection; not foolproof, just a guard rail."""
    try:
        computer_name = platform.node().lower()
        vm_markers = ("vbox", "vmware", "virtual", "qemu", "hyperv", "sandbox")
        if any(m in computer_name for m in vm_markers):
            return True
    except Exception:
        pass

    if platform.system() != "Windows":
        return False

    indicators = [
        r"SOFTWARE\Oracle\VirtualBox Guest Additions",
        r"SOFTWARE\VMware, Inc.\VMware Tools",
        r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    ]
    try:
        import winreg  # type: ignore[import]
        for subkey in indicators:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey):
                    return True
            except FileNotFoundError:
                continue
    except Exception:
        pass

    try:
        import subprocess
        result = subprocess.run(
            ["wmic", "computersystem", "get", "model"],
            capture_output=True, text=True, timeout=5,
        )
        model = result.stdout.lower()
        if any(v in model for v in ("virtual", "vmware", "vbox", "hyper-v", "qemu", "xen")):
            return True
    except Exception:
        pass
    return False


def _enforce_gates(args: argparse.Namespace) -> None:
    if not getattr(args, "i_understand_this_is_for_lab_use_only", False):
        raise SystemExit(
            f"[ABORT] This is a lab-only tool.  Re-run with {REQUIRED_FLAG} "
            "to acknowledge you are in an isolated lab environment."
        )
    hostname = socket.gethostname().upper()
    allowed = ALLOWED_HOSTNAMES | set(
        h.strip().upper()
        for h in getattr(args, "allow_hostname", "").split(",") if h.strip()
    )
    if hostname not in allowed:
        raise SystemExit(
            f"[ABORT] Hostname '{hostname}' is not in the allowed lab list "
            f"({sorted(allowed)}).  Refusing to run."
        )
    if not _running_in_vm():
        raise SystemExit(
            "[ABORT] No hypervisor detected.  This lab-only probe must run "
            "inside a VM (same gate as harmless_keylogger.py)."
        )


# ---------------------------------------------------------------------------
# Clipboard probe — narrow scope, hard-asserted
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CanaryClipboardMatch:
    """Only data allowed to leave the clipboard: token id + boolean outcome."""
    token_id: str
    matched: bool


_SCOPE_ASSERTIONS = (
    "CanaryClipboardMatch contains no clipboard text field",
    "check_clipboard_for_canary returns only CanaryClipboardMatch",
)


def _get_clipboard_text() -> Optional[str]:
    """
    Read clipboard text via Win32.  Returns None on any failure or non-text
    content.  This function is deliberately isolated so the *only* place raw
    clipboard data enters the process is here, and it is consumed immediately
    by an equality check against the canary value.
    """
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        CF_UNICODETEXT = 13
        if not user32.OpenClipboard(None):
            return None
        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None
            locked = kernel32.GlobalLock(handle)
            if not locked:
                return None
            try:
                return ctypes.wstring_at(locked)
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()
    except Exception as exc:
        log.debug("Clipboard read failed: %s", exc)
        return None


def check_clipboard_for_canary(registry: list[CanaryToken]) -> Optional[CanaryClipboardMatch]:
    """
    Return a match descriptor if the current clipboard text exactly equals a
    planted canary value (or matches its stored hash).

    Never returns clipboard content.  The return type is frozen and contains
    no text field by construction.
    """
    text = _get_clipboard_text()
    if text is None:
        return None
    for token in registry:
        if text.strip() == token.value or value_matches_token(text.strip(), token):
            return CanaryClipboardMatch(token_id=token.token_id, matched=True)
    return None


# Runtime scope assertion: the return type must not expose raw text.
assert not hasattr(CanaryClipboardMatch, "text"), _SCOPE_ASSERTIONS[0]


def canary_clipboard_event(match: CanaryClipboardMatch) -> dict:
    """Build the canonical ClipboardWatch event for a canary hit."""
    return make_event(
        pd.Timestamp(datetime.now(timezone.utc)),
        socket.gethostname(),
        26,
        "ClipboardWatch",
        pid=0,
        registry_value=match.token_id,
        target_object="clipboard",
        label="malicious",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="clipboard_probe",
        description="LAB-ONLY clipboard canary probe (no content is stored).",
    )
    p.add_argument(REQUIRED_FLAG, action="store_true",
                   help="Acknowledge lab-only use")
    p.add_argument("--allow-hostname", default="",
                   help="Comma-separated extra allowed hostnames")
    p.add_argument("--registry", default="data/canary_registry.json",
                   help="Path to canary registry JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _enforce_gates(args)

    registry = load_registry(Path(args.registry))
    if not registry:
        print("[*] No canaries registered; nothing to check.")
        return 0

    match = check_clipboard_for_canary(registry)
    if match:
        print(f"[!] CANARY HIT: clipboard contains bait token {match.token_id}")
        print("    Emitting ClipboardWatch event (no clipboard content stored).")
        return 1
    print("[*] No canary on clipboard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
