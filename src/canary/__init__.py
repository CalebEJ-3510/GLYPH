"""
Canary / Deception Detection Lane
=================================

A fourth detection lane based on *deception* rather than behavior.  Instead of
only watching for suspicious process behavior, this lane plants fake "bait"
credentials (canary tokens) and raises a near-zero-false-positive alert when
any process touches the exact, unguessable canary value.

Modules
-------
- :mod:`src.canary.planter`         — writes fake credential artifacts.
- :mod:`src.canary.watcher`         — scans session events for canary values.
- :mod:`src.canary.clipboard_probe` — LAB-ONLY clipboard canary check.

The canary lane has the highest weight of all four lanes because a match can
only mean one thing: something accessed the bait.
"""

from src.canary.planter import CanaryToken, plant_canaries, load_registry
from src.canary.watcher import CanaryMatch, check_canary_access

__all__ = [
    "CanaryToken",
    "plant_canaries",
    "load_registry",
    "CanaryMatch",
    "check_canary_access",
]
