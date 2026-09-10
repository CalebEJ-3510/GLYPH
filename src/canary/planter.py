"""
Canary Planter
==============
Writes realistic-but-fake "bait" credential artifacts to a target directory and
registers each one in a local canary registry so the watcher can later confirm
an access *without re-reading the bait file*.

Every canary embeds a unique, unguessable UUID.  If that exact UUID later shows
up in a process's telemetry (registry value, file path it read, clipboard
contents), it is unambiguous evidence of access — a random process should never
contain the specific planted value, so a match is near-zero-false-positive by
construction.

Safety
------
* All credentials are **structurally fake**: the credit-card string uses the
  well-known test pattern ``4111-1111-1111-1111`` (never a real, issuable
  number), passwords are random throwaway strings, and usernames are clearly
  synthetic.  Nothing here could be mistaken for real PII or a real credential.
* The registry stores only a **hash** of each canary value, never the raw value,
  so the registry file itself is not sensitive.

This module does NOT log, store, or transmit any real user data.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, asdict, field
from pathlib import Path

log = logging.getLogger(__name__)

# Default registry location (relative to the project root).
DEFAULT_REGISTRY = Path("data/canary_registry.json")

# A universally-recognised *test* card number.  This exact value is published
# by every major payment processor as a non-functional test card; it can never
# be confused with real PII and is safe to embed in a lab artifact.
TEST_CARD_PATTERN = "4111-1111-1111-1111"


@dataclass
class CanaryToken:
    """One planted bait artifact and its unguessable identifying value.

    Attributes
    ----------
    token_id:    short id for this canary (first 8 chars of the UUID).
    kind:        what sort of bait it is — "passwords_file", "credit_card",
                 or "clipboard".
    location:    where the bait was planted (file path or "clipboard").
    value:       the full canary string that an attacker would see/exfiltrate.
                 Contains the unique UUID so any later sighting is unambiguous.
    value_hash:  SHA-256 of ``value`` — stored in the registry so a match can
                 be confirmed without persisting the raw value.
    """
    token_id: str
    kind: str
    location: str
    value: str
    value_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.value_hash:
            self.value_hash = hashlib.sha256(self.value.encode("utf-8")).hexdigest()


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _make_password_block(uid: str) -> str:
    """Return a clearly-fake passwords.txt body embedding the canary UUID."""
    return (
        "# ==== DO NOT COMMIT - local dev credentials (SAMPLE/FAKE) ====\n"
        "# NOTE: these are placeholder values for a lab environment only.\n"
        f"admin@example.local        : hunter2-{uid[:6]}\n"
        f"svc_backup@example.local   : Backup!{uid[:8]}\n"
        f"test.user@example.local    : Passw0rd-{uid[:4]}\n"
        f"# recovery-token: {uid}\n"
    )


def plant_canaries(
    target_dir: Path,
    count: int = 3,
    registry_path: Path = DEFAULT_REGISTRY,
) -> list[CanaryToken]:
    """
    Plant ``count`` fake credential canaries under ``target_dir``.

    Writes a mix of bait artifacts (a fake passwords file, a fake
    credit-card-shaped note) each embedding a unique UUID.  Appends each
    token to the on-disk registry (hash only) and returns the live tokens
    (with raw values) for in-memory use by the watcher/tests.

    Parameters
    ----------
    target_dir:
        Directory to write the bait files into.  Created if missing.
    count:
        Number of canaries to plant (minimum 1).  Kinds cycle through
        passwords_file -> credit_card -> clipboard -> ...
    registry_path:
        Path to the JSON canary registry (value-hashes only).

    Returns
    -------
    list[CanaryToken]  (raw ``value`` included for the caller; only the hash
    is persisted to disk).
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    registry_path = Path(registry_path)
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    kinds = ["passwords_file", "credit_card", "clipboard"]
    tokens: list[CanaryToken] = []

    for i in range(count):
        uid = str(uuid.uuid4())
        kind = kinds[i % len(kinds)]

        if kind == "passwords_file":
            loc = target_dir / "passwords.txt"
            loc.write_text(_make_password_block(uid), encoding="utf-8")
            value = uid  # the unguessable marker an exfiltrator would carry
        elif kind == "credit_card":
            loc = target_dir / "card_note.txt"
            value = f"{TEST_CARD_PATTERN}|cvv:{uid[:3]}|ref:{uid}"
            loc.write_text(
                "# FAKE test card for UI development (non-functional)\n"
                f"card: {TEST_CARD_PATTERN}\nref: {uid}\n",
                encoding="utf-8",
            )
        else:  # clipboard
            # The clipboard canary is just the UUID string; the lab-only
            # clipboard_probe.py checks for its presence without ever logging
            # any other clipboard content.
            loc = "clipboard"
            value = uid

        token = CanaryToken(
            token_id=uid[:8],
            kind=kind,
            location=str(loc),
            value=value,
        )
        tokens.append(token)
        log.info("Planted %s canary %s at %s", kind, token.token_id, token.location)

    _append_registry(registry_path, tokens)
    return tokens


def _append_registry(registry_path: Path, tokens: list[CanaryToken]) -> None:
    """Append token metadata (value-HASH only) to the JSON registry."""
    existing: list[dict] = []
    if registry_path.exists():
        try:
            existing = json.loads(registry_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            log.warning("Canary registry %s unreadable; starting fresh.", registry_path)
            existing = []

    # Never persist the raw value — only enough to confirm a later match.
    existing.extend(
        {
            "token_id": t.token_id,
            "kind": t.kind,
            "location": t.location,
            "value_hash": t.value_hash,
        }
        for t in tokens
    )
    registry_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def load_registry(registry_path: Path = DEFAULT_REGISTRY) -> list[CanaryToken]:
    """
    Load the canary registry.

    Returns tokens whose ``value`` field is EMPTY (only the hash is known).
    Use :func:`src.canary.watcher.value_matches_token` to test a candidate
    raw value against a token's stored hash.
    """
    registry_path = Path(registry_path)
    if not registry_path.exists():
        return []
    try:
        rows = json.loads(registry_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return [
        CanaryToken(
            token_id=r["token_id"],
            kind=r["kind"],
            location=r["location"],
            value="",
            value_hash=r["value_hash"],
        )
        for r in rows
    ]


def value_matches_token(raw_value: str, token: CanaryToken) -> bool:
    """
    Return True if ``raw_value`` corresponds to ``token``.

    Matches either the live raw value (when the caller still has it) or the
    stored hash (when only the registry was loaded).  Only an exact match on
    the unique UUID is accepted, keeping false positives at ~zero.
    """
    if not raw_value:
        return False
    if token.value and raw_value == token.value:
        return True
    return _sha256(raw_value) == token.value_hash
