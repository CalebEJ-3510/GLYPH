"""
Signature / Rule Detection Lane
================================
Evaluates canonical events against YAML detection packs and returns
:class:`RuleMatch` objects that form the "evidence chain" for each alert.

Design
------
- Rules are loaded from ``rules/packs/*.yaml`` at startup (hot-reloadable).
- The allow-list from ``rules/allowlist.yaml`` is checked before scoring.
- Every match records the exact field values that triggered it — no black-box.
- Condition evaluation is pure Python; no eval(), no exec().

Usage
-----
    from src.detect.rule_engine import RuleEngine

    engine = RuleEngine()
    engine.load_packs("rules/packs")
    engine.load_allowlist("rules/allowlist.yaml")

    for event in df.to_dict("records"):
        matches = engine.evaluate(event)
        for m in matches:
            print(m.rule_id, m.score, m.evidence)
"""

from __future__ import annotations

import glob
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RuleMatch:
    """A single rule that fired against an event."""
    rule_id: str
    rule_name: str
    severity: str
    score: int
    mitre_technique: str
    evidence: str           # human-readable explanation
    matched_fields: dict    # field_name → matched_value pairs


@dataclass
class RulePack:
    """A loaded YAML detection pack."""
    pack_name: str
    pack_version: str
    rules: list[dict]


# ---------------------------------------------------------------------------
# Allow-list
# ---------------------------------------------------------------------------

class AllowList:
    """
    Checks whether a process is in the known-legitimate allow-list.
    """

    def __init__(self) -> None:
        self._process_names: set[str] = set()
        self._process_paths: list[str] = []
        self._signatures: list[str] = []

    def load(self, path: str | Path) -> None:
        path = Path(path)
        if not path.exists():
            log.warning("Allow-list not found at %s; allow-list disabled", path)
            return
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            log.warning("Allow-list at %s is empty or malformed; allow-list disabled", path)
            return
        self._process_names = {
            n.lower() for n in (data.get("process_names") or [])
        }
        self._process_paths = [
            p.lower() for p in (data.get("process_paths") or [])
        ]
        self._signatures = [
            s.lower() for s in (data.get("signatures") or [])
        ]
        log.info(
            "Allow-list loaded: %d names, %d paths, %d signatures",
            len(self._process_names), len(self._process_paths), len(self._signatures),
        )

    @staticmethod
    def _safe_lower(v: Any) -> str:
        """Coerce to lowercase string, treating None/NaN as empty."""
        if v is None or (isinstance(v, float) and v != v):  # NaN check
            return ""
        return str(v).lower()

    def is_allowed(self, event: dict) -> bool:
        """Return True if the event's process is in the allow-list."""
        name = self._safe_lower(event.get("process_name"))
        path = self._safe_lower(event.get("process_path"))
        sig  = self._safe_lower(event.get("signature"))

        if name in self._process_names:
            return True
        if any(p in path for p in self._process_paths):
            return True
        if sig and any(s in sig for s in self._signatures):
            return True
        return False


# ---------------------------------------------------------------------------
# Condition evaluator
# ---------------------------------------------------------------------------

def _str_lower(v: Any) -> str:
    return str(v).lower() if v is not None else ""


def _eval_condition(condition: dict, event: dict, session_dlls: set[str]) -> tuple[bool, dict]:
    """
    Evaluate a rule condition dict against a single event.

    Returns
    -------
    (matched: bool, matched_fields: dict)
    """
    matched_fields: dict = {}
    negate_block: dict | None = None

    for key, value in condition.items():
        if key == "NOT":
            negate_block = value
            continue

        # image_loaded_endswith
        if key == "image_loaded_endswith":
            il = _str_lower(event.get("image_loaded"))
            if not il.endswith(value.lower()):
                return False, {}
            matched_fields["image_loaded"] = event.get("image_loaded")

        # image_loaded_contains_any
        elif key == "image_loaded_contains_any":
            il = _str_lower(event.get("image_loaded"))
            hit = next((v for v in value if v.lower() in il), None)
            if not hit:
                return False, {}
            matched_fields["image_loaded"] = event.get("image_loaded")

        # process_path_contains_any
        elif key == "process_path_contains_any":
            pp = _str_lower(event.get("process_path"))
            hit = next((v for v in value if v.lower() in pp), None)
            if not hit:
                return False, {}
            matched_fields["process_path"] = event.get("process_path")

        # registry_key_contains
        elif key == "registry_key_contains":
            rk = _str_lower(event.get("registry_key") or event.get("target_object"))
            if value.lower() not in rk:
                return False, {}
            matched_fields["registry_key"] = event.get("registry_key")

        # registry_key_contains_any
        elif key == "registry_key_contains_any":
            rk = _str_lower(event.get("registry_key") or event.get("target_object"))
            hit = next((v for v in value if v.lower() in rk), None)
            if not hit:
                return False, {}
            matched_fields["registry_key"] = event.get("registry_key")

        # registry_value_contains_any
        elif key == "registry_value_contains_any":
            rv = _str_lower(event.get("registry_value"))
            hit = next((v for v in value if v.lower() in rv), None)
            if not hit:
                return False, {}
            matched_fields["registry_value"] = event.get("registry_value")

        # target_object_contains_any
        elif key == "target_object_contains_any":
            to = _str_lower(event.get("target_object"))
            hit = next((v for v in value if v.lower() in to), None)
            if not hit:
                return False, {}
            matched_fields["target_object"] = event.get("target_object")

        # parent_process_name_in
        elif key == "parent_process_name_in":
            ppn = _str_lower(event.get("parent_process_name"))
            if not any(v.lower() == ppn for v in value):
                return False, {}
            matched_fields["parent_process_name"] = event.get("parent_process_name")

        # session_loaded_all — checks DLLs loaded across the session
        elif key == "session_loaded_all":
            for dll in value:
                if not any(dll.lower() in d.lower() for d in session_dlls):
                    return False, {}
            matched_fields["session_dlls"] = list(session_dlls)

        # event_id filter (applied before calling this function, but handle here too)
        elif key == "event_id":
            if event.get("event_id") != value:
                return False, {}

    # Handle NOT block
    if negate_block:
        for neg_key, neg_value in negate_block.items():
            if neg_key == "signed":
                if event.get("signed") == neg_value:
                    return False, {}
            elif neg_key == "process_in_allowlist":
                # Handled by caller; skip here
                pass

    return True, matched_fields


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Loads YAML detection packs and evaluates events against them.

    Parameters
    ----------
    packs_dir:
        Directory containing ``*.yaml`` detection pack files.
    allowlist_path:
        Path to ``allowlist.yaml``.
    """

    def __init__(
        self,
        packs_dir: str | Path | None = None,
        allowlist_path: str | Path | None = None,
    ) -> None:
        self._packs: list[RulePack] = []
        self._allowlist = AllowList()

        if packs_dir:
            self.load_packs(packs_dir)
        if allowlist_path:
            self.load_allowlist(allowlist_path)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_packs(self, packs_dir: str | Path) -> int:
        """
        Load all ``*.yaml`` files from *packs_dir* as detection packs.

        Returns the number of rules loaded.
        """
        packs_dir = Path(packs_dir)
        total_rules = 0
        for yaml_path in sorted(packs_dir.glob("*.yaml")):
            try:
                with open(yaml_path, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                pack = RulePack(
                    pack_name=data.get("pack_name", yaml_path.stem),
                    pack_version=data.get("pack_version", "unknown"),
                    rules=data.get("rules", []),
                )
                self._packs.append(pack)
                total_rules += len(pack.rules)
                log.info(
                    "Loaded pack '%s' v%s: %d rules",
                    pack.pack_name, pack.pack_version, len(pack.rules),
                )
            except Exception as exc:
                log.error("Failed to load pack %s: %s", yaml_path, exc)

        log.info("Total rules loaded: %d from %d packs", total_rules, len(self._packs))
        return total_rules

    def load_allowlist(self, path: str | Path) -> None:
        """Load the allow-list YAML file."""
        self._allowlist.load(path)

    def reload(self, packs_dir: str | Path, allowlist_path: str | Path | None = None) -> None:
        """Hot-reload all packs and optionally the allow-list."""
        self._packs.clear()
        self.load_packs(packs_dir)
        if allowlist_path:
            self.load_allowlist(allowlist_path)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        event: dict,
        *,
        session_dlls: set[str] | None = None,
    ) -> list[RuleMatch]:
        """
        Evaluate a single canonical event dict against all loaded rules.

        Parameters
        ----------
        event:
            Canonical event dict (from :func:`~src.ingest.normalize.normalize_event`).
        session_dlls:
            Set of DLL paths loaded by this process session so far.
            Required for session-level rules (e.g. KL-003).

        Returns
        -------
        list[RuleMatch]
            All rules that matched, with evidence chains.
        """
        if session_dlls is None:
            session_dlls = set()

        event_id = event.get("event_id")
        is_allowed = self._allowlist.is_allowed(event)
        matches: list[RuleMatch] = []

        for pack in self._packs:
            for rule in pack.rules:
                # Check event_id filter
                applies_to = rule.get("applies_to", [])
                if applies_to:
                    applicable_ids = [
                        a["event_id"] if isinstance(a, dict) else a
                        for a in applies_to
                    ]
                    if event_id not in applicable_ids:
                        continue

                condition = rule.get("condition", {})

                # Check allow-list before evaluating NOT: process_in_allowlist
                not_block = condition.get("NOT", {})
                if isinstance(not_block, dict) and not_block.get("process_in_allowlist") and is_allowed:
                    continue

                matched, matched_fields = _eval_condition(condition, event, session_dlls)
                if not matched:
                    continue

                # Build evidence string from template
                template = rule.get("evidence_template", "Rule {rule_id} matched.")
                try:
                    evidence = template.format(
                        rule_id=rule["id"],
                        **{k: (event.get(k) or "") for k in [
                            "process_name", "pid", "process_path",
                            "parent_process_name", "registry_key",
                            "registry_value", "target_object", "image_loaded",
                        ]},
                    ).strip()
                except KeyError:
                    evidence = f"Rule {rule['id']} matched."

                # Downgrade severity if process is allowed but rule still fired
                severity = rule.get("severity", "medium")
                score = int(rule.get("score", 50))
                if is_allowed:
                    severity = "low"
                    score = max(5, score // 4)

                matches.append(RuleMatch(
                    rule_id=rule["id"],
                    rule_name=rule.get("name", ""),
                    severity=severity,
                    score=score,
                    mitre_technique=rule.get("mitre_technique", ""),
                    evidence=evidence,
                    matched_fields=matched_fields,
                ))

        return matches

    def evaluate_df(self, df: "pd.DataFrame") -> list[dict]:
        """
        Evaluate all events in a canonical DataFrame.

        Returns a list of dicts, one per rule match, with the event index
        and match details merged.
        """
        results = []
        # Build per-PID session DLL sets for session-level rules
        session_dlls: dict[Any, set[str]] = {}

        for idx, row in df.iterrows():
            event = row.to_dict()
            pid = event.get("pid")

            # Track DLLs loaded per PID
            if event.get("event_id") == 7 and event.get("image_loaded"):
                if pid not in session_dlls:
                    session_dlls[pid] = set()
                session_dlls[pid].add(event["image_loaded"])

            dlls = session_dlls.get(pid, set())
            matches = self.evaluate(event, session_dlls=dlls)

            for m in matches:
                results.append({
                    "event_index": idx,
                    "timestamp": event.get("timestamp"),
                    "host": event.get("host"),
                    "pid": pid,
                    "process_name": event.get("process_name"),
                    "rule_id": m.rule_id,
                    "rule_name": m.rule_name,
                    "severity": m.severity,
                    "score": m.score,
                    "mitre_technique": m.mitre_technique,
                    "evidence": m.evidence,
                    "matched_fields": m.matched_fields,
                    "label": event.get("label", "unknown"),
                    "technique_tag": event.get("technique_tag", ""),
                })

        return results


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def make_engine(
    packs_dir: str | Path = "rules/packs",
    allowlist_path: str | Path = "rules/allowlist.yaml",
) -> RuleEngine:
    """Create and return a fully-loaded :class:`RuleEngine`."""
    engine = RuleEngine()
    engine.load_packs(packs_dir)
    engine.load_allowlist(allowlist_path)
    return engine