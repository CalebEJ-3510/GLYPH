"""
Alerting, Explainability & Reporting (Phase 6)
================================================
Renders :class:`~src.correlate.session_builder.Incident` objects as:
  - Colorized CLI output via ``rich``
  - JSON for SIEM ingestion
  - Plain-text summary

Every alert shows WHY it fired (evidence chain), not just that it fired.

Usage
-----
    from src.report.evidence_chain import Reporter

    reporter = Reporter()
    reporter.print_incidents(incidents)
    reporter.save_json(incidents, "output/alerts.json")
    reporter.save_summary(incidents, "output/summary.txt")
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional rich import
# ---------------------------------------------------------------------------

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False
    log.warning("rich not installed; falling back to plain-text output. pip install rich")


# ---------------------------------------------------------------------------
# Severity → color mapping
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class Reporter:
    """
    Renders detection incidents to CLI, JSON, and plain-text formats.

    Parameters
    ----------
    console:
        Optional ``rich.console.Console`` instance.  If None, a default
        console is created.
    """

    def __init__(self, console: Any = None) -> None:
        if _RICH_AVAILABLE:
            self._console = console or Console()
        else:
            self._console = None

    # ------------------------------------------------------------------
    # CLI output
    # ------------------------------------------------------------------

    def print_incidents(self, incidents: list, *, min_severity: str = "LOW") -> None:
        """
        Print all incidents to the console with colorized output.

        Parameters
        ----------
        incidents:
            List of :class:`~src.correlate.session_builder.Incident` objects.
        min_severity:
            Minimum severity to display (CRITICAL > HIGH > MEDIUM > LOW > INFO).
        """
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_idx = severity_order.index(min_severity) if min_severity in severity_order else 0

        filtered = [
            i for i in incidents
            if severity_order.index(i.severity) >= min_idx
        ]

        if not filtered:
            self._print("[dim]No incidents above threshold.[/dim]")
            return

        self._print_header(len(filtered), len(incidents))

        for inc in filtered:
            self._print_incident(inc)

        self._print_summary_table(filtered)

    def _print(self, msg: str) -> None:
        if _RICH_AVAILABLE and self._console:
            self._console.print(msg)
        else:
            # Strip rich markup for plain output
            import re
            plain = re.sub(r"\[/?[^\]]*\]", "", msg)
            print(plain)

    def _print_header(self, shown: int, total: int) -> None:
        header = (
            f"\n[bold cyan]╔══════════════════════════════════════════════════╗[/bold cyan]\n"
            f"[bold cyan]║   Glyph — Alert Report   ║[/bold cyan]\n"
            f"[bold cyan]╚══════════════════════════════════════════════════╝[/bold cyan]\n"
            f"[dim]Showing {shown} of {total} incidents[/dim]\n"
        )
        self._print(header)

    def _print_incident(self, inc: Any) -> None:
        color = SEVERITY_COLORS.get(inc.severity, "white")
        emoji = SEVERITY_EMOJI.get(inc.severity, "")

        self._print(
            f"[{color}]{emoji} [{inc.incident_id}] {inc.severity} — "
            f"Score: {inc.composite_score:.1f}/100[/{color}]"
        )
        self._print(f"  Process : [bold]{inc.process_name}[/bold] (PID {inc.pid})")
        self._print(f"  Host    : {inc.host}")
        self._print(f"  Path    : [dim]{inc.process_path}[/dim]")
        self._print(f"  Time    : {inc.start_time} → {inc.end_time}")

        if inc.rule_ids:
            self._print(f"  Rules   : [yellow]{', '.join(inc.rule_ids)}[/yellow]")
        if inc.mitre_techniques:
            self._print(f"  MITRE   : [magenta]{', '.join(inc.mitre_techniques)}[/magenta]")
        if inc.label != "unknown":
            label_color = "green" if inc.label == "benign" else "red"
            self._print(f"  Label   : [{label_color}]{inc.label}[/{label_color}] "
                        f"[dim]({inc.technique_tag})[/dim]")

        narrative = getattr(inc, "narrative", None)
        if narrative:
            self._print("")
            self._print("  [bold]Analyst summary[/bold]")
            self._print(f"  {narrative}")

        self._print("")
        # Print evidence chain (indented) — after the narrative when present
        for line in inc.evidence_chain.split("\n"):
            self._print(f"  [dim]{line}[/dim]")
        self._print("\n" + "─" * 60 + "\n")

    def _print_summary_table(self, incidents: list) -> None:
        if not _RICH_AVAILABLE or not self._console:
            self._print("\n--- Summary ---")
            for inc in incidents:
                self._print(
                    f"{inc.incident_id} | {inc.severity:8s} | "
                    f"{inc.composite_score:5.1f} | {inc.process_name}"
                )
            return

        table = Table(
            title="Incident Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("ID",       style="dim",    width=10)
        table.add_column("Severity", width=10)
        table.add_column("Score",    justify="right", width=7)
        table.add_column("Process",  width=25)
        table.add_column("PID",      justify="right", width=7)
        table.add_column("Rules",    width=20)
        table.add_column("Label",    width=10)

        for inc in incidents:
            color = SEVERITY_COLORS.get(inc.severity, "white")
            label_color = (
                "green" if inc.label == "benign"
                else "red" if inc.label == "malicious"
                else "dim"
            )
            table.add_row(
                inc.incident_id,
                f"[{color}]{inc.severity}[/{color}]",
                f"{inc.composite_score:.1f}",
                inc.process_name or "?",
                str(inc.pid),
                ", ".join(inc.rule_ids[:3]) + ("…" if len(inc.rule_ids) > 3 else ""),
                f"[{label_color}]{inc.label}[/{label_color}]",
            )

        self._console.print(table)

    # ------------------------------------------------------------------
    # JSON export
    # ------------------------------------------------------------------

    def to_json(self, incidents: list) -> list[dict]:
        """Convert incidents to a JSON-serializable list of dicts."""
        result = []
        for inc in incidents:
            result.append({
                "incident_id":      inc.incident_id,
                "pid":              inc.pid,
                "process_name":     inc.process_name,
                "process_path":     inc.process_path,
                "host":             inc.host,
                "start_time":       str(inc.start_time) if inc.start_time else None,
                "end_time":         str(inc.end_time) if inc.end_time else None,
                "composite_score":  inc.composite_score,
                "severity":         inc.severity,
                "label":            inc.label,
                "technique_tag":    inc.technique_tag,
                "rule_ids":         inc.rule_ids,
                "mitre_techniques": inc.mitre_techniques,
                "evidence_chain":   inc.evidence_chain,
                "narrative":        getattr(inc, "narrative", None),
                "rule_matches": [
                    {k: v for k, v in m.items() if k != "matched_fields"}
                    for m in inc.raw_session.rule_matches
                ],
                "heuristic_matches": [
                    {k: v for k, v in m.items() if k != "features"}
                    for m in inc.raw_session.heuristic_matches
                ],
                "ml_matches": [
                    {k: v for k, v in m.items() if k != "features"}
                    for m in inc.raw_session.ml_matches
                ],
            })
        return result

    def save_json(self, incidents: list, path: str | Path) -> None:
        """Save incidents as JSON to *path*."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.to_json(incidents)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        log.info("Saved %d incidents to %s", len(incidents), path)

    # ------------------------------------------------------------------
    # Plain-text summary
    # ------------------------------------------------------------------

    def save_summary(self, incidents: list, path: str | Path) -> None:
        """Save a plain-text summary report to *path*."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "Glyph — Detection Report",
            f"Generated: {datetime.now(timezone.utc).isoformat()}",
            f"Total incidents: {len(incidents)}",
            "",
        ]

        severity_counts: dict[str, int] = {}
        for inc in incidents:
            severity_counts[inc.severity] = severity_counts.get(inc.severity, 0) + 1

        lines.append("Severity breakdown:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            lines.append(f"  {sev:10s}: {count}")
        lines.append("")

        for inc in incidents:
            lines.append("=" * 70)
            lines.append(f"{inc.incident_id} | {inc.severity} | Score: {inc.composite_score:.1f}")
            lines.append(f"Process: {inc.process_name} (PID {inc.pid})")
            lines.append(f"Host: {inc.host}")
            lines.append(f"Rules: {', '.join(inc.rule_ids)}")
            lines.append(f"MITRE: {', '.join(inc.mitre_techniques)}")
            narrative = getattr(inc, "narrative", None)
            if narrative:
                lines.append("")
                lines.append("Analyst summary:")
                lines.append(narrative)
            lines.append("")
            lines.append(inc.evidence_chain)
            lines.append("")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        log.info("Saved summary to %s", path)