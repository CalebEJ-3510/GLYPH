# Glyph

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://glyph-guard.streamlit.app/)

A **blue-team / defensive detection tool** that detects the artifacts and behaviors
keyloggers leave behind in Windows telemetry (Sysmon, Event Logs, ETW, registry,
and process activity).

> **This system does NOT capture keystrokes.** It detects the *artifacts* that
> keyloggers produce — hook registrations, DLL loads, registry persistence, raw
> device access, and periodic I/O patterns.

---

## Architecture

```
Data Sources (EVTX / CSV / Live ETW)
          │ normalize
          ▼
Ingestion & Normalization Layer
          │
          ▼
Detection Engine — 4 Independent Lanes
  ├── Lane 1: Signature/Rule  (YAML packs, KL-001 … KL-015)
  ├── Lane 2: Heuristic/Stat  (polling cadence, FFT periodicity, headless hook)
  ├── Lane 3: ML Anomaly      (Isolation Forest + Gradient Boosted Trees)
  └── Lane 4: Canary/Deception (planted bait credentials; near-zero FP)
          │ per-session scores
          ▼
Correlation & Scoring Engine
  (composite score with diminishing returns, severity thresholds)
          │
          ▼
Alerting & Explainability
  (Streamlit dashboard, JSON/summary export, evidence chain per alert, LLM narratives)
          │
          ▼
Validation: Synthetic Data Gen + Red Team Self-Test
  (precision/recall/F1 per technique × evasion — see docs/evaluation_report.md)
```

---

## What Makes This Different

| Problem in naïve tools | Fix in this project |
|---|---|
| Single-signature detection (grep for "keylog") | Behavior-based rules keyed on API/telemetry patterns |
| High false-positive rate on AutoHotkey, RDP tools | Allow-list layer + multi-signal correlation |
| Alert fatigue — one event = one alert | Session-based correlation with composite scoring |
| No coverage of polling-based loggers | Dedicated heuristic lane for GetAsyncKeyState patterns |
| No coverage of raw input API loggers | Detection lane for RegisterRawInputDevices |
| Static rules go stale | Rules externalized as YAML packs, hot-reloadable |
| No explainability | Every alert carries a full evidence chain |
| Detection never validated | Built-in red team self-test — see [`docs/evaluation_report.md`](docs/evaluation_report.md) for current results and known limitations |
| Behavioral detection only | Canary/deception lane: planted bait credentials catch exfiltration in the act |
| Analyst must read raw evidence | Optional LLM-narrated summaries (dashboard checkbox; template fallback when no key) |

---

## Quick Start

```bash
git clone <repo>
cd glyph
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\Activate.ps1
pip install -e ".[dashboard,dev]"
python scripts/train_models.py  # trains ML models against your installed scikit-learn
streamlit run src/dashboard.py
```

The dashboard opens at `http://localhost:8501`. From there you can:
- Load **demo data** (synthetic, generated instantly) — no setup needed.
- Upload your own **CSV** or **Sysmon EVTX** event log.
- Filter by minimum severity, enable LLM-narrated summaries, and download
  JSON alerts or a plain-text summary.

> **Note on `train_models.py`:** ML models are pickled with whatever
> scikit-learn version is installed. If you ever see `InconsistentVersionWarning`
> or an ML-lane load failure, re-run `python scripts/train_models.py` to retrain
> against your local environment — this is fast and always safe to redo.

### Other useful commands

```bash
# Run the test suite
pytest tests/ -v

# Run the red team self-test (measures detection rate vs. evasion)
python scripts/redteam_selftest.py
# Results saved to docs/evaluation_report.md

# Regenerate the synthetic sample datasets in data/samples/
python scripts/generate_synthetic_dataset.py
```

There is no separate command-line analyzer — the dashboard is the single
entry point for interactive use. `scripts/` holds the standalone utilities
above (training, red-team validation, dataset generation), each runnable
directly with `python scripts/<name>.py`.

---

## Project Structure

```
glyph/
├── docs/
│   ├── schema.md              # Canonical event schema definition
│   ├── sysmon_config.xml      # Sysmon config optimized for keylogger detection
│   └── evaluation_report.md   # Auto-generated precision/recall report
├── rules/
│   ├── allowlist.yaml         # Known-legitimate hook users (AutoHotkey, TeamViewer…)
│   └── packs/
│       ├── KL-hook.yaml       # Hook-based keylogger rules (KL-001 to KL-004)
│       ├── KL-registry.yaml   # Registry persistence rules (KL-005 to KL-008)
│       ├── KL-injection.yaml  # DLL injection rules (KL-009 to KL-012)
│       └── KL-driver.yaml     # Kernel/driver rules (KL-013 to KL-015)
├── data/samples/              # Labeled EVTX/CSV samples (generated or captured)
├── src/
│   ├── schema.py              # Canonical event schema + validation
│   ├── pipeline.py            # run_pipeline(): the shared 4-lane detection pipeline
│   ├── dashboard.py           # Streamlit dashboard — the only entry point (streamlit run src/dashboard.py)
│   ├── harmless_keylogger.py  # Lab-only telemetry harness (VM-gated)
│   ├── ingest/
│   │   ├── evtx_loader.py     # Stream-parse EVTX files
│   │   ├── normalize.py       # Map Sysmon fields → canonical schema
│   │   └── csv_loader.py      # Shared CSV loader (used by the dashboard + tests)
│   ├── detect/
│   │   ├── rule_engine.py     # YAML rule evaluation engine
│   │   ├── heuristics.py      # Polling/periodicity/headless detectors
│   │   └── ml_lane.py         # Isolation Forest + GBT two-stage ML
│   ├── canary/
│   │   ├── planter.py         # Plant fake bait credentials (passwords.txt, card_note.txt)
│   │   ├── watcher.py         # Scan telemetry for canary UUID hits (Lane 4)
│   │   └── clipboard_probe.py # LAB-ONLY clipboard canary probe (VM-gated)
│   ├── correlate/
│   │   └── session_builder.py # Session grouping + composite scoring
│   └── report/
│       ├── evidence_chain.py  # JSON/text/Reporter formatting used by the dashboard
│       └── narrative.py       # LLM-narrated summaries (opt-in; template fallback)
├── scripts/
│   ├── generate_synthetic_dataset.py  # Labeled dataset generator
│   ├── train_models.py                # ML model training
│   ├── redteam_selftest.py            # Evasion self-test + metrics
│   └── install_sysmon.ps1             # Sysmon install script (VM only)
├── models/                    # Trained ML models (joblib) — regenerate with train_models.py
├── tests/                     # pytest test suite
├── requirements.txt
└── pyproject.toml
```

---

## Detection Coverage

| Technique | Detection Lane(s) | Rule IDs |
|---|---|---|
| Hook-based (`SetWindowsHookEx`) | Signature + Heuristic | KL-001, KL-002, KL-003, KL-004 |
| Registry persistence | Signature | KL-005, KL-006, KL-007, KL-008 |
| DLL injection into browser | Signature + ML | KL-009, KL-010, KL-011, KL-012 |
| Kernel filter driver | Signature | KL-013, KL-014, KL-015 |
| Polling (`GetAsyncKeyState`) | Heuristic + ML | PollingDetector |
| Periodic registry/file writes | Heuristic (FFT) | PeriodicWriteDetector |
| Headless hook (no GUI) | Heuristic | HeadlessHookDetector |
| Novel/unseen variants | ML (Isolation Forest) | MLLane |
| Bait credential access | Canary/Deception (Lane 4) | KL-CANARY-001 |

For measured recall/precision/F1 per technique × evasion combination, including
known limitations and evasion strategies that reduce recall below 80%, see
[`docs/evaluation_report.md`](docs/evaluation_report.md) — it leads with the
weakest result, not the strongest.

---

## Severity Scoring

| Severity | Composite Score | Meaning |
|---|---|---|
| CRITICAL | ≥ 80 | High-confidence keylogger; immediate investigation |
| HIGH | ≥ 60 | Strong indicators; likely malicious |
| MEDIUM | ≥ 35 | Multiple weak signals; warrants review |
| LOW | ≥ 10 | Single weak signal; low priority |
| INFO | < 10 | Informational only |

Composite score = weighted sum across lanes with **diminishing returns**:
- Canary lane: 70% weight (near-zero false positive by construction)
- Signature lane: 50% weight
- Heuristic lane: 35% weight
- ML lane: 15% weight

Filter which severities are shown using the sidebar selector in the dashboard.

---

## Lab Harness (Windows VM Only)

`src/harmless_keylogger.py` generates realistic telemetry for each technique
**without capturing keystrokes**. It requires:
1. `--i-understand-this-is-for-lab-use-only` flag
2. Hostname in `ALLOWED_HOSTS` allowlist
3. Hypervisor detected (VM check)

```bash
# Inside an isolated Windows VM only:
python -m src.harmless_keylogger \
  --i-understand-this-is-for-lab-use-only \
  --technique hook \
  --verbose
```

Export the resulting Sysmon log (Event Viewer → Sysmon/Operational →
Save All Events As → `.evtx`) and upload it directly in the dashboard's
"Upload EVTX" data source — no separate analysis step needed.

---

## MITRE ATT&CK Coverage

| Technique | ID |
|---|---|
| Input Capture: Keylogging | T1056.001 |
| Process Injection: DLL Injection | T1055.001 |
| Boot/Logon Autostart: Registry Run Keys | T1547.001 |
| AppInit DLLs | T1546.010 |
| Winlogon Helper DLL | T1547.004 |
| Create/Modify System Process: Windows Service | T1543.003 |
| Rootkit | T1014 |

---

## Safety Note

The only "keylogger" code in this project is `src/harmless_keylogger.py` — a
lab-only, telemetry-generating harness that never persists or exfiltrates
captured input. All design choices assume an isolated VM lab environment.

`src/canary/clipboard_probe.py` is a second lab-only tool that checks whether a
planted canary UUID appears on the clipboard. It implements the same safety gates
as `harmless_keylogger.py` (explicit flag, hostname allowlist, VM detection) and
is hard-asserted to never log or store any clipboard content other than the
boolean "canary found / not found" outcome.

---

## LLM Narratives (opt-in)

The dashboard's **"LLM narratives"** sidebar checkbox generates a 3-5 sentence
plain-English analyst summary per incident. **This feature makes an external
API call per unique incident** when an API key is configured — be aware of
this before enabling it.

- Set `KDS_LLM_API_KEY` or `ANTHROPIC_API_KEY` for Anthropic (primary).
- Set `KDS_OPENAI_API_KEY` or `OPENAI_API_KEY` for OpenAI (fallback).
- If neither is set, a deterministic template summary is used — no network call.
- Only structured detection metadata is sent (rule IDs, scores, MITRE techniques).
  Raw file contents and captured input are never included.
- Narratives are cached in `output/.narrative_cache.json` to avoid re-calling the
  API on unchanged data.
