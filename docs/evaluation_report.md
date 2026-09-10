# Glyph — Evaluation Report

Generated: 2026-09-09T10:43:35.285300+00:00

## Summary

The **weakest** result is listed first, so the honest limitation is the
first thing a reader sees — not buried at the bottom.

- **Lowest recall: 0.00** against `signed_masquerade` evasion targeting `driver` (caught by lanes: —; difficulty: trivial).
- Highest recall (under evasion): 1.00 against `binary_rename` evasion targeting `hook`.
- Mean recall (no evasion): **1.00**
- Mean FPR (no evasion): **0.00**
- Mean recall (with evasion): **0.95**

## Detection Rate by Technique × Evasion

`Lanes` lists which detection lane(s) fired on the detected malicious
sessions.  Detection resting on a single lane is more fragile than
corroborated detection.  `Difficulty` is a plain-language judgment of
how hard the evasion is for a real attacker to pull off.

| Technique | Evasion | Class | Difficulty | Recall | Precision | F1 | FPR | Lanes | TP | FP | FN |
|---|---|---|---|---|---|---|---|---|---|---|---|
| hook | none | baseline | — | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | binary_rename | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | delayed_hook | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | signed_masquerade | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml | 10 | 0 | 0 |
| hook | system_path | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | signature_spoof | cosmetic | moderate | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | low_slow_poll | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | randomized_flush | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | suppress_user32 | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | mimic_benign | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | heuristic | 10 | 0 | 0 |
| hook | lane_spread | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| hook | fft_defeat | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml, signature | 10 | 0 | 0 |
| poll | none | baseline | — | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| poll | binary_rename | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| poll | delayed_hook | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| poll | signed_masquerade | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic | 10 | 0 | 0 |
| poll | system_path | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic | 10 | 0 | 0 |
| poll | signature_spoof | cosmetic | moderate | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| poll | low_slow_poll | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| poll | randomized_flush | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| poll | suppress_user32 | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| poll | mimic_benign | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, ml | 10 | 0 | 0 |
| poll | lane_spread | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| poll | fft_defeat | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | none | baseline | — | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | binary_rename | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | delayed_hook | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | signed_masquerade | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic | 10 | 0 | 0 |
| rawinput | system_path | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | signature_spoof | cosmetic | moderate | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | low_slow_poll | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | randomized_flush | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | suppress_user32 | signal-removal | moderate | 0.40 | 1.00 | 0.57 | 0.00 | signature | 4 | 0 | 6 |
| rawinput | mimic_benign | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | heuristic | 10 | 0 | 0 |
| rawinput | lane_spread | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| rawinput | fft_defeat | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | heuristic, signature | 10 | 0 | 0 |
| injection | none | baseline | — | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | binary_rename | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | delayed_hook | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | signed_masquerade | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | system_path | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | signature_spoof | cosmetic | moderate | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | low_slow_poll | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | randomized_flush | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | suppress_user32 | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | mimic_benign | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | lane_spread | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| injection | fft_defeat | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | none | baseline | — | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | binary_rename | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | delayed_hook | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | signed_masquerade | cosmetic | trivial | 0.00 | 0.00 | 0.00 | 0.00 | — | 0 | 0 | 10 |
| driver | system_path | cosmetic | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | signature_spoof | cosmetic | moderate | 0.70 | 1.00 | 0.82 | 0.00 | signature | 7 | 0 | 3 |
| driver | low_slow_poll | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | randomized_flush | signal-removal | trivial | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | suppress_user32 | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | mimic_benign | signal-removal | sophisticated | 0.00 | 0.00 | 0.00 | 0.00 | — | 0 | 0 | 10 |
| driver | lane_spread | signal-removal | sophisticated | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |
| driver | fft_defeat | signal-removal | moderate | 1.00 | 1.00 | 1.00 | 0.00 | signature | 10 | 0 | 0 |

## Known Limitations

The following evasion strategies reduced recall below 80%.  Each is
a real, reproducible weakness in the current detection lanes.

- **`signed_masquerade` × `driver` — recall 0.00.** This evasion degrades the signal the lane consumes.
- **`mimic_benign` × `driver` — recall 0.00.** Composite masquerade strips signature, headless-parent, and periodicity signals simultaneously.
- **`suppress_user32` × `rawinput` — recall 0.40.** Removing user32.dll ImageLoad telemetry disarms the userland-polling heuristic entirely (its hard gate).  Only signature/ML lanes can still catch it.
- **`signature_spoof` × `driver` — recall 0.70.** This evasion degrades the signal the lane consumes.

## Methodology

- **Sample generation.** Both benign and malicious events are produced by
  `scripts/generate_synthetic_dataset.py`.  Evasion variants are produced
  by `apply_evasion()` in `scripts/redteam_selftest.py`, which mutates the
  synthetic events (rename, re-time, or delete telemetry).
- **Detection pipeline.** Each mutated dataset is run through the full
  pipeline: YAML signature rules (`rules/packs/*.yaml`) + heuristic lane
  (`src/detect/heuristics.py`) + ML lane (`src/detect/ml_lane.py`), then
  correlated/scored by `SessionBuilder`.
- **Metrics.** Recall/precision/F1/FPR computed at composite score ≥ 10,
  where a session counts as detected if any incident fires for its PID.
- **Independence statement.** The evasion generator is parameterized by
  *what a real attacker would tune* (jitter distribution, delay ranges,
  renamed binaries, alternate paths) and does NOT read detector
  thresholds or rule contents.  However, it still *mutates output of the
  same upstream generator* the detectors were developed against, so the
  underlying event structure is shared.  This is a partial, not full,
  decoupling — see the caveat below.

## Notes

- Recall = fraction of malicious sessions correctly detected
- Precision = fraction of detections that are truly malicious
- FPR = false positive rate (benign sessions incorrectly flagged)
- All metrics computed at composite score threshold ≥ 10

## Limitations & Independence Caveat

This self-test does **not** constitute independent adversarial validation:

1. **Shared provenance.** Both the benign baseline and the malicious
   samples are emitted by `scripts/generate_synthetic_dataset.py` — the
   same generator the rules, heuristics, and ML features were developed
   and tuned against.  The detector is therefore being scored on data
   whose structure it already models.
2. **Cosmetic evasions are not evasions.** Renaming the binary, moving
   it to `System32`, or forging a signature does not remove the artifact
   (hook registry key, user32 load, injection thread, driver device read)
   that the corresponding rule matches.  A perfect recall under these
   evasions demonstrates rule *completeness*, not *evasion resistance*.
3. **Signal-removal evasions are the meaningful lower bound.** Only
   `low_slow_poll`, `randomized_flush`, `suppress_user32`, `mimic_benign`,
   `lane_spread`, and `fft_defeat` delete or degrade the telemetry the
   detectors actually consume.  Degraded recall under *these* is the
   honest signal; consult the `Class` column and weight those rows most
   heavily.
4. **Synthetic ≠ real.** None of these samples capture an adaptive
   adversary's full freedom (living-off-the-land binaries, in-memory
   only payloads, kernel tampering, ETW/Sysmon blinding).  Real-world
   performance will be lower.  Independent red-team testing with
   hand-authored samples remains necessary before trusting these numbers.