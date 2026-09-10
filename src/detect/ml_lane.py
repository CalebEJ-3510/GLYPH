"""
ML Anomaly Detection Lane (Phase 5)
=====================================
Two-stage ML pipeline for detecting novel/unseen keylogger variants:

Stage 1 — Unsupervised (Isolation Forest)
    Trained on benign baseline data only.  Flags process sessions that
    are anomalous relative to normal behavior.  High recall, moderate
    precision.

Stage 2 — Supervised (Gradient Boosted Trees)
    Trained on labeled synthetic data (benign + malicious).  Re-ranks
    anomalies from Stage 1 to reduce false positives.  Only runs on
    sessions already flagged by Stage 1.

This two-stage design is more sophisticated than a pure anomaly detector
because it uses the labeled data to calibrate the anomaly scores rather
than treating all anomalies as equally suspicious.

Feature Engineering
-------------------
Per process-session features:
  - hook_dll_count       : number of keyboard-adjacent DLL loads
  - registry_write_count : number of registry write events
  - dll_load_count       : total DLL loads (fan-out)
  - has_remote_thread    : bool — CreateRemoteThread observed
  - has_raw_access       : bool — RawAccessRead observed
  - staging_path         : bool — process in Temp/AppData
  - unsigned             : bool — process not Authenticode-signed
  - parent_rarity        : float — how unusual the parent process is
  - periodicity_score    : float — from PeriodicWriteDetector
  - event_count          : total events in session

Usage
-----
    from src.detect.ml_lane import MLLane

    lane = MLLane()
    lane.train(benign_df, malicious_df)
    lane.save("models/")

    results = lane.predict_df(new_df)
"""

from __future__ import annotations

import logging
import ntpath
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature names (must match feature_vector() output order)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "hook_dll_count",
    "registry_write_count",
    "dll_load_count",
    "has_remote_thread",
    "has_raw_access",
    "staging_path",
    "unsigned",
    "parent_rarity",
    "periodicity_score",
    "event_count",
    "user32_loaded",
    "hid_loaded",
    "run_key_write",
    "appinit_write",
    "browser_parent",
]

# Common parent processes for rarity scoring (lower index = more common)
_COMMON_PARENTS = [
    "explorer.exe", "svchost.exe", "services.exe", "lsass.exe",
    "winlogon.exe", "csrss.exe", "wininit.exe", "system",
    "cmd.exe", "powershell.exe",
]

_BROWSER_PARENTS = frozenset({
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "opera.exe", "brave.exe",
})

_HOOK_DLLS = frozenset({"user32.dll", "hid.dll", "wincred.dll", "credui.dll"})

_STAGING_PATHS = ["\\temp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\downloads\\"]


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_session_features(
    session_events: pd.DataFrame,
    process_meta: dict,
    periodicity_score: float = 0.0,
) -> np.ndarray:
    """
    Extract a fixed-length feature vector from a process session.

    Parameters
    ----------
    session_events:
        All canonical events for this PID.
    process_meta:
        Dict with process_name, process_path, parent_process_name, signed, pid.
    periodicity_score:
        Pre-computed periodicity score from :class:`~src.detect.heuristics.PeriodicWriteDetector`.

    Returns
    -------
    np.ndarray of shape (len(FEATURE_NAMES),)
    """
    dll_loads = session_events[session_events["event_id"] == 7]
    reg_writes = session_events[session_events["event_id"] == 13]
    crt_events = session_events[session_events["event_id"] == 8]
    raw_events = session_events[session_events["event_id"] == 9]

    loaded_dlls = set(
        dll_loads["image_loaded"].str.lower().dropna().apply(
            # Windows paths use backslashes regardless of host OS, so use
            # ntpath.basename (not os.path.basename, which is host-OS aware).
            lambda p: ntpath.basename(p)
        ).tolist()
    )

    proc_path = (process_meta.get("process_path") or "").lower()
    parent    = (process_meta.get("parent_process_name") or "").lower()
    signed    = process_meta.get("signed")

    # hook_dll_count
    hook_dll_count = sum(1 for d in loaded_dlls if d in _HOOK_DLLS)

    # registry_write_count
    registry_write_count = len(reg_writes)

    # dll_load_count
    dll_load_count = len(dll_loads)

    # has_remote_thread
    has_remote_thread = float(len(crt_events) > 0)

    # has_raw_access
    has_raw_access = float(len(raw_events) > 0)

    # staging_path
    staging_path = float(any(p in proc_path for p in _STAGING_PATHS))

    # unsigned
    unsigned = float(signed is False or signed is None)

    # parent_rarity: 0 = very common parent, 1 = rare/unknown parent
    if parent in _COMMON_PARENTS:
        parent_rarity = _COMMON_PARENTS.index(parent) / len(_COMMON_PARENTS)
    else:
        parent_rarity = 1.0

    # periodicity_score (passed in from heuristics layer)
    periodicity_score_f = float(periodicity_score)

    # event_count
    event_count = float(len(session_events))

    # user32_loaded
    user32_loaded = float("user32.dll" in loaded_dlls)

    # hid_loaded
    hid_loaded = float("hid.dll" in loaded_dlls)

    # run_key_write
    run_key_write = float(
        reg_writes["registry_key"].str.lower().str.contains(
            "currentversion\\\\run", na=False
        ).any()
    )

    # appinit_write
    appinit_write = float(
        reg_writes["registry_key"].str.lower().str.contains(
            "appinit_dlls", na=False
        ).any()
    )

    # browser_parent
    browser_parent = float(parent in _BROWSER_PARENTS)

    return np.array([
        hook_dll_count,
        registry_write_count,
        dll_load_count,
        has_remote_thread,
        has_raw_access,
        staging_path,
        unsigned,
        parent_rarity,
        periodicity_score_f,
        event_count,
        user32_loaded,
        hid_loaded,
        run_key_write,
        appinit_write,
        browser_parent,
    ], dtype=float)


def build_feature_matrix(
    df: pd.DataFrame,
    periodicity_scores: dict[Any, float] | None = None,
) -> tuple[np.ndarray, list[Any]]:
    """
    Build a feature matrix from a canonical DataFrame by grouping on PID.

    Returns
    -------
    (X, pids)
        X: np.ndarray of shape (n_sessions, n_features)
        pids: list of PID values corresponding to each row
    """
    if periodicity_scores is None:
        periodicity_scores = {}

    rows = []
    pids = []

    for pid, group in df.groupby("pid", dropna=True):
        proc_create = group[group["event_id"] == 1]
        if not proc_create.empty:
            row = proc_create.iloc[0]
        else:
            row = group.iloc[0]

        meta = {
            "process_name": row.get("process_name"),
            "process_path": row.get("process_path"),
            "parent_process_name": row.get("parent_process_name"),
            "signed": row.get("signed"),
            "pid": pid,
        }

        p_score = periodicity_scores.get(pid, 0.0)
        features = extract_session_features(group, meta, periodicity_score=p_score)
        rows.append(features)
        pids.append(pid)

    if not rows:
        return np.empty((0, len(FEATURE_NAMES))), []

    return np.vstack(rows), pids


# ---------------------------------------------------------------------------
# ML Lane
# ---------------------------------------------------------------------------

@dataclass
class MLPrediction:
    """Prediction result for a single process session."""
    pid: Any
    process_name: str | None
    anomaly_score: float        # Isolation Forest: higher = more anomalous (0–1)
    is_anomaly: bool            # Stage 1 flag
    malicious_prob: float       # Stage 2 GBT probability (0–1); -1 if not run
    final_score: int            # Combined 0–100 score
    evidence: str
    features: dict


class MLLane:
    """
    Two-stage ML detection lane.

    Parameters
    ----------
    contamination:
        Expected fraction of anomalies in the training data (Isolation Forest).
    n_estimators_if:
        Number of trees in the Isolation Forest.
    n_estimators_gbt:
        Number of trees in the Gradient Boosted classifier.
    anomaly_threshold:
        Isolation Forest anomaly score threshold (0–1) above which a session
        is passed to Stage 2.
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators_if: int = 200,
        n_estimators_gbt: int = 100,
        anomaly_threshold: float = 0.55,
    ) -> None:
        self.contamination = contamination
        self.anomaly_threshold = anomaly_threshold

        self._scaler = StandardScaler()
        self._iso_forest = IsolationForest(
            n_estimators=n_estimators_if,
            contamination=contamination,
            random_state=42,
        )
        self._gbt: GradientBoostingClassifier | None = None
        self._n_estimators_gbt = n_estimators_gbt
        self._trained_if = False
        self._trained_gbt = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(
        self,
        benign_df: pd.DataFrame,
        malicious_df: pd.DataFrame | None = None,
        periodicity_scores: dict | None = None,
    ) -> None:
        """
        Train both stages.

        Parameters
        ----------
        benign_df:
            Canonical DataFrame of benign baseline events.
        malicious_df:
            Optional canonical DataFrame of malicious events (for Stage 2).
        periodicity_scores:
            Optional dict mapping PID → periodicity score.
        """
        log.info("Building feature matrix for benign baseline ...")
        X_benign, _ = build_feature_matrix(benign_df, periodicity_scores)

        if len(X_benign) == 0:
            log.warning("No sessions in benign_df; skipping training.")
            return

        # Stage 1: Isolation Forest on benign data only
        log.info("Training Isolation Forest on %d benign sessions ...", len(X_benign))
        X_scaled = self._scaler.fit_transform(X_benign)
        self._iso_forest.fit(X_scaled)
        self._trained_if = True
        log.info("Isolation Forest trained.")

        # Stage 2: GBT on labeled data (benign + malicious)
        if malicious_df is not None and not malicious_df.empty:
            log.info("Building feature matrix for malicious sessions ...")
            X_mal, _ = build_feature_matrix(malicious_df, periodicity_scores)

            if len(X_mal) > 0:
                X_all = np.vstack([X_benign, X_mal])
                y_all = np.array([0] * len(X_benign) + [1] * len(X_mal))

                X_all_scaled = self._scaler.transform(X_all)

                self._gbt = GradientBoostingClassifier(
                    n_estimators=self._n_estimators_gbt,
                    max_depth=4,
                    learning_rate=0.1,
                    random_state=42,
                )
                log.info(
                    "Training GBT on %d sessions (%d benign, %d malicious) ...",
                    len(X_all), len(X_benign), len(X_mal),
                )
                self._gbt.fit(X_all_scaled, y_all)
                self._trained_gbt = True
                log.info("GBT trained.")

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def _anomaly_score(self, X_scaled: np.ndarray) -> np.ndarray:
        """
        Convert Isolation Forest decision_function output to a 0–1 anomaly score.
        Higher = more anomalous.
        """
        raw = self._iso_forest.decision_function(X_scaled)
        # decision_function: negative = anomaly, positive = normal
        # Normalize to [0, 1] where 1 = most anomalous
        score = 1.0 / (1.0 + np.exp(raw * 5))  # sigmoid inversion
        return score

    def predict_session(
        self,
        session_events: pd.DataFrame,
        process_meta: dict,
        periodicity_score: float = 0.0,
    ) -> MLPrediction | None:
        """
        Predict anomaly score for a single process session.

        Returns None if the model has not been trained.
        """
        if not self._trained_if:
            return None

        features = extract_session_features(session_events, process_meta, periodicity_score)
        X = features.reshape(1, -1)
        X_scaled = self._scaler.transform(X)

        anomaly_score = float(self._anomaly_score(X_scaled)[0])
        is_anomaly = anomaly_score >= self.anomaly_threshold

        malicious_prob = -1.0
        if is_anomaly and self._trained_gbt and self._gbt is not None:
            malicious_prob = float(self._gbt.predict_proba(X_scaled)[0, 1])

        # Combine scores: IF score weighted 40%, GBT weighted 60% if available
        if malicious_prob >= 0:
            final_score = int((anomaly_score * 0.4 + malicious_prob * 0.6) * 100)
        else:
            final_score = int(anomaly_score * 100) if is_anomaly else 0

        evidence = (
            f"ML Lane: process '{process_meta.get('process_name')}' "
            f"(PID {process_meta.get('pid')}) — "
            f"anomaly_score={anomaly_score:.3f} "
            f"(threshold={self.anomaly_threshold}), "
            f"is_anomaly={is_anomaly}"
        )
        if malicious_prob >= 0:
            evidence += f", malicious_prob={malicious_prob:.3f}"

        return MLPrediction(
            pid=process_meta.get("pid"),
            process_name=process_meta.get("process_name"),
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            malicious_prob=malicious_prob,
            final_score=final_score,
            evidence=evidence,
            features=dict(zip(FEATURE_NAMES, features.tolist())),
        )

    def predict_df(
        self,
        df: pd.DataFrame,
        periodicity_scores: dict | None = None,
    ) -> list[dict]:
        """
        Predict anomaly scores for all process sessions in a DataFrame.

        Returns a list of dicts, one per session.
        """
        if not self._trained_if:
            log.warning("MLLane not trained; call train() first.")
            return []

        if periodicity_scores is None:
            periodicity_scores = {}

        results = []
        for pid, group in df.groupby("pid", dropna=True):
            proc_create = group[group["event_id"] == 1]
            if not proc_create.empty:
                row = proc_create.iloc[0]
            else:
                row = group.iloc[0]

            meta = {
                "process_name": row.get("process_name"),
                "process_path": row.get("process_path"),
                "parent_process_name": row.get("parent_process_name"),
                "signed": row.get("signed"),
                "pid": pid,
            }

            pred = self.predict_session(group, meta, periodicity_scores.get(pid, 0.0))
            if pred and pred.is_anomaly:
                results.append({
                    "pid": pred.pid,
                    "process_name": pred.process_name,
                    "anomaly_score": pred.anomaly_score,
                    "is_anomaly": pred.is_anomaly,
                    "malicious_prob": pred.malicious_prob,
                    "final_score": pred.final_score,
                    "evidence": pred.evidence,
                    "features": pred.features,
                    "label": group["label"].iloc[0] if "label" in group.columns else "unknown",
                    "technique_tag": group["technique_tag"].iloc[0] if "technique_tag" in group.columns else "",
                })

        return results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, model_dir: str | Path) -> None:
        """Save trained models to *model_dir*."""
        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(self._scaler,     model_dir / "scaler.joblib")
        joblib.dump(self._iso_forest, model_dir / "isolation_forest.joblib")
        if self._gbt is not None:
            joblib.dump(self._gbt,    model_dir / "gbt_classifier.joblib")

        log.info("Models saved to %s", model_dir)

    def load(self, model_dir: str | Path) -> None:
        """Load trained models from *model_dir*."""
        model_dir = Path(model_dir)

        scaler_path = model_dir / "scaler.joblib"
        if_path     = model_dir / "isolation_forest.joblib"
        gbt_path    = model_dir / "gbt_classifier.joblib"

        if not scaler_path.exists() or not if_path.exists():
            raise FileNotFoundError(f"Model files not found in {model_dir}")

        self._scaler     = joblib.load(scaler_path)
        self._iso_forest = joblib.load(if_path)
        self._trained_if = True

        if gbt_path.exists():
            self._gbt        = joblib.load(gbt_path)
            self._trained_gbt = True

        log.info("Models loaded from %s", model_dir)