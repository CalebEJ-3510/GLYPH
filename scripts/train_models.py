"""
Model Training Script (Phase 5)
=================================
Trains the ML detection lane (Isolation Forest + GBT) on the synthetic
labeled dataset and saves models to ``models/``.

Also produces a model card documenting training data and known limitations.

Usage
-----
    python scripts/train_models.py
    python scripts/train_models.py --benign data/samples/benign_synthetic.csv
    python scripts/train_models.py --malicious data/samples/malicious_synthetic.csv
    python scripts/train_models.py --generate  # generate data first, then train
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd

from src.detect.ml_lane import MLLane, FEATURE_NAMES
from src.schema import CANONICAL_COLUMNS


def load_or_generate(
    benign_path: str | Path,
    malicious_path: str | Path,
    generate: bool = False,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load datasets from CSV, or generate them if missing/requested."""
    benign_path   = Path(benign_path)
    malicious_path = Path(malicious_path)

    if generate or not benign_path.exists() or not malicious_path.exists():
        print("[*] Generating synthetic dataset ...")
        from scripts.generate_synthetic_dataset import generate_dataset, save_dataset

        df = generate_dataset(n_benign=300, n_malicious_per_technique=50, seed=42)
        benign_df    = df[df["label"] == "benign"].copy()
        malicious_df = df[df["label"] == "malicious"].copy()

        save_dataset(benign_df,    benign_path.parent,   benign_path.stem)
        save_dataset(malicious_df, malicious_path.parent, malicious_path.stem)
        return benign_df, malicious_df

    print(f"[*] Loading benign data from {benign_path} ...")
    benign_df = pd.read_csv(benign_path)

    print(f"[*] Loading malicious data from {malicious_path} ...")
    malicious_df = pd.read_csv(malicious_path)

    return benign_df, malicious_df


def save_model_card(
    model_dir: Path,
    benign_sessions: int,
    malicious_sessions: int,
    feature_names: list[str],
) -> None:
    """Write a model card documenting training data and limitations."""
    card = f"""# ML Detection Lane — Model Card

Generated: {datetime.now(timezone.utc).isoformat()}

## Models

| Model | File | Purpose |
|---|---|---|
| StandardScaler | scaler.joblib | Feature normalization |
| Isolation Forest | isolation_forest.joblib | Stage 1: unsupervised anomaly detection |
| Gradient Boosted Trees | gbt_classifier.joblib | Stage 2: supervised re-ranking |

## Training Data

| Split | Sessions | Source |
|---|---|---|
| Benign baseline | {benign_sessions} | Synthetic (generate_synthetic_dataset.py) |
| Malicious | {malicious_sessions} | Synthetic (5 techniques × 3 stealth levels) |

## Features ({len(feature_names)} total)

{chr(10).join(f'- `{f}`' for f in feature_names)}

## Known Limitations

1. **Synthetic training data**: Models are trained on procedurally generated
   events, not real Sysmon logs.  Real-world performance may differ.
   Retrain on real labeled data when available.

2. **No temporal features**: The current feature set is per-session aggregate;
   it does not capture temporal ordering of events within a session.

3. **Isolation Forest contamination**: Set to 5%.  If the real environment has
   more anomalous-but-benign processes, increase this value to reduce FPR.

4. **GBT class imbalance**: Training data has roughly equal benign/malicious
   sessions.  In production, benign sessions vastly outnumber malicious ones;
   consider class weighting or threshold adjustment.

5. **Evasion**: A sufficiently sophisticated attacker who knows the feature set
   can craft sessions that score low.  The signature and heuristic lanes provide
   complementary coverage.

## Versioning

Models are versioned alongside detection rule packs.  When rules change
significantly, retrain the models to maintain calibration.
"""
    card_path = model_dir / "MODEL_CARD.md"
    with open(card_path, "w", encoding="utf-8") as fh:
        fh.write(card)
    print(f"[+] Model card saved to {card_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train ML detection lane models")
    parser.add_argument("--benign",    default="data/samples/benign_synthetic.csv")
    parser.add_argument("--malicious", default="data/samples/malicious_synthetic.csv")
    parser.add_argument("--output",    default="models")
    parser.add_argument("--generate",  action="store_true",
                        help="Generate synthetic data before training")
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    benign_df, malicious_df = load_or_generate(
        args.benign, args.malicious, generate=args.generate
    )

    print(f"[*] Benign sessions    : {benign_df['pid'].nunique() if 'pid' in benign_df.columns else '?'}")
    print(f"[*] Malicious sessions : {malicious_df['pid'].nunique() if 'pid' in malicious_df.columns else '?'}")

    lane = MLLane(contamination=args.contamination)

    print("[*] Training ML lane ...")
    lane.train(benign_df, malicious_df)

    model_dir = Path(args.output)
    lane.save(model_dir)

    benign_sessions   = benign_df["pid"].nunique() if "pid" in benign_df.columns else 0
    malicious_sessions = malicious_df["pid"].nunique() if "pid" in malicious_df.columns else 0
    save_model_card(model_dir, benign_sessions, malicious_sessions, FEATURE_NAMES)

    print(f"\n[+] Training complete.  Models saved to {model_dir}/")


if __name__ == "__main__":
    main()