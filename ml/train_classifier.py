#!/usr/bin/env python3
"""
Train a RandomForestClassifier to classify MAVLink attack types.

Input  : ml/dataset/train.csv   (produced by generate_dataset.py)
         ml/dataset/test.csv
Output : detection/models/classifier.pkl

The model is a sklearn Pipeline:
  StandardScaler → RandomForestClassifier (200 trees)

StandardScaler matters here because ts_gap ~ 86 400, gps_sys_delta can
reach 2.48 × 10⁹, and is_duplicate is binary {0, 1}.  Without scaling,
tree-based models are scale-invariant but the scaler future-proofs the
pipeline for any linear models added later.

Usage
-----
  python3 ml/generate_dataset.py   # build train/test CSVs first
  python3 ml/train_classifier.py   # train and save classifier.pkl
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
TRAIN_CSV   = os.path.join(SCRIPT_DIR, "dataset", "train.csv")
TEST_CSV    = os.path.join(SCRIPT_DIR, "dataset", "test.csv")
MODEL_PATH  = os.path.join(SCRIPT_DIR, "..", "detection", "models", "classifier.pkl")

FEATURES    = ["ts_gap", "gps_sys_delta", "is_duplicate"]
TARGET      = "label_id"

LABEL_NAMES = {
    0: "NORMAL",
    1: "ATK1_FUTURE",
    2: "ATK2_SPOOF",
    3: "ATK3_OVER",
    4: "ATK3B_UNDER",
    5: "ATK4_REPLAY",
}


def load(csv_path: str):
    df = pd.read_csv(csv_path)
    X  = df[FEATURES].values
    y  = df[TARGET].values
    return X, y


def main():
    if not os.path.exists(TRAIN_CSV):
        raise FileNotFoundError(
            f"Training data not found: {TRAIN_CSV}\n"
            "Run ml/generate_dataset.py first."
        )

    print("=" * 60)
    print("  MAVLink Attack Classifier — Training")
    print("=" * 60)

    print("\nLoading data...")
    X_train, y_train = load(TRAIN_CSV)
    X_test,  y_test  = load(TEST_CSV)
    print(f"  Train : {X_train.shape[0]:,} samples  {X_train.shape[1]} features")
    print(f"  Test  : {X_test.shape[0]:,}  samples  {X_test.shape[1]} features")

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("\nTraining RandomForestClassifier (200 trees)...")
    model.fit(X_train, y_train)
    print("  Done.")

    print("\nEvaluating on held-out test set...")
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    print(f"\n  Accuracy : {acc * 100:.2f}%")

    target_names = [LABEL_NAMES[i] for i in sorted(LABEL_NAMES)]
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=target_names))

    print("Confusion Matrix (rows=actual, cols=predicted):")
    cm = confusion_matrix(y_test, y_pred)
    header = f"{'':15s}" + "".join(f"{n:>15s}" for n in target_names)
    print(header)
    for i, row in enumerate(cm):
        print(f"{target_names[i]:15s}" + "".join(f"{v:>15d}" for v in row))

    # Feature importance
    rf = model.named_steps["clf"]
    print("\nFeature Importances:")
    for name, imp in zip(FEATURES, rf.feature_importances_):
        bar = "█" * int(imp * 40)
        print(f"  {name:20s} {imp:.4f}  {bar}")

    # Save
    model_path = os.path.abspath(MODEL_PATH)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump({"model": model, "features": FEATURES, "label_names": LABEL_NAMES}, f)
    print(f"\nModel saved → {model_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
