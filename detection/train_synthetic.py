#!/usr/bin/env python3
"""
=============================================================
Step 3 (Alternative) — Synthetic Baseline Training
=============================================================
Trains the Isolation Forest WITHOUT needing SITL or MAVProxy.

Generates synthetic normal-traffic samples from the known
statistical distributions of the two clean ML features:

  ts_gap        ~ N(-4.33, 2.95)   clipped to [-15, 0]
  gps_sys_delta ~ N(-0.001, 0.007) clipped to [-0.15, 0.10]

These distributions were measured from real ArduPilot SITL
traffic across multiple 5-minute capture sessions.

Attack values are so far from these ranges that the model
learns the normal cluster with zero risk of confusion:
  ATK1/ATK4: ts_gap        = +86,400 s   (~30,000 sigma away)
  ATK2:      gps_sys_delta = +864,000 s  (~120M sigma away)
  ATK3/3B:   gps_sys_delta = ±billions s

Run
---
  python3 detection/train_synthetic.py

No SITL, no MAVProxy, no GPS simulator needed.
=============================================================
"""

import os
import sys
import time
import pickle
import numpy as np

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR   = os.path.join(SCRIPT_DIR, "models")
MODEL_FILE  = os.path.join(MODEL_DIR, "baseline.pkl")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("\n[ERROR] scikit-learn not installed.  Run: pip install scikit-learn numpy")
    sys.exit(1)

# ── Synthetic data parameters ─────────────────────────────────────────────────
# Measured from real SITL captures (multiple 5-minute sessions)
TS_GAP_MEAN        = -4.33
TS_GAP_STD         =  2.95
TS_GAP_CLIP        = (-15.0, 0.0)

GPS_DELTA_MEAN     = -0.0008
GPS_DELTA_STD      =  0.0072
GPS_DELTA_CLIP     = (-0.15, 0.10)

# Mix: ~80% MAVLink packets (have ts_gap, no gps_sys_delta)
#      ~20% GPS packets (have gps_sys_delta, ts_gap=0)
N_SAMPLES          = 100_000
MAVLink_FRACTION   = 0.80

# ── Model parameters ─────────────────────────────────────────────────────────
N_ESTIMATORS       = 200
CONTAMINATION      = 0.05
RANDOM_STATE       = 42

FEATURE_NAMES      = ["ts_gap", "gps_sys_delta"]


def generate_samples(n: int, rng: np.random.Generator) -> np.ndarray:
    """Generate n synthetic normal-traffic feature vectors."""
    n_mav = int(n * MAVLink_FRACTION)
    n_gps = n - n_mav

    # MAVLink packets: ts_gap from measured distribution, gps_sys_delta = 0
    ts_gap_mav = rng.normal(TS_GAP_MEAN, TS_GAP_STD, n_mav)
    ts_gap_mav = np.clip(ts_gap_mav, *TS_GAP_CLIP)
    mav = np.column_stack([ts_gap_mav, np.zeros(n_mav)])

    # GPS packets: ts_gap = 0, gps_sys_delta from measured distribution
    gps_delta = rng.normal(GPS_DELTA_MEAN, GPS_DELTA_STD, n_gps)
    gps_delta = np.clip(gps_delta, *GPS_DELTA_CLIP)
    gps = np.column_stack([np.zeros(n_gps), gps_delta])

    X = np.vstack([mav, gps])
    rng.shuffle(X)
    return X.astype(np.float64)


def main():
    print()
    print("=" * 62)
    print("  Step 3 (Synthetic) — Baseline Training")
    print("=" * 62)
    print()
    print(f"  Features        : {FEATURE_NAMES}")
    print(f"  Samples         : {N_SAMPLES:,}")
    print(f"  MAVLink mix     : {int(MAVLink_FRACTION*100)}%  GPS mix: {int((1-MAVLink_FRACTION)*100)}%")
    print(f"  Contamination   : {CONTAMINATION}")
    print(f"  Trees           : {N_ESTIMATORS}")
    print(f"  Model output    : {MODEL_FILE}")
    print()
    print("  Normal distributions used:")
    print(f"    ts_gap        ~ N({TS_GAP_MEAN}, {TS_GAP_STD})  clipped {TS_GAP_CLIP}")
    print(f"    gps_sys_delta ~ N({GPS_DELTA_MEAN}, {GPS_DELTA_STD})  clipped {GPS_DELTA_CLIP}")
    print()

    rng = np.random.default_rng(RANDOM_STATE)

    print("  Generating synthetic samples...")
    X = generate_samples(N_SAMPLES, rng)
    print(f"  Generated {len(X):,} samples.")
    print()

    print("  Feature statistics:")
    print(f"  {'Feature':<20}  {'Mean':>12}  {'Std':>12}  {'Min':>12}  {'Max':>12}")
    print(f"  {'-'*20}  {'-'*12}  {'-'*12}  {'-'*12}  {'-'*12}")
    for i, name in enumerate(FEATURE_NAMES):
        col = X[:, i]
        print(f"  {name:<20}  {col.mean():>12.4f}  {col.std():>12.4f}"
              f"  {col.min():>12.4f}  {col.max():>12.4f}")
    print()

    print("  Fitting StandardScaler...")
    scaler  = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"  Training IsolationForest  "
          f"(n_estimators={N_ESTIMATORS}, contamination={CONTAMINATION})...")
    t0  = time.time()
    clf = IsolationForest(
        n_estimators  = N_ESTIMATORS,
        contamination = CONTAMINATION,
        random_state  = RANDOM_STATE,
        n_jobs        = -1,
    )
    clf.fit(X_scaled)
    print(f"  Training complete in {time.time()-t0:.1f}s.")
    print()

    scores = clf.decision_function(X_scaled)
    preds  = clf.predict(X_scaled)
    n_anom = (preds == -1).sum()
    print("  Self-evaluation on training set:")
    print(f"    Total samples      : {len(X):,}")
    print(f"    Flagged as anomaly : {n_anom:,}  ({100*n_anom/len(X):.1f}%)")
    print(f"    Score range        : [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"    Score mean         : {scores.mean():.4f}")
    print()

    os.makedirs(MODEL_DIR, exist_ok=True)
    bundle = {
        "scaler"        : scaler,
        "clf"           : clf,
        "feature_names" : FEATURE_NAMES,
        "n_samples"     : len(X),
        "contamination" : CONTAMINATION,
        "capture_sec"   : 0,
        "trained_at"    : time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "score_mean"    : float(scores.mean()),
        "score_std"     : float(scores.std()),
        "synthetic"     : True,
    }
    with open(MODEL_FILE, "wb") as f:
        pickle.dump(bundle, f)

    kb = os.path.getsize(MODEL_FILE) / 1024
    print(f"  Model saved → {MODEL_FILE}  ({kb:.1f} KB)")
    print()
    print("─" * 62)
    print("  NEXT STEP")
    print()
    print("  Run two-layer detector:")
    print("    python3 detection/detector_ml.py")
    print("─" * 62)
    print()


if __name__ == "__main__":
    main()
