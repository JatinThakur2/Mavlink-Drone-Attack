#!/usr/bin/env python3
"""
Generate synthetic labeled dataset for MAVLink attack classification.

Classes
-------
0  NORMAL       — no attack; ts_gap and gps_sys_delta ~ 0
1  ATK1_FUTURE  — signed future timestamp (+1 day in MAVLink sig block)
2  ATK2_SPOOF   — GPS clock spoofed +10 days ahead
3  ATK3_OVER    — 48-bit MAVLink timestamp overflow (points to year 2104)
4  ATK3B_UNDER  — GPS clock forced to year 2010 (before MAVLink epoch)
5  ATK4_REPLAY  — replayed ATK1 packet; same ts_gap as ATK1, is_duplicate=1

Feature vector (mirrors features.py ml_vector, plus is_duplicate)
------------------------------------------------------------------
  ts_gap        — sig_timestamp_unix − time.time()    (seconds)
  gps_sys_delta — gps_unix − time.time()              (seconds)
  is_duplicate  — 1 if SHA-256 of raw bytes seen before, else 0

How means are derived
---------------------
Each attack class's mean is computed from the *same constants* that the
attack script uses, so the synthetic distribution is anchored to real
injected values — not guessed.

  ATK1/4  ts_gap       = FUTURE_DAYS × 86 400               = 86 400
  ATK2    gps_sys_delta = SPOOF_DAYS × 86 400                = 864 000
  ATK3    gps_sys_delta = OVERFLOW_UNIX − reference_time    ≈ +2.48 × 10⁹
  ATK3B   gps_sys_delta = UNDERFLOW_UNIX − reference_time   ≈ −4.88 × 10⁸

Output
------
  ml/dataset/train.csv  (80 % of each class, stratified)
  ml/dataset/test.csv   (20 % of each class, stratified)
  ml/dataset/meta.txt   reference_time used for ATK3/ATK3B means
"""

import os
import time
import numpy as np
import pandas as pd

# ── Constants (must match the attack scripts exactly) ─────────
MAVLINK_EPOCH    = 1_420_070_400           # Jan 1 2015 00:00:00 UTC
FUTURE_DAYS      = 1
SPOOF_DAYS       = 10
MAX_48BIT        = (2 ** 48) - 1
OVERFLOW_UNIX    = MAVLINK_EPOCH + int(MAX_48BIT / 100_000)   # 4 234 820 167
UNDERFLOW_UNIX   = 1_262_304_000                               # Jan 1 2010

SAMPLES_PER_CLASS = 1_000
TRAIN_RATIO       = 0.80
RANDOM_SEED       = 42

# Gaussian noise std-dev added to each sample (seconds)
NOISE_NORMAL = 2.0    # NTP / kernel scheduling jitter for legitimate packets
NOISE_ATK    = 50.0   # small measurement noise around the injected constant


def generate(reference_time: float, seed: int = RANDOM_SEED) -> pd.DataFrame:
    """
    Build the full dataset DataFrame.

    reference_time is used ONLY to compute ATK3 and ATK3B means, which
    are offsets from the current wall clock.  All other class means are
    constant offsets derived directly from attack-script constants.
    """
    rng = np.random.default_rng(seed)

    atk3_gps_mean  = OVERFLOW_UNIX  - reference_time   # ~+2.48 × 10⁹ s
    atk3b_gps_mean = UNDERFLOW_UNIX - reference_time   # ~−4.88 × 10⁸ s

    # (label_id, label_name, ts_gap_mean, gps_sys_delta_mean, is_duplicate)
    classes = [
        (0, "NORMAL",      0.0,                 0.0,                   0),
        (1, "ATK1_FUTURE", FUTURE_DAYS * 86400, 0.0,                   0),
        (2, "ATK2_SPOOF",  0.0,                 SPOOF_DAYS * 86400,    0),
        (3, "ATK3_OVER",   0.0,                 atk3_gps_mean,         0),
        (4, "ATK3B_UNDER", 0.0,                 atk3b_gps_mean,        0),
        (5, "ATK4_REPLAY", FUTURE_DAYS * 86400, 0.0,                   1),
    ]

    rows = []
    for label_id, label_name, ts_mean, gps_mean, is_dup in classes:
        noise = NOISE_NORMAL if label_id == 0 else NOISE_ATK
        ts_samples  = rng.normal(ts_mean,  noise, SAMPLES_PER_CLASS)
        gps_samples = rng.normal(gps_mean, noise, SAMPLES_PER_CLASS)

        for ts_g, gps_d in zip(ts_samples, gps_samples):
            rows.append({
                "ts_gap":        round(float(ts_g),  4),
                "gps_sys_delta": round(float(gps_d), 4),
                "is_duplicate":  int(is_dup),
                "label_id":      label_id,
                "label_name":    label_name,
            })

    return pd.DataFrame(rows)


def main():
    reference_time = time.time()
    ref_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(reference_time))
    print(f"Reference time : {reference_time:.2f}  ({ref_str})")

    df = generate(reference_time)

    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
    os.makedirs(out_dir, exist_ok=True)

    # Stratified 80/20 split
    train_parts, test_parts = [], []
    for lid in sorted(df["label_id"].unique()):
        subset  = df[df["label_id"] == lid].sample(frac=1, random_state=RANDOM_SEED)
        n_train = int(len(subset) * TRAIN_RATIO)
        train_parts.append(subset.iloc[:n_train])
        test_parts.append(subset.iloc[n_train:])

    train_df = pd.concat(train_parts).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    test_df  = pd.concat(test_parts ).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    train_path = os.path.join(out_dir, "train.csv")
    test_path  = os.path.join(out_dir, "test.csv")
    meta_path  = os.path.join(out_dir, "meta.txt")

    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path,   index=False)

    with open(meta_path, "w") as f:
        f.write(f"reference_time_unix={reference_time:.2f}\n")
        f.write(f"reference_time_utc={ref_str}\n")
        f.write(f"samples_per_class={SAMPLES_PER_CLASS}\n")
        f.write(f"train_ratio={TRAIN_RATIO}\n")
        f.write(f"atk3_gps_mean={OVERFLOW_UNIX - reference_time:.2f}\n")
        f.write(f"atk3b_gps_mean={UNDERFLOW_UNIX - reference_time:.2f}\n")

    print(f"\nDataset written:")
    print(f"  {train_path}  ({len(train_df):,} rows)")
    print(f"  {test_path}   ({len(test_df):,} rows)")
    print(f"  {meta_path}")

    print(f"\nClass distribution (train):")
    dist = train_df.groupby(["label_id", "label_name"]).size().reset_index(name="count")
    print(dist.to_string(index=False))

    print(f"\nFeature statistics (train):")
    print(train_df[["ts_gap", "gps_sys_delta", "is_duplicate"]].describe().round(2).to_string())


if __name__ == "__main__":
    main()
