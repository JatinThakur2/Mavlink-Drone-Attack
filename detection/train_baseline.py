#!/usr/bin/env python3
"""
=============================================================
Step 3 — Baseline Training (Isolation Forest)
=============================================================
Captures NORMAL traffic from the running SITL for a fixed
duration, then trains an Isolation Forest on the collected
feature vectors and saves the model.

HOW TO USE
----------
1. Start SITL normally (no attacks):
       cd ~/ardupilot
       python3 Tools/autotest/sim_vehicle.py -v ArduCopter \
           --out=udp:127.0.0.1:14550 -w

2. Wait for "EKF3 IMU0 is using GPS" in the SITL console.

3. In a second terminal, run this script:
       python3 detection/train_baseline.py

4. Let it run for the full capture window (default 5 min).
   The model is saved to detection/models/baseline.pkl.

5. The saved model is loaded by detector.py (Step 4) to add
   ML-based anomaly scoring alongside the statistical rules.

TRAINING PRINCIPLE
------------------
Isolation Forest is an UNSUPERVISED algorithm.
It trains ONLY on normal packets — no attack data is used.
During inference, attack packets produce extreme feature values
(ts_gap in hours, gps_sys_delta in days, etc.) that are far
from the normal cluster, so the Isolation Forest scores them
as anomalies without ever having seen them before.
=============================================================
"""

import os
import sys
import socket
import threading
import queue
import time
import pickle
import numpy as np

# ─── Resolve paths so the script can be run from any directory ───────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)

from features import FeatureExtractor

# ─── sklearn Isolation Forest ────────────────────────────────────────────────
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("\n[ERROR] scikit-learn is not installed.")
    print("        Run:  pip install scikit-learn numpy")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
CAPTURE_SEC    = 300          # capture window — 5 minutes of normal traffic
MIN_SAMPLES    = 500          # abort if we get fewer than this (SITL not running)

MAVLINK_PORT   = 14550
MONITOR_PORT   = 14551
GPS_PORT       = 25100
GPS_MONITOR    = 25101

CONTAMINATION  = 0.05         # 5% — expected fraction of outliers in training data
N_ESTIMATORS   = 200          # number of trees in the forest
RANDOM_STATE   = 42

MODEL_DIR  = os.path.join(SCRIPT_DIR, "models")
MODEL_FILE = os.path.join(MODEL_DIR, "baseline.pkl")

FEATURE_NAMES = [
    "ts_gap",
    "gps_sys_delta",
]

# ─────────────────────────────────────────────────────────────────────────────
# Packet capture thread
# ─────────────────────────────────────────────────────────────────────────────
pkt_queue: queue.Queue = queue.Queue()
_stop_event = threading.Event()


def _listen(port: int, label: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    sock.settimeout(1.0)
    sock.bind(("0.0.0.0", port))

    while not _stop_event.is_set():
        try:
            data, _ = sock.recvfrom(65535)
            pkt_queue.put((label, data))
        except socket.timeout:
            continue
        except OSError:
            break
    sock.close()


# ─────────────────────────────────────────────────────────────────────────────
# Progress bar helper
# ─────────────────────────────────────────────────────────────────────────────
def _bar(elapsed: float, total: float, width: int = 40) -> str:
    frac   = min(elapsed / total, 1.0)
    filled = int(frac * width)
    return f"[{'█' * filled}{'░' * (width - filled)}] {int(frac*100):3d}%"


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print()
    print("=" * 62)
    print("  Step 3 — Baseline Training  (Isolation Forest)")
    print("=" * 62)
    print()
    print(f"  Capture window  : {CAPTURE_SEC}s  ({CAPTURE_SEC//60} min)")
    print(f"  Listening on    : UDP {MONITOR_PORT} (MAVLink monitor), {GPS_MONITOR} (GPS monitor)")
    print(f"  Model output    : {MODEL_FILE}")
    print(f"  Contamination   : {CONTAMINATION}  (5% allowed anomaly rate)")
    print(f"  Trees           : {N_ESTIMATORS}")
    print()
    print("  IMPORTANT: Make sure SITL is running with NO attacks active.")
    print("  The model trains ONLY on normal traffic.")
    print()
    input("  Press ENTER when SITL is ready...")
    print()

    # ── Start listener threads ────────────────────────────────────────────────
    # Use ONLY the exclusive monitor ports (14551, 25101) — not the shared main
    # ports (14550, 25100).  SITL outputs to 14551 directly (via --out flag) and
    # simulate_normal_gps.py mirrors to 25101, so these ports receive one clean
    # copy of every packet.  Listening on 14550 alongside MAVProxy via
    # SO_REUSEPORT causes each heartbeat to arrive twice, producing seq_jump≈0.5
    # and corrupted iat_ms in the training data.
    for port, label in [
        (MONITOR_PORT,  "MAVLink"),
        (GPS_MONITOR,   "GPS_INPUT"),
    ]:
        t = threading.Thread(target=_listen, args=(port, label), daemon=True)
        t.start()

    print(f"  Capturing normal traffic for {CAPTURE_SEC} seconds...\n")

    extractor = FeatureExtractor()
    vectors   = []

    start_time = time.time()
    last_print = start_time

    while True:
        elapsed = time.time() - start_time
        if elapsed >= CAPTURE_SEC:
            break

        # Drain queue
        try:
            while True:
                label, raw = pkt_queue.get_nowait()
                feat = None
                if label == "MAVLink":
                    feat = extractor.from_mavlink(raw)
                elif label == "GPS_INPUT":
                    try:
                        feat = extractor.from_gps_json(raw.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
                if feat is not None:
                    vectors.append(feat.ml_vector)
        except queue.Empty:
            pass

        # Print progress every 10 seconds
        now = time.time()
        if now - last_print >= 10:
            last_print = now
            remaining  = CAPTURE_SEC - (now - start_time)
            bar        = _bar(now - start_time, CAPTURE_SEC)
            print(f"  {bar}  pkts={len(vectors):,}  remaining={remaining:.0f}s")

        time.sleep(0.1)

    _stop_event.set()

    print()
    print(f"  Capture complete — {len(vectors):,} feature vectors collected.")
    print()

    # ── Sanity check ─────────────────────────────────────────────────────────
    if len(vectors) < MIN_SAMPLES:
        print(f"[ERROR] Only {len(vectors)} samples — need at least {MIN_SAMPLES}.")
        print("        Is SITL running?  Is the capture window long enough?")
        sys.exit(1)

    # ── Convert to numpy array ────────────────────────────────────────────────
    X = np.array(vectors, dtype=np.float64)

    print("  Feature statistics (normal traffic):")
    print(f"  {'Feature':<20}  {'Mean':>12}  {'Std':>12}  {'Min':>12}  {'Max':>12}")
    print(f"  {'-'*20}  {'-'*12}  {'-'*12}  {'-'*12}  {'-'*12}")
    for i, name in enumerate(FEATURE_NAMES):
        col = X[:, i]
        print(f"  {name:<20}  {col.mean():>12.4f}  {col.std():>12.4f}"
              f"  {col.min():>12.4f}  {col.max():>12.4f}")
    print()

    # ── Scale features ────────────────────────────────────────────────────────
    # StandardScaler so that features with different magnitudes (e.g. iat_ms
    # in hundreds vs is_duplicate in 0/1) have equal influence on the forest.
    print("  Fitting StandardScaler...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Train Isolation Forest ────────────────────────────────────────────────
    print(f"  Training IsolationForest  (n_estimators={N_ESTIMATORS}, "
          f"contamination={CONTAMINATION})...")
    t0 = time.time()
    clf = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    clf.fit(X_scaled)
    elapsed_train = time.time() - t0
    print(f"  Training complete in {elapsed_train:.1f}s.")
    print()

    # ── Quick sanity: score on the training data itself ───────────────────────
    scores = clf.decision_function(X_scaled)   # higher = more normal
    preds  = clf.predict(X_scaled)             # +1 = normal, -1 = anomaly
    n_anom = (preds == -1).sum()
    print(f"  Self-evaluation on training set:")
    print(f"    Total samples  : {len(X):,}")
    print(f"    Flagged as anomaly : {n_anom:,}  ({100*n_anom/len(X):.1f}%)")
    print(f"    Score range    : [{scores.min():.4f}, {scores.max():.4f}]")
    print(f"    Score mean     : {scores.mean():.4f}")
    print()

    # ── Save model bundle ─────────────────────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)

    bundle = {
        "scaler"        : scaler,
        "clf"           : clf,
        "feature_names" : FEATURE_NAMES,
        "n_samples"     : len(X),
        "contamination" : CONTAMINATION,
        "capture_sec"   : CAPTURE_SEC,
        "trained_at"    : time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "score_mean"    : float(scores.mean()),
        "score_std"     : float(scores.std()),
    }

    with open(MODEL_FILE, "wb") as f:
        pickle.dump(bundle, f)

    model_kb = os.path.getsize(MODEL_FILE) / 1024
    print(f"  Model saved → {MODEL_FILE}  ({model_kb:.1f} KB)")
    print()
    print("─" * 62)
    print("  NEXT STEP")
    print()
    print("  Run detector with ML layer (Step 4):")
    print("    python3 detection/detector_ml.py")
    print()
    print("  Or validate the model manually:")
    print("    python3 detection/validate_model.py")
    print("─" * 62)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _stop_event.set()
        print()
        print("  Interrupted — no model saved.")
        print()
