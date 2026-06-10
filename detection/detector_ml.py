#!/usr/bin/env python3
"""
=============================================================
Step 4 — Two-Layer Real-Time Detector
=============================================================
Combines the Step 2 statistical rules with the Step 3
Isolation Forest model for two-layer anomaly detection.

Layer 1 — Statistical rules (instant, no training needed)
    Same 6 rules as detector.py:
      Rule 1  ATK1_FUTURE_TS     — future MAVLink signature
      Rule 2  ATK3B_UNDERFLOW    — GPS pre-epoch timestamp
      Rule 3  ATK3_OVERFLOW      — GPS far-future timestamp
      Rule 4  ATK2_GPS_SPOOF     — GPS clock >1 day ahead
      Rule 5  ATK4_REPLAY        — duplicate packet hash
      Rule 6  ATK3B_BURST        — GPS burst DoS pattern

Layer 2 — Isolation Forest (trained on Step 3 normal traffic)
    Scores every feature vector against the learned normal
    distribution.  Fires ATK_ML_ANOMALY when the anomaly
    score crosses the threshold.

Prerequisites
-------------
  1. Run Step 3 first to train the model:
         python3 detection/train_baseline.py
  2. Model must exist at detection/models/baseline.pkl

Run
---
  python3 detection/detector_ml.py

Stop: Ctrl+C
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
from collections import deque
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from features import FeatureExtractor, Features, MAVLINK_EPOCH
import alerts as A

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
MAVLINK_PORT   = 14550
MONITOR_PORT   = 14551
GPS_PORT       = 25100
GPS_MONITOR    = 25101
RECV_BUF       = 65535

MODEL_FILE     = os.path.join(SCRIPT_DIR, "models", "baseline.pkl")

# ── Statistical rule thresholds (identical to detector.py) ────
TS_GAP_FUTURE_SEC   = 3600
GPS_UNDERFLOW_UNIX  = MAVLINK_EPOCH
GPS_OVERFLOW_UNIX   = 2_524_608_000
GPS_SPOOF_DELTA_SEC = 86_400
BURST_COUNT         = 5
BURST_WINDOW_SEC    = 2.0

# ── ML layer threshold ─────────────────────────────────────────
# Isolation Forest decision_function returns:
#   >  0.0  →  clearly normal
#   ~  0.0  →  borderline
#   < -0.1  →  anomaly (tune this based on false-positive rate)
ML_SCORE_THRESHOLD  = -0.13

# ─────────────────────────────────────────────────────────────
# Load model bundle
# ─────────────────────────────────────────────────────────────
def _load_model():
    if not os.path.exists(MODEL_FILE):
        print(f"\n[ERROR] Model not found: {MODEL_FILE}")
        print("        Run Step 3 first:")
        print("          python3 detection/train_baseline.py\n")
        sys.exit(1)

    with open(MODEL_FILE, "rb") as f:
        bundle = pickle.load(f)

    A.info("ML", f"Model loaded — trained {bundle['trained_at']}")
    A.info("ML", f"  samples={bundle['n_samples']:,}  "
                 f"contamination={bundle['contamination']}  "
                 f"capture={bundle['capture_sec']}s")
    A.info("ML", f"  score_mean={bundle['score_mean']:.4f}  "
                 f"threshold={ML_SCORE_THRESHOLD}")
    return bundle["scaler"], bundle["clf"]


# ─────────────────────────────────────────────────────────────
# Packet queue
# ─────────────────────────────────────────────────────────────
pkt_queue: queue.Queue = queue.Queue()


def _listen(port: int, label: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    sock.bind(("0.0.0.0", port))
    A.info("DETECTOR", f"Listening on UDP {port}  ({label})")

    while True:
        try:
            data, addr = sock.recvfrom(RECV_BUF)
            pkt_queue.put((label, data, addr))
        except OSError:
            break


# ─────────────────────────────────────────────────────────────
# Statistical rule engine  (copy of detector.py RuleEngine)
# ─────────────────────────────────────────────────────────────
class RuleEngine:
    def __init__(self):
        self._gps_arrivals: deque = deque()

    def check(self, feat: Features) -> list[tuple[str, str]]:
        fired = []

        if feat.ts_gap is not None and feat.ts_gap > TS_GAP_FUTURE_SEC:
            h = feat.ts_gap / 3600
            fired.append((
                "ATK1_FUTURE_TS",
                f"sig timestamp {h:.1f}h in the future | "
                f"sysid={feat.sysid} msgid={feat.msgid} seq={feat.seq}"
            ))

        if feat.gps_unix is not None and feat.gps_unix < GPS_UNDERFLOW_UNIX:
            gps_date = datetime.utcfromtimestamp(feat.gps_unix).strftime("%Y-%m-%d")
            fired.append((
                "ATK3B_UNDERFLOW",
                f"GPS date={gps_date} before MAVLink epoch | uint64 wrap DoS"
            ))

        elif feat.gps_unix is not None and feat.gps_unix > GPS_OVERFLOW_UNIX:
            gps_date = datetime.utcfromtimestamp(feat.gps_unix).strftime("%Y-%m-%d")
            yrs = (feat.gps_unix - time.time()) / (365.25 * 86400)
            fired.append((
                "ATK3_OVERFLOW",
                f"GPS date={gps_date} (+{yrs:.0f} years) | signing clock → 2^48-1 | PERMANENT DoS"
            ))

        elif feat.gps_sys_delta is not None and feat.gps_sys_delta > GPS_SPOOF_DELTA_SEC:
            days  = feat.gps_sys_delta / 86400
            drift = f"{feat.drift_m_per_s:.1f} m/s" if feat.drift_m_per_s is not None else "?"
            fired.append((
                "ATK2_GPS_SPOOF",
                f"GPS clock +{days:.1f} days ahead | drift={drift}"
            ))

        if feat.is_duplicate:
            fired.append((
                "ATK4_REPLAY",
                f"exact duplicate hash | source={feat.source} sysid={feat.sysid}"
            ))

        if feat.source == "gps_json":
            now = time.time()
            self._gps_arrivals.append(now)
            while self._gps_arrivals and self._gps_arrivals[0] < now - BURST_WINDOW_SEC:
                self._gps_arrivals.popleft()
            count = len(self._gps_arrivals)
            if count > BURST_COUNT:
                fired.append((
                    "ATK3B_BURST",
                    f"{count} GPS packets in {BURST_WINDOW_SEC}s | DoS burst pattern"
                ))

        return fired


# ─────────────────────────────────────────────────────────────
# ML scoring layer
# ─────────────────────────────────────────────────────────────
class MLLayer:
    def __init__(self, scaler, clf):
        self._scaler = scaler
        self._clf    = clf

    def score(self, feat: Features) -> tuple[float, bool]:
        """
        Returns (anomaly_score, is_anomaly).
        anomaly_score < ML_SCORE_THRESHOLD → is_anomaly = True.
        Uses ml_vector (5 features) — is_duplicate excluded, handled by Rule 5.
        """
        v      = np.array([feat.ml_vector], dtype=np.float64)
        v_sc   = self._scaler.transform(v)
        score  = float(self._clf.decision_function(v_sc)[0])
        return score, score < ML_SCORE_THRESHOLD


# ─────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────
def run():
    A.banner("MAVLink Two-Layer Detector — Step 4 (Rules + Isolation Forest)")

    scaler, clf = _load_model()

    A.info("DETECTOR", "Starting listeners...")

    extractor  = FeatureExtractor()
    rules      = RuleEngine()
    ml         = MLLayer(scaler, clf)

    for port, label in [
        (MAVLINK_PORT, "MAVLink"),
        (MONITOR_PORT, "MAVLink"),
        (GPS_PORT,     "GPS_INPUT"),
        (GPS_MONITOR,  "GPS_INPUT"),
    ]:
        t = threading.Thread(target=_listen, args=(port, label), daemon=True)
        t.start()

    total_pkts   = 0
    rule_alerts  = 0
    ml_alerts    = 0

    A.info("DETECTOR", "Ready. Waiting for packets... (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                label, raw, addr = pkt_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            total_pkts += 1

            feat = None
            if label == "MAVLink":
                feat = extractor.from_mavlink(raw)
            elif label == "GPS_INPUT":
                try:
                    feat = extractor.from_gps_json(raw.decode("utf-8", errors="ignore"))
                except Exception:
                    pass

            if feat is None:
                continue

            # ── Layer 1: Statistical rules ────────────────────────
            findings = rules.check(feat)
            if findings:
                for tag, detail in findings:
                    A.alert(tag, detail)
                    rule_alerts += 1

            # ── Layer 2: Isolation Forest ─────────────────────────
            score, is_anom = ml.score(feat)
            if is_anom:
                # Only fire ML alert if rules did NOT already flag this packet
                # to avoid double-counting obvious attacks.
                if not findings:
                    A.alert(
                        "ATK_ML_ANOMALY",
                        f"ML score={score:.4f} < threshold={ML_SCORE_THRESHOLD} | "
                        f"source={feat.source} vector={[round(v,2) for v in feat.vector]}"
                    )
                    ml_alerts += 1

            # ── Normal packet summary every 50 packets ────────────
            if not findings and not is_anom and total_pkts % 50 == 0:
                A.norm(
                    "NORMAL",
                    f"pkt={total_pkts} rule_alerts={rule_alerts} ml_alerts={ml_alerts} "
                    f"ml_score={score:.3f} | vector={[round(v,1) for v in feat.vector]}"
                )
    except KeyboardInterrupt:
        pass
    finally:
        print()
        A.banner("Detector stopped")
        A.session_summary(total_pkts, rule_alerts + ml_alerts)


if __name__ == "__main__":
    run()
