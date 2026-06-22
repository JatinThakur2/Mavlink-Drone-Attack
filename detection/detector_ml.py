#!/usr/bin/env python3
"""
=============================================================
Step 4 — Two-Layer Real-Time Detector
=============================================================
Combines the Step 2 statistical rules with a supervised
RandomForestClassifier that names the specific attack type.

Layer 1 — Statistical rules (instant, no training needed)
    Rule 1  ATK1_FUTURE_TS     — future MAVLink signature
    Rule 2  ATK3B_UNDERFLOW    — GPS pre-epoch timestamp
    Rule 3  ATK3_OVERFLOW      — GPS far-future timestamp
    Rule 4  ATK2_GPS_SPOOF     — GPS clock >1 day ahead
    Rule 5  ATK4_REPLAY        — duplicate packet hash
    Rule 6  ATK3B_BURST        — GPS burst DoS pattern

Layer 2 — RandomForestClassifier (ml/train_classifier.py)
    Classifies every packet into one of six named classes:
      NORMAL | ATK1_FUTURE | ATK2_SPOOF | ATK3_OVER
      ATK3B_UNDER | ATK4_REPLAY
    Fires ATK_ML_<CLASS> only when Layer 1 did not already
    catch the packet, avoiding duplicate alerts.

Prerequisites
-------------
  1. python3 ml/generate_dataset.py
  2. python3 ml/train_classifier.py
     (saves detection/models/classifier.pkl)

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

MODEL_FILE     = os.path.join(SCRIPT_DIR, "models", "classifier.pkl")

# Minimum confidence for the classifier to fire an ML alert.
# Below this threshold the prediction is treated as NORMAL.
ML_CONF_THRESHOLD = 0.70

# ── Statistical rule thresholds (identical to detector.py) ────
TS_GAP_FUTURE_SEC   = 3600
GPS_UNDERFLOW_UNIX  = MAVLINK_EPOCH
GPS_OVERFLOW_UNIX   = 2_524_608_000
GPS_SPOOF_DELTA_SEC = 86_400
BURST_COUNT         = 5
BURST_WINDOW_SEC    = 2.0

# ─────────────────────────────────────────────────────────────
# Load model bundle
# ─────────────────────────────────────────────────────────────
def _load_model():
    if not os.path.exists(MODEL_FILE):
        print(f"\n[ERROR] Classifier not found: {MODEL_FILE}")
        print("        Build it first:")
        print("          python3 ml/generate_dataset.py")
        print("          python3 ml/train_classifier.py\n")
        sys.exit(1)

    with open(MODEL_FILE, "rb") as f:
        bundle = pickle.load(f)

    label_names = bundle["label_names"]
    classes_str = "  ".join(f"{k}={v}" for k, v in sorted(label_names.items()))
    A.info("ML", f"Classifier loaded — features={bundle['features']}")
    A.info("ML", f"  classes: {classes_str}")
    A.info("ML", f"  confidence threshold: {ML_CONF_THRESHOLD}")
    return bundle["model"], label_names


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
            pkt_queue.put((label, port, data, addr))
        except OSError:
            break


# ─────────────────────────────────────────────────────────────
# Statistical rule engine  (copy of detector.py RuleEngine)
# ─────────────────────────────────────────────────────────────
class RuleEngine:
    def __init__(self):
        self._gps_arrivals: deque = deque()

    def check(self, feat: Features, is_monitor: bool = True) -> list[tuple[str, str]]:
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

        # Only fires for monitor port (14551) MAVLink packets.
        # SO_REUSEPORT causes the same heartbeat to arrive on both 14550 and 14551;
        # alerting on 14550 duplicates creates constant false positives.
        # GPS duplicates are never replays; attack2 mirrors the same packet to both
        # 25100 and 25101, so filtering by source=="mavlink" prevents false ATK4_REPLAY.
        if feat.is_duplicate and feat.source == "mavlink" and is_monitor:
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
# ML classification layer
# ─────────────────────────────────────────────────────────────
class ClassifierLayer:
    """
    Wraps the RandomForestClassifier pipeline.

    classify() returns (label_id, label_name, confidence).
    The pipeline already includes StandardScaler internally,
    so raw feature values are passed directly.

    Features used: [ts_gap, gps_sys_delta, is_duplicate]
    """

    NORMAL_ID = 0

    def __init__(self, model, label_names: dict):
        self._model       = model
        self._label_names = label_names

    def classify(self, feat: Features) -> tuple[int, str, float]:
        x = np.array([feat.ml_vector], dtype=np.float64)

        label_id   = int(self._model.predict(x)[0])
        proba      = self._model.predict_proba(x)[0]
        confidence = float(proba[label_id])
        label_name = self._label_names.get(label_id, "UNKNOWN")
        return label_id, label_name, confidence


# ─────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────
def run():
    A.banner("MAVLink Two-Layer Detector — Rules + RandomForest Classifier")

    model, label_names = _load_model()

    A.info("DETECTOR", "Starting listeners...")

    extractor  = FeatureExtractor()
    rules      = RuleEngine()
    clf_layer  = ClassifierLayer(model, label_names)

    for port, label in [
        (MAVLINK_PORT, "MAVLink"),
        (MONITOR_PORT, "MAVLink"),
        (GPS_PORT,     "GPS_INPUT"),
        (GPS_MONITOR,  "GPS_INPUT"),
    ]:
        t = threading.Thread(target=_listen, args=(port, label), daemon=True)
        t.start()

    total_pkts  = 0
    rule_alerts = 0
    ml_alerts   = 0
    last_conf   = 0.0
    last_class  = "NORMAL"

    A.info("DETECTOR", "Ready. Waiting for packets... (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                label, port, raw, addr = pkt_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            total_pkts += 1
            is_monitor = port in (MONITOR_PORT, GPS_MONITOR)

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
            findings = rules.check(feat, is_monitor=is_monitor)
            if findings:
                for tag, detail in findings:
                    A.alert(tag, detail)
                    rule_alerts += 1

            # ── Layer 2: RandomForest classifier ──────────────────
            label_id, label_name, confidence = clf_layer.classify(feat)
            last_conf  = confidence
            last_class = label_name

            is_attack = (label_id != ClassifierLayer.NORMAL_ID
                         and confidence >= ML_CONF_THRESHOLD)

            if is_attack and not findings:
                # Rules did not catch it — ML classifier provides the alert
                fv = [
                    feat.ts_gap        if feat.ts_gap        is not None else 0.0,
                    feat.gps_sys_delta if feat.gps_sys_delta is not None else 0.0,
                    float(feat.is_duplicate),
                ]
                A.alert(
                    f"ATK_ML_{label_name}",
                    f"classifier={label_name} conf={confidence:.2%} | "
                    f"source={feat.source} "
                    f"features=[ts_gap={fv[0]:.1f}, gps_delta={fv[1]:.1f}, dup={int(fv[2])}]"
                )
                ml_alerts += 1

            # ── Normal packet summary every 50 packets ────────────
            if not findings and not is_attack and total_pkts % 50 == 0:
                A.norm(
                    "NORMAL",
                    f"pkt={total_pkts} rule_alerts={rule_alerts} ml_alerts={ml_alerts} "
                    f"ml={last_class}({last_conf:.0%}) | "
                    f"vector={[round(v,1) for v in feat.vector]}"
                )
    except KeyboardInterrupt:
        pass
    finally:
        print()
        A.banner("Detector stopped")
        A.session_summary(total_pkts, rule_alerts + ml_alerts)


if __name__ == "__main__":
    run()
