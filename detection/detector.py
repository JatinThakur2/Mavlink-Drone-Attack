#!/usr/bin/env python3
"""
=============================================================
Step 2 — Real-Time Detector
=============================================================
Listens on two UDP ports simultaneously:
  - 14550  MAVLink 2.0 stream  (signed commands, heartbeats)
  - 25100  GPS_INPUT JSON      (GPS spoofing / DoS packets)

For every packet:
  1. Extracts 6 features  (features.py)
  2. Applies 6 statistical rules  (instant, no training needed)
  3. Prints colour-coded alert to terminal
  4. Appends entry to detection/results/alerts.log

Run:
  python3 detection/detector.py

Stop: Ctrl+C
=============================================================
"""

import os
import sys
import socket
import threading
import queue
import time
from collections import deque
from datetime import datetime

# Make sure sibling modules are importable when run from any directory
sys.path.insert(0, os.path.dirname(__file__))

from features import FeatureExtractor, Features, MAVLINK_EPOCH
import alerts as A

# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────
MAVLINK_PORT   = 14550
MONITOR_PORT   = 14551   # attack scripts mirror MAVLink attack packets here
GPS_PORT       = 25100
GPS_MONITOR    = 25101   # attack scripts mirror GPS attack packets here
RECV_BUF       = 65535

# ── Rule thresholds ───────────────────────────────────────────
# Rule 1 — future timestamp on a signed MAVLink packet
TS_GAP_FUTURE_SEC    = 3600            # 1 hour ahead → likely replay/attack 1

# Rule 2 — GPS time before MAVLink epoch (Jan 1 2015) → underflow
GPS_UNDERFLOW_UNIX   = MAVLINK_EPOCH   # 1_420_070_400

# Rule 3 — GPS time after year 2050 → overflow DoS
GPS_OVERFLOW_UNIX    = 2_524_608_000   # Jan 1 2050 (Unix)

# Rule 4 — GPS clock more than 1 day ahead of system → spoof
GPS_SPOOF_DELTA_SEC  = 86_400          # 1 day

# Rule 5 — duplicate packet → replay
# (handled by is_duplicate flag from features.py)

# Rule 6 — GPS burst: more than N packets in T seconds → DoS burst
BURST_COUNT          = 5
BURST_WINDOW_SEC     = 2.0

# ─────────────────────────────────────────────────────────────
# Shared packet queue  (listener threads → main thread)
# ─────────────────────────────────────────────────────────────
pkt_queue: queue.Queue = queue.Queue()


# ─────────────────────────────────────────────────────────────
# Statistical rule engine
# ─────────────────────────────────────────────────────────────
class RuleEngine:
    """
    Applies 6 deterministic threshold rules to a feature vector.
    Returns a list of (tag, detail) tuples — one per rule that fired.
    Empty list means no anomaly detected.
    """

    def __init__(self):
        # Rolling window of GPS packet arrival times for burst detection
        self._gps_arrivals: deque = deque()

    def check(self, feat: Features) -> list[tuple[str, str]]:
        fired = []

        # ── Rule 1: Future signature timestamp ────────────────
        if feat.ts_gap is not None and feat.ts_gap > TS_GAP_FUTURE_SEC:
            h = feat.ts_gap / 3600
            fired.append((
                "ATK1_FUTURE_TS",
                f"sig timestamp {h:.1f}h in the future | "
                f"sysid={feat.sysid} msgid={feat.msgid} seq={feat.seq} | "
                f"possible REPLAY or signed command injection"
            ))

        # ── Rule 2: GPS underflow (pre-epoch) ─────────────────
        if feat.gps_unix is not None and feat.gps_unix < GPS_UNDERFLOW_UNIX:
            gps_date = datetime.utcfromtimestamp(feat.gps_unix).strftime("%Y-%m-%d")
            fired.append((
                "ATK3B_UNDERFLOW",
                f"GPS date={gps_date} is BEFORE MAVLink epoch (Jan 1 2015) | "
                f"signed ts will be NEGATIVE → uint64 wrap to ~2^64 | DoS or clock reset"
            ))

        # ── Rule 3: GPS overflow (far future) ─────────────────
        elif feat.gps_unix is not None and feat.gps_unix > GPS_OVERFLOW_UNIX:
            gps_date = datetime.utcfromtimestamp(feat.gps_unix).strftime("%Y-%m-%d")
            yrs = (feat.gps_unix - time.time()) / (365.25 * 86400)
            fired.append((
                "ATK3_OVERFLOW",
                f"GPS date={gps_date} (+{yrs:.0f} years) | "
                f"signing clock → 2^48-1 | all real 2026 cmds rejected | PERMANENT DoS"
            ))

        # ── Rule 4: GPS clock advance (spoof) ─────────────────
        elif feat.gps_sys_delta is not None and feat.gps_sys_delta > GPS_SPOOF_DELTA_SEC:
            days = feat.gps_sys_delta / 86400
            drift = f"{feat.drift_m_per_s:.1f} m/s" if feat.drift_m_per_s is not None else "?"
            fired.append((
                "ATK2_GPS_SPOOF",
                f"GPS clock +{days:.1f} days ahead of system | "
                f"drift={drift} | drone will compensate → flies in opposite direction"
            ))

        # ── Rule 5: Duplicate packet (replay) ─────────────────
        if feat.is_duplicate:
            fired.append((
                "ATK4_REPLAY",
                f"exact duplicate packet hash detected | "
                f"source={feat.source} sysid={feat.sysid} msgid={feat.msgid} | "
                f"byte-for-byte replay — signature still valid if ts in future"
            ))

        # ── Rule 6: GPS burst (DoS burst pattern) ─────────────
        if feat.source == "gps_json":
            now = time.time()
            self._gps_arrivals.append(now)
            # Drop arrivals outside the window
            while self._gps_arrivals and self._gps_arrivals[0] < now - BURST_WINDOW_SEC:
                self._gps_arrivals.popleft()
            count = len(self._gps_arrivals)
            if count > BURST_COUNT:
                fired.append((
                    "ATK3B_BURST",
                    f"{count} GPS packets in {BURST_WINDOW_SEC}s | "
                    f"normal rate is 1 per 200ms | DoS burst pattern (Attack 3B style)"
                ))

        return fired


# ─────────────────────────────────────────────────────────────
# UDP listener threads
# ─────────────────────────────────────────────────────────────
def _listen(port: int, label: str):
    """
    Bind a UDP socket on `port` and push every received datagram
    onto pkt_queue as (label, raw_bytes, addr).

    Uses SO_REUSEPORT so we can listen alongside MAVProxy/GPSInput
    without interrupting them.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass  # SO_REUSEPORT not available on all platforms

    sock.bind(("0.0.0.0", port))
    A.info("DETECTOR", f"Listening on UDP {port}  ({label})")

    while True:
        try:
            data, addr = sock.recvfrom(RECV_BUF)
            pkt_queue.put((label, data, addr))
        except OSError:
            break


# ─────────────────────────────────────────────────────────────
# Main processing loop
# ─────────────────────────────────────────────────────────────
def run():
    A.banner("MAVLink Anomaly Detector — Step 2 (Statistical Rules)")
    A.info("DETECTOR", "Starting listeners...")

    extractor = FeatureExtractor()
    engine    = RuleEngine()

    # Start listener threads
    for port, label in [(MAVLINK_PORT, "MAVLink"), (MONITOR_PORT, "MAVLink"),
                        (GPS_PORT, "GPS_INPUT"), (GPS_MONITOR, "GPS_INPUT")]:
        t = threading.Thread(target=_listen, args=(port, label), daemon=True)
        t.start()

    # Packet counters
    total_pkts  = 0
    alert_count = 0

    A.info("DETECTOR", "Ready. Waiting for packets... (Ctrl+C to stop)\n")

    while True:
        try:
            label, raw, addr = pkt_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        total_pkts += 1

        # ── Extract features ──────────────────────────────────
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

        # ── Apply rules ───────────────────────────────────────
        findings = engine.check(feat)

        if findings:
            for tag, detail in findings:
                A.alert(tag, detail)
                alert_count += 1
        else:
            # Normal packet — print brief summary every 50 packets
            if total_pkts % 50 == 0:
                A.norm(
                    "NORMAL",
                    f"pkt={total_pkts} alerts={alert_count} | "
                    f"vector={[round(v,1) for v in feat.vector]}"
                )


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print()
        A.banner("Detector stopped")
        A.info("SESSION", f"Log saved → {A.LOG_FILE}")
