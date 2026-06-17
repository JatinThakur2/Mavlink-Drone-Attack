#!/usr/bin/env python3
"""
Standalone attack injector — no SITL / MAVProxy / simulation required.

Sends crafted attack packets directly to the detector's monitor ports:
  14551  — MAVLink monitor  (ATK1, ATK4)
  25101  — GPS monitor      (ATK2, ATK3, ATK3B)

Usage
-----
  # terminal 1: start detector
  python3 detection/detector_ml.py

  # terminal 2: inject one specific attack
  python3 tests/inject_test.py atk1
  python3 tests/inject_test.py atk2
  python3 tests/inject_test.py atk3
  python3 tests/inject_test.py atk3b
  python3 tests/inject_test.py atk4
  python3 tests/inject_test.py normal

  # inject all attacks in sequence
  python3 tests/inject_test.py all
"""

import json
import socket
import struct
import sys
import time

# ── Detector monitor ports (matches detector_ml.py) ───────────
MAV_MONITOR_PORT = 14551
GPS_MONITOR_PORT = 25101
HOST             = "127.0.0.1"

# ── Attack constants (must match attack scripts) ───────────────
MAVLINK_EPOCH   = 1_420_070_400
FUTURE_DAYS     = 1
SPOOF_DAYS      = 10
OVERFLOW_UNIX   = MAVLINK_EPOCH + int(((2 ** 48) - 1) / 100_000)   # 4,234,820,167
UNDERFLOW_UNIX  = 1_262_304_000                                      # Jan 1, 2010


# ─────────────────────────────────────────────────────────────
# Packet builders
# ─────────────────────────────────────────────────────────────

def _build_mavlink_signed(ts_unix: float, seq: int = 1) -> bytes:
    """
    Build a minimal MAVLink 2.0 signed packet.

    The detector only reads: magic byte, payload_len, incompat_flags,
    signing timestamp (6 bytes LE in 10µs units), sysid, seq.
    CRC and signature hash are not validated by the detector —
    any 2-byte CRC and 6-byte hash placeholder are fine here.
    """
    payload      = b'\x00' * 9       # minimal non-empty payload
    payload_len  = len(payload)
    incompat     = 0x01              # bit 0 = signed

    header = struct.pack(
        "BBBBBBBBBB",
        0xFD,         # magic
        payload_len,  # payload length
        incompat,     # incompat_flags (0x01 = signed)
        0x00,         # compat_flags
        seq % 256,    # sequence number
        1,            # sysid
        1,            # compid
        0, 0, 0,      # msgid (3 bytes LE) — HEARTBEAT = 0
    )
    crc         = b'\x00\x00'        # placeholder CRC
    link_id     = b'\x01'            # signing link ID

    ts_val      = int((ts_unix - MAVLINK_EPOCH) * 100_000)
    ts_bytes    = ts_val.to_bytes(6, "little")
    sig_hash    = b'\x00' * 6       # placeholder hash

    return header + payload + crc + link_id + ts_bytes + sig_hash


def _build_gps_json(time_usec: int) -> bytes:
    """
    Build a GPS_INPUT JSON packet (same format MAVProxy GPSInput sends).
    """
    pkt = {
        "time_usec":          time_usec,
        "gps_id":             0,
        "ignore_flags":       0,
        "time_week_ms":       0,
        "time_week":          0,
        "fix_type":           3,
        "lat":                -353632620,   # Canberra SITL position
        "lon":                1491652374,
        "alt":                584.0,
        "hdop":               1,
        "vdop":               1,
        "vn":                 0,
        "ve":                 0,
        "vd":                 0,
        "speed_accuracy":     0.3,
        "horiz_accuracy":     1.0,
        "vert_accuracy":      1.5,
        "satellites_visible": 10,
    }
    return json.dumps(pkt).encode()


# ─────────────────────────────────────────────────────────────
# Sender helpers
# ─────────────────────────────────────────────────────────────

def _send_mav(raw: bytes, label: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(raw, (HOST, MAV_MONITOR_PORT))
    print(f"  [{label}]  sent {len(raw)} bytes → UDP {HOST}:{MAV_MONITOR_PORT}")


def _send_gps(raw: bytes, label: str):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(raw, (HOST, GPS_MONITOR_PORT))
    print(f"  [{label}]  sent {len(raw)} bytes → UDP {HOST}:{GPS_MONITOR_PORT}")


# ─────────────────────────────────────────────────────────────
# Attack injectors
# ─────────────────────────────────────────────────────────────

def inject_normal(n: int = 5):
    """Send n normal MAVLink heartbeats and n normal GPS packets."""
    print(f"\n[NORMAL] Sending {n} normal packets...")
    now = time.time()
    for i in range(n):
        _send_mav(_build_mavlink_signed(now, seq=i), "MAV NORMAL")
        _send_gps(_build_gps_json(int(now * 1_000_000)), "GPS NORMAL")
        time.sleep(0.1)


def inject_atk1(n: int = 5):
    """ATK1 — future MAVLink signing timestamp (+1 day)."""
    print(f"\n[ATK1] Sending {n} future-timestamp MAVLink packets...")
    future_unix = time.time() + FUTURE_DAYS * 86400
    for i in range(n):
        _send_mav(_build_mavlink_signed(future_unix, seq=i), "ATK1_FUTURE")
        time.sleep(0.1)


def inject_atk2(n: int = 5):
    """ATK2 — GPS clock +10 days ahead."""
    print(f"\n[ATK2] Sending {n} spoofed GPS packets (+{SPOOF_DAYS} days)...")
    spoofed_usec = int((time.time() + SPOOF_DAYS * 86400) * 1_000_000)
    for i in range(n):
        _send_gps(_build_gps_json(spoofed_usec), "ATK2_SPOOF")
        time.sleep(0.1)


def inject_atk3(n: int = 5):
    """ATK3 — GPS timestamp overflow (year 2104 / 48-bit MAX)."""
    print(f"\n[ATK3] Sending {n} overflow GPS packets (OVERFLOW_UNIX={OVERFLOW_UNIX})...")
    overflow_usec = OVERFLOW_UNIX * 1_000_000
    for i in range(n):
        _send_gps(_build_gps_json(overflow_usec), "ATK3_OVER")
        time.sleep(0.1)


def inject_atk3b(n: int = 5):
    """ATK3B — GPS timestamp underflow (year 2010 / pre-MAVLink epoch)."""
    print(f"\n[ATK3B] Sending {n} underflow GPS packets (UNDERFLOW_UNIX={UNDERFLOW_UNIX})...")
    underflow_usec = UNDERFLOW_UNIX * 1_000_000
    for i in range(n):
        _send_gps(_build_gps_json(underflow_usec), "ATK3B_UNDER")
        time.sleep(0.1)


def inject_atk4(n: int = 5):
    """ATK4 — replay: same packet sent multiple times (is_duplicate=1 on 2nd+)."""
    print(f"\n[ATK4] Sending {n} replayed MAVLink packets (same bytes each time)...")
    future_unix = time.time() + FUTURE_DAYS * 86400
    # Build one packet and send the exact same bytes every time
    packet = _build_mavlink_signed(future_unix, seq=77)
    for i in range(n):
        _send_mav(packet, "ATK4_REPLAY")
        time.sleep(0.1)


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

ATTACKS = {
    "normal": inject_normal,
    "atk1":   inject_atk1,
    "atk2":   inject_atk2,
    "atk3":   inject_atk3,
    "atk3b":  inject_atk3b,
    "atk4":   inject_atk4,
}


def main():
    choice = sys.argv[1].lower() if len(sys.argv) > 1 else "all"

    print("=" * 55)
    print("  MAVLink Attack Injector — no SITL required")
    print("=" * 55)
    print(f"  MAVLink monitor : {HOST}:{MAV_MONITOR_PORT}")
    print(f"  GPS monitor     : {HOST}:{GPS_MONITOR_PORT}")
    print()

    if choice == "all":
        inject_normal()
        time.sleep(0.5)
        inject_atk1()
        time.sleep(0.5)
        inject_atk2()
        time.sleep(0.5)
        inject_atk3()
        time.sleep(0.5)
        inject_atk3b()
        time.sleep(0.5)
        inject_atk4()
    elif choice in ATTACKS:
        ATTACKS[choice]()
    else:
        print(f"Unknown attack: {choice}")
        print(f"Valid choices: {', '.join(ATTACKS)} all")
        sys.exit(1)

    print("\nDone. Check your detector terminal for alerts.")


if __name__ == "__main__":
    main()
