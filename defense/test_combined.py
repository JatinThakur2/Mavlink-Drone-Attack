#!/usr/bin/env python3
"""
Combined attack injector — exercises the DETECTOR and the DEFENSE proxy at once.

Each attack packet is sent to BOTH:
  • the detector's mirror port   127.0.0.1:14551   (+ GPS JSON on :25101)
  • the defense proxy's input     127.0.0.1:14549

So a single run shows, side by side:
  • the DETECTOR flagging the attack   (Terminal running realtime_detector_v4.py)
  • the DEFENSE proxy blocking it       (Terminal running secure_timestamp_defense.py)

Usage:
  python3 test_combined.py        # run all 4 attacks
  python3 test_combined.py 1      # Attack 1 only   (2/3/4 likewise)
"""

import socket, struct, hashlib, time, sys, json

HOST          = '127.0.0.1'
DETECTOR_PORT = 14551            # detector mirror (sees signed packets intact)
DEFENSE_PORT  = 14549            # defense proxy input
GPS_PORT      = 25101            # shared GPS JSON feed (both components read this)
MAVLINK_EPOCH = 1_420_070_400
SECRET_KEY    = 'key'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


# ── CRC-16/MCRF4XX (MAVLink x25crc) ──────────────────────────
def crc16(data: bytes) -> int:
    crc = 0xffff
    for b in data:
        tmp = b ^ (crc & 0xff)
        tmp = (tmp ^ (tmp << 4)) & 0xff
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
    return crc & 0xffff


# ── Build signed COMMAND_LONG (msg_id=76) ─────────────────────
def build_signed_packet(signing_unix: float, seq: int = 200) -> bytes:
    key = hashlib.sha256(SECRET_KEY.encode('ascii')).digest()

    PAYLOAD_VALS = [217.0, 9.0, 0.0, 0.0, 0.0, 0.0, 0.0, 176, 1, 0, 0]
    payload = struct.pack('<fffffffHBBB', *PAYLOAD_VALS)
    while len(payload) > 1 and payload[-1] == 0:
        payload = payload[:-1]

    MSG_ID = 76
    body = bytearray(
        [len(payload), 0x01, 0x00, seq % 256, 255, 230]
        + list(MSG_ID.to_bytes(3, 'little'))
        + list(payload)
    )
    crc_val   = crc16(bytes(body) + bytes([152]))
    crc_bytes = crc_val.to_bytes(2, 'little')

    ts_val    = int((signing_unix - MAVLINK_EPOCH) * 1e5)
    ts_bytes  = ts_val.to_bytes(6, 'little')
    link      = bytes([1])
    magic     = bytes([0xfd])

    m = hashlib.sha256()
    m.update(key); m.update(magic); m.update(body)
    m.update(crc_bytes); m.update(link); m.update(ts_bytes)
    sig = m.digest()[:6]

    return magic + bytes(body) + crc_bytes + link + ts_bytes + sig


# ── Build unsigned SYSTEM_TIME (msg_id=2) for GPS spoof ───────
def build_system_time(gps_unix: float, seq: int = 10) -> bytes:
    time_usec    = int(gps_unix * 1_000_000)
    time_boot_ms = 5000
    payload = struct.pack('<QI', time_usec, time_boot_ms)

    MSG_ID = 2
    body = bytearray(
        [len(payload), 0x00, 0x00, seq % 256, 1, 1]
        + list(MSG_ID.to_bytes(3, 'little'))
        + list(payload)
    )
    crc_val = crc16(bytes(body) + bytes([137]))   # SYSTEM_TIME CRC_EXTRA = 137
    return bytes([0xfd]) + bytes(body) + crc_val.to_bytes(2, 'little')


# ── Dual-send: same packet to BOTH detector and defense ───────
def send_both(pkt: bytes):
    sock.sendto(pkt, (HOST, DETECTOR_PORT))   # → detector flags it
    sock.sendto(pkt, (HOST, DEFENSE_PORT))    # → defense blocks it


def send_gps_json(gps_unix: float):
    """GPS mirror JSON to :25101 (read by both detector and defense L3)."""
    GPS_EPOCH_UNIX   = 315_964_800
    SECONDS_PER_WEEK = 604_800
    elapsed = gps_unix - GPS_EPOCH_UNIX
    data = {
        'time_usec':          int(gps_unix * 1_000_000),
        'time_unix_usec':     int(gps_unix * 1_000_000),   # defense L3 key
        'gps_id':             0,
        'ignore_flags':       0,
        'time_week_ms':       int((elapsed % SECONDS_PER_WEEK) * 1000),
        'time_week':          int(elapsed / SECONDS_PER_WEEK),
        'fix_type':           3,
        'lat':                int(-35.363261 * 1e7),
        'lon':                int(149.165237 * 1e7),
        'alt':                584.0,
        'hdop':               1, 'vdop': 1,
        'vn': 0, 've': 0, 'vd': 0,
        'speed_accuracy':     0.3,
        'horiz_accuracy':     1.0,
        'vert_accuracy':      1.5,
        'satellites_visible': 10,
    }
    sock.sendto(json.dumps(data).encode(), (HOST, GPS_PORT))


def banner(title):
    print(f'\n{"─"*54}\n  {title}\n{"─"*54}')


# ── Attack tests ──────────────────────────────────────────────
def test_attack1():
    banner('Attack 1 — Timestamp Injection (future timestamp)')
    now = time.time()
    send_both(build_signed_packet(now + 86400))          # +1 day
    time.sleep(0.4)
    send_both(build_signed_packet(now + 31536000, seq=201))  # +1 year
    print('  Detector expect : ATTACK-1  Timestamp Injection')
    print('  Defense  expect : BLOCK L1  (timestamp outside window)')
    time.sleep(0.5)


def test_attack2():
    banner('Attack 2 — GPS Spoofing (+10 days)')
    now = time.time()
    for i in range(5):
        send_gps_json(now + 864000)                      # spoofed GPS clock
        send_both(build_system_time(now + 864000, seq=i))
        send_both(build_signed_packet(now, seq=i))       # real ts → defense L3 catches GPS/clock gap
        time.sleep(0.2)
    print('  Detector expect : ATTACK-2  GPS Spoofing')
    print('  Defense  expect : BLOCK L3-GPS-CROSS')


def test_attack3():
    banner('Attack 3 — Overflow / DoS (~78 years offset)')
    import calendar
    from datetime import datetime as _dt, timezone
    feb2104 = calendar.timegm(_dt(2104, 2, 1, tzinfo=timezone.utc).timetuple())
    now     = time.time()
    offset  = feb2104 - now
    for i in range(5):
        send_gps_json(now + offset)
        send_both(build_system_time(now + offset, seq=i))
        send_both(build_signed_packet(now, seq=i))
        time.sleep(0.2)
    print(f'  GPS offset = {offset/31536000:.1f} years')
    print('  Detector expect : ATTACK-3  Overflow / DoS')
    print('  Defense  expect : BLOCK L3-GPS-CROSS')


def test_attack4():
    banner('Attack 4 — Replay Attack')

    # 4a) Stale-timestamp replay (~5.3 yr old) — this is what the DETECTOR
    #     flags as replay (past offset). At the defense proxy the old ts is
    #     caught by L1 first, so it never reaches L4 (expected).
    past_ts = time.time() - 166_910_935                  # ~5.3 years ago (2021)
    for i in range(3):
        send_both(build_signed_packet(past_ts + i * 0.1, seq=i))
        time.sleep(0.4)
    print('  4a stale-ts : Detector -> ATTACK-4 replay | Defense -> BLOCK L1 (old ts)')

    # 4b) Duplicate-of-valid replay — one valid-NOW signed packet sent 3x.
    #     Copy 1 passes all layers and forwards; copies 2-3 match the cache
    #     -> Defense L4-REPLAY. The detector's raw-hash check also flags the
    #     repeats as duplicates.
    dup = build_signed_packet(time.time(), seq=99)       # same bytes each send
    for i in range(3):
        send_both(dup)
        time.sleep(0.4)
    print('  4b dup-valid: Defense -> 1st forwards, copies 2-3 BLOCK L4-REPLAY')


# ── Main ──────────────────────────────────────────────────────
tests = {'1': test_attack1, '2': test_attack2, '3': test_attack3, '4': test_attack4}

print('=' * 54)
print('  MAVLink Combined Injector — Detector + Defense')
print(f'  Detector mirror : {HOST}:{DETECTOR_PORT}   (GPS :{GPS_PORT})')
print(f'  Defense proxy   : {HOST}:{DEFENSE_PORT}')
print('=' * 54)
print('  Run BOTH in separate terminals first:')
print('    Terminal A: python3 realtime_detector_v4.py')
print('    Terminal B: python3 secure_timestamp_defense.py')
print()

if len(sys.argv) > 1 and sys.argv[1] in tests:
    tests[sys.argv[1]]()
else:
    for fn in tests.values():
        fn()
        time.sleep(1)

print('\nDone. Check BOTH terminals: detector = alerts, defense = BLOCK lines.')
