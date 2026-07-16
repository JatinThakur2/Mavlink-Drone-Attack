#!/usr/bin/env python3
# Attack 3 — GPS overflow / DoS (~78 years into the future).
# Feed an overflow-range GPS time to the proxy (port 25101), then send a normal,
# correctly-timestamped signed command (port 14549). L1 passes (ts is real),
# but L3 sees the signing clock and GPS disagree by ~78 years → BLOCK L3-GPS-CROSS.
import socket, time, hashlib, struct, json

MAVLINK_EPOCH = 1420070400

# ── 1. Spoofed GPS time: ~78 years in the future (overflow / DoS range) ───────
gps_spoof_unix = time.time() + 78 * 365 * 86400    # ~78 years
gps_msg = json.dumps({'time_unix_usec': int(gps_spoof_unix * 1e6)}).encode()

# ── 2. Build a normal signed packet (sig_ts = now → passes L1) ────────────────
ts = time.time()                                   # real current time
ts_units = int((ts - MAVLINK_EPOCH) * 1e5)
ts_bytes = ts_units.to_bytes(6, 'little')
payload = b'\x00' * 9
header = bytes([0xFD, 9, 1, 0, 1, 1, 1, 0, 0, 0]) + payload
crc_data = header[1:] + bytes([50])
crc = 0xFFFF
for b in crc_data:
    tmp = b ^ (crc & 0xFF)
    tmp = (tmp ^ (tmp << 4)) & 0xFF
    crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
frame = header + struct.pack('<H', crc)
sig_input = frame + bytes([0]) + ts_bytes
digest = hashlib.sha256(b'key' + sig_input).digest()[:6]
pkt = frame + bytes([0]) + ts_bytes + digest

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Prime the proxy with the overflow-range GPS time first
for i in range(5):
    s.sendto(gps_msg, ('127.0.0.1', 25101))
time.sleep(0.3)

# Now send the signed command — L3 should reject it
for i in range(10):
    s.sendto(pkt, ('127.0.0.1', 14549))

print('Sent spoofed GPS (+78 years) + 10 signed packets '
      '→ check Terminal B for BLOCK L3-GPS-CROSS lines')
