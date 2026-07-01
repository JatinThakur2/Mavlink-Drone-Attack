#!/usr/bin/env python3
import socket, time, hashlib, struct

MAVLINK_EPOCH = 1420070400
ts = time.time() + 86400          # +1 day in the future
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
for i in range(10):
    s.sendto(pkt, ('127.0.0.1', 14549))
print('Sent 10 future-timestamp packets → check Terminal B for BLOCK L1 lines')
