#!/usr/bin/env python3
"""
Normal GPS simulator — sends real-time GPS_INPUT packets to MAVProxy.
Used during baseline training so the model learns normal gps_sys_delta ≈ 0.

Run this alongside train_baseline.py (not during attacks).
Stop with Ctrl+C.
"""

import socket
import json
import time
import signal
import sys

GPS_HOST  = "127.0.0.1"
GPS_PORT  = 25100        # MAVProxy GPSInput module
MIRROR    = 25101        # detector monitor port

GPS_EPOCH_UNIX   = 315_964_800
SECONDS_PER_WEEK = 604_800

# SITL home — Canberra
HOME_LAT = -35.363261
HOME_LON =  149.165237
HOME_ALT =  584.0

RATE_HZ  = 5   # 5 packets/second — same as SITL's internal GPS rate


def unix_to_gps(unix_time: float):
    elapsed  = unix_time - GPS_EPOCH_UNIX
    week     = int(elapsed / SECONDS_PER_WEEK)
    tow_ms   = int((elapsed % SECONDS_PER_WEEK) * 1000)
    return week, tow_ms


def main():
    print("Normal GPS simulator — sending real-time GPS_INPUT to MAVProxy")
    print(f"  → UDP {GPS_HOST}:{GPS_PORT}  (and mirror to :{MIRROR})")
    print(f"  Rate : {RATE_HZ} Hz    Ctrl+C to stop\n")

    sock     = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / RATE_HZ
    count    = 0

    def _stop(sig, frame):
        print(f"\nStopped after {count} packets.")
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)

    while True:
        now              = time.time()
        week, tow_ms     = unix_to_gps(now)

        data = {
            "time_usec"         : int(now * 1_000_000),
            "gps_id"            : 0,
            "ignore_flags"      : 0,
            "time_week_ms"      : tow_ms,
            "time_week"         : week,
            "fix_type"          : 3,
            "lat"               : int(HOME_LAT * 1e7),
            "lon"               : int(HOME_LON * 1e7),
            "alt"               : HOME_ALT,
            "hdop"              : 1,
            "vdop"              : 1,
            "vn"                : 0,
            "ve"                : 0,
            "vd"                : 0,
            "speed_accuracy"    : 0.3,
            "horiz_accuracy"    : 1.0,
            "vert_accuracy"     : 1.5,
            "satellites_visible": 10,
        }
        pkt = json.dumps(data).encode()
        sock.sendto(pkt, (GPS_HOST, GPS_PORT))
        sock.sendto(pkt, (GPS_HOST, MIRROR))

        count += 1
        if count % (RATE_HZ * 10) == 0:   # print every 10 seconds
            print(f"  [{count:,} pkts]  gps_time={time.strftime('%H:%M:%S', time.gmtime(now))} UTC"
                  f"  gps_sys_delta≈0  (normal)")

        time.sleep(interval)


if __name__ == "__main__":
    main()
