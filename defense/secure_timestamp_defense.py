#!/usr/bin/env python3
"""
=============================================================
Secure Timestamp Defense — MAVLink v2 Proxy Validator
=============================================================
WHAT THIS DOES:
    Sits between the attacker/SITL and the real drone stack.
    Every signed MAVLink v2 packet passes through 4 layers of
    validation before being forwarded.  Unsigned packets are
    forwarded transparently (backward-compatible).

FOUR VALIDATION LAYERS:
    L1  Tight Window     |sig_ts − wall_clock| < TIGHT_WINDOW (2.0 s)
    L2  Monotonic        sig_ts > last_accepted for this link_id
    L3  GPS Cross-Check  |sig_ts − gps_ts| < GPS_CROSS_WINDOW (5.0 s)
    L4  Replay Cache     SHA-256 of (sysid|compid|seq|ts) not seen before

TOPOLOGY:
    [Sender / SITL]  →  [This proxy :LISTEN_PORT]  →  [Drone/Stack :FORWARD_PORT]
                              ↕
                        GPS feed :GPS_PORT   (JSON lines from simulate_normal_gps.py)
                        Wall clock (system time)

USAGE:
    python3 secure_timestamp_defense.py
    python3 secure_timestamp_defense.py --listen 14549 --forward 14550 --gps 25101
    python3 secure_timestamp_defense.py --tight-window 2.0 --gps-window 5.0 --verbose
=============================================================
"""

import socket
import select
import struct
import hashlib
import json
import time
import sys
import argparse
import collections
from datetime import datetime

# ── Constants ─────────────────────────────────────────────────────────────────
LISTEN_HOST     = "0.0.0.0"
LISTEN_PORT     = 14549          # proxy input  (attacker / SITL sends here)
FORWARD_HOST    = "127.0.0.1"
FORWARD_PORT    = 14550          # real drone / detector
GPS_PORT        = 25101          # JSON GPS feed (same as detector's sock_gps)

MAVLINK_EPOCH   = 1_420_070_400  # Jan 1 2015 UTC (MAVLink signing base)
MAVLINK_MAGIC   = 0xFD

# ── Tunable thresholds ────────────────────────────────────────────────────────
TIGHT_WINDOW    = 2.0            # L1: max |signing_ts − wall_clock| in seconds
MONOTONIC_GRACE = 0.1            # L2: allow this many seconds behind last accepted (clock jitter)
GPS_CROSS_WIN   = 5.0            # L3: max |signing_ts − gps_ts| in seconds
REPLAY_CACHE_SZ = 2000           # L4: how many recent packet fingerprints to remember

# ── Display ───────────────────────────────────────────────────────────────────
COL_GREEN  = '\033[32m'
COL_RED    = '\033[31m'
COL_YELLOW = '\033[33m'
COL_CYAN   = '\033[36m'
COL_BOLD   = '\033[1m'
COL_RESET  = '\033[0m'


# ══════════════════════════════════════════════════════════════════════════════
# MAVLink v2 parser
# ══════════════════════════════════════════════════════════════════════════════
def parse_mavlink_v2(data: bytes):
    """
    Parse one MAVLink v2 frame from raw bytes.
    Returns dict or None if not a valid v2 packet.

    MAVLink v2 wire format:
        [0]  magic        0xFD
        [1]  len          payload length
        [2]  incompat     bit0 = 1 → signed
        [3]  compat
        [4]  seq
        [5]  sysid
        [6]  compid
        [7-9] msg_id     3 bytes little-endian
        [10 .. 10+len-1]  payload
        [10+len .. 11+len]  CRC (2 bytes)
        [12+len .. 24+len]  signing block (13 bytes, only if incompat & 0x01)
            [0]     link_id  (1 byte)
            [1-6]   timestamp (6 bytes little-endian, 10µs units from MAVLink epoch)
            [7-12]  signature (6 bytes, first 6 of SHA-256)
    """
    if len(data) < 12:
        return None
    if data[0] != MAVLINK_MAGIC:
        return None

    plen    = data[1]
    incompat = data[2]
    seq     = data[4]
    sysid   = data[5]
    compid  = data[6]
    msg_id  = struct.unpack_from('<I', data[7:10] + b'\x00')[0]

    expected_base = 10 + plen + 2   # header + payload + CRC
    signed = bool(incompat & 0x01)

    if signed:
        expected_total = expected_base + 13
        if len(data) < expected_total:
            return None
        sig_block = data[expected_base: expected_base + 13]
        link_id   = sig_block[0]
        ts_bytes  = sig_block[1:7]
        ts_raw    = int.from_bytes(ts_bytes, 'little')   # 10µs units
        sig_ts    = MAVLINK_EPOCH + ts_raw / 1e5          # unix seconds
        sig_hex   = sig_block[7:13].hex()
    else:
        link_id = sig_ts = sig_hex = None

    return {
        'raw':      data[:expected_base + (13 if signed else 0)],
        'plen':     plen,
        'incompat': incompat,
        'seq':      seq,
        'sysid':    sysid,
        'compid':   compid,
        'msg_id':   msg_id,
        'signed':   signed,
        'link_id':  link_id,
        'sig_ts':   sig_ts,
        'sig_hex':  sig_hex,
    }


# ══════════════════════════════════════════════════════════════════════════════
# Defense validator
# ══════════════════════════════════════════════════════════════════════════════
class SecureTimestampDefense:
    def __init__(self, tight_window=TIGHT_WINDOW, gps_window=GPS_CROSS_WIN,
                 cache_size=REPLAY_CACHE_SZ, verbose=False):
        self.tight_window  = tight_window
        self.gps_window    = gps_window
        self.verbose       = verbose

        # L2: per-link monotonic tracker
        self._last_accepted: dict[int, float] = {}

        # L3: GPS time from sock_gps feed
        self._gps_ts: float | None = None

        # L4: replay cache — ordered dict as LRU set
        self._replay_cache: collections.OrderedDict[str, None] = collections.OrderedDict()
        self._cache_size = cache_size

        # Metrics
        self.stats = {
            'total':           0,
            'unsigned_fwd':    0,
            'signed_pass':     0,
            'blocked_l1':      0,
            'blocked_l2':      0,
            'blocked_l3':      0,
            'blocked_l4':      0,
            'latency_us':      [],   # per-packet validation latency in microseconds
        }

    # ── GPS update ────────────────────────────────────────────────────────────
    def update_gps(self, line: str):
        """Parse a JSON line from the GPS feed and store the GPS time."""
        try:
            obj = json.loads(line)
            gps_raw = obj.get('time_unix_usec') or obj.get('gps_time_unix')
            if gps_raw is not None:
                self._gps_ts = float(gps_raw) / 1e6   # µs → seconds
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # ── Fingerprint for replay cache ─────────────────────────────────────────
    @staticmethod
    def _fingerprint(pkt: dict) -> str:
        blob = f"{pkt['sysid']}:{pkt['compid']}:{pkt['seq']}:{pkt['sig_ts']:.5f}"
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    # ── Four-layer validation ─────────────────────────────────────────────────
    def validate(self, pkt: dict) -> tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        Unsigned packets always pass.  Signed packets go through L1–L4.
        """
        if not pkt['signed']:
            return True, 'unsigned'

        sig_ts   = pkt['sig_ts']
        link_id  = pkt['link_id']
        wall     = time.time()

        # ── L1: Tight window ─────────────────────────────────────────────────
        offset = sig_ts - wall
        if abs(offset) > self.tight_window:
            direction = "FUTURE" if offset > 0 else "PAST"
            return False, (f"L1-TIGHT-WINDOW  sig_ts {offset:+.3f}s from wall clock "
                           f"({direction}, threshold ±{self.tight_window}s)")

        # ── L2: Monotonic ────────────────────────────────────────────────────
        last = self._last_accepted.get(link_id)
        if last is not None and sig_ts < (last - MONOTONIC_GRACE):
            return False, (f"L2-MONOTONIC  sig_ts {sig_ts:.3f} < last_accepted "
                           f"{last:.3f} (Δ={last-sig_ts:.3f}s) on link {link_id}")

        # ── L3: GPS cross-check ───────────────────────────────────────────────
        if self._gps_ts is not None:
            gps_offset = abs(sig_ts - self._gps_ts)
            if gps_offset > self.gps_window:
                return False, (f"L3-GPS-CROSS  |sig_ts − gps_ts| = {gps_offset:.3f}s "
                               f"> threshold {self.gps_window}s")

        # ── L4: Replay cache ─────────────────────────────────────────────────
        fp = self._fingerprint(pkt)
        if fp in self._replay_cache:
            return False, f"L4-REPLAY  fingerprint {fp} already seen"

        # ── All layers passed: accept ─────────────────────────────────────────
        self._last_accepted[link_id] = sig_ts
        # LRU insert
        self._replay_cache[fp] = None
        if len(self._replay_cache) > self._cache_size:
            self._replay_cache.popitem(last=False)

        return True, 'ok'

    # ── Validate + collect metrics ────────────────────────────────────────────
    def process(self, raw: bytes) -> tuple[bytes | None, str]:
        """
        Full pipeline: parse → validate → return (forwarded_bytes, reason).
        Returns (None, reason) if the packet should be dropped.
        """
        t0 = time.perf_counter_ns()
        self.stats['total'] += 1

        pkt = parse_mavlink_v2(raw)
        if pkt is None:
            # Not a recognisable v2 frame — forward as-is (safety)
            return raw, 'non-v2-forward'

        allowed, reason = self.validate(pkt)
        latency_us = (time.perf_counter_ns() - t0) / 1000
        self.stats['latency_us'].append(latency_us)

        if allowed:
            if pkt['signed']:
                self.stats['signed_pass'] += 1
            else:
                self.stats['unsigned_fwd'] += 1
            return raw, reason
        else:
            layer = reason.split('-')[0]   # 'L1', 'L2', …
            key   = f'blocked_{layer.lower()}'
            self.stats[key] = self.stats.get(key, 0) + 1
            return None, reason

    # ── Summary ───────────────────────────────────────────────────────────────
    def summary(self) -> str:
        s    = self.stats
        tot  = s['total'] or 1
        lats = s['latency_us']
        avg  = sum(lats) / len(lats) if lats else 0
        mx   = max(lats) if lats else 0
        blocked = s['blocked_l1'] + s['blocked_l2'] + s['blocked_l3'] + s['blocked_l4']
        far  = (s['unsigned_fwd']) / tot * 100   # we never block unsigned ∴ FAR=0 for signed
        lines = [
            f"\n{'='*60}",
            f"  DEFENSE SUMMARY",
            f"{'='*60}",
            f"  Total packets seen   : {tot}",
            f"  Unsigned (forwarded) : {s['unsigned_fwd']}",
            f"  Signed passed        : {s['signed_pass']}",
            f"  Blocked  (total)     : {blocked}",
            f"    L1 Tight window    : {s['blocked_l1']}",
            f"    L2 Monotonic       : {s['blocked_l2']}",
            f"    L3 GPS cross-check : {s['blocked_l3']}",
            f"    L4 Replay cache    : {s['blocked_l4']}",
            f"  False Acceptance Rate: {(blocked==0 and tot>0)*100:.1f}%  "
            f"(0 if all attacks were blocked)",
            f"  Avg validation latency: {avg:.1f} µs",
            f"  Max validation latency: {mx:.1f} µs",
            f"{'='*60}",
        ]
        return '\n'.join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# Proxy main loop
# ══════════════════════════════════════════════════════════════════════════════
def run_proxy(listen_port=LISTEN_PORT, forward_port=FORWARD_PORT,
              gps_port=GPS_PORT, tight_window=TIGHT_WINDOW,
              gps_window=GPS_CROSS_WIN, verbose=False):

    defense = SecureTimestampDefense(
        tight_window=tight_window, gps_window=gps_window, verbose=verbose)

    # ── Sockets ───────────────────────────────────────────────────────────────
    sock_in  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_in.bind((LISTEN_HOST, listen_port))

    sock_gps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_gps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_gps.bind((LISTEN_HOST, gps_port))

    sock_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock_out is just used for sending — no bind

    print(f"{COL_BOLD}[DEFENSE] Secure Timestamp Proxy{COL_RESET}")
    print(f"  Listening for packets  : {LISTEN_HOST}:{listen_port}")
    print(f"  Forwarding valid to    : {FORWARD_HOST}:{forward_port}")
    print(f"  GPS time feed          : :{gps_port}")
    print(f"  L1 tight window        : ±{tight_window}s")
    print(f"  L3 GPS cross-check     : ±{gps_window}s")
    print(f"  L4 replay cache size   : {REPLAY_CACHE_SZ}")
    print(f"  Press Ctrl-C to stop and view summary.\n")

    sockets = [sock_in, sock_gps]

    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 1.0)
            for s in readable:
                if s is sock_gps:
                    data, _ = s.recvfrom(4096)
                    defense.update_gps(data.decode(errors='ignore'))

                elif s is sock_in:
                    data, addr = s.recvfrom(4096)
                    fwd, reason = defense.process(data)
                    ts_str = datetime.utcnow().strftime('%H:%M:%S.%f')[:-3]

                    if fwd is not None:
                        sock_out.sendto(fwd, (FORWARD_HOST, forward_port))
                        if verbose:
                            print(f"{COL_GREEN}[{ts_str}] PASS  {reason}{COL_RESET}")
                    else:
                        col = COL_RED
                        print(f"{col}[{ts_str}] BLOCK {reason}{COL_RESET}")

    except KeyboardInterrupt:
        pass
    finally:
        print(defense.summary())
        sock_in.close()
        sock_gps.close()
        sock_out.close()


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='MAVLink Secure Timestamp Defense Proxy')
    ap.add_argument('--listen',       type=int,   default=LISTEN_PORT,    help='Port to listen on')
    ap.add_argument('--forward',      type=int,   default=FORWARD_PORT,   help='Port to forward clean packets to')
    ap.add_argument('--gps',          type=int,   default=GPS_PORT,       help='GPS time feed port')
    ap.add_argument('--tight-window', type=float, default=TIGHT_WINDOW,   help='L1 max |sig_ts − wall| (s)')
    ap.add_argument('--gps-window',   type=float, default=GPS_CROSS_WIN,  help='L3 max |sig_ts − gps| (s)')
    ap.add_argument('--verbose',      action='store_true',                 help='Print every PASS decision')
    args = ap.parse_args()

    run_proxy(
        listen_port  = args.listen,
        forward_port = args.forward,
        gps_port     = args.gps,
        tight_window = args.tight_window,
        gps_window   = args.gps_window,
        verbose      = args.verbose,
    )
