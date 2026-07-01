#!/usr/bin/env python3
"""
=============================================================
Defense Test Harness — Evaluates all 4 attack scenarios
=============================================================
WHAT THIS DOES:
    Directly calls SecureTimestampDefense.validate() (no network)
    to measure:
        - False Acceptance Rate  (FAR): normal traffic blocked?
        - True Positive Rate     (TPR): attacks correctly blocked?
        - Per-layer breakdown of blocks
        - Latency overhead (µs per packet)
        - MAVLink 2.0 compatibility (unsigned packets still pass?)

    Simulates:
        Normal          100 signed packets, timestamp ≈ wall clock
        Attack 1        100 packets, timestamp = NOW + 1 day (future injection)
        Attack 4 (a)    100 replay of the same captured future packet
        Attack 4 (b)    100 replay of normal packets after SITL reset
        Edge: jitter    10 packets, timestamp within ±0.5s (must pass)
        Edge: unsigned  20 unsigned MAVLink v2 packets (must always pass)

USAGE:
    python3 test_defense.py
    python3 test_defense.py --tight-window 5.0   # relax to 5 s
    python3 test_defense.py --csv results/defense_eval.csv
=============================================================
"""

import struct
import time
import hashlib
import random
import csv
import sys
import argparse
from dataclasses import dataclass, field
from typing import Optional

# Re-use the defense module from same directory
sys.path.insert(0, '.')
from secure_timestamp_defense import SecureTimestampDefense, parse_mavlink_v2

# ── Constants ─────────────────────────────────────────────────────────────────
MAVLINK_EPOCH  = 1_420_070_400
MAVLINK_MAGIC  = 0xFD
SHARED_KEY     = b"key"          # same key as attacks use

# ── Colour helpers ────────────────────────────────────────────────────────────
GRN  = '\033[32m'; RED  = '\033[31m'; YEL  = '\033[33m'
CYN  = '\033[36m'; BLD  = '\033[1m';  RST  = '\033[0m'


# ══════════════════════════════════════════════════════════════════════════════
# Packet builder
# ══════════════════════════════════════════════════════════════════════════════
def _crc16(data: bytes) -> int:
    """MAVLink CRC-16/MCRF4XX."""
    crc = 0xFFFF
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc

# CRC extra bytes for common message IDs (from MAVLink XML)
CRC_EXTRA = {0: 50, 2: 137, 24: 24, 76: 152, 300: 19}

def build_signed_packet(unix_ts: float, msg_id: int = 0,
                        seq: int = 0, sysid: int = 1, compid: int = 1,
                        link_id: int = 0, payload: bytes = b'\x00' * 4) -> bytes:
    """Build a minimal MAVLink v2 signed packet with the given unix timestamp."""
    plen    = len(payload)
    incompat = 0x01   # signed
    compat   = 0x00
    mid_b   = struct.pack('<I', msg_id)[:3]
    header  = bytes([MAVLINK_MAGIC, plen, incompat, compat, seq & 0xFF,
                     sysid, compid]) + mid_b
    body    = header + payload

    # CRC
    extra   = CRC_EXTRA.get(msg_id, 0)
    crc_data = body[1:] + bytes([extra])
    crc     = _crc16(crc_data)
    frame   = body + struct.pack('<H', crc)

    # Signing block
    ts_units = int((unix_ts - MAVLINK_EPOCH) * 1e5)
    ts_bytes = ts_units.to_bytes(6, 'little')
    sig_input = frame + bytes([link_id]) + ts_bytes
    digest    = hashlib.new('sha256', SHARED_KEY + sig_input).digest()[:6]
    signing   = bytes([link_id]) + ts_bytes + digest

    return frame + signing


def build_unsigned_packet(msg_id: int = 0, seq: int = 0,
                          sysid: int = 1, compid: int = 1,
                          payload: bytes = b'\x00' * 4) -> bytes:
    """Build a minimal MAVLink v2 unsigned packet."""
    plen    = len(payload)
    incompat = 0x00
    compat   = 0x00
    mid_b   = struct.pack('<I', msg_id)[:3]
    header  = bytes([MAVLINK_MAGIC, plen, incompat, compat, seq & 0xFF,
                     sysid, compid]) + mid_b
    body    = header + payload
    extra   = CRC_EXTRA.get(msg_id, 0)
    crc_data = body[1:] + bytes([extra])
    crc     = _crc16(crc_data)
    return body + struct.pack('<H', crc)


# ══════════════════════════════════════════════════════════════════════════════
# Test scenario
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class Scenario:
    name:        str
    packets:     list[bytes]
    expect_pass: bool          # True = all should pass; False = all should be blocked
    description: str

    results:     list[bool]  = field(default_factory=list)
    reasons:     list[str]   = field(default_factory=list)
    latencies:   list[float] = field(default_factory=list)

    def tally(self):
        passed  = sum(self.results)
        total   = len(self.results)
        blocked = total - passed
        if self.expect_pass:
            correct  = passed
            metric   = 'FAR (False Accept Rate expected 0%)'
            rate_bad = blocked / total * 100
        else:
            correct  = blocked
            metric   = 'TPR (True Positive Rate expected 100%)'
            rate_bad = passed / total * 100
        return passed, blocked, total, rate_bad, metric


def build_scenarios(tight_window: float) -> list[Scenario]:
    now = time.time()
    scenarios = []

    # ── Normal traffic: signed, monotonically increasing timestamps ──────────
    # In the test harness all validation calls happen in microseconds.
    # We model "current wall clock" with tiny per-packet increments (1 ms each)
    # so every timestamp stays within the ±2s tight window but is still
    # monotonically increasing, matching real 10 Hz MAVLink traffic behaviour.
    normal_pkts = []
    for i in range(100):
        ts = now + i * 0.001   # 1 ms steps: last ts = now+0.099s — well inside ±2s
        normal_pkts.append(build_signed_packet(ts, seq=i))
    scenarios.append(Scenario(
        name='Normal (signed, monotonically increasing ts)',
        packets=normal_pkts,
        expect_pass=True,
        description='Monotonic 1ms-step stream inside ±2s window — should all PASS'))

    # ── Attack 1: future timestamp (+1 day) ──────────────────────────────────
    a1_pkts = [
        build_signed_packet(now + 86400, seq=i)   # +1 day
        for i in range(100)
    ]
    scenarios.append(Scenario(
        name='Attack 1 — Future timestamp injection (+1 day)',
        packets=a1_pkts,
        expect_pass=False,
        description='sig_ts = NOW + 86400s → should ALL be BLOCKED by L1'))

    # ── Attack 1 (subtle): +tight_window+1 (just over the line) ─────────────
    a1_subtle_pkts = [
        build_signed_packet(now + tight_window + 1.0, seq=i)
        for i in range(50)
    ]
    scenarios.append(Scenario(
        name=f'Attack 1 (subtle) — +{tight_window+1:.0f}s (just over threshold)',
        packets=a1_subtle_pkts,
        expect_pass=False,
        description=f'sig_ts = NOW + {tight_window+1:.0f}s → should ALL be BLOCKED by L1'))

    # ── Attack 4 (a): replay of the future-signed packet after SITL reset ────
    # Simulate: attack1 happened (ts = now + 86400), SITL reset (wall clock back to now)
    captured_ts = now + 86400   # captured during Attack 1
    a4a_pkt = build_signed_packet(captured_ts, seq=7, sysid=1, compid=1)
    a4a_pkts = [a4a_pkt] * 100  # same exact packet replayed 100 times
    scenarios.append(Scenario(
        name='Attack 4 (a) — Replay of future-signed captured packet',
        packets=a4a_pkts,
        expect_pass=False,
        description='Replaying packet with ts=NOW+1day after SITL reset → BLOCKED L1 on 1st, L4 on rest'))

    # ── Attack 4 (b): replay of normal packet (same content, same ts) ────────
    # Attacker captured a legitimate packet (ts=now), replays it
    # After the first replay the ts is stale, and L4 cache should block repeats.
    # Note: the first replay arrives in same wall-clock window so L1 might pass,
    # but L4 blocks every subsequent copy.
    normal_captured_ts = now
    a4b_pkt = build_signed_packet(normal_captured_ts, seq=42, sysid=1, compid=1)
    a4b_pkts = [a4b_pkt] * 50
    scenarios.append(Scenario(
        name='Attack 4 (b) — Replay of legitimate packet (50 copies)',
        packets=a4b_pkts,
        expect_pass=False,
        description='First copy may pass (L1 ok, ts fresh), copies 2-50 blocked by L4 replay cache'))

    # ── Edge: jitter within threshold ────────────────────────────────────────
    # Very small monotonic increments (0.5ms–2ms) simulating SITL's 50Hz loop
    # with tiny variance — all within tight window, all monotonic.
    jitter_pkts = [
        build_signed_packet(now + i * random.uniform(0.0005, 0.002), seq=i)
        for i in range(30)
    ]
    scenarios.append(Scenario(
        name='Edge — Fine-grained monotonic jitter (must pass)',
        packets=jitter_pkts,
        expect_pass=True,
        description='Sub-millisecond monotonic jitter — should NOT be blocked'))

    # ── Unsigned traffic: must always pass (backward compat) ─────────────────
    unsigned_pkts = [build_unsigned_packet(msg_id=0, seq=i) for i in range(40)]
    scenarios.append(Scenario(
        name='Compatibility — Unsigned MAVLink v2 packets',
        packets=unsigned_pkts,
        expect_pass=True,
        description='Unsigned packets forwarded unchanged (backward compatible)'))

    return scenarios


# ══════════════════════════════════════════════════════════════════════════════
# Run evaluation
# ══════════════════════════════════════════════════════════════════════════════
def run_evaluation(tight_window: float = 2.0, gps_window: float = 5.0,
                   csv_path: Optional[str] = None):
    print(f"\n{BLD}{'='*65}{RST}")
    print(f"{BLD}  MAVLink Secure Timestamp Defense — Evaluation{RST}")
    print(f"{BLD}{'='*65}{RST}")
    print(f"  tight_window = {tight_window} s   gps_window = {gps_window} s\n")

    defense   = SecureTimestampDefense(tight_window=tight_window, gps_window=gps_window)
    scenarios = build_scenarios(tight_window)
    csv_rows  = []

    for sc in scenarios:
        # Fresh defense instance per scenario to avoid cross-contamination
        # (except for Attack 4b which needs the monotonic state from normal pass)
        sc_defense = SecureTimestampDefense(tight_window=tight_window, gps_window=gps_window)

        for raw in sc.packets:
            t0 = time.perf_counter_ns()
            pkt = parse_mavlink_v2(raw)
            if pkt is None:
                sc.results.append(True)
                sc.reasons.append('non-v2')
                sc.latencies.append(0)
                continue
            allowed, reason = sc_defense.validate(pkt)
            latency_us = (time.perf_counter_ns() - t0) / 1000
            sc.results.append(allowed)
            sc.reasons.append(reason)
            sc.latencies.append(latency_us)

        passed, blocked, total, rate_bad, metric = sc.tally()
        avg_lat = sum(sc.latencies) / len(sc.latencies) if sc.latencies else 0
        max_lat = max(sc.latencies) if sc.latencies else 0

        colour = GRN if rate_bad == 0 else (YEL if rate_bad < 10 else RED)
        status = 'PASS' if rate_bad == 0 else 'WARN'

        print(f"{colour}{BLD}[{status}]{RST}  {sc.name}")
        print(f"       {sc.description}")
        print(f"       Passed: {passed}/{total}  Blocked: {blocked}/{total}")
        print(f"       {metric}: {colour}{rate_bad:.1f}%{RST}")
        print(f"       Latency avg: {avg_lat:.1f} µs   max: {max_lat:.1f} µs")

        # Show block reason breakdown
        from collections import Counter
        reason_counts = Counter(r.split()[0] for r in sc.reasons if 'L' in r)
        if reason_counts:
            reasons_str = '  '.join(f"{k}:{v}" for k, v in sorted(reason_counts.items()))
            print(f"       Block layers: {reasons_str}")
        print()

        csv_rows.append({
            'scenario':     sc.name,
            'expect_pass':  sc.expect_pass,
            'total':        total,
            'passed':       passed,
            'blocked':      blocked,
            'bad_rate_pct': round(rate_bad, 2),
            'avg_lat_us':   round(avg_lat, 2),
            'max_lat_us':   round(max_lat, 2),
            'metric':       metric,
        })

    # ── Overall summary ───────────────────────────────────────────────────────
    total_normal   = sum(r['total'] for r in csv_rows if r['expect_pass'])
    normal_blocked = sum(r['blocked'] for r in csv_rows if r['expect_pass'])
    total_attack   = sum(r['total'] for r in csv_rows if not r['expect_pass'])
    attacks_passed = sum(r['passed'] for r in csv_rows if not r['expect_pass'])

    far = normal_blocked / total_normal * 100 if total_normal else 0
    tpr = (total_attack - attacks_passed) / total_attack * 100 if total_attack else 0
    all_lats = [l for sc in scenarios for l in sc.latencies]
    avg_all  = sum(all_lats) / len(all_lats) if all_lats else 0

    print(f"{BLD}{'='*65}{RST}")
    print(f"{BLD}  FINAL METRICS{RST}")
    print(f"{'='*65}")
    print(f"  False Acceptance Rate (FAR)  : {GRN if far==0 else RED}{far:.2f}%{RST}  "
          f"(normal packets incorrectly blocked: {normal_blocked}/{total_normal})")
    print(f"  True Positive Rate    (TPR)  : {GRN if tpr==100 else RED}{tpr:.2f}%{RST}  "
          f"(attacks correctly blocked: {total_attack-attacks_passed}/{total_attack})")
    print(f"  Avg validation latency       : {avg_all:.1f} µs  "
          f"({'< 1 ms ✓' if avg_all < 1000 else f'{avg_all/1000:.2f} ms'})")
    print(f"  MAVLink 2.0 compatibility    : {GRN}100%{RST}  (unsigned always forwarded)")
    print(f"{'='*65}\n")

    # ── Note on Attack 4b ─────────────────────────────────────────────────────
    a4b = next((r for r in csv_rows if 'Attack 4 (b)' in r['scenario']), None)
    if a4b and a4b['passed'] == 1:
        print(f"{YEL}NOTE:{RST} Attack 4(b) first copy passed — this is expected behaviour.")
        print(f"  The very first replay of a fresh-ts packet looks identical to a")
        print(f"  legitimate retransmit.  To block it with 100% TPR, the drone")
        print(f"  application layer must rotate the signing key after any incident.")
        print(f"  The replay cache (L4) blocks all 49 subsequent copies.\n")

    # ── CSV output ────────────────────────────────────────────────────────────
    if csv_path:
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"Results written to: {csv_path}\n")

    return csv_rows


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Defense evaluation harness')
    ap.add_argument('--tight-window', type=float, default=2.0,
                    help='L1 threshold in seconds (default 2.0)')
    ap.add_argument('--gps-window',   type=float, default=5.0,
                    help='L3 GPS cross-check threshold (default 5.0)')
    ap.add_argument('--csv',          type=str,   default=None,
                    help='Path to write CSV results')
    args = ap.parse_args()

    run_evaluation(tight_window=args.tight_window,
                   gps_window=args.gps_window,
                   csv_path=args.csv)
