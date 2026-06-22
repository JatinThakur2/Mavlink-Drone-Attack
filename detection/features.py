#!/usr/bin/env python3
"""
=============================================================
Step 1 — Feature Extraction
=============================================================
Extracts 6 features from every MAVLink / GPS_INPUT packet.

Supports two packet types:
  - MAVLink 2.0 raw bytes  (UDP 14550)
  - GPS_INPUT JSON string  (UDP 25100)

Features extracted:
  1. ts_gap          — signature timestamp vs wall clock (seconds)
  2. iat_ms          — inter-arrival time vs previous packet (ms)
  3. seq_jump        — sequence number discontinuity (0 = normal)
  4. gps_sys_delta   — GPS time vs system clock (seconds)
  5. drift_m_per_s   — position drift rate between GPS packets (m/s)
  6. is_duplicate    — 1 if exact packet seen before, else 0

Usage:
  extractor = FeatureExtractor()

  # For MAVLink raw bytes:
  result = extractor.from_mavlink(raw_bytes)

  # For GPS JSON string:
  result = extractor.from_gps_json(json_string)

  print(result)          # human-readable
  print(result.vector)   # [f1, f2, f3, f4, f5, f6] for ML model
=============================================================
"""

import hashlib
import json
import math
import time
import struct
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────
# MAVLink constants
# ─────────────────────────────────────────────────────────────
MAVLINK2_MAGIC   = 0xFD
MAVLINK_EPOCH    = 1_420_070_400        # Jan 1 2015 00:00:00 UTC (Unix)
INCOMPAT_SIGNED  = 0x01                 # incompat_flags bit 0 = packet is signed

# MAVLink 2.0 header layout (all offsets are 0-based byte indices)
HDR_PAYLOAD_LEN  = 1   # byte index of payload length
HDR_INCOMPAT     = 2   # byte index of incompat_flags
HDR_SEQ          = 4   # byte index of sequence number
HDR_SYSID        = 5
HDR_COMPID       = 6
HDR_MSGID_START  = 7   # msgid occupies bytes 7, 8, 9 (3-byte LE)
HDR_PAYLOAD_START= 10  # payload starts at byte 10

# Signature block layout (relative to start of signature block):
SIG_LINK_ID      = 0   # 1 byte
SIG_TIMESTAMP    = 1   # 6 bytes LE — 10µs units since MAVLINK_EPOCH
SIG_HASH         = 7   # 6 bytes

# Earth radius for Haversine distance
EARTH_RADIUS_M   = 6_371_000.0

# Rolling hash store size — keeps last N packet hashes for duplicate detection
HASH_STORE_SIZE  = 10_000


# ─────────────────────────────────────────────────────────────
# Feature result dataclass
# ─────────────────────────────────────────────────────────────
@dataclass
class Features:
    """
    One feature vector extracted from a single packet.

    Fields
    ------
    source        : 'mavlink' or 'gps_json'
    ts_gap        : sig_timestamp_unix - time.time()  (seconds)
                    Positive = future timestamp (attack signal)
                    None if packet is unsigned
    iat_ms        : milliseconds since previous packet of same type
                    None for the very first packet seen
    seq_jump      : |received_seq - expected_seq| mod 256
                    0 = consecutive, >0 = gap or replay
                    None for GPS JSON (no sequence number)
    gps_sys_delta : gps_unix - time.time()  (seconds)
                    Large positive = GPS clock ahead (attack 2/3)
                    Large negative = GPS clock behind (attack 3B)
                    None for MAVLink packets with no GPS payload
    drift_m_per_s : metres/second position change between GPS packets
                    None for MAVLink packets or first GPS packet
    is_duplicate  : 1 if SHA-256(raw_bytes) seen before, else 0

    vector        : [ts_gap or 0, iat_ms or 0, seq_jump or 0,
                     gps_sys_delta or 0, drift_m_per_s or 0, is_duplicate]
                    (None replaced with 0.0 for ML model input)
    """
    source        : str
    ts_gap        : Optional[float] = None
    iat_ms        : Optional[float] = None
    seq_jump      : Optional[int]   = None
    gps_sys_delta : Optional[float] = None
    drift_m_per_s : Optional[float] = None
    is_duplicate  : int             = 0

    # Raw packet metadata (not part of ML vector, for logging only)
    msgid         : Optional[int]   = None
    seq           : Optional[int]   = None
    sysid         : Optional[int]   = None
    signed        : bool            = False
    sig_unix      : Optional[float] = None
    gps_unix      : Optional[float] = None
    lat           : Optional[float] = None
    lon           : Optional[float] = None

    @property
    def vector(self) -> list:
        """Full 6-feature vector — used for display and statistical rules."""
        return [
            self.ts_gap        if self.ts_gap        is not None else 0.0,
            self.iat_ms        if self.iat_ms        is not None else 0.0,
            self.seq_jump      if self.seq_jump      is not None else 0.0,
            self.gps_sys_delta if self.gps_sys_delta is not None else 0.0,
            self.drift_m_per_s if self.drift_m_per_s is not None else 0.0,
            float(self.is_duplicate),
        ]

    @property
    def ml_vector(self) -> list:
        """3-feature vector for the RandomForest classifier.

        Features: [ts_gap, gps_sys_delta, is_duplicate]
        Matches FEATURES in ml/train_classifier.py and ClassifierLayer.classify().
        """
        return [
            self.ts_gap        if self.ts_gap        is not None else 0.0,
            self.gps_sys_delta if self.gps_sys_delta is not None else 0.0,
            float(self.is_duplicate),
        ]

    def __str__(self) -> str:
        lines = [f"[{self.source.upper()}]"]
        if self.msgid   is not None: lines.append(f"  msgid        : {self.msgid}")
        if self.seq     is not None: lines.append(f"  seq          : {self.seq}")
        if self.sysid   is not None: lines.append(f"  sysid        : {self.sysid}")
        lines.append(    f"  signed       : {self.signed}")
        if self.ts_gap  is not None:
            lines.append(f"  ts_gap       : {self.ts_gap:+.1f} s  {'<<< FUTURE' if self.ts_gap > 3600 else ''}")
        if self.iat_ms  is not None:
            lines.append(f"  iat_ms       : {self.iat_ms:.1f} ms")
        if self.seq_jump is not None:
            lines.append(f"  seq_jump     : {self.seq_jump}  {'<<< ANOMALY' if self.seq_jump > 1 else ''}")
        if self.gps_sys_delta is not None:
            lines.append(f"  gps_sys_delta: {self.gps_sys_delta:+.1f} s  {'<<< ATTACK' if abs(self.gps_sys_delta) > 86400 else ''}")
        if self.drift_m_per_s is not None:
            lines.append(f"  drift        : {self.drift_m_per_s:.2f} m/s  {'<<< SPOOF' if self.drift_m_per_s > 5 else ''}")
        lines.append(    f"  is_duplicate : {self.is_duplicate}  {'<<< REPLAY' if self.is_duplicate else ''}")
        lines.append(    f"  vector       : {[round(v,2) for v in self.vector]}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────
# Low-level parsers
# ─────────────────────────────────────────────────────────────
def _parse_mavlink_header(raw: bytes) -> Optional[dict]:
    """
    Parse MAVLink 2.0 header fields from raw bytes.
    Returns None if the packet is too short or not MAVLink 2.0.
    """
    if len(raw) < 10:
        return None
    if raw[0] != MAVLINK2_MAGIC:
        return None

    payload_len = raw[HDR_PAYLOAD_LEN]
    incompat    = raw[HDR_INCOMPAT]
    signed      = bool(incompat & INCOMPAT_SIGNED)
    seq         = raw[HDR_SEQ]
    sysid       = raw[HDR_SYSID]
    compid      = raw[HDR_COMPID]
    msgid       = raw[7] | (raw[8] << 8) | (raw[9] << 16)

    return {
        "payload_len": payload_len,
        "incompat"   : incompat,
        "signed"     : signed,
        "seq"        : seq,
        "sysid"      : sysid,
        "compid"     : compid,
        "msgid"      : msgid,
    }


def _parse_signature_timestamp(raw: bytes, payload_len: int) -> Optional[float]:
    """
    Extract the signing timestamp from a signed MAVLink 2.0 packet.
    Returns Unix timestamp (float) or None if packet is too short.

    Signature block starts at: 10 + payload_len + 2 (CRC)
    Layout: [link_id(1)] [timestamp(6 LE)] [sig_hash(6)]
    """
    sig_start = HDR_PAYLOAD_START + payload_len + 2  # skip CRC
    if len(raw) < sig_start + 1 + 6:
        return None

    ts_bytes = raw[sig_start + SIG_TIMESTAMP : sig_start + SIG_TIMESTAMP + 6]
    ts_val   = int.from_bytes(ts_bytes, "little")          # 10µs units since epoch
    ts_unix  = MAVLINK_EPOCH + ts_val / 100_000.0
    return ts_unix


def _parse_gps_json(raw_str: str) -> Optional[dict]:
    """
    Parse a GPS_INPUT JSON string from MAVProxy GPSInput module.
    Returns dict with relevant fields or None on parse failure.
    """
    try:
        data = json.loads(raw_str)
    except (json.JSONDecodeError, ValueError):
        return None

    time_usec = data.get("time_usec")
    lat_raw   = data.get("lat")
    lon_raw   = data.get("lon")

    if time_usec is None:
        return None

    return {
        "gps_unix": time_usec / 1_000_000.0,
        "lat"     : lat_raw / 1e7 if lat_raw is not None else None,
        "lon"     : lon_raw / 1e7 if lon_raw is not None else None,
    }


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Haversine distance between two lat/lon points in metres.
    """
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi       = math.radians(lat2 - lat1)
    dlambda    = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return 2 * EARTH_RADIUS_M * math.asin(math.sqrt(a))


# ─────────────────────────────────────────────────────────────
# Stateful Feature Extractor
# ─────────────────────────────────────────────────────────────
class FeatureExtractor:
    """
    Stateful extractor — maintains history across packets to compute
    inter-arrival times, sequence jumps, and position drift rate.

    One instance should be used for the lifetime of a capture session.
    """

    def __init__(self, hash_store_size: int = HASH_STORE_SIZE):
        # Last arrival time per message type key (msgid or 'gps')
        self._last_arrival: dict[str, float] = {}

        # Last sequence number per (sysid, compid) pair
        self._last_seq: dict[tuple, int] = {}

        # Last GPS position and timestamp for drift calculation
        self._last_gps_lat  : Optional[float] = None
        self._last_gps_lon  : Optional[float] = None
        self._last_gps_time : Optional[float] = None   # wall clock time

        # Rolling SHA-256 hash store for duplicate detection
        self._hash_store: set   = set()
        self._hash_queue: deque = deque(maxlen=hash_store_size)

    # ── Public API ────────────────────────────────────────────

    def from_mavlink(self, raw: bytes) -> Optional[Features]:
        """
        Extract features from a raw MAVLink 2.0 packet (bytes).
        Returns None if the bytes are not a valid MAVLink 2.0 packet.
        """
        hdr = _parse_mavlink_header(raw)
        if hdr is None:
            return None

        now     = time.time()
        feat    = Features(source="mavlink")
        feat.msgid  = hdr["msgid"]
        feat.seq    = hdr["seq"]
        feat.sysid  = hdr["sysid"]
        feat.signed = hdr["signed"]

        # ── Feature 1: Timestamp gap ──────────────────────────
        if hdr["signed"]:
            sig_unix = _parse_signature_timestamp(raw, hdr["payload_len"])
            if sig_unix is not None:
                feat.sig_unix = sig_unix
                feat.ts_gap   = sig_unix - now

        # ── Feature 2: Inter-arrival time ─────────────────────
        key = f"mav_{hdr['msgid']}"
        if key in self._last_arrival:
            feat.iat_ms = (now - self._last_arrival[key]) * 1000.0
        self._last_arrival[key] = now

        # ── Feature 3: Sequence consistency ───────────────────
        sc_key = (hdr["sysid"], hdr["compid"])
        if sc_key in self._last_seq:
            expected   = (self._last_seq[sc_key] + 1) % 256
            feat.seq_jump = abs(hdr["seq"] - expected)
            # Handle wrap-around (e.g. 255 → 0)
            feat.seq_jump = min(feat.seq_jump, 256 - feat.seq_jump)
        self._last_seq[sc_key] = hdr["seq"]

        # ── Feature 4: GPS vs system clock (N/A for MAVLink) ──
        # Only meaningful for GPS_INPUT packets — left as None here.

        # ── Feature 5: Drift rate (N/A for plain MAVLink) ─────
        # Populated only from GPS_INPUT packets.

        # ── Feature 6: Duplicate detection ───────────────────
        feat.is_duplicate = self._check_duplicate(raw)

        return feat

    def from_gps_json(self, raw_str: str) -> Optional[Features]:
        """
        Extract features from a GPS_INPUT JSON string.
        Returns None if the string is not valid GPS_INPUT JSON.
        """
        parsed = _parse_gps_json(raw_str)
        if parsed is None:
            return None

        now  = time.time()
        feat = Features(source="gps_json")
        feat.gps_unix = parsed["gps_unix"]
        feat.lat      = parsed["lat"]
        feat.lon      = parsed["lon"]

        # ── Feature 1: ts_gap (GPS clock vs wall clock) ───────
        # Reuse ts_gap field — here it means GPS time vs system time.
        # For GPS packets there is no MAVLink signature timestamp.
        feat.ts_gap = None   # ts_gap is MAVLink-only; use gps_sys_delta below.

        # ── Feature 2: Inter-arrival time ─────────────────────
        key = "gps"
        if key in self._last_arrival:
            feat.iat_ms = (now - self._last_arrival[key]) * 1000.0
        self._last_arrival[key] = now

        # ── Feature 3: Sequence (no seq in GPS JSON) ──────────
        feat.seq_jump = None

        # ── Feature 4: GPS vs system clock delta ──────────────
        feat.gps_sys_delta = parsed["gps_unix"] - now

        # ── Feature 5: Position drift rate ────────────────────
        if (parsed["lat"] is not None and parsed["lon"] is not None
                and self._last_gps_lat is not None
                and self._last_gps_time is not None):

            dist_m   = _haversine_m(
                self._last_gps_lat, self._last_gps_lon,
                parsed["lat"],      parsed["lon"]
            )
            elapsed  = now - self._last_gps_time
            feat.drift_m_per_s = dist_m / elapsed if elapsed > 0 else 0.0

        # Update GPS state
        if parsed["lat"] is not None:
            self._last_gps_lat  = parsed["lat"]
            self._last_gps_lon  = parsed["lon"]
            self._last_gps_time = now

        # ── Feature 6: Duplicate detection ───────────────────
        feat.is_duplicate = self._check_duplicate(raw_str.encode())

        return feat

    # ── Private helpers ───────────────────────────────────────

    def _check_duplicate(self, data: bytes) -> int:
        h = hashlib.sha256(data).hexdigest()
        if h in self._hash_store:
            return 1
        # Evict oldest if at capacity
        if len(self._hash_queue) == self._hash_queue.maxlen:
            oldest = self._hash_queue[0]
            self._hash_store.discard(oldest)
        self._hash_queue.append(h)
        self._hash_store.add(h)
        return 0

    def reset(self):
        """Clear all state — call between test runs."""
        self._last_arrival.clear()
        self._last_seq.clear()
        self._last_gps_lat  = None
        self._last_gps_lon  = None
        self._last_gps_time = None
        self._hash_store.clear()
        self._hash_queue.clear()


# ─────────────────────────────────────────────────────────────
# Quick self-test  (python3 features.py)
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import struct

    print("=" * 60)
    print("  Feature Extractor — Self Test")
    print("=" * 60)

    extractor = FeatureExtractor()

    # ── Test 1: Normal GPS packet ─────────────────────────────
    print("\n[TEST 1] Normal GPS packet (time ≈ now)")
    now_us = int(time.time() * 1_000_000)
    gps_normal = json.dumps({
        "time_usec": now_us,
        "gps_id": 0, "ignore_flags": 0,
        "time_week_ms": 0, "time_week": 0,
        "fix_type": 3,
        "lat": -353632610, "lon": 1491652370,
        "alt": 584.0, "hdop": 1, "vdop": 1,
        "vn": 0, "ve": 0, "vd": 0,
        "speed_accuracy": 0.3, "horiz_accuracy": 1.0,
        "vert_accuracy": 1.5, "satellites_visible": 10,
    })
    f = extractor.from_gps_json(gps_normal)
    print(f)

    # ── Test 2: Attack 2 — GPS +10 days ───────────────────────
    print("\n[TEST 2] Attack 2 — GPS timestamp +10 days")
    spoof_us = int((time.time() + 10 * 86400) * 1_000_000)
    gps_spoof = json.dumps({
        "time_usec": spoof_us,
        "gps_id": 0, "ignore_flags": 0,
        "time_week_ms": 0, "time_week": 0,
        "fix_type": 3,
        "lat": -353830000, "lon": 1491652370,   # 200m south drift
        "alt": 584.0, "hdop": 1, "vdop": 1,
        "vn": 0, "ve": 0, "vd": 0,
        "speed_accuracy": 0.3, "horiz_accuracy": 1.0,
        "vert_accuracy": 1.5, "satellites_visible": 10,
    })
    f = extractor.from_gps_json(gps_spoof)
    print(f)

    # ── Test 3: Attack 3 — Overflow (year 2104) ───────────────
    print("\n[TEST 3] Attack 3 — Overflow DoS (year 2104)")
    overflow_us = 4_234_820_167_000_000
    gps_overflow = json.dumps({
        "time_usec": overflow_us,
        "gps_id": 0, "ignore_flags": 0,
        "time_week_ms": 0, "time_week": 0,
        "fix_type": 3,
        "lat": -353632610, "lon": 1491652370,
        "alt": 584.0, "hdop": 1, "vdop": 1,
        "vn": 0, "ve": 0, "vd": 0,
        "speed_accuracy": 0.3, "horiz_accuracy": 1.0,
        "vert_accuracy": 1.5, "satellites_visible": 10,
    })
    f = extractor.from_gps_json(gps_overflow)
    print(f)

    # ── Test 4: Attack 3B — Underflow (year 2010) ─────────────
    print("\n[TEST 4] Attack 3B — Underflow DoS (year 2010)")
    underflow_us = 1_262_304_000_000_000
    gps_underflow = json.dumps({
        "time_usec": underflow_us,
        "gps_id": 0, "ignore_flags": 0,
        "time_week_ms": 0, "time_week": 0,
        "fix_type": 3,
        "lat": -353632610, "lon": 1491652370,
        "alt": 584.0, "hdop": 1, "vdop": 1,
        "vn": 0, "ve": 0, "vd": 0,
        "speed_accuracy": 0.3, "horiz_accuracy": 1.0,
        "vert_accuracy": 1.5, "satellites_visible": 10,
    })
    f = extractor.from_gps_json(gps_underflow)
    print(f)

    # ── Test 5: Duplicate detection ───────────────────────────
    print("\n[TEST 5] Duplicate packet detection")
    extractor2 = FeatureExtractor()
    f1 = extractor2.from_gps_json(gps_normal)
    f2 = extractor2.from_gps_json(gps_normal)   # same packet again
    print(f"  First send  → is_duplicate = {f1.is_duplicate}  (expected 0)")
    print(f"  Second send → is_duplicate = {f2.is_duplicate}  (expected 1)")

    # ── Test 6: Sequence jump ─────────────────────────────────
    print("\n[TEST 6] Sequence number jump")

    def make_heartbeat(seq: int) -> bytes:
        payload = b'\x00' * 9
        header  = struct.pack("<BBBBBBBBBB",
            0xFD, len(payload), 0x00, 0x00, seq, 1, 1, 0, 0, 0)
        crc     = b'\x00\x00'
        return header + payload + crc

    extractor3 = FeatureExtractor()
    for seq_val in [10, 11, 15, 16]:   # jump from 11→15 = seq_jump 4
        raw  = make_heartbeat(seq_val)
        feat = extractor3.from_mavlink(raw)
        if feat:
            print(f"  seq={seq_val:3d}  seq_jump={feat.seq_jump}")

    print("\n" + "=" * 60)
    print("  All tests complete.")
    print("=" * 60)
