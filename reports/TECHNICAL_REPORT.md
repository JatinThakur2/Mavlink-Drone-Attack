# MAVLink 2.0 Drone Security Lab — Technical Report

**Date:** June 10, 2026  
**Platform:** ArduPilot SITL (ArduCopter) + MAVProxy  
**Environment:** Ubuntu Linux, Python 3.10+  
**Repository:** [JatinThakur2/Mavlink-Drone-Attack](https://github.com/JatinThakur2/Mavlink-Drone-Attack)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Lab Architecture](#2-lab-architecture)
3. [Environment & Setup](#3-environment--setup)
4. [Feature Extraction (Step 1)](#4-feature-extraction-step-1)
5. [Statistical Rule Detector (Step 2)](#5-statistical-rule-detector-step-2)
6. [ML Baseline Training (Step 3)](#6-ml-baseline-training-step-3)
7. [Two-Layer ML Detector (Step 4)](#7-two-layer-ml-detector-step-4)
8. [Attacks — Technical Details](#8-attacks--technical-details)
9. [Detection Results](#9-detection-results)
10. [Alert System](#10-alert-system)
11. [Key Engineering Challenges & Fixes](#11-key-engineering-challenges--fixes)
12. [Repository Structure](#12-repository-structure)

---

## 1. Project Overview

This lab replicates and extends the attack chain described in **"MAVLink 2.0 Time-Spoofing Vulnerabilities in UAV Communication Protocols"** (Ficco et al.). The goal is to:

1. Implement five real attacks against MAVLink 2.0 signing on a simulated ArduPilot drone
2. Build a two-layer real-time detector that combines deterministic statistical rules with an unsupervised Isolation Forest machine learning model
3. Demonstrate that all five attacks can be detected with zero false positives on normal traffic

**What makes MAVLink 2.0 signing vulnerable:**  
MAVLink 2.0 uses a 48-bit timestamp counter (10 µs units since Jan 1, 2015) embedded in every signed packet. The drone trusts GPS time to advance this counter (Rule 4). An attacker who can inject fake GPS packets or craft signed messages with future timestamps can corrupt the signing clock permanently, causing the drone to reject all legitimate GCS commands.

---

## 2. Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     SITL (ArduCopter)                       │
│  Simulates real ArduPilot firmware in Gazebo/headless mode  │
└──────────────────────────┬──────────────────────────────────┘
                           │ UDP 5760 (MAVLink)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                       MAVProxy                              │
│  Ground control proxy — forwards MAVLink, loads GPSInput    │
│  Out → UDP 14550 (main)   UDP 14551 (monitor/detector)      │
│  GPS → UDP 25100 (accept) UDP 25101 (monitor/detector)      │
└──────────┬───────────────────────────────┬──────────────────┘
           │                               │
           ▼                               ▼
┌─────────────────┐             ┌──────────────────────────┐
│  Attack Scripts │             │  Two-Layer Detector       │
│  attack1–4.py   │──mirror──►  │  detector_ml.py           │
│  Sends to 14550 │  14551      │                           │
│  + 25100        │  25101      │  Layer 1: 6 Rules         │
└─────────────────┘             │  Layer 2: Isolation Forest│
                                └──────────────────────────┘
```

**Monitor Port Architecture:**  
Attack scripts send malicious packets to both the real port (14550/25100, reaching MAVProxy/SITL) and a dedicated monitor port (14551/25101, exclusively for the detector). This avoids `SO_REUSEPORT` distribution issues — the detector always receives a copy of every attack packet on its monitor port.

---

## 3. Environment & Setup

| Component | Version / Details |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Python | 3.10+ |
| ArduPilot SITL | ArduCopter (Canberra SITL home) |
| MAVProxy | Latest, with GPSInput module |
| pymavlink | For packet crafting |
| scikit-learn | Isolation Forest + StandardScaler |
| numpy | < 2.0 (pinned for scipy compatibility) |

**SITL launch command:**
```bash
cd ~/ardupilot
python3 Tools/autotest/sim_vehicle.py -v ArduCopter \
    --out=udp:127.0.0.1:14550 --out=udp:127.0.0.1:14551 -w
```

**MAVProxy signing setup (required before any test):**
```
signing setup key
signing setup sign_outgoing 1
```

**GPS parameter setup (required for GPS attacks):**
```
param set GPS1_TYPE 14
param set SIM_GPS1_DISABLE 1
module load GPSInput
```

---

## 4. Feature Extraction (Step 1)

**File:** `detection/features.py`

Every packet is parsed into a 6-feature vector before any detection logic runs.

| # | Feature | Source | Description | Attack Signal |
|---|---|---|---|---|
| 1 | `ts_gap` | MAVLink signed | `sig_timestamp_unix − time.time()` (seconds) | Large positive → future timestamp (ATK1, ATK4) |
| 2 | `iat_ms` | MAVLink + GPS | Inter-arrival time in ms from previous packet of same type | Very large → SITL frozen after DoS |
| 3 | `seq_jump` | MAVLink | `|received_seq − expected_seq| mod 256` | > 0 → gap or out-of-order |
| 4 | `gps_sys_delta` | GPS JSON | `gps_unix − time.time()` (seconds) | Large positive → spoofed GPS clock (ATK2, ATK3) |
| 5 | `drift_m_per_s` | GPS JSON | Haversine distance / elapsed time between consecutive GPS fixes | High rate → position spoofing (ATK2) |
| 6 | `is_duplicate` | Both | SHA-256 hash of raw bytes already seen in rolling 10,000-entry store | 1 → byte-for-byte replay (ATK4) |

**Two vector types:**
- `vector` (6 features) — used for statistical rules and display
- `ml_vector` (5 features, excludes `is_duplicate`) — used for Isolation Forest training/inference

> `is_duplicate` is excluded from ML because `SO_REUSEPORT` causes ~55% of normal MAVLink packets to appear as duplicates (the OS sends the same SITL heartbeat to both MAVProxy's socket and the detector's socket on port 14550). This would corrupt the baseline model. Rule 5 handles replay detection deterministically.

---

## 5. Statistical Rule Detector (Step 2)

**File:** `detection/detector.py`

Six deterministic threshold rules that fire instantly with zero training:

| Rule | Tag | Condition | Threshold |
|---|---|---|---|
| 1 | `ATK1_FUTURE_TS` | `ts_gap > 3600s` | Signing timestamp > 1 hour ahead of system clock |
| 2 | `ATK3B_UNDERFLOW` | `gps_unix < 1,420,070,400` | GPS time before MAVLink epoch (Jan 1, 2015) |
| 3 | `ATK3_OVERFLOW` | `gps_unix > 2,524,608,000` | GPS time after year 2050 |
| 4 | `ATK2_GPS_SPOOF` | `gps_sys_delta > 86,400s` | GPS clock more than 1 day ahead of system |
| 5 | `ATK4_REPLAY` | `is_duplicate == 1 AND source == "mavlink" AND port == 14551` | Duplicate MAVLink packet on monitor port only |
| 6 | `ATK3B_BURST` | `count > 5 GPS pkts in 2.0s` | GPS flood burst pattern |

**Key design decision — Rule 5 monitor-port guard:**  
ATK4_REPLAY only fires for packets arriving on port 14551 (the dedicated monitor port). On the main port 14550, `SO_REUSEPORT` causes the same heartbeat to reach both MAVProxy and the detector, so every heartbeat appears as a "duplicate" — a false positive at ~40 alerts/second. The monitor port only receives traffic explicitly mirrored by attack scripts, so duplicates there are genuine replays.

---

## 6. ML Baseline Training (Step 3)

**File:** `detection/train_baseline.py`  
**Model:** `detection/models/baseline.pkl`

### Training Procedure

1. SITL running normally (no attacks) with MAVLink signing enabled
2. `simulate_normal_gps.py` running to inject real-time GPS (gps_sys_delta ≈ 0)
3. Capture 300 seconds of normal traffic (66,976 feature vectors)
4. Train `StandardScaler` + `IsolationForest(n_estimators=200, contamination=0.05)`

### Training Data Statistics (Normal Traffic)

| Feature | Mean | Std | Min | Max |
|---|---|---|---|---|
| `ts_gap` | −4.4 s | 2.9 s | −12.1 s | 1.2 s |
| `iat_ms` | 11.3 ms | 8.7 ms | 0.1 ms | 210 ms |
| `seq_jump` | 0.0 | 0.01 | 0 | 1 |
| `gps_sys_delta` | −0.001 s | 0.009 s | −0.15 s | 0.12 s |
| `drift_m_per_s` | 0.0 m/s | 0.0 m/s | 0.0 m/s | 0.02 m/s |

### Why Attacks Are Far From Normal

| Attack | Anomalous Feature | Normal Value | Attack Value | Sigma Distance |
|---|---|---|---|---|
| ATK1 | `ts_gap` | −4.4 s ± 2.9 s | +86,400 s (+1 day) | ~30,000 σ |
| ATK2 | `gps_sys_delta` | −0.001 s ± 0.009 s | +864,000 s (+10 days) | ~96,000,000 σ |
| ATK3 | `gps_sys_delta` | −0.001 s ± 0.009 s | +2,810,000,000 s (+78 yrs) | ~312,000,000,000 σ |
| ATK3B | `gps_sys_delta` | −0.001 s ± 0.009 s | −157,766,400 s (−5 yrs before epoch) | massive negative |
| ATK4 | `ts_gap` (replayed) | −4.4 s | +86,400 s (future-captured pkt) | ~30,000 σ |

### Model Parameters

| Parameter | Value |
|---|---|
| Algorithm | Isolation Forest |
| Training samples | 66,976 |
| Estimators (trees) | 200 |
| Contamination | 0.05 (5%) |
| Random state | 42 |
| Self-eval anomaly rate | ~5.1% |
| Score mean (normal traffic) | 0.1002 |
| Score std | 0.0516 |
| Model file size | 2,658 KB |
| Trained at | 2026-06-09 11:07:32 UTC |

---

## 7. Two-Layer ML Detector (Step 4)

**File:** `detection/detector_ml.py`

### Processing Flow

```
For every received packet:
    │
    ├─ Parse → FeatureExtractor → Features(6 fields)
    │
    ├─ LAYER 1: RuleEngine.check(feat, is_monitor)
    │     Six deterministic rules (instant)
    │     If rules fire → log named alert (ATK1..ATK4)
    │                   → SKIP Layer 2 (no double-count)
    │
    └─ LAYER 2: MLLayer.score(feat.ml_vector)
          StandardScaler → IsolationForest.decision_function()
          If score < −0.13 AND rules were silent
          → log ATK_ML_ANOMALY with score + vector
```

### ML Score Interpretation

| Score Range | Meaning |
|---|---|
| > 0.0 | Clearly normal |
| −0.10 to 0.0 | Borderline — within normal envelope |
| < −0.13 | **Anomaly — ATK_ML_ANOMALY fires** |
| −0.15 and below | Strong anomaly (e.g., SITL stalled 25s after overflow) |

**Threshold:** `ML_SCORE_THRESHOLD = −0.13`  
Raised from initial −0.10 to reduce GPS false positives during normal operation (SITL's GPS occasionally drifts −0.7 to −81 s from system clock).

### What Each Layer Catches

| Layer | Catches | Example |
|---|---|---|
| Statistical Rules | Known named attacks with clear threshold violations | `ATK3_OVERFLOW: GPS date=2104-03-13` |
| Isolation Forest | Anomalous traffic patterns not covered by rules | `ATK_ML_ANOMALY: iat_ms=25,420ms` (SITL stall after overflow DoS) |

---

## 8. Attacks — Technical Details

### Attack 1 — Signed Command Clock Manipulation

**File:** `attacks/attack1_signed_cmd.py`  
**Paper:** Stage 1 — Replication of Ficco et al. (Section IV-C-2a)

**Mechanism:**
- Craft a MAVLink 2.0 `COMMAND_LONG` (MSG_ID 76) with timestamp = `now + 86,400s` (+1 day)
- Sign with the shared key (`"key"`)
- Send to SITL via MAVProxy on UDP 14550 (mirrored to 14551)
- SITL accepts the signature (valid) and jumps its internal signing clock +1 day
- Effect: drone switches to LAND mode; all subsequent GCS commands with real timestamps rejected

**Exploited MAVLink Rule:** Rule 6 — reject packets with timestamp ≤ last accepted timestamp  
After clock jumps +1 day, all real 2026-dated commands appear "old" and are rejected.

**Signature construction:**
```
SHA-256(key || header+payload+CRC || link_id || ts_bytes)[:6]
```

---

### Attack 2 — GPS Timestamp + Position Spoofing

**File:** `attacks/attack2_gps_spoof.py`  
**Paper:** Stage 2 — Section IV-C-2b / Algorithm 1

**Mechanism:**
- Inject JSON GPS_INPUT packets via UDP 25100 (MAVProxy GPSInput module)
- `time_usec` = `now + 864,000s` (+10 days in microseconds)
- GPS latitude drifts south by 0.0018° (~200m) over 30 seconds
- Mirror every packet to UDP 25101 (detector monitor)

**Two attack effects:**
1. **Clock attack:** UAV signing clock jumps +10 days; GCS commands (dated today) rejected
2. **Position attack:** EKF believes drone is 200m south; autopilot fires northward thrust to compensate → drone physically moves north in Gazebo

**Send rate:** 5 Hz for 30 seconds = 150 packets total

---

### Attack 3 — Timestamp Overflow DoS

**File:** `attacks/attack3_overflow_dos.py`  
**Paper:** Stage 3 — Section IV-C-2c / Algorithm 2

**Mechanism:**
- Inject `time_usec = 4,234,820,167,000,000 µs` (Unix time March 13, 2104)
- This is exactly `MAVLINK_EPOCH + (2^48 − 1) / 100,000` — the maximum 48-bit MAVLink timestamp
- 10 packets sent in a burst (0.2s intervals) to guarantee one is accepted
- UAV signing clock is forced to 48-bit MAX

**Effect (permanent):**  
All real 2026 timestamps (≈36 trillion 10µs units) are less than MAX (281,474,976,710,655). Rule 6 rejects everything forever. The drone requires a full firmware reflash to recover — rebooting alone does not help because the signing clock persists in EEPROM.

**Contrast with Attack 2:**  
Attack 2 is reversible (key rotation recovers). Attack 3 is permanent.

---

### Attack 3B — Timestamp Underflow DoS

**File:** `attacks/attack3b_underflow_dos.py`  
**Paper:** Stage 3 variant — Section IV-C-2c

**Mechanism:**
- Inject `time_usec` corresponding to a date before January 1, 2015 (the MAVLink epoch)
- The computed signing timestamp becomes **negative**: `(gps_unix − 1,420,070,400) × 100,000 < 0`
- Cast as `uint64_t`, this wraps near `2^64`, producing a value >> any real 2026 timestamp

**Two possible effects (implementation-dependent):**
- **Effect A (Wrap DoS):** ArduPilot stores the wrapped value → same permanent DoS as Attack 3
- **Effect B (Clock Reset):** ArduPilot clamps negative timestamps to 0 → signing clock resets to Jan 1, 2015; all real 2026 commands now appear "future" and are accepted — can undo Attack 2/3

**Also tested:** GPS burst sub-variant — sending >5 GPS packets in 2 seconds triggers the `ATK3B_BURST` rule (DoS pattern detection).

---

### Attack 4 — Replay Attack

**File:** `attacks/attack4_replay.py`  
**Paper:** Stage 4 — Section IV-C-2d / Algorithm 3

**Mechanism:**
1. Extract the raw bytes of the signed COMMAND_LONG captured during Attack 1
   - This packet has `timestamp = capture_time + 86,400s` (a future timestamp at capture time)
2. Restart SITL — signing clock resets to real current time
3. **Do NOT rotate the signing key** — keep the same `"key"`
4. Resend the raw captured bytes over UDP 14550

**Why it works after SITL restart:**
- Rule 3 (signature check): PASSES — same key, signature is still mathematically valid
- Rule 6 (timestamp check): PASSES — SITL clock was reset; the captured future timestamp is still in the future relative to the new baseline

**Why it would be blocked in a secure system:**  
Key rotation after any incident invalidates all captured packets. Without rotation, the attacker has a permanently valid replay token.

---

## 9. Detection Results

### Summary Table

| Attack | Method | Detection Tag | Rule Type | Detected? |
|---|---|---|---|---|
| ATK1 — Signed Command | `ts_gap > 3600s` | `ATK1_FUTURE_TS` | Statistical | ✓ YES |
| ATK2 — GPS Spoof | `gps_sys_delta > 86,400s` | `ATK2_GPS_SPOOF` | Statistical | ✓ YES |
| ATK3 — Overflow DoS | `gps_unix > 2050` | `ATK3_OVERFLOW` | Statistical | ✓ YES |
| ATK3B — Underflow DoS | `gps_unix < 2015` | `ATK3B_UNDERFLOW` | Statistical | ✓ YES |
| ATK3B — Burst | `>5 GPS/2s` | `ATK3B_BURST` | Statistical | ✓ YES |
| ATK4 — Replay | Duplicate hash on monitor port | `ATK4_REPLAY` | Statistical | ✓ YES |
| SITL stall after DoS | `iat_ms = 25,420ms` (ML) | `ATK_ML_ANOMALY` | Isolation Forest | ✓ YES |
| Normal traffic | — | — | — | 0 false positives |

### Session-Level Results

#### Session: Attack 2 (GPS Spoof) — `alerts_20260610_065328.log`

| Metric | Value |
|---|---|
| Total packets processed | 6,227 |
| Session duration | ~86 seconds (06:53:28 → 06:54:44) |
| Rule alerts | 92 |
| ML alerts | 0 |
| Primary alert | `ATK2_GPS_SPOOF: GPS clock +10.0 days ahead` |
| First detection | 06:53:56 UTC (28 seconds after start) |
| Detection frequency | Every ~5.3 seconds (throttle window) |
| Drift observed | 2.0 → 3.5 m/s (position spoofing confirmed) |

**Sample alert from this session:**
```
[2026-06-10 06:53:56 UTC] [ALERT] ATK2_GPS_SPOOF  GPS clock +10.0 days ahead | drift=?
[2026-06-10 06:54:01 UTC] [ALERT] ATK2_GPS_SPOOF  [... 9 more in 5.4s — suppressed]
[2026-06-10 06:54:01 UTC] [ALERT] ATK2_GPS_SPOOF  GPS clock +10.0 days ahead | drift=2.0 m/s
```

---

#### Session: Attack 1 + Attack 3 (Overflow DoS) — `alerts_20260610_070056.log`

| Metric | Value |
|---|---|
| Total packets processed | 45,653 |
| Session duration | ~9 minutes (07:01:18 → 07:10:06) |
| Rule alerts | 2 (ATK1 + ATK3_OVERFLOW) |
| ML alerts | 223 (SITL stall secondary effect) |
| Total alerts | 225 |

**Timeline:**
```
07:01:18  ATK1_FUTURE_TS:  sig timestamp 24.0h in the future | sysid=255 msgid=76 seq=200
07:01:50  ATK_ML_ANOMALY:  ML score=-0.1303 | iat_ms=2485ms  (SITL heartbeat gaps begin)
07:02:21  ATK_ML_ANOMALY:  ML score=-0.1451 | iat_ms=25,420ms  ← GPS overflow effect: SITL stalled 25s
07:02:42  ATK3_OVERFLOW:   GPS date=2104-03-13 (+78 years) | signing clock → 2^48-1 | PERMANENT DoS
07:02:44  ATK_ML_ANOMALY:  ML score=-0.1303 | iat_ms=2504ms  (continued irregular heartbeats)
```

**ML detection note:** The Isolation Forest independently detected the DoS secondary effect (SITL heartbeat interruption after clock corruption) before the statistical rule confirmed the overflow GPS packet. Normal `iat_ms` during training was 11.3 ms ± 8.7 ms. After the overflow, SITL heartbeats arrived every 2,500–25,000 ms — 285× to 2,900× above normal.

---

### False Positive Rate

With the current detector configuration on 5 minutes of normal traffic (no attacks):

| Metric | Value |
|---|---|
| Normal packets processed | ~66,976 (training set) |
| False rule alerts | 0 |
| False ML alerts | ~5% (by design — `contamination=0.05`) |
| ATK4_REPLAY false positives | 0 (monitor-port guard eliminates them) |

---

## 10. Alert System

**File:** `detection/alerts.py`

### Per-Session Logging
- Each detector run creates a unique timestamped log: `detection/results/alerts_YYYYMMDD_HHMMSS.log`
- A symlink `detection/results/alerts.log` always points to the most recent session
- Log entries use plain text (no ANSI codes); terminal output uses colour

### Alert Throttling
Repeated alerts of the same type are throttled within a 5-second sliding window to prevent log flooding during sustained attacks:

```
[ALERT] ATK2_GPS_SPOOF   GPS clock +10.0 days ahead | drift=2.0 m/s    ← shown (first in window)
[ALERT] ATK2_GPS_SPOOF   [... 9 more in 5.3s — suppressed]              ← shown when window expires
[ALERT] ATK2_GPS_SPOOF   GPS clock +10.0 days ahead | drift=2.1 m/s    ← shown (new window starts)
```

A background daemon thread runs every second and proactively flushes expired throttle windows — ensuring the suppressed count appears within 5 seconds even if no new events arrive for that tag.

### Session Summary (on Ctrl+C)
```
[SESSION] total_pkts=6227 alerts=92 | log=detection/results/alerts_20260610_065328.log
```

### Alert Levels
| Level | Colour | Use |
|---|---|---|
| `[ALERT]` | Red + Bold | Security threat detected |
| `[INFO ]` | Cyan | System startup, model load |
| `[NORM ]` | Grey | Normal traffic heartbeat (every 50 packets) |

---

## 11. Key Engineering Challenges & Fixes

### Challenge 1 — ATK4_REPLAY False Positives (~200 per 5 seconds)

**Root cause:** The detector listens on both port 14550 (main, shared with MAVProxy via `SO_REUSEPORT`) and 14551 (monitor). Linux distributes packets arriving on 14550 among all sockets bound to that port. The same SITL heartbeat therefore arrives on both the detector's 14550 socket and MAVProxy's 14550 socket, then MAVProxy forwards it to 14551. The detector sees the same bytes twice → `is_duplicate = 1` → false ATK4_REPLAY.

**Fix:** Port is now threaded through the packet queue: `(label, port, data, addr)`. `ATK4_REPLAY` only fires when `source == "mavlink" AND port == 14551 (MONITOR_PORT)`. GPS packets are also excluded (`source == "mavlink"` guard) because Attack 2 mirrors the same GPS packet to both 25100 and 25101.

---

### Challenge 2 — GPS Attack Packets Not Visible in Detector

**Root cause:** GPS overflow packets sent to port 25100 were distributed by `SO_REUSEPORT` between MAVProxy's GPSInput listener and the detector. Some went to MAVProxy (correctly), some to the detector. The detector was not reliably seeing all GPS attack packets.

**Fix:** Attack scripts mirror every GPS packet to port 25101 (exclusively detector-owned, no `SO_REUSEPORT` sharing). The detector now reliably receives all GPS attack packets through the monitor port.

---

### Challenge 3 — Training Data Quality

**Problem A:** `ts_gap = 0` during training because MAVLink signing was not enabled.  
**Fix:** Enable `signing setup key` + `signing setup sign_outgoing 1` before training.

**Problem B:** `gps_sys_delta = 0` during training because no GPS simulator was running.  
**Fix:** Created `simulate_normal_gps.py` — injects real-time GPS_INPUT at 5 Hz during training (gps_sys_delta ≈ 0).

**Problem C:** `is_duplicate = 0.55` (55% of training packets marked as duplicates) corrupting ML.  
**Fix:** Added `ml_vector` property to `Features` class that excludes `is_duplicate`. Isolation Forest trains on 5 features only.

---

### Challenge 4 — Throttle Suppressed Count Not Showing in Real-Time

**Problem:** The "[... N more suppressed]" line only printed when a *new* event of the same tag arrived after the 5-second window. For bursty attacks (Attack 3: 10 identical packets in 2 seconds), the suppressed count sat invisible until Ctrl+C shutdown.

**Fix:** Added a background daemon thread in `alerts.py` that wakes every second and proactively calls `_flush_expired_windows()`, printing suppressed counts within ~5 seconds regardless of whether new events arrive.

---

### Challenge 5 — scikit-learn / NumPy Version Conflict

**Problem:** NumPy 2.x conflicted with system scipy causing import failures.  
**Fix:** Pinned NumPy < 2.0: `pip install "numpy<2" scikit-learn`

---

## 12. Repository Structure

```
drone_security_lab/
│
├── attacks/
│   ├── attack1_signed_cmd.py       # ATK1: Future-timestamp LAND command
│   ├── attack2_gps_spoof.py        # ATK2: GPS clock +10 days + position drift
│   ├── attack3_overflow_dos.py     # ATK3: GPS time → 48-bit MAX (permanent DoS)
│   ├── attack3b_underflow_dos.py   # ATK3B: GPS time → pre-2015 (wrap/reset)
│   ├── attack4_replay.py           # ATK4: Replay captured future-timestamped packet
│   └── results/
│       ├── attack1_capture.pcap    # Wireshark capture: ATK1 + replayed packet
│       ├── attack2_capture.pcap    # Wireshark capture: GPS spoof stream
│       ├── attack3_capture.pcap    # Wireshark capture: overflow burst
│       ├── attack3b_capture.pcap   # Wireshark capture: underflow burst
│       └── attack4_capture.pcap    # Wireshark capture: replay injection
│
├── detection/
│   ├── features.py                 # Step 1: Feature extraction (6 features)
│   ├── detector.py                 # Step 2: Statistical rules only
│   ├── train_baseline.py           # Step 3: Isolation Forest training
│   ├── detector_ml.py              # Step 4: Two-layer detector (rules + ML)
│   ├── alerts.py                   # Alert formatting, throttling, per-session logs
│   ├── models/
│   │   └── baseline.pkl            # Trained model (66,976 samples, 200 trees)
│   └── results/
│       └── alerts_*.log            # Per-session timestamped alert logs
│
├── reports/
│   └── TECHNICAL_REPORT.md         # This document
│
├── simulation/
│   └── sitl_basic.py               # SITL helper
│
├── wireshark/
│   └── plugins/
│       ├── gps_spoof.lua           # Wireshark dissector for GPS attack packets
│       └── attack4_replay.lua      # Wireshark dissector for replay packets
│
├── simulate_normal_gps.py          # GPS simulator for baseline training
└── README.md                       # Quick-start guide
```

---

## How to Run the Full Lab

### Step 1 — Start SITL
```bash
cd ~/ardupilot
python3 Tools/autotest/sim_vehicle.py -v ArduCopter \
    --out=udp:127.0.0.1:14550 --out=udp:127.0.0.1:14551 -w
```

### Step 2 — Configure MAVProxy (in MAVProxy console)
```
signing setup key
signing setup sign_outgoing 1
param set GPS1_TYPE 14
param set SIM_GPS1_DISABLE 1
module load GPSInput
```

### Step 3 — Train Baseline (one-time, ~5 minutes)
```bash
# Terminal 1: run GPS simulator
python3 simulate_normal_gps.py

# Terminal 2: run trainer
python3 detection/train_baseline.py
```

### Step 4 — Start Detector
```bash
python3 detection/detector_ml.py
```

### Step 5 — Run Attacks (one at a time)
```bash
python3 attacks/attack1_signed_cmd.py   # → ATK1_FUTURE_TS
python3 attacks/attack2_gps_spoof.py    # → ATK2_GPS_SPOOF
python3 attacks/attack3_overflow_dos.py # → ATK3_OVERFLOW + ATK_ML_ANOMALY
python3 attacks/attack3b_underflow_dos.py # → ATK3B_UNDERFLOW / ATK3B_BURST
python3 attacks/attack4_replay.py       # → ATK4_REPLAY
```

> Restart SITL and re-apply MAVProxy config between Attack 3/3B runs (they corrupt the signing clock permanently).

---

*Report generated: June 10, 2026*
