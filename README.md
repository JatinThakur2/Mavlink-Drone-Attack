# MAVLink 2.0 Drone Security Lab

Real-time attack detection for MAVLink 2.0 timestamp vulnerabilities on ArduPilot SITL.

Based on: *"Timestamp Manipulation-Based GPS Spoofing Attacks on the MAVLink 2.0 Protocol for UAV Communication"* (Ficco et al.)

---

## Status — All 5 Attacks Implemented and Detected

| Attack | Script | Detection Tag | Detected |
|---|---|---|---|
| ATK1 — Signed command injection (future timestamp) | `attack1_signed_cmd.py` | `ATK1_FUTURE_TS` | ✓ |
| ATK2 — GPS clock + position spoof | `attack2_gps_spoof.py` | `ATK2_GPS_SPOOF` | ✓ |
| ATK3 — Timestamp overflow DoS (permanent) | `attack3_overflow_dos.py` | `ATK3_OVERFLOW` | ✓ |
| ATK3B — Timestamp underflow / GPS burst | `attack3b_underflow_dos.py` | `ATK3B_UNDERFLOW` / `ATK3B_BURST` | ✓ |
| ATK4 — Replay attack | `attack4_replay.py` | `ATK4_REPLAY` | ✓ |
| DoS side-effect (SITL stall) | _(secondary)_ | `ATK_ML_ANOMALY` | ✓ |

Full technical details: [`reports/TECHNICAL_REPORT.md`](reports/TECHNICAL_REPORT.md)

---

## Architecture

```
SITL (ArduCopter)
    │ TCP 5760
    ▼
MAVProxy  ──out──►  UDP 14550 (main)    UDP 14551 (detector monitor)
          ──gps──►  UDP 25100 (GPSInput) UDP 25101 (detector monitor)
                                                │
                                    ┌───────────┴────────────┐
                                    │   detector_ml.py        │
                                    │                         │
                                    │  Layer 1: 6 rules       │
                                    │  Layer 2: Isolation     │
                                    │           Forest        │
                                    └─────────────────────────┘
```

Attack scripts send to both the real port (hits SITL) and the monitor port (hits detector exclusively).

---

## Quick Start

### 1 — Start SITL
```bash
cd ~/ardupilot
python3 Tools/autotest/sim_vehicle.py -v ArduCopter \
    --out=udp:127.0.0.1:14550 --out=udp:127.0.0.1:14551 -w
```

### 2 — Configure MAVProxy
```
signing setup key
signing setup sign_outgoing 1
param set GPS1_TYPE 14
param set SIM_GPS1_DISABLE 1
module load GPSInput
```

### 3 — Train Baseline Model (one-time, ~5 minutes)
```bash
# Terminal A: GPS simulator (keep running during training)
python3 simulate_normal_gps.py

# Terminal B: trainer
python3 detection/train_baseline.py
```

### 4 — Start Two-Layer Detector
```bash
python3 detection/detector_ml.py
```

### 5 — Run Attacks
```bash
python3 attacks/attack1_signed_cmd.py     # → ATK1_FUTURE_TS
python3 attacks/attack2_gps_spoof.py      # → ATK2_GPS_SPOOF
python3 attacks/attack3_overflow_dos.py   # → ATK3_OVERFLOW + ATK_ML_ANOMALY
python3 attacks/attack3b_underflow_dos.py # → ATK3B_UNDERFLOW / ATK3B_BURST
python3 attacks/attack4_replay.py         # → ATK4_REPLAY
```

> Restart SITL and re-run MAVProxy config between Attack 3/3B runs (they corrupt the signing clock permanently).

---

## Detection Layers

### Layer 1 — Statistical Rules (instant, no training)

| Rule | Tag | Trigger |
|---|---|---|
| 1 | `ATK1_FUTURE_TS` | MAVLink signing timestamp > 1 hour in future |
| 2 | `ATK3B_UNDERFLOW` | GPS time before Jan 1, 2015 (MAVLink epoch) |
| 3 | `ATK3_OVERFLOW` | GPS time after year 2050 |
| 4 | `ATK2_GPS_SPOOF` | GPS clock > 1 day ahead of system clock |
| 5 | `ATK4_REPLAY` | Duplicate MAVLink hash on monitor port 14551 |
| 6 | `ATK3B_BURST` | More than 5 GPS packets in 2 seconds |

### Layer 2 — Isolation Forest (trained on normal traffic)

- 5-feature vector: `[ts_gap, iat_ms, seq_jump, gps_sys_delta, drift_m_per_s]`
- Fires `ATK_ML_ANOMALY` when score < −0.13 **and** Layer 1 rules are silent
- Catches secondary effects: e.g., SITL heartbeat stall (iat_ms = 25,420 ms) after GPS overflow DoS

### ML Model Stats

| Parameter | Value |
|---|---|
| Training samples | 66,976 (5 min normal traffic) |
| Algorithm | Isolation Forest, 200 trees |
| Contamination | 5% |
| Score mean (normal) | 0.1002 |
| Score threshold | −0.13 |
| Model size | 2,658 KB |

---

## Features Extracted Per Packet

| Feature | Description | Attack Signal |
|---|---|---|
| `ts_gap` | MAVLink signing timestamp − system time | ATK1/ATK4: +86,400 s |
| `iat_ms` | Inter-arrival time (ms) | ATK3 side-effect: 25,000+ ms |
| `seq_jump` | Sequence number gap | Gaps / out-of-order |
| `gps_sys_delta` | GPS time − system time | ATK2: +864,000 s; ATK3: +2.8B s |
| `drift_m_per_s` | GPS position change rate | ATK2: 2–4 m/s |
| `is_duplicate` | SHA-256 match in 10k-entry store | ATK4: 1 (rules only, not ML) |

---

## Project Structure

```
drone_security_lab/
├── attacks/
│   ├── attack1_signed_cmd.py
│   ├── attack2_gps_spoof.py
│   ├── attack3_overflow_dos.py
│   ├── attack3b_underflow_dos.py
│   ├── attack4_replay.py
│   └── results/                  ← pcap captures per attack
│
├── detection/
│   ├── features.py               ← Step 1: Feature extraction
│   ├── detector.py               ← Step 2: Statistical rules
│   ├── train_baseline.py         ← Step 3: ML training
│   ├── detector_ml.py            ← Step 4: Two-layer detector
│   ├── alerts.py                 ← Alert formatting + throttling + logs
│   ├── models/baseline.pkl       ← Trained Isolation Forest
│   └── results/                  ← Per-session timestamped alert logs
│
├── reports/
│   └── TECHNICAL_REPORT.md       ← Full technical report
│
├── wireshark/plugins/            ← Lua dissectors for Wireshark
├── simulate_normal_gps.py        ← GPS simulator for training
└── simulation/                   ← SITL helpers
```

---

## Wireshark Dissectors

```bash
cp wireshark/plugins/*.lua ~/.config/wireshark/plugins/
# Restart Wireshark
```

Useful filters:
```
udp.dstport == 25100   # GPS injection stream
udp.dstport == 14550   # MAVLink command stream
atk2gps.gap            # GPS time gap field
atk4replay.type        # Replay detection field
```

---

## Dependencies

```bash
pip install "numpy<2" scikit-learn pymavlink
sudo apt install tshark
```

| Component | Version |
|---|---|
| Python | 3.10+ |
| ArduPilot SITL | ArduCopter |
| MAVProxy | Latest |
| scikit-learn | 1.x |
| numpy | < 2.0 |
| pymavlink | 2.4.x |
