# Drone Security Lab

Implementation and detection of MAVLink 2.0 timestamp-based attacks on ArduPilot SITL.

Based on the IEEE paper:
> *"Timestamp Manipulation-Based GPS Spoofing Attacks on the MAVLink 2.0 Protocol for UAV Communication"*
> Colton, Oracevic, Dilek — 2026

---

## Project Overview

Two-phase project:

- **Phase 1 (Complete):** Implement five MAVLink attacks against ArduPilot SITL, capture traffic, decode in Wireshark with custom Lua dissectors.
- **Phase 2 (In Progress):** Real-time anomaly detection system — statistical rules + Isolation Forest ML — to catch those same attacks automatically.

---

## Folder Structure

```
drone_security_lab/
│
├── attacks/                          ← Phase 1: Attack implementations
│   ├── attack1_signed_cmd.py         ← Attack 1: Signed command with future timestamp
│   ├── attack2_gps_spoof.py          ← Attack 2: GPS clock advance + position drift
│   ├── attack3_overflow_dos.py       ← Attack 3: 48-bit timestamp overflow DoS
│   ├── attack3b_underflow_dos.py     ← Attack 3B: Pre-epoch underflow (novel attack)
│   ├── attack4_replay.py             ← Attack 4: Replay signed packet from Attack 1
│   └── results/
│       ├── attack1_capture.pcap
│       ├── attack2_capture.pcap
│       ├── attack3_capture.pcap
│       ├── attack3b_capture.pcap
│       └── attack4_capture.pcap
│
├── detection/                        ← Phase 2: Anomaly detection (in progress)
│   ├── features.py                   ← Feature extraction (6 features per packet)
│   ├── detector.py                   ← Main loop: capture + rules + ML alerts
│   ├── alerts.py                     ← Alert formatting and log writer
│   ├── models/
│   │   └── train_baseline.py         ← Train Isolation Forest on normal traffic
│   └── results/
│       └── alerts.log                ← Runtime log (generated, git-ignored)
│
├── wireshark/
│   └── plugins/
│       ├── gps_spoof.lua             ← Dissector for GPS_INPUT packets (Attacks 2, 3, 3B)
│       └── attack4_replay.lua        ← Post-dissector for MAVLink replay (Attack 4)
│
├── simulation/
│   ├── sitl_basic.py                 ← SITL + Gazebo + MAVProxy launcher
│   └── mav.parm                      ← ArduPilot parameter file
│
├── scripts/                          ← Report generators
│   ├── generate_june4_daily.py
│   ├── generate_june2_daily.py
│   ├── generate_june1_daily.py
│   ├── generate_full_report_v2.py
│   └── ...
│
├── reports/                          ← Generated Word documents
│   ├── daily_report_june4.docx       ← Detection framework design
│   ├── daily_report_june2.docx       ← Attack alignment + Wireshark dissectors
│   ├── daily_report_june1.docx       ← Attack 3B + replay demo
│   ├── full_attack_report_v2.docx    ← Full technical report (all 5 attacks)
│   └── ...
│
└── reference/
    └── mavlink-time-spoofing-main/   ← Original research repo (reference only)
        └── simulate/
            ├── custom-input.py       ← Reference: manual SHA-256 signing
            └── simulate-gps.py      ← Reference: JSON GPS injection
```

---

## Attacks Implemented

| # | Name | Method | Effect | Capture |
|---|------|--------|--------|---------|
| 1 | Signed Command Injection | Manual SHA-256, future timestamp | Drone accepts forged LAND command | `attack1_capture.pcap` |
| 2 | GPS Timestamp + Position Spoof | JSON to UDP 25100, lat drift | Clock +10 days, drone moves 200m north | `attack2_capture.pcap` |
| 3 | Timestamp Overflow DoS | GPS time_usec = year 2104 | Signing clock at 2^48-1, total blackout | `attack3_capture.pcap` |
| 3B | Timestamp Underflow DoS | GPS time_usec = year 2010 (pre-epoch) | Negative int → uint64 wrap or clock reset | `attack3b_capture.pcap` |
| 4 | Replay Attack | Resend Attack 1 packet verbatim | Future timestamp still valid, drone lands | `attack4_capture.pcap` |

---

## Wireshark Dissectors

Copy plugins to `~/.config/wireshark/plugins/` then restart Wireshark:

```bash
cp wireshark/plugins/*.lua ~/.config/wireshark/plugins/
```

| Plugin | Port | Protocol Label | Detects |
|--------|------|---------------|---------|
| `gps_spoof.lua` | UDP 25100 | `ATK0_UNDERFLOW` / `ATK2_GPS_SPOOF` / `ATK3_OVERFLOW` | Attacks 2, 3, 3B |
| `attack4_replay.lua` | UDP 14550 | `ATK4_REPLAY` / `ATK4_ACCEPTED` | Attack 4 |

**Useful display filters:**
```
udp.dstport == 25100        # GPS injection stream
udp.dstport == 14550        # MAVLink command stream
atk4replay.type             # Replay dissector fields
atk2gps.gap                 # GPS time gap field
```

---

## Setup & Running Attacks

### Step 1 — Start SITL + Gazebo

```bash
# Terminal 1
sim_vehicle.py -v ArduCopter -f gazebo-iris --model JSON --console

# Terminal 2
mavproxy.py --master tcp:127.0.0.1:5760 --out udp:127.0.0.1:14550
```

### Step 2 — Configure MAVProxy (once per session)

```
param set GPS1_TYPE 14
module load GPSInput
signing setup key
signing setup sign_outgoing 1
mode guided
arm throttle force
takeoff 20
```

### Step 3 — Run an Attack

```bash
python3 attacks/attack1_signed_cmd.py    # Signed command + future timestamp
python3 attacks/attack2_gps_spoof.py    # GPS spoof + position drift
python3 attacks/attack3_overflow_dos.py # 48-bit overflow DoS
python3 attacks/attack3b_underflow_dos.py # Underflow / pre-epoch
python3 attacks/attack4_replay.py       # Replay Attack 1 packet
```

Each script auto-captures a `.pcap` in `attacks/results/`.

---

## Port Architecture

```
Gazebo  ←── UDP 9002 (JSON FDM) ──→  ArduPilot SITL
                                            │
                                       TCP 5760 (MAVLink)
                                            │
                                       MAVProxy
                                            │
                               ┌─────── UDP 14550 ──────────┐
                               │                             │
                          Wireshark                   Attack scripts
                       (attack4_replay.lua)      (attack1 / attack4)
                                            │
                               ┌─────── UDP 25100 ──────────┐
                               │                             │
                          Wireshark                   Attack scripts
                        (gps_spoof.lua)         (attack2 / attack3 / 3B)
                                     GPSInput module
```

---

## Detection Framework (Phase 2 — In Progress)

Six features extracted per packet:

| Feature | Normal Range | Attack Signal |
|---------|-------------|---------------|
| `ts_gap` | ±2 s | Attack 1: +8 h · Attack 3: +78 yr |
| `gps_sys_delta` | ±0.5 s | Attack 2: +10 d · Attack 3: +78 yr |
| `drift_m_per_s` | < 0.5 m/s | Attack 2: ~6 m/s |
| `iat_ms` | ~200 ms | Attack 3B: burst 10 packets/2 s |
| `seq_jump` | 0–1 | Replay: duplicate sequence |
| `is_duplicate` | 0 | Attack 4: 1 (same SHA-256 hash) |

Detection layers:
1. **Statistical rules** — 6 threshold rules, instant, zero training required
2. **Isolation Forest** — trained on normal traffic, scores novel anomalies

---

## Environment

| Component | Version |
|-----------|---------|
| ArduPilot SITL | v4.8.0-dev |
| Gazebo | Harmonic |
| MAVProxy | 1.8.74 |
| Wireshark | 3.6.2 + Lua 5.1 |
| Python | 3.10.12 |
| pymavlink | 2.4.49 |
| scikit-learn | 1.x (Phase 2) |

---

## Reports

| File | Contents |
|------|----------|
| `reports/daily_report_june4.docx` | Detection framework design — today |
| `reports/daily_report_june2.docx` | Attack alignment, position spoofing, Wireshark dissectors |
| `reports/daily_report_june1.docx` | Attack 3B, replay demo |
| `reports/full_attack_report_v2.docx` | Complete technical report — all 5 attacks |
