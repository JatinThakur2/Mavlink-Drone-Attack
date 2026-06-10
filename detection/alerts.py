#!/usr/bin/env python3
"""
=============================================================
alerts.py  —  Alert formatting, colour output, log writer
=============================================================
"""

import os
import time
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# ANSI colours
# ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GREY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# ─────────────────────────────────────────────────────────────
# Alert levels
# ─────────────────────────────────────────────────────────────
LEVEL_ALERT = "ALERT"
LEVEL_INFO  = "INFO"
LEVEL_NORM  = "NORM"

LEVEL_COLOUR = {
    LEVEL_ALERT : RED + BOLD,
    LEVEL_INFO  : CYAN,
    LEVEL_NORM  : GREY,
}

# ─────────────────────────────────────────────────────────────
# Log file — new file per session (timestamped)
# ─────────────────────────────────────────────────────────────
_RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
_SESSION_TS  = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
LOG_FILE     = os.path.join(_RESULTS_DIR, f"alerts_{_SESSION_TS}.log")

# Keep a symlink "alerts.log" always pointing at the latest session file
# so external tools that expect alerts.log still work.
_LOG_LATEST  = os.path.join(_RESULTS_DIR, "alerts.log")

def _init_log():
    os.makedirs(_RESULTS_DIR, exist_ok=True)
    # Create the session file
    open(LOG_FILE, "w").close()
    # Update symlink to latest session
    if os.path.islink(_LOG_LATEST) or os.path.exists(_LOG_LATEST):
        os.remove(_LOG_LATEST)
    os.symlink(LOG_FILE, _LOG_LATEST)

_init_log()

# ─────────────────────────────────────────────────────────────
# Alert throttling — suppress repeated alerts of the same type.
# Within THROTTLE_SEC seconds, only the first fires fully;
# the rest are counted. When a new event arrives after the
# window expires, a summary "[suppressed N repeats]" is logged
# first, then the new alert is logged normally.
# ─────────────────────────────────────────────────────────────
THROTTLE_SEC = 5.0   # seconds per tag before flushing suppressed count

_throttle: dict = {}   # tag → {"first_ts": float, "count": int, "last_detail": str}


def _throttle_check(tag: str, detail: str) -> bool:
    """
    Returns True if the alert should be emitted now.
    Manages the throttle state for `tag`.
    """
    now = time.time()

    if tag not in _throttle:
        _throttle[tag] = {"first_ts": now, "count": 1, "last_detail": detail}
        return True   # first occurrence — emit

    state = _throttle[tag]
    elapsed = now - state["first_ts"]

    if elapsed >= THROTTLE_SEC:
        # Window expired — flush suppressed count if any, then reset
        suppressed = state["count"] - 1
        if suppressed > 0:
            ts    = _timestamp()
            plain = (f"[{ts} UTC] [ALERT] {tag:<20} "
                     f"[... {suppressed} more in {elapsed:.1f}s — suppressed to reduce noise]")
            colour = LEVEL_COLOUR.get(LEVEL_ALERT, RESET)
            term   = (f"{GREY}[{ts} UTC]{RESET} "
                      f"{colour}[ALERT]{RESET} "
                      f"{colour}{tag:<20}{RESET} "
                      f"{GREY}[... {suppressed} more in {elapsed:.1f}s — suppressed]{RESET}")
            print(term)
            _write_log(plain)

        _throttle[tag] = {"first_ts": now, "count": 1, "last_detail": detail}
        return True   # start of new window — emit

    # Still within window — suppress but count
    state["count"] += 1
    return False


def _flush_all_throttled():
    """Flush any remaining suppressed counts (call at shutdown)."""
    now = time.time()
    for tag, state in _throttle.items():
        suppressed = state["count"] - 1
        if suppressed > 0:
            elapsed = now - state["first_ts"]
            ts    = _timestamp()
            plain = (f"[{ts} UTC] [ALERT] {tag:<20} "
                     f"[... {suppressed} more in {elapsed:.1f}s — suppressed]")
            _write_log(plain)
            print(f"{GREY}{plain}{RESET}")


# ─────────────────────────────────────────────────────────────
# Core helpers
# ─────────────────────────────────────────────────────────────
def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _write_log(line: str):
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def emit(level: str, tag: str, detail: str):
    """
    Print a formatted alert line and append to the session log.

    level  : ALERT | INFO | NORM
    tag    : short attack/event label  e.g. ATK2_GPS_SPOOF
    detail : human-readable detail string
    """
    # Only apply throttling to ALERT-level messages
    if level == LEVEL_ALERT:
        if not _throttle_check(tag, detail):
            return

    ts     = _timestamp()
    colour = LEVEL_COLOUR.get(level, RESET)
    tag_w  = f"{tag:<20}"

    # Terminal line
    line = (
        f"{GREY}[{ts} UTC]{RESET} "
        f"{colour}[{level:<5}]{RESET} "
        f"{colour}{tag_w}{RESET} "
        f"{WHITE}{detail}{RESET}"
    )
    print(line)

    # Log file (no ANSI)
    plain = f"[{ts} UTC] [{level:<5}] {tag_w} {detail}"
    _write_log(plain)


def alert(tag: str, detail: str):
    emit(LEVEL_ALERT, tag, detail)


def info(tag: str, detail: str):
    emit(LEVEL_INFO, tag, detail)


def norm(tag: str, detail: str):
    emit(LEVEL_NORM, tag, detail)


def banner(text: str):
    line = f"{BOLD}{CYAN}{'─'*60}{RESET}"
    print(line)
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(line)


def session_summary(total_pkts: int, alert_count: int):
    """Print and log end-of-session summary."""
    _flush_all_throttled()
    ts    = _timestamp()
    plain = (f"[{ts} UTC] [INFO ] {'SESSION':<20} "
             f"total_pkts={total_pkts} alerts={alert_count} | log={LOG_FILE}")
    _write_log(plain)
    colour = LEVEL_COLOUR[LEVEL_INFO]
    print(f"{GREY}[{ts} UTC]{RESET} {colour}[INFO ]{RESET} "
          f"{colour}{'SESSION':<20}{RESET} "
          f"{WHITE}total_pkts={total_pkts} alerts={alert_count}{RESET}")
    print(f"{GREY}  Log → {LOG_FILE}{RESET}")
