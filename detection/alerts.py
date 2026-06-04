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
    LEVEL_ALERT : RED    + BOLD,
    LEVEL_INFO  : CYAN,
    LEVEL_NORM  : GREY,
}

# ─────────────────────────────────────────────────────────────
# Log file
# ─────────────────────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(__file__), "results", "alerts.log")


def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _write_log(line: str):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def emit(level: str, tag: str, detail: str):
    """
    Print a formatted alert line and append to alerts.log.

    level  : ALERT | INFO | NORM
    tag    : short attack/event label  e.g. ATK2_GPS_SPOOF
    detail : human-readable detail string
    """
    ts    = _timestamp()
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
