#!/usr/bin/env python3
"""
sitl_basic.py  —  ArduCopter SITL + Gazebo + MAVProxy

3 windows open automatically:
  Window 1 — Gazebo       3D world with iris drone model
  Window 2 — ArduCopter  flight controller (talks to Gazebo via JSON/UDP 9002)
  Window 3 — MAVProxy    your command console

Data flow:
  Gazebo <--UDP 9002--> arducopter <--TCP 5760--> MAVProxy

Usage:
  python3 sitl_basic.py            launch all 3 windows
  python3 sitl_basic.py --kill     stop everything
  python3 sitl_basic.py --no-gz    skip Gazebo (plain X-frame, no 3D)
"""

import os
import shutil
import subprocess
import sys

# ── Paths ──────────────────────────────────────────────────────────────────────
ARDUPILOT    = os.path.expanduser("~/ardupilot")
AP_GZ_DIR    = os.path.expanduser("~/ardupilot_gazebo")
ARDUCOPTER   = os.path.join(ARDUPILOT, "build", "sitl", "bin", "arducopter")
WORKDIR      = os.path.join(ARDUPILOT, "ArduCopter")
MAVPROXY     = shutil.which("mavproxy.py") or os.path.expanduser("~/.local/bin/mavproxy.py")

WORLD_FILE   = os.path.join(AP_GZ_DIR, "worlds", "iris_ardupilot_runway.sdf")
PLUGIN_DIR   = os.path.join(AP_GZ_DIR, "build")
MODELS_DIR   = os.path.join(AP_GZ_DIR, "models")
WORLDS_DIR   = os.path.join(AP_GZ_DIR, "worlds")

SITL_TCP     = 5760
GCS_UDP      = 14550

# Gazebo env vars so it can find the ArduPilot plugin and drone models
GZ_ENV = (
    f"export GZ_SIM_SYSTEM_PLUGIN_PATH={PLUGIN_DIR}:$GZ_SIM_SYSTEM_PLUGIN_PATH && "
    f"export GZ_SIM_RESOURCE_PATH={MODELS_DIR}:{WORLDS_DIR}:$GZ_SIM_RESOURCE_PATH"
)


def open_terminal(title: str, command: str) -> None:
    subprocess.Popen([
        "gnome-terminal", f"--title={title}",
        "--", "bash", "-c", f"{command}; exec bash",
    ])


def kill_all() -> None:
    for proc in ["gz sim", "arducopter", "mavproxy.py", "ruby"]:
        subprocess.run(["pkill", "-f", proc], capture_output=True)
    print("All stopped.")


def mavproxy_loop(sitl_tcp: int, gcs_udp: int) -> str:
    """Shell snippet: wait for port, then loop MAVProxy so it survives SITL reboots."""
    mav_cmd = (
        f"{MAVPROXY} "
        f"--master=tcp:127.0.0.1:{sitl_tcp} "
        f"--out=udp:127.0.0.1:{gcs_udp} "
        f"--retries=10"
    )
    return (
        f"echo 'Waiting for SITL on TCP {sitl_tcp}...' && "
        f"until python3 -c \""
        f"import socket; socket.create_connection(('127.0.0.1',{sitl_tcp}),1)"
        f"\" 2>/dev/null; do sleep 1; done && "
        f"echo 'SITL ready — connecting MAVProxy...' && echo '' && "
        f"while true; do "
        f"  {mav_cmd}; "
        f"  echo ''; echo 'Link lost — reconnecting in 3s...'; sleep 3; "
        f"  until python3 -c \""
        f"import socket; socket.create_connection(('127.0.0.1',{sitl_tcp}),1)"
        f"\" 2>/dev/null; do sleep 1; done; "
        f"done"
    )


def launch_with_gazebo() -> None:
    # Startup order matters because Gazebo uses lock_step=1:
    #   Gazebo freezes and waits for SITL control data before advancing time.
    #   If both start together, SITL is mid-reboot when Gazebo tries to lock-step → deadlock.
    #
    # Correct order:
    #   1. SITL starts first  → completes its param-load reboot (~10s)
    #   2. Gazebo starts      → plugin finds SITL already in phase 2, lock-step works
    #   3. MAVProxy connects  → SITL now fully initialised

    # ── Window 1: ArduCopter SITL ─────────────────────────────────────────────
    params = (
        f"{ARDUPILOT}/Tools/autotest/default_params/copter.parm,"
        f"{ARDUPILOT}/Tools/autotest/default_params/gazebo-iris.parm"
    )
    sitl_cmd = (
        f"cd {WORKDIR} && "
        # Wipe stale eeprom.bin and mav.parm — these cache old frame settings
        # and override --defaults, causing 'Frame: UNSUPPORTED' on relaunch
        f"rm -f eeprom.bin mav.parm && "
        f"echo '' && "
        f"echo '  ArduCopter SITL — gazebo-iris / JSON model' && "
        f"echo '  TCP 5760 | JSON → UDP 9002 → Gazebo' && "
        f"echo '' && "
        f"{ARDUCOPTER} --model JSON --speedup 1 --slave 0 --sim-address=127.0.0.1 -I0 "
        f"--defaults {params}"
    )
    print("[1/3] Opening SITL window...")
    open_terminal("ArduCopter SITL", sitl_cmd)

    # ── Window 2: Gazebo ──────────────────────────────────────────────────────
    # Wait 12s so SITL finishes its phase-1 reboot before Gazebo lock-steps with it
    gz_cmd = (
        f"{GZ_ENV} && "
        f"echo '' && "
        f"echo '  Gazebo Harmonic — iris_ardupilot_runway' && "
        f"echo '  Waiting 12s for SITL to finish boot cycle...' && "
        f"sleep 12 && "
        f"echo '  Starting Gazebo...' && "
        f"echo '' && "
        f"gz sim -v4 -r {WORLD_FILE}"
    )
    print("[2/3] Opening Gazebo window (starts in 12s after SITL)...")
    open_terminal("Gazebo — Iris World", gz_cmd)

    # ── Window 3: MAVProxy ────────────────────────────────────────────────────
    print("[3/3] Opening MAVProxy window (auto-connects once SITL is ready)...")
    open_terminal("MAVProxy Console", mavproxy_loop(SITL_TCP, GCS_UDP))

    # ── Window 4: Wireshark ───────────────────────────────────────────────────
    # Captures MAVLink traffic on UDP 14550 (MAVProxy output port).
    # The MAVLink Lua dissector (~/.config/wireshark/plugins/mavlink.lua)
    # decodes every packet into human-readable MAVLink messages.
    ws_cmd = (
        f"echo '' && "
        f"echo '  Wireshark — capturing MAVLink on UDP {GCS_UDP}' && "
        f"echo '  Plugin: ~/.config/wireshark/plugins/mavlink.lua' && "
        f"echo '' && "
        f"sleep 5 && "
        f"sg wireshark -c \"wireshark -i lo -k -f 'udp port {GCS_UDP}'\""
    )
    print("[4/4] Opening Wireshark window...")
    open_terminal("Wireshark — MAVLink", ws_cmd)


def launch_without_gazebo() -> None:
    # ── Window 1: ArduCopter SITL (plain X frame) ─────────────────────────────
    sitl_cmd = (
        f"cd {WORKDIR} && "
        f"rm -f eeprom.bin mav.parm && "
        f"echo '' && "
        f"echo '  ArduCopter SITL — X frame (no Gazebo)' && "
        f"echo '  TCP 5760  |  waiting for MAVProxy...' && "
        f"echo '' && "
        f"{ARDUCOPTER} --model X --speedup 1 --slave 0 --sim-address=127.0.0.1 -I0"
    )
    print("[1/2] Opening SITL window...")
    open_terminal("ArduCopter SITL", sitl_cmd)

    # ── Window 2: MAVProxy ────────────────────────────────────────────────────
    print("[2/2] Opening MAVProxy window...")
    open_terminal("MAVProxy Console", mavproxy_loop(SITL_TCP, GCS_UDP))


def main() -> None:
    if "--kill" in sys.argv:
        kill_all()
        return

    # Checks
    if not os.path.isfile(ARDUCOPTER):
        sys.exit(f"arducopter binary not found:\n  {ARDUCOPTER}\n"
                 f"Build:  cd {ARDUPILOT} && ./waf copter")
    if not os.path.isfile(MAVPROXY):
        sys.exit("mavproxy.py not found — run:  pip install MAVProxy")

    no_gazebo = "--no-gz" in sys.argv

    if not no_gazebo:
        if not shutil.which("gz"):
            sys.exit("gz not found — install Gazebo Harmonic")
        if not os.path.isfile(WORLD_FILE):
            sys.exit(f"World file not found:\n  {WORLD_FILE}")
        if not os.path.isdir(PLUGIN_DIR):
            sys.exit(f"Plugin not built:\n  {PLUGIN_DIR}\n"
                     f"Build:  cd {AP_GZ_DIR} && mkdir build && cd build && cmake .. && make -j4")
        launch_with_gazebo()
        print()
        print("  Window 1: SITL      — flight controller")
        print("  Window 2: Gazebo    — 3D world (starts in 12s)")
        print("  Window 3: MAVProxy  — type commands here")
        print("  Window 4: Wireshark — live MAVLink packets (starts in 5s)")
        print()
        print("  Wait until Window 3 shows:")
        print("    Mode: STABILIZE")
        print("    Heartbeat from APM")
        print("    MAV>")
    else:
        launch_without_gazebo()
        print()
        print("  Window 1: SITL     — flight controller")
        print("  Window 2: MAVProxy — type commands here")
        print()

    print("  Then fly:")
    print("    mode GUIDED")
    print("    arm throttle")
    print("    takeoff 10")
    print()
    print("  Stop:  python3 sitl_basic.py --kill")


if __name__ == "__main__":
    main()
