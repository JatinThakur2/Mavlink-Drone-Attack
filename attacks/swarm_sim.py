#!/usr/bin/env python3
"""
=============================================================================
SWARM DESYNCHRONIZATION SIMULATOR  —  Systemic Risk in UAV Swarms (Task 3)
=============================================================================
The paper notes the timestamp vulnerability is PROTOCOL-LEVEL and therefore
affects ALL MAVLink systems (pp. 9-10). This simulator elevates that from a
single-drone problem to a SYSTEMIC one: it shows how a timestamp attack on
ONE node cascades into swarm-wide desynchronization and formation collapse.

MODEL (intentionally simple, no SITL required)
    * N UAVs fly in formation and share a common time base.
    * They time-sync to a leader (node 0) every tick, MAVLink-style: each
      follower nudges its clock toward the newest timestamp it has heard.
    * A collaborative-swarm assumption -> a follower trusts a peer/leader
      timestamp that is NEWER than its own (exactly the property the
      signed-timestamp attack abuses).

ATTACK
    At t = INJECT_T we poison ONE node with a far-future signed timestamp.
    Because followers accept the newest timestamp, the poison propagates:
    neighbours adopt the bad clock, their control loops (which schedule
    waypoints by time) skew, and the formation desynchronizes and collapses.

DEFENSE COMPARISON
    Run with --defense to put every node behind the L1 tight-window check
    (reject any timestamp more than TIGHT_WINDOW seconds off local wall time).
    The poison is rejected at the first hop and the swarm stays synced.

Usage:
    python3 swarm_sim.py --uavs 5
    python3 swarm_sim.py --uavs 5 --defense        # with L1 tight-window on
    python3 swarm_sim.py --uavs 8 --inject 2.0 --poison 1e9
=============================================================================
"""
import argparse, random

TICK          = 0.2      # seconds per simulation step
DURATION      = 8.0      # total simulated seconds
INJECT_T      = 2.0      # when the attack fires
SYNC_GAIN     = 0.5      # how strongly a follower pulls toward heard timestamp
DESYNC_LIMIT  = 1.0      # clock skew (s) beyond which a node loses formation
TIGHT_WINDOW  = 2.0      # defense L1: max |heard_ts - local_wall| accepted


class UAV:
    def __init__(self, uid, leader=False):
        self.uid    = uid
        self.leader = leader
        self.clock_offset = 0.0     # this node's clock error vs true time
        self.lost   = False         # dropped out of formation?
        self.poisoned = False

    def local_time(self, wall):
        return wall + self.clock_offset


def simulate(n_uavs, inject_t, poison_offset, defense):
    uavs = [UAV(i, leader=(i == 0)) for i in range(n_uavs)]
    log = []
    events = []
    injected = False
    collapse_t = None

    steps = int(DURATION / TICK)
    for s in range(steps + 1):
        wall = s * TICK

        # ── attack injection: poison one interior node ──────────────────────
        if not injected and wall >= inject_t:
            victim = uavs[min(2, n_uavs - 1)]   # a follower, not the leader
            injected = True
            if defense and abs(poison_offset) > TIGHT_WINDOW:
                # the victim itself runs the L1 tight-window check and rejects
                # the poisoned signed timestamp before it ever adopts it
                events.append((wall, f"UAV-{victim.uid} received poison "
                                     f"(+{poison_offset:g}s) -> REJECTED by L1"))
            else:
                victim.clock_offset = poison_offset
                victim.poisoned = True
                events.append((wall, f"UAV-{victim.uid} timestamp-poisoned "
                                     f"(+{poison_offset:g}s signed ts)"))

        # ── one round of MAVLink-style time-sync gossip ─────────────────────
        # each follower hears the NEWEST timestamp among its neighbours and
        # nudges its own clock toward it (collaborative-swarm assumption).
        heard = [u.local_time(wall) for u in uavs]
        newest = max(heard)
        for u in uavs:
            if u.leader or u.lost:
                continue
            candidate = newest
            # ── DEFENSE: L1 tight window rejects implausible timestamps ─────
            if defense and abs(candidate - wall) > TIGHT_WINDOW:
                continue   # reject poison, keep current clock
            skew_before = u.clock_offset
            u.clock_offset += SYNC_GAIN * (candidate - u.local_time(wall))
            # a node whose clock skews past the limit loses formation
            if not u.lost and abs(u.clock_offset) > DESYNC_LIMIT:
                u.lost = True
                events.append((wall, f"UAV-{u.uid} DESYNC -> lost formation "
                                     f"(skew {u.clock_offset:+.2f}s)"))

        lost = sum(1 for u in uavs if u.lost)
        max_skew = max(abs(u.clock_offset) for u in uavs)
        log.append((wall, lost, max_skew))

        if collapse_t is None and lost >= (n_uavs - 1) / 2:
            collapse_t = wall
            events.append((wall, f"FORMATION COLLAPSE ({lost}/{n_uavs} nodes lost)"))

    return uavs, log, events, collapse_t


def render(n_uavs, defense, uavs, log, events, collapse_t):
    mode = "WITH DEFENSE (L1 tight-window)" if defense else "NO DEFENSE"
    print("=" * 62)
    print(f"  UAV SWARM TIMESTAMP-CASCADE SIMULATION   [{mode}]")
    print(f"  Swarm size: {n_uavs}   Leader: UAV-0   Tick: {TICK}s")
    print("=" * 62)

    print("\n  TIMELINE")
    print("  " + "-" * 58)
    for t, msg in events:
        print(f"  t={t:4.1f}s   {msg}")
    if not events:
        print("  (no attack events)")

    print("\n  CLOCK-SKEW / LOST-NODE TRACE")
    print("  " + "-" * 58)
    print(f"  {'t(s)':>5} | {'lost':>4} | {'max skew(s)':>11} | formation")
    print("  " + "-" * 58)
    for t, lost, skew in log:
        if abs(t / TICK - round(t / TICK)) < 1e-9 and round(t / TICK) % 2 == 0:
            bar = "#" * lost + "." * (n_uavs - lost)
            print(f"  {t:5.1f} | {lost:4d} | {skew:11.2f} | [{bar}]")

    print("\n  RESULT")
    print("  " + "-" * 58)
    lost = sum(1 for u in uavs if u.lost)
    if collapse_t is not None:
        print(f"  SWARM COMPROMISED: formation collapsed at t={collapse_t:.1f}s")
        print(f"  {lost}/{n_uavs} UAVs desynchronized from a SINGLE poisoned node.")
        print("  -> One protocol-level timestamp attack = systemic swarm failure.")
    else:
        print(f"  SWARM HELD: {lost}/{n_uavs} UAVs lost — no cascade.")
        if defense:
            print("  L1 tight-window rejected the poisoned timestamp at hop 1.")
            print("  -> The defense contains the attack to zero nodes.")
    print("=" * 62)


def main():
    ap = argparse.ArgumentParser(description="UAV swarm timestamp-cascade simulator")
    ap.add_argument('--uavs',    type=int,   default=5,     help='number of UAVs')
    ap.add_argument('--inject',  type=float, default=INJECT_T, help='attack time (s)')
    ap.add_argument('--poison',  type=float, default=1e6,   help='poison clock offset (s)')
    ap.add_argument('--defense', action='store_true',       help='enable L1 tight-window defense')
    args = ap.parse_args()

    random.seed(1)
    uavs, log, events, collapse_t = simulate(
        args.uavs, args.inject, args.poison, args.defense)
    render(args.uavs, args.defense, uavs, log, events, collapse_t)


if __name__ == '__main__':
    main()
