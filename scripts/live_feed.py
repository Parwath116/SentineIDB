"""Stream new events into SentinelDB every second, with occasional injected attacks.

Usage:  python scripts/live_feed.py [--rate 25] [--attack-every 45]
Writes events, raw_logs, connections and upserts ip_state (the change-stream source).
"""
from __future__ import annotations

import argparse
import logging
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.db import get_db  # noqa: E402
from backend.ipstate import IpStateAccumulator  # noqa: E402
from backend.simulator import (NormalTraffic, attack_brute_force, attack_exfil, attack_lateral,  # noqa: E402
                               attack_password_spray, attack_port_scan, raw_message)
from backend.simulator import build_network  # noqa: E402

log = logging.getLogger("live_feed")


def compress(events: list[dict], start: datetime, seconds: float) -> None:
    """Squeeze event timestamps into `seconds` after `start` so a live attack unfolds in a few ticks."""
    span = max((e["ts"] - start).total_seconds() for e in events) or 1.0
    f = seconds / span
    for e in events:
        ms = int((e["ts"] - start).total_seconds() * f * 1000)
        e["ts"] = start + timedelta(milliseconds=ms)
    events.sort(key=lambda e: e["ts"])


def load_network_from_db(db, rng: random.Random):
    """Rebuild the in-memory Network view from the stored hosts/users so live data matches history."""
    net = build_network(rng)  # provides external IP pool and structure; replace hosts/users from DB below
    hosts = list(db["hosts"].aggregate([{"$project": {"_id": 0}}]))
    users = list(db["users"].aggregate([{"$match": {"role": "employee"}}, {"$project": {"_id": 0}}]))
    if hosts:
        net.hosts = hosts
        net.by_subnet = {}
        for h in hosts:
            net.by_subnet.setdefault(h["subnet"], []).append(h)
        net.by_ip = {h["ip"]: h for h in hosts}
        for u in users:
            u["remote"] = u["username"] not in {h.get("owner") for h in hosts}
        net.users = users
        net.ws_of_user = {h["owner"]: h for h in hosts if h.get("owner")}
    return net


def spawn_attack(rng, net, db, now: datetime) -> tuple[list[dict], list[dict], list[dict], dict]:
    """Create one random attack; returns (events, connections, extra raw logs, scenario)."""
    ip = f"{rng.choice([45, 91, 103, 185, 194])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    kind = rng.choice(["brute_force", "password_spraying", "port_scan", "lateral_movement", "exfiltration"])
    conns: list[dict] = []
    extras: list[dict] = []
    if kind == "brute_force":
        evs, sc = attack_brute_force(rng, net, now, ip, failures=rng.randint(120, 200), spread_ms=300_000)
        compress(evs, now, 6)
    elif kind == "password_spraying":
        evs, sc = attack_password_spray(rng, net, now, ip, users_n=rng.randint(18, 25), attempts=2)
        compress(evs, now, 8)
    elif kind == "port_scan":
        evs, sc = attack_port_scan(rng, net, now, ip, ports=rng.randint(130, 250), spread_ms=20_000)
        compress(evs, now, 5)
    elif kind == "lateral_movement":
        evs, conns, extras, sc = attack_lateral(rng, net, now)
        compress(evs, now, 4)
        for c, e in zip(conns, evs):
            c["ts"] = e["ts"]
    else:
        evs, extras, sc = attack_exfil(rng, net, now, ip, chunks=9)
        compress(evs, now, 8)
    for x in extras:
        x["ts"] = now
    if rng.random() < 0.5 and kind not in ("lateral_movement",):
        db["threat_intel"].update_one(
            {"ip": ip}, {"$setOnInsert": {"category": "scanner", "confidence": 80, "source": "Internal blocklist",
                                          "firstSeen": now}}, upsert=True)
    sc["live"] = True
    return evs, conns, extras, sc


def main() -> None:
    """Entry point."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rate", type=int, default=25, help="normal events per second")
    ap.add_argument("--attack-every", type=float, default=45.0, help="average seconds between attacks")
    args = ap.parse_args()
    rng = random.Random()
    db = get_db()
    net = load_network_from_db(db, rng)
    traffic = NormalTraffic(net, rng)
    pending: list[dict] = []  # attack events waiting for their timestamp
    log.info("live feed started: %d ev/s, attack every ~%.0fs. Ctrl+C to stop.", args.rate, args.attack_every)
    try:
        while True:
            tick_start = time.perf_counter()
            now = datetime.now(timezone.utc).replace(microsecond=0)
            events: list[dict] = []
            conns: list[dict] = []
            raws: list[dict] = []
            for _ in range(max(1, int(rng.gauss(args.rate, args.rate * 0.2)))):
                ts = now + timedelta(milliseconds=rng.randrange(1000))
                ev, conn = traffic.event(ts)
                events.append(ev)
                if conn:
                    conns.append(conn)
            if rng.random() < 1.0 / args.attack_every:
                evs, c, x, sc = spawn_attack(rng, net, db, now)
                pending += evs
                conns += c
                raws += x
                db["scenarios"].insert_one(sc)
                log.warning("injected %s from %s (%d events)", sc["type"], sc["srcIp"], len(evs))
            horizon = now + timedelta(seconds=1)
            due = [e for e in pending if e["ts"] < horizon]
            pending = [e for e in pending if e["ts"] >= horizon]
            events += due
            acc = IpStateAccumulator()
            for ev in events:
                acc.add(ev)
                raws.append({"ts": ev["ts"], "host": ev["host"], "source": ev["meta"]["source"], "srcIp": ev["srcIp"],
                             "eventType": ev["eventType"], "message": raw_message(rng, ev)})
            events.sort(key=lambda e: e["ts"])
            db["events"].insert_many(events, ordered=False)
            db["raw_logs"].insert_many(raws, ordered=False)
            if conns:
                db["connections"].insert_many(conns, ordered=False)
            acc.flush(db)
            time.sleep(max(0.0, 1.0 - (time.perf_counter() - tick_start)))
    except KeyboardInterrupt:
        log.info("live feed stopped")


if __name__ == "__main__":
    main()
