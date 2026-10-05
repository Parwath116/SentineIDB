"""Generate a synthetic history for Northwind Logistics and load it into SentinelDB.

Usage:  python scripts/generate_data.py --count 500000 --days 7 [--seed 42]
Destructive for event data: events/raw_logs/ip_state/connections/scenarios/alerts/incidents are rebuilt.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

import init_db  # noqa: E402  (scripts/init_db.py)
from backend.auth import seed_accounts  # noqa: E402
from backend.db import get_db  # noqa: E402
from backend.ipstate import IpStateAccumulator  # noqa: E402
from backend.simulator import (NormalTraffic, attack_brute_force, attack_low_and_slow_brute_force, attack_exfil, attack_lateral,  # noqa: E402
                               attack_password_spray, attack_port_scan, build_network, make_event,
                               raw_message)

log = logging.getLogger("generate_data")
BATCH = 10_000


def fresh_ip(rng: random.Random, taken: set[str]) -> str:
    """Return a public-looking IP that is not already in use."""
    while True:
        ip = f"{rng.choice([45, 91, 103, 141, 185, 194])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        if ip not in taken:
            taken.add(ip)
            return ip


class Loader:
    """Buffers documents and writes them with unordered insert_many batches."""

    def __init__(self, db) -> None:
        self.db = db
        self.buf: dict[str, list[dict]] = {"events": [], "raw_logs": [], "connections": []}
        self.counts = {k: 0 for k in self.buf}

    def add(self, coll: str, doc: dict) -> None:
        buf = self.buf[coll]
        buf.append(doc)
        if len(buf) >= BATCH:
            self.flush(coll)

    def flush(self, coll: str | None = None) -> None:
        for name in ([coll] if coll else list(self.buf)):
            if self.buf[name]:
                self.db[name].insert_many(self.buf[name], ordered=False)
                self.counts[name] += len(self.buf[name])
                self.buf[name] = []


def plan_scenarios(rng, net, start, end, taken):
    """Build all attack scenarios + benign decoys; returns (events, connections, extra_raw, scenario_docs)."""
    events, conns, extras, scenarios = [], [], [], []
    bad = list(net.bad_ips)
    rng.shuffle(bad)
    attackers = {"brute_force": [bad.pop(), bad.pop(), fresh_ip(rng, taken)],
                 "low_and_slow": [fresh_ip(rng, taken)],
                 "password_spraying": [bad.pop(), fresh_ip(rng, taken)],
                 "port_scan": [bad.pop(), bad.pop(), fresh_ip(rng, taken)],
                 "exfil_dest": [bad.pop(), fresh_ip(rng, taken)]}
    span = (end - start).total_seconds() - 6 * 3600
    slots = sorted(start + timedelta(hours=1, seconds=rng.uniform(0, span)) for _ in range(13))
    rng.shuffle(slots)
    slot = iter(slots)
    ms = lambda dt: dt.replace(microsecond=(dt.microsecond // 1000) * 1000)  # noqa: E731

    for ip in attackers["brute_force"]:
        e, sc = attack_brute_force(rng, net, ms(next(slot)), ip, failures=rng.randint(300, 900))
        events += e; scenarios.append(sc)
    for ip in attackers["low_and_slow"]:
        e, sc = attack_low_and_slow_brute_force(rng, net, ms(next(slot)), ip, duration_hours=4, fails_per_5m=8)
        events += e; scenarios.append(sc)
    for ip in attackers["password_spraying"]:
        e, sc = attack_password_spray(rng, net, ms(next(slot)), ip, users_n=rng.randint(30, 60))
        events += e; scenarios.append(sc)
    for ip in attackers["port_scan"]:
        e, sc = attack_port_scan(rng, net, ms(next(slot)), ip, ports=rng.randint(300, 900))
        events += e; scenarios.append(sc)

    # Kill chain: lateral movement ends at a db server which then exfiltrates (pair 1); pair 2 is independent.
    t_lat = ms(next(slot))
    e, c, x, sc = attack_lateral(rng, net, t_lat)
    events += e; conns += c; extras += x; scenarios.append(sc)
    db1 = next(h for h in net.hosts if h["hostname"] == sc["chain"][-1])
    e, x, sc = attack_exfil(rng, net, ms(t_lat + timedelta(minutes=20)), attackers["exfil_dest"][0], db1)
    events += e; extras += x; scenarios.append(sc)
    e, c, x, sc = attack_lateral(rng, net, ms(next(slot)))
    events += e; conns += c; extras += x; scenarios.append(sc)
    e, x, sc = attack_exfil(rng, net, ms(next(slot)), attackers["exfil_dest"][1])
    events += e; extras += x; scenarios.append(sc)

    # ---- benign decoys: behaviours that look noisy but must NOT be flagged
    u = rng.choice([x for x in net.users if x["username"] in net.ws_of_user])
    ws = net.ws_of_user[u["username"]]
    t0 = ms(start + timedelta(hours=30))
    host = rng.choice(net.by_subnet["app"])
    for i in range(12):
        events.append(make_event(t0 + timedelta(seconds=15 * i), "auth_fail", ws["ip"], host, host["ip"], 443,
                                 u["username"], None, None, "low"))
    events.append(make_event(t0 + timedelta(seconds=200), "auth_success", ws["ip"], host, host["ip"], 443,
                             u["username"], None, None, "info"))
    scenarios.append({"type": "benign_mistyped_password", "malicious": False, "detectKey": ws["ip"], "srcIp": ws["ip"],
                      "startTs": t0})

    it_ws = rng.choice(net.by_subnet["workstation"])
    srv = rng.choice(net.by_subnet["app"])
    for d in range(3):
        t = ms(start + timedelta(hours=10 + 24 * d))
        events.append(make_event(t, "auth_success", it_ws["ip"], srv, srv["ip"], 22, it_ws.get("owner") or "svc-it",
                                 None, None, "info"))
        conns.append({"srcHost": it_ws["hostname"], "dstHost": srv["hostname"], "ts": t, "protocol": "ssh"})
    scenarios.append({"type": "benign_admin_session", "malicious": False, "detectKey": it_ws["hostname"],
                      "srcIp": it_ws["ip"], "startTs": ms(start + timedelta(hours=10))})

    db = rng.choice(net.by_subnet["db"])
    bk = net.by_subnet["app"][-1]
    for d in range(int((end - start).days)):
        t = ms(start + timedelta(hours=2 + 24 * d))
        for i in range(6):
            events.append(make_event(t + timedelta(minutes=2 * i), "fw_allow", db["ip"], db, bk["ip"], 5432, None,
                                     rng.randint(300_000_000, 450_000_000), None, "info"))
    scenarios.append({"type": "benign_backup", "malicious": False, "detectKey": db["ip"], "srcIp": db["ip"],
                      "startTs": ms(start + timedelta(hours=2))})
    events.sort(key=lambda ev: ev["ts"])
    return events, conns, extras, scenarios


def main() -> None:
    """Entry point."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--count", type=int, default=500_000, help="approximate total number of events")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    db = get_db()

    # ---- reset data collections
    db.drop_collection("events")
    for name in ["raw_logs", "ip_state", "connections", "scenarios", "alerts", "incidents", "hosts", "threat_intel",
                 "hourly_summary", "daily_summary"]:
        db[name].delete_many({})
    db["users"].delete_many({"role": "employee"})
    init_db.ensure_timeseries(db)
    init_db.create_indexes(db)

    net = build_network(rng)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start, end = now - timedelta(days=args.days), now
    taken = set(net.external_ips) | set(net.bad_ips)

    db["hosts"].insert_many(net.hosts, ordered=False)
    db["users"].insert_many([{k: v for k, v in u.items() if k != "remote"} for u in net.users], ordered=False)
    intel_cats = ["botnet C2", "ssh brute-force source", "scanner", "credential stuffing", "data-theft infrastructure"]
    scen_events, scen_conns, scen_extras, scenarios = plan_scenarios(rng, net, start, end, taken)
    malicious_ips = {s["srcIp"] for s in scenarios if s["malicious"]} | {s["destination"] for s in scenarios if "destination" in s}
    intel_ips = [ip for ip in net.bad_ips]
    db["threat_intel"].insert_many(
        [{"ip": ip, "category": rng.choice(intel_cats), "confidence": rng.randint(60, 99),
          "source": rng.choice(["AbuseIPDB feed", "Internal blocklist", "OTX pulse"]),
          "firstSeen": start - timedelta(days=rng.randint(5, 200))} for ip in intel_ips], ordered=False)
    seed_accounts()
    log.info("network: %d hosts, %d users, %d external IPs, %d intel entries; %d attack/decoy events planned",
             len(net.hosts), len(net.users), len(net.external_ips), len(intel_ips), len(scen_events))

    # ---- hourly synthesis
    hours = [start + timedelta(hours=h) for h in range(args.days * 24)]
    weights = [1.0 if NormalTraffic.is_business_hour(h) else 0.35 for h in hours]
    normal_total = max(0, args.count - len(scen_events))
    per_hour = [round(normal_total * w / sum(weights)) for w in weights]
    traffic = NormalTraffic(net, rng)
    loader, acc = Loader(db), IpStateAccumulator()
    si = 0
    t0 = time.perf_counter()

    for idx, (hs, n) in enumerate(zip(hours, per_hour)):
        he = hs + timedelta(hours=1)
        window = []
        for _ in range(n):
            ts = hs + timedelta(milliseconds=rng.randrange(3_600_000))
            ev, conn = traffic.event(ts)
            window.append(ev)
            if conn:
                loader.add("connections", conn)
        while si < len(scen_events) and scen_events[si]["ts"] < he:
            window.append(scen_events[si]); si += 1
        window.sort(key=lambda e: e["ts"])  # time-ordered inserts keep time-series buckets compact
        for ev in window:
            acc.add(ev)
            loader.add("raw_logs", {"ts": ev["ts"], "host": ev["host"], "source": ev["meta"]["source"],
                                    "srcIp": ev["srcIp"], "eventType": ev["eventType"], "message": raw_message(rng, ev)})
            loader.add("events", ev)
        acc.flush(db)
        if idx % 24 == 23:
            log.info("day %d/%d loaded (%d events so far)", idx // 24 + 1, args.days,
                     loader.counts["events"] + len(loader.buf["events"]))
    for c in scen_conns:
        loader.add("connections", c)
    for x in scen_extras:
        loader.add("raw_logs", x)
    loader.flush()
    elapsed = time.perf_counter() - t0

    db["scenarios"].insert_many(scenarios, ordered=False)
    n_ev, n_raw = loader.counts["events"], loader.counts["raw_logs"]
    print("\n=== Load report ===")
    print(f"events        : {n_ev:>9,}")
    print(f"raw_logs      : {n_raw:>9,}")
    print(f"connections   : {loader.counts['connections']:>9,}")
    print(f"ip_state      : {db['ip_state'].estimated_document_count():>9,}")
    print(f"scenarios     : {len(scenarios):>9,}  ({sum(s['malicious'] for s in scenarios)} malicious, "
          f"{sum(not s['malicious'] for s in scenarios)} benign decoys)")
    print(f"elapsed       : {elapsed:.1f}s   throughput: {n_ev / elapsed:,.0f} events/s "
          f"({(n_ev + n_raw) / elapsed:,.0f} docs/s incl. raw_logs)")


if __name__ == "__main__":
    main()
