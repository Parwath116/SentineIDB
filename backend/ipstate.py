"""Per-source-IP state maintained during ingestion (the change-stream source for detection).

Why a separate collection: time-series collections do not support change streams or
single-document updates, so rolling counters live in a regular collection that the
detector can watch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pymongo import UpdateOne
from pymongo.database import Database

ADMIN_PORTS = {22, 445, 3389, 5985}
SET_CAP = 5000  # upper bound for the distinct-value arrays kept per IP


def is_internal(ip: str) -> bool:
    """True for RFC1918 10.0.0.0/8 addresses used by the fictional network."""
    return ip.startswith("10.")


def is_server_ip(ip: str) -> bool:
    """Servers (web/app/db) live in 10.10.0.0/16."""
    return ip.startswith("10.10.")


@dataclass
class IpDelta:
    """Counters accumulated for one IP since the last flush."""

    failed: int = 0
    ports: set[int] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    bytes_total: int = 0
    bytes_external: int = 0
    admin_logons: int = 0
    first: datetime | None = None
    last: datetime | None = None


class IpStateAccumulator:
    """Collects deltas in memory and upserts them into ip_state in one bulk write."""

    def __init__(self) -> None:
        self.deltas: dict[str, IpDelta] = {}

    def add(self, ev: dict[str, Any]) -> None:
        """Fold one event into the per-IP deltas."""
        d = self.deltas.setdefault(ev["srcIp"], IpDelta())
        etype, ts = ev["eventType"], ev["ts"]
        if d.first is None or ts < d.first:
            d.first = ts
        if d.last is None or ts > d.last:
            d.last = ts
        d.hosts.add(ev["host"])
        if ev.get("dstPort") is not None:
            d.ports.add(int(ev["dstPort"]))
        if etype == "auth_fail":
            d.failed += 1
            if ev.get("user"):
                d.users.add(ev["user"])
        elif etype == "auth_success" and is_internal(ev["srcIp"]) and ev.get("dstPort") in ADMIN_PORTS:
            d.admin_logons += 1
        elif etype == "fw_allow":
            d.bytes_total += int(ev.get("bytesOut", 0))
            if not is_internal(ev["dstIp"]):
                d.bytes_external += int(ev.get("bytesOut", 0))

    def flush(self, db: Database) -> int:
        """Upsert all accumulated deltas; returns the number of IP documents touched."""
        ops = [self._op(ip, d) for ip, d in self.deltas.items()]
        if ops:
            db["ip_state"].bulk_write(ops, ordered=False)
        n = len(ops)
        self.deltas.clear()
        return n

    @staticmethod
    def _op(ip: str, d: IpDelta) -> UpdateOne:
        """Build a pipeline-style upsert that merges the delta into the stored document."""

        def add(field_name: str, value: int) -> dict:
            return {"$add": [{"$ifNull": [f"${field_name}", 0]}, value]}

        def union(field_name: str, values: list) -> dict:
            return {"$slice": [{"$setUnion": [{"$ifNull": [f"${field_name}", []]}, values]}, SET_CAP]}

        update = [
            {
                "$set": {
                    "failedLogins": add("failedLogins", d.failed),
                    "bytesOutTotal": add("bytesOutTotal", d.bytes_total),
                    "bytesOutExternal": add("bytesOutExternal", d.bytes_external),
                    "adminLogons": add("adminLogons", d.admin_logons),
                    "ports": union("ports", sorted(d.ports)),
                    "hosts": union("hosts", sorted(d.hosts)),
                    "users": union("users", sorted(d.users)),
                    "firstSeen": {"$ifNull": ["$firstSeen", d.first]},
                    "lastSeen": {"$max": [{"$ifNull": ["$lastSeen", d.last]}, d.last]},
                    "isExternal": not is_internal(ip),
                    "isServer": is_server_ip(ip),
                }
            },
            {
                "$set": {
                    "distinctPortsHit": {"$size": "$ports"},
                    "distinctHostsHit": {"$size": "$hosts"},
                    "distinctUsersTried": {"$size": "$users"},
                }
            },
            {
                # risk = weighted counters, capped at 100
                "$set": {
                    "riskScore": {
                        "$min": [
                            100,
                            {
                                "$round": [
                                    {
                                        "$add": [
                                            {"$multiply": ["$failedLogins", 0.2]},
                                            {"$multiply": ["$distinctPortsHit", 0.25]},
                                            {"$multiply": ["$distinctUsersTried", 2]},
                                            {"$divide": ["$bytesOutExternal", 50_000_000]},
                                            {"$multiply": ["$adminLogons", 15]},
                                        ]
                                    },
                                    0,
                                ]
                            },
                        ]
                    }
                }
            },
        ]
        return UpdateOne({"_id": ip}, update, upsert=True)
