"""Create the SentinelDB schema: collections, validators, indexes. Safe to run repeatedly.

Also probes which index types the time-series `events` collection supports on this server
and prints the findings, so limitations are visible rather than silently worked around.
"""
from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymongo import ASCENDING, DESCENDING, TEXT
from pymongo.database import Database
from pymongo.errors import OperationFailure

from backend.db import get_db

log = logging.getLogger("init_db")

SEVERITIES = ["low", "medium", "high", "critical"]
EVENT_TYPES = ["auth_fail", "auth_success", "fw_deny", "fw_allow", "http_request"]

MITRE_SCHEMA = {
    "bsonType": "object",
    "required": ["id", "name", "tactic"],
    "properties": {
        "id": {"bsonType": "string", "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"},
        "name": {"bsonType": "string"},
        "tactic": {"bsonType": "string"},
    },
}

# Strict validators: validationLevel=strict, validationAction=error.
VALIDATORS: dict[str, dict] = {
    "alerts": {
        "bsonType": "object",
        "required": ["ts", "ruleId", "type", "severity", "status", "srcIp", "mitre", "evidence"],
        "properties": {
            "ts": {"bsonType": "date"},
            "ruleId": {"bsonType": "string"},
            "type": {"bsonType": "string"},
            "severity": {"enum": SEVERITIES},
            "status": {"enum": ["open", "acknowledged", "escalated", "closed"]},
            "srcIp": {"bsonType": "string"},
            "targetHost": {"bsonType": ["string", "null"]},
            "mitre": MITRE_SCHEMA,
            "evidence": {"bsonType": "object"},
            "acknowledgedBy": {"bsonType": ["string", "null"]},
            "incidentId": {"bsonType": ["objectId", "null"]},
        },
    },
    "incidents": {
        "bsonType": "object",
        "required": ["createdAt", "title", "severity", "status", "alertIds", "createdBy"],
        "properties": {
            "createdAt": {"bsonType": "date"},
            "title": {"bsonType": "string"},
            "severity": {"enum": SEVERITIES},
            "status": {"enum": ["open", "investigating", "resolved"]},
            "alertIds": {"bsonType": "array", "items": {"bsonType": "objectId"}},
            "createdBy": {"bsonType": "string"},
            "notes": {"bsonType": "string"},
        },
    },
    "hosts": {
        "bsonType": "object",
        "required": ["hostname", "ip", "subnet", "role", "criticality"],
        "properties": {
            "hostname": {"bsonType": "string"},
            "ip": {"bsonType": "string"},
            "subnet": {"enum": ["web", "app", "db", "workstation", "vpn"]},
            "role": {"bsonType": "string"},
            "os": {"bsonType": "string"},
            "owner": {"bsonType": ["string", "null"]},
            "criticality": {"enum": SEVERITIES},
        },
    },
    "users": {
        "bsonType": "object",
        "required": ["username", "fullName", "department", "role"],
        "properties": {
            "username": {"bsonType": "string", "minLength": 3},
            "fullName": {"bsonType": "string"},
            "department": {"bsonType": "string"},
            "role": {"enum": ["employee", "analyst", "admin"]},
            "passwordHash": {"bsonType": "string"},
        },
    },
    "threat_intel": {
        "bsonType": "object",
        "required": ["ip", "category", "confidence", "source"],
        "properties": {
            "ip": {"bsonType": "string"},
            "category": {"bsonType": "string"},
            "confidence": {"bsonType": ["int", "long", "double"], "minimum": 0, "maximum": 100},
            "source": {"bsonType": "string"},
            "firstSeen": {"bsonType": "date"},
        },
    },
}


def ensure_timeseries(db: Database) -> None:
    """Create the time-series `events` collection if it does not exist."""
    if "events" in db.list_collection_names():
        log.info("events already exists - skipping creation")
        return
    db.create_collection(
        "events",
        timeseries={"timeField": "ts", "metaField": "meta", "granularity": "seconds"},
    )
    log.info("created time-series collection events")


def ensure_validated(db: Database, name: str, schema: dict) -> None:
    """Create (or update via collMod) a collection with a strict $jsonSchema validator."""
    validator = {"$jsonSchema": schema}
    if name not in db.list_collection_names():
        db.create_collection(name, validator=validator, validationLevel="strict", validationAction="error")
        log.info("created %s with validator", name)
    else:
        db.command("collMod", name, validator=validator, validationLevel="strict", validationAction="error")
        log.info("updated validator on %s", name)


def ensure_plain(db: Database, name: str) -> None:
    """Create a plain collection if missing."""
    if name not in db.list_collection_names():
        db.create_collection(name)
        log.info("created %s", name)


def create_indexes(db: Database) -> None:
    """Create all indexes (create_index is idempotent for identical specs)."""
    ev = db["events"]
    ev.create_index([("eventType", ASCENDING), ("ts", ASCENDING)], name="eventType_1_ts_1")
    ev.create_index([("srcIp", ASCENDING), ("ts", ASCENDING)], name="srcIp_1_ts_1")
    ev.create_index([("user", ASCENDING), ("ts", ASCENDING)], name="user_1_ts_1")
    ev.create_index([("meta.host", ASCENDING), ("ts", ASCENDING)], name="metaHost_1_ts_1")

    raw = db["raw_logs"]
    raw.create_index([("message", TEXT)], name="message_text", default_language="none")
    raw.create_index([("ts", ASCENDING)], name="ts_ttl_14d", expireAfterSeconds=14 * 24 * 3600)
    raw.create_index([("srcIp", ASCENDING), ("ts", ASCENDING)], name="srcIp_1_ts_1")

    ips = db["ip_state"]
    ips.create_index([("riskScore", DESCENDING)], name="riskScore_-1")
    ips.create_index([("lastSeen", DESCENDING)], name="lastSeen_-1")

    conn = db["connections"]
    # $graphLookup walks srcHost -> dstHost; connectFromField/connectToField need this index.
    conn.create_index([("srcHost", ASCENDING)], name="srcHost_1")
    conn.create_index([("dstHost", ASCENDING), ("ts", ASCENDING)], name="dstHost_1_ts_1")

    al = db["alerts"]
    al.create_index([("status", ASCENDING), ("severity", ASCENDING), ("ts", DESCENDING)], name="status_severity_ts")
    al.create_index([("srcIp", ASCENDING), ("ruleId", ASCENDING)], name="srcIp_1_ruleId_1")
    al.create_index(
        [("ts", DESCENDING)], name="open_alerts_ts", partialFilterExpression={"status": "open"}
    )

    db["incidents"].create_index([("status", ASCENDING), ("createdAt", DESCENDING)], name="status_createdAt")
    db["hosts"].create_index([("hostname", ASCENDING)], name="hostname_unique", unique=True)
    db["hosts"].create_index([("subnet", ASCENDING)], name="subnet_1")
    db["users"].create_index([("username", ASCENDING)], name="username_unique", unique=True)
    db["threat_intel"].create_index([("ip", ASCENDING)], name="ip_unique", unique=True)

    db["hourly_summary"].create_index([("hour", ASCENDING)], name="hour_1")
    db["scenarios"].create_index([("type", ASCENDING)], name="type_1")
    log.info("indexes ensured")


def probe_timeseries_capabilities(db: Database) -> list[tuple[str, str]]:
    """Try each index type on a throwaway time-series collection and report what works."""
    probe_name = "_ts_probe"
    db.drop_collection(probe_name)
    db.create_collection(probe_name, timeseries={"timeField": "ts", "metaField": "meta", "granularity": "seconds"})
    probe = db[probe_name]
    attempts = [
        ("compound on measurement + time", lambda: probe.create_index([("srcIp", 1), ("ts", 1)], name="a")),
        ("single measurement field only (no ts)", lambda: probe.create_index([("srcIp", 1)], name="b")),
        ("compound on metaField subfield + time", lambda: probe.create_index([("meta.host", 1), ("ts", 1)], name="c")),
        ("partial index", lambda: probe.create_index([("srcIp", 1), ("ts", 1)], name="d", partialFilterExpression={"eventType": "auth_fail"})),
        ("unique index", lambda: probe.create_index([("srcIp", 1), ("ts", 1)], name="e", unique=True)),
        ("text index", lambda: probe.create_index([("message", TEXT)], name="f")),
        ("TTL on non-time field", lambda: probe.create_index([("srcIp", 1)], name="g", expireAfterSeconds=60)),
    ]
    results: list[tuple[str, str]] = []
    for label, fn in attempts:
        try:
            fn()
            results.append((label, "SUPPORTED"))
        except OperationFailure as exc:
            results.append((label, f"NOT SUPPORTED ({str(exc)[:90]})"))
    # Other behavioural limits worth confirming on this server
    try:
        probe.insert_one({"ts": datetime.now(timezone.utc), "meta": {"host": "x"}, "n": 1})
        probe.update_one({"n": 1}, {"$set": {"n": 2}})
        results.append(("update_one by measurement field", "SUPPORTED"))
    except OperationFailure as exc:
        results.append(("update_one by measurement field", f"NOT SUPPORTED ({str(exc)[:90]})"))
    try:
        with db.client.start_session() as s:
            cs = probe.watch(session=s, max_await_time_ms=100)
            cs.close()
        results.append(("change stream on collection", "SUPPORTED"))
    except OperationFailure as exc:
        results.append(("change stream on collection", f"NOT SUPPORTED ({str(exc)[:90]})"))
    db.drop_collection(probe_name)
    return results


def main() -> None:
    """Entry point."""
    db = get_db()
    t0 = time.time()
    db.client.admin.command("ping")
    ensure_timeseries(db)
    for name, schema in VALIDATORS.items():
        ensure_validated(db, name, schema)
    for name in ["raw_logs", "ip_state", "connections", "hourly_summary", "daily_summary", "scenarios"]:
        ensure_plain(db, name)
    create_indexes(db)

    print("\n=== Collections ===")
    for c in db.list_collections():
        kind = c.get("type")
        print(f"  {c['name']:<16} type={kind}")
    print("\n=== events (time-series) options ===")
    print("  ", db.command("listCollections", filter={"name": "events"})["cursor"]["firstBatch"][0]["options"])
    print("\n=== Indexes ===")
    for name in ["events", "raw_logs", "alerts", "users", "threat_intel", "connections", "ip_state"]:
        for ix in db[name].list_indexes():
            extra = {k: v for k, v in ix.items() if k in ("unique", "partialFilterExpression", "expireAfterSeconds", "weights")}
            print(f"  {name:<13} {ix['name']:<22} key={dict(ix['key'])} {extra or ''}")
    print("\n=== Time-series capability probe (this server) ===")
    for label, res in probe_timeseries_capabilities(db):
        print(f"  {label:<42} {res}")
    print(f"\ninit_db finished in {time.time() - t0:.2f}s")


if __name__ == "__main__":
    main()
