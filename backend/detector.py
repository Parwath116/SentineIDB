"""Real-time detection: a change stream on ip_state evaluates thresholds and writes alerts.

Flow: ingestion upserts ip_state -> change stream emits the updated document -> rules evaluate counters ->
a matching rule upserts an alert (de-duplicated per rule+IP while open/acknowledged) -> the alert is
published to SSE subscribers.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Callable

from pymongo.errors import PyMongoError

from backend import config
from backend.db import get_db
from backend.mitre import MITRE, RULE_TITLES

log = logging.getLogger("detector")

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


class EventBus:
    """Fan-out of messages from the watcher thread to async SSE subscribers."""

    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self.subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        """Register a new subscriber queue."""
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Remove a subscriber."""
        self.subscribers.discard(q)

    def publish(self, message: dict[str, Any]) -> None:
        """Thread-safe publish."""
        if not self.loop:
            return
        for q in list(self.subscribers):
            self.loop.call_soon_threadsafe(self._put, q, message)

    @staticmethod
    def _put(q: asyncio.Queue, message: dict) -> None:
        try:
            q.put_nowait(message)
        except asyncio.QueueFull:
            pass  # slow consumer: drop rather than block ingestion


bus = EventBus()


# ----------------------------------------------------------------------------- rules

def _bump(sev: str) -> str:
    """Raise a severity one level (used when the source IP is in threat intelligence)."""
    return SEVERITY_ORDER[min(SEVERITY_ORDER.index(sev) + 1, len(SEVERITY_ORDER) - 1)]


def _rule_brute_force(s: dict) -> dict | None:
    if s.get("failedLogins", 0) >= config.TH_FAILED_LOGINS and s.get("distinctUsersTried", 0) <= 5:
        return {"severity": "high", "threshold": f"failedLogins >= {config.TH_FAILED_LOGINS} on <= 5 accounts",
                "evidence": {"failedLogins": s["failedLogins"], "accountsTried": s.get("users", [])[:5]}}
    return None


def _rule_spraying(s: dict) -> dict | None:
    users, fails = s.get("distinctUsersTried", 0), s.get("failedLogins", 0)
    if users >= config.TH_DISTINCT_USERS and fails / max(users, 1) <= 5:
        return {"severity": "high", "threshold": f"distinct accounts >= {config.TH_DISTINCT_USERS}, <= 5 attempts each",
                "evidence": {"distinctUsers": users, "failedLogins": fails, "sampleUsers": s.get("users", [])[:5]}}
    return None


def _rule_port_scan(s: dict) -> dict | None:
    if s.get("distinctPortsHit", 0) >= config.TH_DISTINCT_PORTS:
        return {"severity": "medium", "threshold": f"distinct ports >= {config.TH_DISTINCT_PORTS}",
                "evidence": {"distinctPorts": s["distinctPortsHit"], "samplePorts": s.get("ports", [])[:10]}}
    return None


def _rule_lateral(s: dict) -> dict | None:
    if s.get("isServer") and s.get("adminLogons", 0) >= 1:
        return {"severity": "critical", "threshold": "server-originated remote admin logon",
                "evidence": {"adminLogons": s["adminLogons"], "targetHosts": s.get("hosts", [])[:5]}}
    return None


def _rule_exfil(s: dict) -> dict | None:
    if s.get("isServer") and s.get("bytesOutExternal", 0) >= config.TH_BYTES_OUT:
        return {"severity": "critical", "threshold": f"external bytesOut >= {config.TH_BYTES_OUT:,}",
                "evidence": {"bytesOutExternal": s["bytesOutExternal"], "bytesOutTotal": s.get("bytesOutTotal", 0)}}
    return None


RULES: dict[str, Callable[[dict], dict | None]] = {
    "brute_force": _rule_brute_force, "password_spraying": _rule_spraying, "port_scan": _rule_port_scan,
    "lateral_movement": _rule_lateral, "exfiltration": _rule_exfil,
}


def threshold_prefilter() -> dict[str, Any]:
    """$match used for the startup backfill: documents that could trigger any rule."""
    return {"$or": [{"failedLogins": {"$gte": config.TH_FAILED_LOGINS}},
                    {"distinctUsersTried": {"$gte": config.TH_DISTINCT_USERS}},
                    {"distinctPortsHit": {"$gte": config.TH_DISTINCT_PORTS}},
                    {"isServer": True, "adminLogons": {"$gte": 1}},
                    {"isServer": True, "bytesOutExternal": {"$gte": config.TH_BYTES_OUT}}]}


# ----------------------------------------------------------------------------- evaluation

def enrich(ip: str) -> dict[str, Any]:
    """Threat-intel match and 'success after failures' flag for the source IP, via aggregation."""
    db = get_db()
    intel = next(db["threat_intel"].aggregate([{"$match": {"ip": ip}}, {"$project": {"_id": 0, "category": 1, "confidence": 1, "source": 1}}]), None)
    ok = next(db["events"].aggregate([{"$match": {"srcIp": ip, "eventType": "auth_success"}}, {"$count": "n"}]), None)
    return {"intel": intel, "successfulLogins": ok["n"] if ok else 0}


def evaluate(state: dict[str, Any]) -> list[str]:
    """Run all rules against one ip_state document; returns the ids of newly created alerts."""
    created: list[str] = []
    ip = state["_id"]
    extra: dict[str, Any] | None = None
    for rule_id, rule in RULES.items():
        hit = rule(state)
        if not hit:
            continue
        if extra is None:
            extra = enrich(ip)
        severity = _bump(hit["severity"]) if extra["intel"] and hit["severity"] != "critical" else hit["severity"]
        evidence = {**hit["evidence"], "rule": hit["threshold"], "firstSeen": state.get("firstSeen"),
                    "lastSeen": state.get("lastSeen"), "riskScore": state.get("riskScore"),
                    "threatIntel": extra["intel"]}
        if rule_id == "brute_force":
            evidence["successAfterFailures"] = extra["successfulLogins"] > 0
            if extra["successfulLogins"] > 0:
                severity = "critical"
        host_list = state.get("hosts") or []
        doc = {
            "ts": state.get("lastSeen") or datetime.now(timezone.utc),
            "ruleId": rule_id,
            "srcIp": ip,
            "detectedAt": datetime.now(timezone.utc),
            "type": RULE_TITLES[rule_id],
            "severity": severity,
            "status": "open",
            "mitre": MITRE[rule_id],
            "targetHost": host_list[0] if host_list else None,
            "evidence": evidence,
            "acknowledgedBy": None,
            "incidentId": None,
        }
        res = get_db()["alerts"].update_one(
            {"ruleId": rule_id, "srcIp": ip, "status": {"$in": ["open", "acknowledged"]}},
            {"$setOnInsert": doc}, upsert=True)
        if res.upserted_id is not None:
            created.append(str(res.upserted_id))
            alert = next(get_db()["alerts"].aggregate([{"$match": {"_id": res.upserted_id}}]))
            bus.publish({"type": "alert", "data": alert})
            log.warning("ALERT %s %s from %s [%s]", severity.upper(), rule_id, ip, MITRE[rule_id]["id"])
    return created


def backfill() -> int:
    """Evaluate existing ip_state documents that exceed any threshold (covers data loaded before startup)."""
    n = 0
    for state in get_db()["ip_state"].aggregate([{"$match": threshold_prefilter()}]):
        n += len(evaluate(state))
    log.info("backfill complete: %d alert(s) created", n)
    return n


def watch_loop(stop: threading.Event) -> None:
    """Blocking loop: tail the ip_state change stream and evaluate each changed document."""
    pipeline = [{"$match": {"operationType": {"$in": ["insert", "update", "replace"]}}}]
    resume_token = None
    while not stop.is_set():
        try:
            watch_kwargs: dict[str, Any] = {"full_document": "updateLookup", "max_await_time_ms": 1000}
            if resume_token:
                watch_kwargs["resume_after"] = resume_token
            with get_db()["ip_state"].watch(pipeline, **watch_kwargs) as stream:
                log.info("change stream on ip_state open (resume_after=%s)", bool(resume_token))
                while not stop.is_set():
                    change = stream.try_next()
                    if change:
                        resume_token = change.get("_id")
                        if change.get("fullDocument"):
                            evaluate(change["fullDocument"])
        except PyMongoError as exc:
            log.error("change stream error: %s - retrying in 2s", exc)
            stop.wait(2)


def start_background(loop: asyncio.AbstractEventLoop) -> tuple[threading.Thread, threading.Event]:
    """Start backfill + watcher in a daemon thread."""
    bus.loop = loop
    stop = threading.Event()

    def run() -> None:
        try:
            backfill()
        except PyMongoError as exc:
            log.error("backfill failed: %s", exc)
        watch_loop(stop)

    t = threading.Thread(target=run, name="detector", daemon=True)
    t.start()
    return t, stop
