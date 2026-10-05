"""Performance benchmarks: identical queries without and with the relevant index, plus storage and text-search comparisons.

Each measurement captures explain("executionStats"): plan stage (COLLSCAN / IXSCAN), totalDocsExamined, nReturned,
executionTimeMillis. For the time-series collection, "docs examined" counts internal buckets (each bucket packs many
measurements), which is stated in the output. Results are saved to benchmarks/results.json.
"""
from __future__ import annotations

import json
import logging
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from pymongo import ASCENDING, DESCENDING, TEXT
from pymongo.database import Database

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import config  # noqa: E402
from backend.db import get_db  # noqa: E402
from backend.serialize import jsonable  # noqa: E402

log = logging.getLogger("benchmark")
REPEATS = 7


# ----------------------------------------------------------------------------- explain helpers

def _walk(node: Any, key: str, found: list) -> None:
    """Collect every value stored under `key` anywhere in a nested explain document."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                found.append(v)
            _walk(v, key, found)
    elif isinstance(node, list):
        for v in node:
            _walk(v, key, found)


def summarise(explain: dict) -> dict[str, Any]:
    """Reduce an explain() document to the four headline metrics."""
    stages: list = []
    _walk(explain, "stage", stages)
    scan = "IXSCAN" if "IXSCAN" in stages else ("COLLSCAN" if "COLLSCAN" in stages else (stages[0] if stages else "n/a"))
    if "TEXT_MATCH" in stages or "TEXT_OR" in stages:
        scan = "TEXT (IXSCAN)"
    stats = explain.get("executionStats")
    if stats is None:
        cursor_stats: list = []
        _walk(explain, "executionStats", cursor_stats)
        stats = cursor_stats[0] if cursor_stats else {}
    index_names: list = []
    _walk(explain, "indexName", index_names)
    return {"stage": scan, "index": index_names[0] if index_names else None,
            "totalDocsExamined": stats.get("totalDocsExamined"), "totalKeysExamined": stats.get("totalKeysExamined"),
            "nReturned": stats.get("nReturned"), "executionTimeMillis": stats.get("executionTimeMillis")}


def explain_aggregate(db: Database, coll: str, pipeline: list[dict]) -> dict[str, Any]:
    """explain('executionStats') for an aggregation, plus min/median/max wall-clock times of 7 runs."""
    ex = db.command({"explain": {"aggregate": coll, "pipeline": pipeline, "cursor": {}, "allowDiskUse": True},
                     "verbosity": "executionStats"})
    out = summarise(ex)
    times = []
    for _ in range(REPEATS):
        t = time.perf_counter()
        list(db[coll].aggregate(pipeline, allowDiskUse=True))
        times.append((time.perf_counter() - t) * 1000)
    out["wallClockMillisMin"] = round(min(times), 1)
    out["wallClockMillisMedian"] = round(statistics.median(times), 1)
    out["wallClockMillisMax"] = round(max(times), 1)
    return out


def explain_find(db: Database, coll: str, flt: dict, projection: dict | None = None) -> dict[str, Any]:
    """explain('executionStats') for a find-shaped query, plus min/median/max wall-clock times of 7 runs."""
    cmd: dict[str, Any] = {"find": coll, "filter": flt}
    if projection:
        cmd["projection"] = projection
    ex = db.command({"explain": cmd, "verbosity": "executionStats"})
    out = summarise(ex)
    times = []
    for _ in range(REPEATS):
        t = time.perf_counter()
        list(db[coll].aggregate([{"$match": flt}, {"$project": {"_id": 1}}]))
        times.append((time.perf_counter() - t) * 1000)
    out["wallClockMillisMin"] = round(min(times), 1)
    out["wallClockMillisMedian"] = round(statistics.median(times), 1)
    out["wallClockMillisMax"] = round(max(times), 1)
    return out


# ----------------------------------------------------------------------------- 1. index before / after

def _index_case(db: Database, label: str, coll: str, description: str, pipeline: list[dict], index_name: str,
                drop: Callable[[], None], create: Callable[[], None], note: str = "") -> dict[str, Any]:
    """Run the same pipeline with the index dropped, then recreated."""
    log.info("benchmark: %s", label)
    drop()
    try:
        without = explain_aggregate(db, coll, pipeline)
    finally:
        create()
    with_idx = explain_aggregate(db, coll, pipeline)
    speed = None
    if without["wallClockMillisMedian"] and with_idx["wallClockMillisMedian"]:
        speed = round(without["wallClockMillisMedian"] / max(with_idx["wallClockMillisMedian"], 0.1), 1)
    return {"label": label, "collection": coll, "description": description, "index": index_name,
            "pipeline": jsonable(pipeline), "without": without, "with": with_idx, "speedup": speed, "note": note}


def index_benchmarks(db: Database) -> list[dict[str, Any]]:
    """Index before/after comparisons on the main query shapes."""
    now = datetime.now(timezone.utc)
    ip = next(db["ip_state"].aggregate([{"$match": {"isExternal": True}}, {"$sort": {"distinctPortsHit": -1}}, {"$limit": 1}]))["_id"]
    since = now - timedelta(days=7)
    events, raw, conns = db["events"], db["raw_logs"], db["connections"]
    cases = []

    cases.append(_index_case(
        db, "Events by source IP (time-series)", "events", "All events from one source IP in the last 7 days.",
        [{"$match": {"srcIp": ip, "ts": {"$gte": since}}}, {"$group": {"_id": "$eventType", "n": {"$sum": 1}}}],
        "srcIp_1_ts_1", lambda: events.drop_index("srcIp_1_ts_1"),
        lambda: events.create_index([("srcIp", ASCENDING), ("ts", ASCENDING)], name="srcIp_1_ts_1"),
        "Time-series explain counts buckets, not individual events."))

    cases.append(_index_case(
        db, "Failed logins in a window (time-series)", "events", "auth_fail events in the last 3 days.",
        [{"$match": {"eventType": "auth_fail", "ts": {"$gte": now - timedelta(days=3)}}},
         {"$group": {"_id": "$srcIp", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}, {"$limit": 5}],
        "eventType_1_ts_1", lambda: events.drop_index("eventType_1_ts_1"),
        lambda: events.create_index([("eventType", ASCENDING), ("ts", ASCENDING)], name="eventType_1_ts_1"),
        "Time-series explain counts buckets, not individual events."))

    cases.append(_index_case(
        db, "Raw logs by source IP", "raw_logs", "Raw log lines from one IP in the last 7 days, newest first.",
        [{"$match": {"srcIp": ip, "ts": {"$gte": since}}}, {"$sort": {"ts": -1}}, {"$limit": 50}],
        "srcIp_1_ts_1", lambda: raw.drop_index("srcIp_1_ts_1"),
        lambda: raw.create_index([("srcIp", ASCENDING), ("ts", ASCENDING)], name="srcIp_1_ts_1")))

    cases.append(_index_case(
        db, "Attack-chain traversal ($graphLookup)", "hosts",
        "Trace remote-admin chains (maxDepth 5) from every workstation, as the detection sweep does.",
        [{"$match": {"subnet": "workstation"}},
         {"$graphLookup": {"from": "connections", "startWith": "$hostname", "connectFromField": "dstHost",
                           "connectToField": "srcHost", "as": "chain", "maxDepth": 5, "depthField": "hop",
                           "restrictSearchWithMatch": {"protocol": {"$in": ["ssh", "rdp", "smb", "winrm"]}}}},
         {"$match": {"chain.0": {"$exists": True}}}, {"$project": {"hostname": 1, "hops": {"$size": "$chain"}}}],
        "srcHost_1", lambda: conns.drop_index("srcHost_1"),
        lambda: conns.create_index([("srcHost", ASCENDING)], name="srcHost_1"),
        "Each $graphLookup hop is an equality lookup on connections.srcHost; without the index every hop scans the collection. "
        "Explain reports only the outer stage on hosts; the wall-clock time shows the real cost."))

    alerts = db["alerts"]
    open_filter = [{"$match": {"status": "open"}}, {"$sort": {"ts": -1}}, {"$limit": 50}]
    cases.append(_index_case(
        db, "Open alerts (partial index)", "alerts", "Latest open alerts. Partial index covers only status=open documents.",
        open_filter, "open_alerts_ts + status_severity_ts",
        lambda: (alerts.drop_index("open_alerts_ts"), alerts.drop_index("status_severity_ts")),
        lambda: (alerts.create_index([("ts", DESCENDING)], name="open_alerts_ts", partialFilterExpression={"status": "open"}),
                 alerts.create_index([("status", ASCENDING), ("severity", ASCENDING), ("ts", DESCENDING)], name="status_severity_ts")),
        "The alerts collection is small in this deployment, so absolute times are tiny; the plan change is what matters."))
    return cases


# ----------------------------------------------------------------------------- 2. time-series vs regular

def storage_stats(db: Database, coll: str) -> dict[str, Any]:
    """collStats essentials."""
    s = db.command("collStats", coll)
    return {"count": s.get("count"), "sizeBytes": s.get("size"), "storageSizeBytes": s.get("storageSize"),
            "totalIndexSizeBytes": s.get("totalIndexSize"), "avgObjSizeBytes": s.get("avgObjSize"),
            "timeseries": s.get("timeseries") is not None}


def timeseries_vs_regular(db: Database) -> dict[str, Any]:
    """Copy events into a regular collection with equivalent indexes; compare storage and a time-range query."""
    log.info("benchmark: time-series vs regular")
    db.drop_collection("events_regular")
    list(db["events"].aggregate([{"$out": "events_regular"}]))
    reg = db["events_regular"]
    reg.create_index([("ts", ASCENDING)], name="ts_1")
    reg.create_index([("srcIp", ASCENDING), ("ts", ASCENDING)], name="srcIp_1_ts_1")
    reg.create_index([("eventType", ASCENDING), ("ts", ASCENDING)], name="eventType_1_ts_1")
    reg.create_index([("user", ASCENDING), ("ts", ASCENDING)], name="user_1_ts_1")
    reg.create_index([("meta.host", ASCENDING), ("ts", ASCENDING)], name="metaHost_1_ts_1")
    start = datetime.now(timezone.utc) - timedelta(days=2)
    pipe = [{"$match": {"ts": {"$gte": start, "$lt": start + timedelta(hours=6)}}},
            {"$group": {"_id": "$eventType", "n": {"$sum": 1}, "bytes": {"$sum": {"$ifNull": ["$bytesOut", 0]}}}}]
    result = {"timeSeries": {"storage": storage_stats(db, "events"), "query": explain_aggregate(db, "events", pipe)},
              "regular": {"storage": storage_stats(db, "events_regular"), "query": explain_aggregate(db, "events_regular", pipe)},
              "queryDescription": "Count and bytes by eventType for a 6-hour window two days ago.",
              "pipeline": jsonable(pipe),
              "notes": ["Time-series 'docs examined' counts buckets (many events each); regular counts individual documents.",
                        "Both collections carry equivalent secondary indexes; the time-series collection also keeps its automatic (meta, ts) index.",
                        "Time-series storage is compressed column-wise per bucket; the saving depends on how clustered the data is."]}
    db.drop_collection("events_regular")
    return result


# ----------------------------------------------------------------------------- 3. text search

def text_search(db: Database) -> list[dict[str, Any]]:
    """$text (text index) vs a case-insensitive regex scan, which is the only option without the index."""
    log.info("benchmark: text search")
    out = []
    for term, regex in [("rclone", "rclone"), ("psexec", "psexec"), ('"Failed password"', "failed password")]:
        text_pipe = [{"$match": {"$text": {"$search": term}}}, {"$limit": 1_000_000}, {"$count": "hits"}]
        scan_pipe = [{"$match": {"message": {"$regex": regex, "$options": "i"}}}, {"$count": "hits"}]
        out.append({"term": term, "withIndex": {"method": "$text on message_text index", **explain_aggregate(db, "raw_logs", text_pipe)},
                    "withoutIndex": {"method": "case-insensitive $regex (no text index can serve it)", **explain_aggregate(db, "raw_logs", scan_pipe)},
                    "pipelines": {"text": jsonable(text_pipe), "regex": jsonable(scan_pipe)}})
    return out


def run_all() -> dict[str, Any]:
    """Run every benchmark and save benchmarks/results.json."""
    db = get_db()
    t0 = time.time()
    results = {"generatedAt": datetime.now(timezone.utc), "mongoVersion": db.client.server_info()["version"],
               "dataset": {"events": db["events"].estimated_document_count(), "raw_logs": db["raw_logs"].estimated_document_count(),
                           "connections": db["connections"].estimated_document_count()},
               "indexComparisons": index_benchmarks(db), "timeSeriesVsRegular": timeseries_vs_regular(db),
               "textSearch": text_search(db)}
    results["elapsedSeconds"] = round(time.time() - t0, 1)
    results = jsonable(results)
    config.BENCHMARK_FILE.parent.mkdir(exist_ok=True)
    config.BENCHMARK_FILE.write_text(json.dumps(results, indent=2))
    log.info("saved %s", config.BENCHMARK_FILE)
    return results


def print_report(r: dict[str, Any]) -> None:
    """Console summary."""
    print(f"\nDataset: {r['dataset']}  (MongoDB {r['mongoVersion']})")
    print("\n=== Index before / after ===")
    print(f"{'query':<42}{'':<9}{'stage':<10}{'docsExam':>10}{'returned':>9}{'ms(exec)':>9}{'ms(wall)':>9}")
    for c in r["indexComparisons"]:
        for tag in ("without", "with"):
            m = c[tag]
            print(f"{c['label'] if tag == 'without' else '':<42}{tag:<9}{str(m['stage']):<10}{str(m['totalDocsExamined']):>10}"
                  f"{str(m['nReturned']):>9}{str(m['executionTimeMillis']):>9}{m['wallClockMillisMedian']:>9}")
        print(f"{'':<42}speedup x{c['speedup']}")
    ts, rg = r["timeSeriesVsRegular"]["timeSeries"], r["timeSeriesVsRegular"]["regular"]
    print("\n=== Time-series vs regular collection ===")
    for name, d in (("time-series", ts), ("regular", rg)):
        s, q = d["storage"], d["query"]
        print(f"{name:<12} storage={s['storageSizeBytes']/1e6:8.1f} MB  indexes={s['totalIndexSizeBytes']/1e6:7.1f} MB  "
              f"| query: {q['stage']} examined={q['totalDocsExamined']} returned={q['nReturned']} wall={q['wallClockMillisMedian']}ms")
    print("\n=== Text search ===")
    for t in r["textSearch"]:
        w, wo = t["withIndex"], t["withoutIndex"]
        print(f"'{t['term']:<8}' text-index: {w['stage']} examined={w['totalDocsExamined']} wall={w['wallClockMillisMedian']}ms"
              f"  | regex: {wo['stage']} examined={wo['totalDocsExamined']} wall={wo['wallClockMillisMedian']}ms")


if __name__ == "__main__":
    print_report(run_all())
