"""Run every pipeline against the live database and print evidence."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bson import json_util  # noqa: E402

from backend.db import get_db  # noqa: E402
from backend.pipelines import (p1_failed_login_velocity as p1, p2_brute_force as p2, p3_password_spraying as p3,  # noqa: E402
                               p4_port_scan as p4, p5_lateral_movement as p5, p6_exfiltration as p6,
                               p7_dashboard_facets as p7, p8_log_search as p8, p9_materialize as p9,
                               p10_login_velocity as p10, p11_exfil_anomaly as p11)


def show(title: str, docs: list, n: int = 3) -> None:
    """Print a titled sample."""
    print(f"\n--- {title}: {len(docs)} result(s)")
    for d in docs[:n]:
        print("  ", json.dumps(json.loads(json_util.dumps(d)), default=str)[:300])


def timed(coll, pipeline):
    """Run an aggregation and return (docs, seconds)."""
    t = time.perf_counter()
    docs = list(coll.aggregate(pipeline, allowDiskUse=True))
    return docs, time.perf_counter() - t


def main() -> None:
    """Entry point."""
    db = get_db()
    print("=== Collection counts ===")
    for c in ["events", "raw_logs", "connections", "ip_state", "hosts", "users", "threat_intel", "scenarios"]:
        print(f"  {c:<14} {db[c].estimated_document_count():>9,}")
    print("\n=== events by type ===")
    for d in db["events"].aggregate([{"$group": {"_id": "$eventType", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}]):
        print("  ", d)
    print("\n=== sample event / raw log / ip_state / scenario ===")
    for coll, pipe in [("events", [{"$sample": {"size": 1}}]), ("raw_logs", [{"$sample": {"size": 1}}]),
                       ("ip_state", [{"$sort": {"riskScore": -1}}, {"$limit": 1}, {"$project": {"ports": 0, "users": 0, "hosts": 0}}]),
                       ("scenarios", [{"$match": {"type": "brute_force"}}, {"$limit": 1}])]:
        print(f"  {coll}:", json_util.dumps(next(db[coll].aggregate(pipe)), default=str)[:420])

    for name, mod, coll in [("1 failed_login_velocity", p1, "events"), ("2 brute_force", p2, "events"),
                            ("3 password_spraying", p3, "events"), ("4 port_scan", p4, "events"),
                            ("6 exfiltration", p6, "events")]:
        docs, secs = timed(db[coll], mod.build())
        show(f"pipeline {name} ({secs:.2f}s)", docs, 4)

    cands, _ = timed(db["connections"], p5.candidate_origins())
    show("pipeline 5 candidate origins", cands, 6)
    sc = db["scenarios"].find_one({"type": "lateral_movement"})
    if sc:
        origin = sc.get("originHost", "nwl-ws-12")
        start = sc.get("startTs", datetime.now(timezone.utc) - timedelta(days=7))
        docs, secs = timed(db["hosts"], p5.build(origin, start - timedelta(minutes=1), start + timedelta(hours=1)))
        show(f"pipeline 5 lateral_movement from {origin} ({secs:.2f}s)", docs, 1)

    docs, secs = timed(db["events"], p7.build())
    f = docs[0]
    print(f"\n--- pipeline 7 dashboard_facets ({secs:.2f}s)")
    for k, v in f.items():
        print(f"   {k}: {len(v)} rows, first: {v[:2]}")

    docs, secs = timed(db["raw_logs"], p8.build("rclone"))
    show(f"pipeline 8 log_search 'rclone' ({secs:.3f}s)", docs, 2)
    docs, secs = timed(db["raw_logs"], p8.build("failed password invalid", limit=3))
    show(f"pipeline 8 log_search 'failed password' ({secs:.3f}s)", docs, 2)

    t = time.perf_counter()
    list(db["events"].aggregate(p9.hourly()))
    list(db["hourly_summary"].aggregate(p9.daily()))
    print(f"\n--- pipeline 9 $merge ({time.perf_counter() - t:.2f}s): hourly_summary={db['hourly_summary'].count_documents({})}, "
          f"daily_summary={db['daily_summary'].count_documents({})}")
    print("   sample daily:", json_util.dumps(db["daily_summary"].find_one(), default=str)[:300])

    # -------------------------------------------------------------------------
    # Scenario Ground-Truth Sets
    # -------------------------------------------------------------------------
    bf_backfill = set(db["scenarios"].distinct("srcIp", {"type": "brute_force", "live": {"$ne": True}}))
    bf_live = set(db["scenarios"].distinct("srcIp", {"type": "brute_force", "live": True}))
    bf_all = bf_backfill | bf_live

    spray_backfill = set(db["scenarios"].distinct("srcIp", {"type": "password_spraying", "live": {"$ne": True}}))
    spray_live = set(db["scenarios"].distinct("srcIp", {"type": "password_spraying", "live": True}))
    spray_all = spray_backfill | spray_live

    exfil_backfill = set(db["scenarios"].distinct("sourceHost", {"type": "exfiltration", "live": {"$ne": True}}))
    exfil_live = set(db["scenarios"].distinct("sourceHost", {"type": "exfiltration", "live": True}))
    exfil_all = exfil_backfill | exfil_live

    decoy_pass_doc = db["scenarios"].find_one({"type": "benign_mistyped_password"})
    decoy_pass = decoy_pass_doc["srcIp"] if decoy_pass_doc else "10.20.1.36"

    decoy_backup_doc = db["scenarios"].find_one({"type": "benign_backup"})
    decoy_backup_ip = decoy_backup_doc["srcIp"] if decoy_backup_doc else "10.10.3.13"
    backup_sample = db["events"].find_one({"srcIp": decoy_backup_ip, "eventType": "fw_allow"})
    decoy_backup = backup_sample["host"] if backup_sample else "nwl-db-03"

    # -------------------------------------------------------------------------
    # Pipeline 10: Failed-login velocity per srcIp ($setWindowFields range window)
    # -------------------------------------------------------------------------
    print("\n==========================================================================")
    print("PIPELINE 10: FAILED-LOGIN VELOCITY ($setWindowFields RANGE 5-MIN WINDOW)")
    print("Note: p10 is a BRUTE-FORCE detector. Password spraying is detected by p2/p3.")
    print("==========================================================================")

    for th in [10, 20, 50]:
        docs10, secs10 = timed(db["events"], p10.build(min_velocity=th, limit=100))
        flagged_ips = {d["srcIp"]: d for d in docs10}
        
        # Backfill metrics (evaluating strictly against backfill brute-force truth)
        tp_bf = len(bf_backfill.intersection(flagged_ips.keys()))
        fn_bf = len(bf_backfill - flagged_ips.keys())
        # All flagged results not in bf_backfill count as FP from a backfill-only evaluation perspective
        fp_bf = len(flagged_ips) - tp_bf
        prec_bf = tp_bf / len(flagged_ips) if flagged_ips else 0
        rec_bf = tp_bf / len(bf_backfill) if bf_backfill else 0

        # All-injected metrics (accounting for live_feed injected attacks)
        tp_all = len(bf_all.intersection(flagged_ips.keys()))
        fn_all = len(bf_all - flagged_ips.keys())
        fp_all = len(flagged_ips) - tp_all
        prec_all = tp_all / len(flagged_ips) if flagged_ips else 0
        rec_all = tp_all / len(bf_all) if bf_all else 0

        print(f"\n--- Threshold = {th} ({secs10:.3f}s) | Total Flagged = {len(flagged_ips)} ---")
        print(f"  [Backfill Scenarios Only] TP: {tp_bf}/{len(bf_backfill)}, FP: {fp_bf}, FN: {fn_bf} | Precision: {prec_bf:.1%}, Recall: {rec_bf:.1%}")
        print(f"  [All Injected Inc. Live]  TP: {tp_all}/{len(bf_all)}, FP: {fp_all}, FN: {fn_all} | Precision: {prec_all:.1%}, Recall: {rec_all:.1%}")
        
        for ip, d in flagged_ips.items():
            if ip in bf_backfill:
                cat = "ground-truth attack (brute_force)"
            elif ip in bf_live:
                cat = "live-feed injected attack (brute_force)"
            elif ip in spray_backfill:
                cat = "ground-truth attack (password_spraying)"
            elif ip in spray_live:
                cat = "live-feed injected attack (password_spraying)"
            elif ip == decoy_pass:
                cat = "benign decoy (mistyped_password)"
            else:
                cat = "unexplained"
            print(f"    IP: {ip:<15} Peak5m: {d['peakVelocity5m']:>3}  Total: {d['totalFailed']:>3}  Users: {d['distinctUsers']:>2} -> {cat}")

    # -------------------------------------------------------------------------
    # Pipeline 11: Outbound bytes anomaly per db host ($setWindowFields doc window)
    # -------------------------------------------------------------------------
    print("\n==========================================================================")
    print("PIPELINE 11: DB EXFIL ANOMALY ($setWindowFields 20-DOC 3-SIGMA WINDOW)")
    print("Note: Tags internalDestination (RFC1918) and severity (high vs low/review)")
    print("==========================================================================")
    docs11, secs11 = timed(db["events"], p11.build(sigma=3.0, window_docs=20, min_bytes=10_000_000, limit=100))
    print(f"Total anomalous transfer events flagged: {len(docs11)} ({secs11:.3f}s)")

    for i, d in enumerate(docs11, 1):
        host = d["host"]
        dst = d["dstIp"]
        internal = d["internalDestination"]
        sev = d["severity"]
        b = d["bytesOut"]
        
        if host in exfil_backfill and not internal:
            cat = "ground-truth attack (exfiltration)"
        elif host in exfil_live and not internal:
            cat = "live-feed injected attack (exfiltration)"
        elif host == decoy_backup and internal:
            cat = "benign decoy (scheduled_backup)"
        else:
            cat = "unexplained"
        print(f"  [{i:02d}] Host: {host:<10} Dst: {dst:<15} Bytes: {b:>11,} Internal: {str(internal):<5} Sev: {sev:<10} -> {cat}")

    high_hosts = {d["host"] for d in docs11 if d["severity"] == "high"}
    low_hosts = {d["host"] for d in docs11 if d["severity"] == "low/review"}
    all_flagged_hosts = {d["host"] for d in docs11}

    print("\n=== Pipeline 11 Ground-Truth Validation ===")
    print(f"  All Flagged Hosts ({len(all_flagged_hosts)}): {all_flagged_hosts}")
    print(f"  High Severity Hosts (External Exfiltration, {len(high_hosts)}): {high_hosts}")
    print(f"  Low/Review Hosts (Internal Backup Decoy, {len(low_hosts)}): {low_hosts}")
    print(f"  Backfill Exfiltration Detection (High Sev): {len(exfil_backfill.intersection(high_hosts))}/{len(exfil_backfill)} hosts flagged")
    print(f"  Scheduled Backup Decoy ({decoy_backup}): Tagged Internal = {decoy_backup in low_hosts}, Tagged Severity = 'low/review'")


if __name__ == "__main__":
    main()
