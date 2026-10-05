"""Validate detections against the scenarios ground truth and report precision / recall.

Two detection paths are evaluated:
  * batch   - the aggregation pipelines of Phase 3 run over the full history
  * realtime - alerts produced by the change-stream detector (requires the API to have run once)
Writes docs/detection-validation.json and prints a table.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.analytics import batch_detections  # noqa: E402
from backend.db import get_db  # noqa: E402

RULES = ["brute_force", "password_spraying", "port_scan", "lateral_movement", "exfiltration"]
TYPE_TO_RULE = {"brute_force": "brute_force", "password_spraying": "password_spraying", "port_scan": "port_scan",
                "lateral_movement": "lateral_movement", "exfiltration": "exfiltration"}


def score(truth: set[str], found: set[str]) -> dict:
    """Precision/recall from two sets."""
    tp, fp, fn = len(truth & found), len(found - truth), len(truth - found)
    return {"truth": len(truth), "detected": len(found), "tp": tp, "fp": fp, "fn": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "falsePositives": sorted(found - truth), "missed": sorted(truth - found)}


def main() -> None:
    """Entry point."""
    db = get_db()
    scen = list(db["scenarios"].aggregate([{"$match": {"malicious": True, "live": {"$ne": True}}}]))
    truth: dict[str, set[str]] = {r: set() for r in RULES}
    hop_ips: set[str] = set()
    for s in scen:
        truth[TYPE_TO_RULE[s["type"]]].add(s["detectKey"])
        hop_ips.update(s.get("hopSrcIps", []))

    batch = batch_detections(db)
    realtime: dict[str, set[str]] = {r: set() for r in RULES}
    for a in db["alerts"].aggregate([{"$group": {"_id": {"rule": "$ruleId", "ip": "$srcIp"}}}]):
        realtime[a["_id"]["rule"]].add(a["_id"]["ip"])
    # lateral alerts fire on the server hop IP; translate ground truth to those IPs for the real-time check
    rt_truth = {**truth, "lateral_movement": hop_ips}
    # ignore alerts caused by live-feed attacks (they are labelled live=true in scenarios)
    live_ips = {s["srcIp"] for s in db["scenarios"].aggregate([{"$match": {"live": True}}])}
    for r in RULES:
        realtime[r] -= live_ips

    report = {"batch": {r: score(truth[r], batch[r]) for r in RULES},
              "realtime": {r: score(rt_truth[r], realtime[r]) for r in RULES}}
    for path_name in ("batch", "realtime"):
        tp = sum(v["tp"] for v in report[path_name].values())
        fp = sum(v["fp"] for v in report[path_name].values())
        fn = sum(v["fn"] for v in report[path_name].values())
        report[path_name]["overall"] = {"tp": tp, "fp": fp, "fn": fn,
                                        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                                        "recall": round(tp / (tp + fn), 3) if tp + fn else None}
    out = Path(__file__).resolve().parent.parent / "docs" / "detection-validation.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report, indent=2))

    for path_name in ("batch", "realtime"):
        print(f"\n=== {path_name} detections vs ground truth ===")
        print(f"{'rule':<20}{'truth':>6}{'found':>7}{'TP':>4}{'FP':>4}{'FN':>4}{'precision':>11}{'recall':>8}")
        for r in RULES + ["overall"]:
            v = report[path_name][r]
            print(f"{r:<20}{v.get('truth', ''):>6}{v.get('detected', ''):>7}{v['tp']:>4}{v['fp']:>4}{v['fn']:>4}"
                  f"{str(v['precision']):>11}{str(v['recall']):>8}")


if __name__ == "__main__":
    main()
