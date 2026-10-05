"""Batch analytics shared by the API and the validation script."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from pymongo.database import Database

from backend.pipelines import (p2_brute_force, p3_password_spraying, p4_port_scan, p5_lateral_movement,
                               p6_exfiltration)

CHAIN_WINDOW = timedelta(minutes=60)


def lateral_chains(db: Database) -> list[dict[str, Any]]:
    """Trace every remote-admin origin host with $graphLookup; `flagged` means 2+ hops (a real chain)."""
    out: list[dict[str, Any]] = []
    for cand in db["connections"].aggregate(p5_lateral_movement.candidate_origins()):
        since = cand["firstTs"] - timedelta(minutes=1)
        res = next(db["hosts"].aggregate(p5_lateral_movement.build(cand["host"], since, since + CHAIN_WINDOW)), None)
        deepest = res["deepest"] if res and res["chain"] else 0
        out.append({"host": cand["host"], "firstTs": cand["firstTs"], "sessions": cand["sessions"],
                    "targets": cand["targets"], "hops": deepest, "flagged": deepest >= 2})
    return out


def batch_detections(db: Database) -> dict[str, set[str]]:
    """Run the detection pipelines over all data; returns {rule: {detectKey,...}}."""
    return {
        "brute_force": {d["srcIp"] for d in db["events"].aggregate(p2_brute_force.build())},
        "password_spraying": {d["srcIp"] for d in db["events"].aggregate(p3_password_spraying.build())},
        "port_scan": {d["srcIp"] for d in db["events"].aggregate(p4_port_scan.build())},
        "lateral_movement": {c["host"] for c in lateral_chains(db) if c["flagged"]},
        "exfiltration": {d["srcIp"] for d in db["events"].aggregate(p6_exfiltration.build())},
    }
