"""Pipeline 5 - Lateral movement chains (T1021) with $graphLookup over the connections edge collection.

Run on the `hosts` collection: start at one (possibly compromised) host and follow remote-admin
connections (ssh/rdp/smb/winrm) hop by hop. `candidate_origins` lists hosts worth tracing.
"""
from __future__ import annotations

from datetime import datetime

from backend.simulator import ADMIN_PROTOCOLS

NAME = "lateral_movement"
TITLE = "Lateral movement chain"
COLLECTION = "hosts"
MITRE = "T1021"
DESCRIPTION = ("$graphLookup from a start host across connections (srcHost -> dstHost), restricted to remote-admin "
               "protocols inside a time window, with maxDepth and depthField to number each hop.")


def build(start_host: str, since: datetime, until: datetime, max_depth: int = 5) -> list[dict]:
    """Return the aggregation pipeline for one start host."""
    return [
        # Start from the single host document we want to trace.
        {"$match": {"hostname": start_host}},
        # Walk srcHost -> dstHost edges, admin protocols only, inside the window; record the hop number.
        {"$graphLookup": {"from": "connections", "startWith": "$hostname", "connectFromField": "dstHost",
                          "connectToField": "srcHost", "as": "chain", "maxDepth": max_depth, "depthField": "hop",
                          "restrictSearchWithMatch": {"protocol": {"$in": ADMIN_PROTOCOLS},
                                                      "ts": {"$gte": since, "$lt": until}}}},
        # Keep only the fields needed to draw the chain and compute its length.
        {"$project": {"_id": 0, "origin": "$hostname", "subnet": 1, "chain": 1,
                      "hops": {"$size": "$chain"}, "deepest": {"$add": [{"$max": "$chain.hop"}, 1]}}},
    ]


def candidate_origins(since: datetime | None = None, until: datetime | None = None) -> list[dict]:
    """Pipeline on connections: hosts that opened remote-admin sessions, with their first session time."""
    match: dict = {"protocol": {"$in": ADMIN_PROTOCOLS}}
    if since or until:
        match["ts"] = {**({"$gte": since} if since else {}), **({"$lt": until} if until else {})}
    return [
        # Remote-admin connections only.
        {"$match": match},
        # One row per source host: first session time, number of sessions, distinct targets.
        {"$group": {"_id": "$srcHost", "firstTs": {"$min": "$ts"}, "sessions": {"$sum": 1},
                    "targets": {"$addToSet": "$dstHost"}}},
        # Flatten.
        {"$project": {"_id": 0, "host": "$_id", "firstTs": 1, "sessions": 1, "targets": 1}},
        # Earliest first.
        {"$sort": {"firstTs": 1}},
    ]
