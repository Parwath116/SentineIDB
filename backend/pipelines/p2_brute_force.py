"""Pipeline 2 - Brute-force detection (T1110).

Groups failed (and successful) logins by source IP + target user, keeps pairs over the failure threshold,
then enriches the source IP from threat_intel with $lookup.
"""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import THREAT_INTEL_LOOKUP, ts_range

NAME = "brute_force"
TITLE = "Brute-force detection"
COLLECTION = "events"
MITRE = "T1110"
DESCRIPTION = ("Many failed logins from one IP against one account ($group + $match on threshold), flagged "
               "when a success follows; source IP enriched against threat_intel via $lookup.")


def build(since: datetime | None = None, until: datetime | None = None, min_failures: int = 50) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Only authentication outcomes in the time range.
        {"$match": {"eventType": {"$in": ["auth_fail", "auth_success"]}, **ts_range(since, until)}},
        # One row per (source IP, user) with failure/success counters and the failure time span.
        {"$group": {"_id": {"srcIp": "$srcIp", "user": "$user"},
                    "failures": {"$sum": {"$cond": [{"$eq": ["$eventType", "auth_fail"]}, 1, 0]}},
                    "successes": {"$sum": {"$cond": [{"$eq": ["$eventType", "auth_success"]}, 1, 0]}},
                    "firstFail": {"$min": {"$cond": [{"$eq": ["$eventType", "auth_fail"]}, "$ts", None]}},
                    "lastFail": {"$max": {"$cond": [{"$eq": ["$eventType", "auth_fail"]}, "$ts", None]}},
                    "targetHost": {"$last": "$host"}}},
        # Threshold: at least N failures against the same account from the same IP.
        {"$match": {"failures": {"$gte": min_failures}}},
        # Flatten the compound _id into plain fields and compute 'compromised' (failures then a success).
        {"$project": {"_id": 0, "srcIp": "$_id.srcIp", "user": "$_id.user", "failures": 1, "successes": 1,
                      "firstFail": 1, "lastFail": 1, "targetHost": 1, "compromised": {"$gt": ["$successes", 0]}}},
        # Join threat intelligence on the source IP (unique index on threat_intel.ip makes this an index seek).
        THREAT_INTEL_LOOKUP,
        # Reduce the joined array to a simple knownMalicious flag plus the intel category.
        {"$set": {"knownMalicious": {"$gt": [{"$size": "$intel"}, 0]},
                  "intelCategory": {"$first": "$intel.category"}}},
        # Drop the raw joined array.
        {"$unset": "intel"},
        # Most failures first.
        {"$sort": {"failures": -1}},
    ]
