"""Pipeline 3 - Password spraying (T1110.003).

One source IP failing against many different accounts, only a few times each.
"""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import THREAT_INTEL_LOOKUP, ts_range

NAME = "password_spraying"
TITLE = "Password spraying detection"
COLLECTION = "events"
MITRE = "T1110.003"
DESCRIPTION = ("Groups auth_fail by source IP and collects distinct usernames with $addToSet; flags IPs that hit many "
               "accounts with few attempts each.")


def build(since: datetime | None = None, until: datetime | None = None, min_users: int = 15,
          max_attempts_per_user: float = 5) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Failed logins only, in range.
        {"$match": {"eventType": "auth_fail", **ts_range(since, until)}},
        # Per source IP: total attempts, the set of distinct usernames tried, and the time span.
        {"$group": {"_id": "$srcIp", "attempts": {"$sum": 1}, "users": {"$addToSet": "$user"},
                    "firstSeen": {"$min": "$ts"}, "lastSeen": {"$max": "$ts"}, "targetHost": {"$last": "$host"}}},
        # Derive the distinct-user count and the average number of attempts per user.
        {"$set": {"distinctUsers": {"$size": "$users"},
                  "attemptsPerUser": {"$divide": ["$attempts", {"$size": "$users"}]}}},
        # Spraying signature: many users, low attempts per user (a brute force would have a high ratio).
        {"$match": {"distinctUsers": {"$gte": min_users}, "attemptsPerUser": {"$lte": max_attempts_per_user}}},
        # Rename _id to srcIp so the threat-intel join key is explicit.
        {"$set": {"srcIp": "$_id"}},
        # Enrich with threat intelligence.
        THREAT_INTEL_LOOKUP,
        # Collapse intel to flag + category and drop the bulky username list (keep a short sample).
        {"$set": {"knownMalicious": {"$gt": [{"$size": "$intel"}, 0]}, "intelCategory": {"$first": "$intel.category"},
                  "sampleUsers": {"$slice": ["$users", 5]}}},
        # Remove helper fields.
        {"$project": {"_id": 0, "intel": 0, "users": 0}},
        # Widest spray first.
        {"$sort": {"distinctUsers": -1}},
    ]
