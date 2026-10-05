"""Pipeline 10 - Failed-login velocity per srcIp using $setWindowFields (range-based window)."""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import ts_range

NAME = "login_velocity"
TITLE = "Failed-login velocity ($setWindowFields)"
COLLECTION = "events"
MITRE = "T1110"
DESCRIPTION = ("Failed-login velocity per srcIp using $setWindowFields with a range-based sliding window "
               "(5 minutes) over ts, partitioned by srcIp, computing a windowed count; flags IPs crossing threshold.")


def build(since: datetime | None = None, until: datetime | None = None, min_velocity: int = 20,
          limit: int = 50) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Keep only authentication failure events within the target time range.
        {"$match": {"eventType": "auth_fail", **ts_range(since, until)}},
        # Count failures from the same source IP in the preceding 5-minute sliding window.
        {"$setWindowFields": {
            "partitionBy": "$srcIp",
            "sortBy": {"ts": 1},
            "output": {
                "windowedCount": {
                    "$count": {},
                    "window": {"range": [-5, "current"], "unit": "minute"}
                }
            }
        }},
        # Group by source IP to obtain peak burst velocity, total failures, and targeted endpoints.
        {"$group": {
            "_id": "$srcIp",
            "peakVelocity5m": {"$max": "$windowedCount"},
            "totalFailed": {"$sum": 1},
            "firstSeen": {"$min": "$ts"},
            "lastSeen": {"$max": "$ts"},
            "targetHosts": {"$addToSet": "$host"},
            "targetUsers": {"$addToSet": "$user"}
        }},
        # Derive distinct target host and user counts.
        {"$set": {
            "srcIp": "$_id",
            "distinctUsers": {"$size": "$targetUsers"},
            "distinctHosts": {"$size": "$targetHosts"}
        }},
        # Filter for source IPs whose sliding 5-minute velocity reached or exceeded threshold.
        {"$match": {"peakVelocity5m": {"$gte": min_velocity}}},
        # Sort by highest peak velocity burst.
        {"$sort": {"peakVelocity5m": -1}},
        # Cap the output size.
        {"$limit": limit},
        # Project final structured report shape.
        {"$project": {
            "_id": 0,
            "srcIp": 1,
            "peakVelocity5m": 1,
            "totalFailed": 1,
            "firstSeen": 1,
            "lastSeen": 1,
            "distinctUsers": 1,
            "distinctHosts": 1,
            "sampleHosts": {"$slice": ["$targetHosts", 3]}
        }}
    ]
