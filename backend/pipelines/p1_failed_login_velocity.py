"""Pipeline 1 - Failed-login velocity per IP (sliding 5-minute window).

Collection: events (time-series). For each failed login, $setWindowFields counts the failures from the
same source IP in the trailing five minutes; the peak per IP is the 'velocity' used to spot bursts.
"""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import ts_range

NAME = "failed_login_velocity"
TITLE = "Failed-login velocity per IP"
COLLECTION = "events"
MITRE = "T1110"
DESCRIPTION = ("Sliding 5-minute count of auth_fail events per source IP using $setWindowFields; "
               "reports each IP's peak burst rate.")


def build(since: datetime | None = None, until: datetime | None = None, min_peak: int = 20, limit: int = 20) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Keep only failed logins in the requested time range (uses the eventType+ts index).
        {"$match": {"eventType": "auth_fail", **ts_range(since, until)}},
        # For every row, count failures from the same IP in the trailing 5 minutes (range window on ts).
        {"$setWindowFields": {"partitionBy": "$srcIp", "sortBy": {"ts": 1},
                              "output": {"failsLast5m": {"$count": {}, "window": {"range": [-5, "current"], "unit": "minute"}}}}},
        # Collapse to one row per IP: peak burst, total failures, and last activity.
        {"$group": {"_id": "$srcIp", "peakFailsIn5m": {"$max": "$failsLast5m"}, "totalFails": {"$sum": 1},
                    "lastSeen": {"$max": "$ts"}}},
        # Only IPs whose peak burst reaches the threshold.
        {"$match": {"peakFailsIn5m": {"$gte": min_peak}}},
        # Worst offenders first.
        {"$sort": {"peakFailsIn5m": -1}},
        # Cap the result size.
        {"$limit": limit},
    ]
