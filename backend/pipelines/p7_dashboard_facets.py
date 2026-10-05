"""Pipeline 7 - Dashboard analytics in one pass with $facet and $bucket."""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import ts_range

NAME = "dashboard_facets"
TITLE = "Top attackers, targeted hosts, severity and time-of-day"
COLLECTION = "events"
MITRE = None
DESCRIPTION = ("Single $facet over suspicious events (auth_fail, fw_deny, medium+ severity): top source IPs, most "
               "targeted hosts, hourly attack counts, severity mix and a $bucket of attacks by time of day.")


def build(since: datetime | None = None, until: datetime | None = None, top_n: int = 10) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Suspicious activity only: failed logins, firewall denies, or events rated medium and above.
        {"$match": {"$or": [{"eventType": {"$in": ["auth_fail", "fw_deny"]}}, {"severity": {"$in": ["medium", "high", "critical"]}}],
                    **ts_range(since, until)}},
        # Run several independent summaries over the same filtered input.
        {"$facet": {
            # Top attacking source IPs by event volume, with the number of distinct targets hit.
            "topAttackers": [{"$group": {"_id": "$srcIp", "events": {"$sum": 1}, "targets": {"$addToSet": "$host"}}},
                             {"$set": {"distinctTargets": {"$size": "$targets"}}}, {"$project": {"targets": 0}},
                             {"$sort": {"events": -1}}, {"$limit": top_n}],
            # Most targeted hosts.
            "targetedHosts": [{"$group": {"_id": "$host", "events": {"$sum": 1}}}, {"$sort": {"events": -1}}, {"$limit": top_n}],
            # Attacks per hour.
            "attacksPerHour": [{"$group": {"_id": {"$dateTrunc": {"date": "$ts", "unit": "hour"}}, "events": {"$sum": 1}}},
                               {"$sort": {"_id": 1}}],
            # Severity distribution of the suspicious events.
            "severity": [{"$group": {"_id": "$severity", "events": {"$sum": 1}}}, {"$sort": {"events": -1}}],
            # $bucket: attacks by time of day (6-hour boundaries).
            "timeOfDay": [{"$bucket": {"groupBy": {"$hour": "$ts"}, "boundaries": [0, 6, 12, 18, 24], "default": "other",
                                       "output": {"events": {"$sum": 1}}}}],
        }},
    ]
