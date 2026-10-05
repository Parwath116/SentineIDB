"""Pipeline 9 - Materialise hourly_summary and daily_summary with $merge (dashboards read precomputed data)."""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import ts_range

NAME = "materialize_summaries"
TITLE = "Hourly and daily summaries ($merge)"
COLLECTION = "events"
MITRE = None
DESCRIPTION = ("Aggregates events per hour into hourly_summary using $merge (upsert by hour), then rolls "
               "hourly_summary up into daily_summary; both are re-runnable.")


def hourly(since: datetime | None = None, until: datetime | None = None) -> list[dict]:
    """events -> hourly_summary."""
    def count(etype: str) -> dict:
        return {"$sum": {"$cond": [{"$eq": ["$eventType", etype]}, 1, 0]}}

    return [
        # Time range (re-running for the latest hours only is cheap).
        {"$match": ts_range(since, until)},
        # One row per hour with a counter per event type, volume and high-severity count.
        {"$group": {"_id": {"$dateTrunc": {"date": "$ts", "unit": "hour"}},
                    "total": {"$sum": 1}, "authFail": count("auth_fail"), "authSuccess": count("auth_success"),
                    "fwDeny": count("fw_deny"), "fwAllow": count("fw_allow"), "httpRequest": count("http_request"),
                    "bytesOut": {"$sum": {"$ifNull": ["$bytesOut", 0]}},
                    "highSeverity": {"$sum": {"$cond": [{"$in": ["$severity", ["high", "critical"]]}, 1, 0]}}}},
        # Add an 'attacks' measure (suspicious event count) and name the key.
        {"$set": {"hour": "$_id", "suspicious": {"$add": ["$authFail", "$fwDeny"]}}},
        # Upsert into the materialised collection keyed by hour (_id).
        {"$merge": {"into": "hourly_summary", "on": "_id", "whenMatched": "replace", "whenNotMatched": "insert"}},
    ]


def daily() -> list[dict]:
    """hourly_summary -> daily_summary."""
    return [
        # Roll hours up into days.
        {"$group": {"_id": {"$dateTrunc": {"date": "$hour", "unit": "day"}}, "total": {"$sum": "$total"},
                    "authFail": {"$sum": "$authFail"}, "authSuccess": {"$sum": "$authSuccess"},
                    "fwDeny": {"$sum": "$fwDeny"}, "fwAllow": {"$sum": "$fwAllow"}, "httpRequest": {"$sum": "$httpRequest"},
                    "bytesOut": {"$sum": "$bytesOut"}, "highSeverity": {"$sum": "$highSeverity"},
                    "suspicious": {"$sum": "$suspicious"}, "peakSuspiciousHour": {"$max": "$suspicious"}}},
        # Name the key.
        {"$set": {"day": "$_id"}},
        # Upsert into daily_summary.
        {"$merge": {"into": "daily_summary", "on": "_id", "whenMatched": "replace", "whenNotMatched": "insert"}},
    ]


def build() -> list[dict]:
    """Return the hourly pipeline (the daily one is available as daily())."""
    return hourly()
