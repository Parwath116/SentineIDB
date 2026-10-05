"""Pipeline 11 - Database exfiltration anomaly using $setWindowFields (documents-based window)."""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import ts_range

NAME = "exfil_anomaly"
TITLE = "Database host exfiltration anomaly ($setWindowFields)"
COLLECTION = "events"
MITRE = "T1041"
DESCRIPTION = ("Outbound bytes per database host evaluated with $setWindowFields using a documents-based "
               "moving average and standard deviation; tags internalDestination (RFC1918) and sets "
               "severity high (external) vs low/review (internal).")

# RFC 1918 private address spaces: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
RFC1918_REGEX = r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"


def build(since: datetime | None = None, until: datetime | None = None, sigma: float = 3.0,
          window_docs: int = 20, min_bytes: int = 10_000_000, limit: int = 50) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Match outbound database host flows with non-zero payload within target time range.
        {"$match": {"meta.host": {"$regex": r"^nwl-db-"}, "bytesOut": {"$gt": 0}, **ts_range(since, until)}},
        # Destination-aware tagging before windowing: separate external egress from internal workflows.
        {"$set": {
            "internalDestination": {
                "$regexMatch": {
                    "input": "$dstIp",
                    "regex": RFC1918_REGEX
                }
            }
        }},
        # Calculate moving average and standard deviation partitioned by BOTH host and internalDestination.
        # This isolates internal backup baselines from external boundary egress baselines.
        {"$setWindowFields": {
            "partitionBy": {"host": "$meta.host", "internalDestination": "$internalDestination"},
            "sortBy": {"ts": 1},
            "output": {
                "movingAvg": {"$avg": "$bytesOut", "window": {"documents": [-window_docs, -1]}},
                "movingStd": {"$stdDevSamp": "$bytesOut", "window": {"documents": [-window_docs, -1]}}
            }
        }},
        # Filter transfers exceeding moving average by more than sigma standard deviations (or cold-start large transfers).
        {"$match": {
            "$expr": {
                "$and": [
                    {"$gte": ["$bytesOut", min_bytes]},
                    {"$or": [
                        {"$eq": ["$movingAvg", None]},
                        {"$and": [
                            {"$gt": ["$movingStd", 0]},
                            {"$gt": ["$bytesOut", {"$add": ["$movingAvg", {"$multiply": [sigma, "$movingStd"]}]}]}
                        ]}
                    ]}
                ]
            }
        }},
        # Assign severity without dropping internal transfers: external is high, internal is low/review.
        {"$set": {
            "severity": {
                "$cond": [{"$eq": ["$internalDestination", True]}, "low/review", "high"]
            }
        }},
        # Sort anomalous transfers by largest payload volume descending.
        {"$sort": {"bytesOut": -1}},
        # Cap the result size.
        {"$limit": limit},
        # Project output document structure with dynamic baseline statistics and triage tags.
        {"$project": {
            "_id": 0,
            "host": "$meta.host",
            "srcIp": 1,
            "dstIp": 1,
            "bytesOut": 1,
            "movingAvg": {"$cond": [{"$ne": ["$movingAvg", None]}, {"$round": ["$movingAvg", 2]}, None]},
            "movingStd": {"$cond": [{"$ne": ["$movingStd", None]}, {"$round": ["$movingStd", 2]}, None]},
            "threshold": {"$cond": [
                {"$ne": ["$movingAvg", None]},
                {"$round": [{"$add": ["$movingAvg", {"$multiply": [sigma, {"$ifNull": ["$movingStd", 0]}]}]}, 2]},
                min_bytes
            ]},
            "internalDestination": 1,
            "severity": 1,
            "ts": 1
        }}
    ]
