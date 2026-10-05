"""Pipeline 6 - Data exfiltration (T1041): outbound bytes anomaly with a moving average and standard deviation."""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import INTERNAL_IP_REGEX, SERVER_IP_REGEX, ts_range

NAME = "exfiltration"
TITLE = "Exfiltration (bytesOut anomaly)"
COLLECTION = "events"
MITRE = "T1041"
DESCRIPTION = ("Per-server 5-minute outbound byte totals, compared to a trailing moving average and standard "
               "deviation with $setWindowFields; flags buckets above avg + 3 sigma that sent a large volume to external IPs.")


def build(since: datetime | None = None, until: datetime | None = None, min_external_bytes: int = 100_000_000,
          sigma: float = 3.0, window: int = 12) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Allowed outbound flows from server-subnet addresses (web/app/db), in range.
        {"$match": {"eventType": "fw_allow", "srcIp": {"$regex": SERVER_IP_REGEX}, **ts_range(since, until)}},
        # Per (server, 5-minute bucket): total bytes, bytes to non-internal destinations, destinations used.
        {"$group": {"_id": {"srcIp": "$srcIp", "bucket": {"$dateTrunc": {"date": "$ts", "unit": "minute", "binSize": 5}}},
                    "bytes": {"$sum": "$bytesOut"},
                    "externalBytes": {"$sum": {"$cond": [{"$regexMatch": {"input": "$dstIp", "regex": INTERNAL_IP_REGEX}}, 0, "$bytesOut"]}},
                    "destinations": {"$addToSet": "$dstIp"}, "host": {"$first": "$host"}}},
        # Flatten the key so the window stage can partition and sort on plain fields.
        {"$set": {"srcIp": "$_id.srcIp", "bucket": "$_id.bucket"}},
        # Moving average and standard deviation of the previous `window` buckets for the same server.
        {"$setWindowFields": {"partitionBy": "$srcIp", "sortBy": {"bucket": 1},
                              "output": {"movingAvg": {"$avg": "$bytes", "window": {"documents": [-window, -1]}},
                                         "movingStd": {"$stdDevPop": "$bytes", "window": {"documents": [-window, -1]}}}}},
        # Anomaly = bytes above avg + sigma*std (or no baseline yet) AND a large external transfer.
        {"$match": {"$expr": {"$and": [
            {"$gte": ["$externalBytes", min_external_bytes]},
            {"$or": [{"$eq": ["$movingAvg", None]},
                     {"$gt": ["$bytes", {"$add": ["$movingAvg", {"$multiply": [sigma, {"$ifNull": ["$movingStd", 0]}]}]}]}]}]}}},
        # Output shape.
        {"$project": {"_id": 0, "srcIp": 1, "host": 1, "bucket": 1, "bytes": 1, "externalBytes": 1, "movingAvg": 1,
                      "movingStd": 1, "destinations": {"$slice": ["$destinations", 5]}}},
        # Largest transfers first.
        {"$sort": {"externalBytes": -1}},
    ]
