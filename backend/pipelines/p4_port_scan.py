"""Pipeline 4 - Port-scan detection (T1046): distinct destination ports per source IP per time bucket."""
from __future__ import annotations

from datetime import datetime

from backend.pipelines.common import THREAT_INTEL_LOOKUP, ts_range

NAME = "port_scan"
TITLE = "Port scan detection"
COLLECTION = "events"
MITRE = "T1046"
DESCRIPTION = ("Counts distinct dstPort values per source IP in 10-minute buckets over firewall denies "
               "($dateTrunc + $addToSet); flags buckets above the port threshold.")


def build(since: datetime | None = None, until: datetime | None = None, min_ports: int = 100, bucket_minutes: int = 10) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Firewall denies only, in range.
        {"$match": {"eventType": "fw_deny", **ts_range(since, until)}},
        # Per (source IP, 10-minute bucket): distinct ports and distinct destination hosts.
        {"$group": {"_id": {"srcIp": "$srcIp", "bucket": {"$dateTrunc": {"date": "$ts", "unit": "minute", "binSize": bucket_minutes}}},
                    "ports": {"$addToSet": "$dstPort"}, "hosts": {"$addToSet": "$host"}, "denies": {"$sum": 1}}},
        # Count the distinct values.
        {"$set": {"distinctPorts": {"$size": "$ports"}, "distinctHosts": {"$size": "$hosts"}}},
        # Threshold on the number of distinct ports within one bucket.
        {"$match": {"distinctPorts": {"$gte": min_ports}}},
        # Flatten the key and keep a short port sample as evidence.
        {"$project": {"_id": 0, "srcIp": "$_id.srcIp", "bucket": "$_id.bucket", "distinctPorts": 1, "distinctHosts": 1,
                      "denies": 1, "targetHost": {"$first": "$hosts"}, "samplePorts": {"$slice": ["$ports", 8]}}},
        # Enrich with threat intelligence.
        THREAT_INTEL_LOOKUP,
        # Reduce intel to a flag and category.
        {"$set": {"knownMalicious": {"$gt": [{"$size": "$intel"}, 0]}, "intelCategory": {"$first": "$intel.category"}}},
        # Remove the joined array.
        {"$unset": "intel"},
        # Largest scans first.
        {"$sort": {"distinctPorts": -1}},
    ]
