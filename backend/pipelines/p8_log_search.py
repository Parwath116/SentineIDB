"""Pipeline 8 - Log message search: $text with relevance score, joined to the structured events."""
from __future__ import annotations

NAME = "log_search"
TITLE = "Log message search"
COLLECTION = "raw_logs"
MITRE = None
DESCRIPTION = ("$text search on raw_logs (text index), ranked by textScore, then $lookup into events to attach "
               "the structured record with the same source IP and timestamp.")


def build(query: str, limit: int = 25) -> list[dict]:
    """Return the aggregation pipeline."""
    return [
        # Full-text match using the text index on `message` ($text must be the first stage).
        {"$match": {"$text": {"$search": query}}},
        # Attach the relevance score computed by the text engine.
        {"$set": {"score": {"$meta": "textScore"}}},
        # Best matches first.
        {"$sort": {"score": -1}},
        # Limit the hits before the join so the lookup runs on few documents.
        {"$limit": limit},
        # Join the structured event (same srcIp + ts + host) from the time-series collection.
        {"$lookup": {"from": "events", "let": {"ip": "$srcIp", "t": "$ts", "h": "$host"},
                     "pipeline": [{"$match": {"$expr": {"$and": [{"$eq": ["$srcIp", "$$ip"]}, {"$eq": ["$ts", "$$t"]},
                                                                  {"$eq": ["$host", "$$h"]}]}}},
                                  {"$project": {"_id": 0, "eventType": 1, "dstIp": 1, "dstPort": 1, "user": 1, "severity": 1,
                                                "bytesOut": 1, "statusCode": 1}},
                                  {"$limit": 1}],
                     "as": "event"}},
        # Flatten the joined array to one object (or null when the log line has no structured event).
        {"$set": {"event": {"$first": "$event"}}},
        # Output shape.
        {"$project": {"message": 1, "ts": 1, "host": 1, "srcIp": 1, "source": 1, "score": 1, "event": 1}},
    ]
