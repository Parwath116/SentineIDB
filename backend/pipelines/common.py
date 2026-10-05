"""Shared helpers for pipeline modules."""
from __future__ import annotations

from datetime import datetime
from typing import Any


def ts_range(since: datetime | None, until: datetime | None) -> dict[str, Any]:
    """Return a `ts` range filter fragment (empty when unbounded) usable inside $match."""
    cond: dict[str, Any] = {}
    if since:
        cond["$gte"] = since
    if until:
        cond["$lt"] = until
    return {"ts": cond} if cond else {}


INTERNAL_IP_REGEX = r"^10\."
SERVER_IP_REGEX = r"^10\.10\."

# Threat-intel enrichment, reused by several detections.
THREAT_INTEL_LOOKUP = {
    "$lookup": {
        "from": "threat_intel",
        "localField": "srcIp",
        "foreignField": "ip",
        "as": "intel",
    }
}
