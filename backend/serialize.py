"""JSON serialisation helpers for BSON values."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from bson import ObjectId


def jsonable(obj: Any) -> Any:
    """Recursively convert ObjectId -> str and datetime -> ISO-8601 (UTC)."""
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=timezone.utc)
        return obj.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(obj, dict):
        return {k: jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [jsonable(v) for v in obj]
    return obj
