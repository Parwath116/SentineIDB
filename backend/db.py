"""MongoDB connection helpers shared by the API, scripts and benchmarks."""
from __future__ import annotations

from functools import lru_cache

from pymongo import MongoClient
from pymongo.database import Database

from backend import config


@lru_cache(maxsize=1)
def get_client() -> MongoClient:
    """Return a process-wide MongoClient (thread-safe, pooled)."""
    return MongoClient(config.MONGO_URI, tz_aware=True, serverSelectionTimeoutMS=5000)


def get_db() -> Database:
    """Return the sentineldb database handle."""
    return get_client()[config.MONGO_DB]
