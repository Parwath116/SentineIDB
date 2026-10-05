"""Central configuration, loaded from environment variables / .env."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/?replicaSet=rs0&directConnection=true")
MONGO_DB: str = os.getenv("MONGO_DB", "sentineldb")
JWT_SECRET: str = os.getenv("JWT_SECRET", "change-me")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))
CORS_ORIGINS: list[str] = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")]
APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")

# Detection thresholds applied to ip_state counters.
TH_FAILED_LOGINS: int = int(os.getenv("TH_FAILED_LOGINS", "100"))
TH_DISTINCT_PORTS: int = int(os.getenv("TH_DISTINCT_PORTS", "100"))
TH_DISTINCT_USERS: int = int(os.getenv("TH_DISTINCT_USERS", "15"))
TH_BYTES_OUT: int = int(os.getenv("TH_BYTES_OUT", "500000000"))

BENCHMARK_FILE: Path = ROOT_DIR / "benchmarks" / "results.json"

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
