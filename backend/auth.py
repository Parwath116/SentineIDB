"""Authentication helpers: bcrypt password hashing, JWT issue/verify, and account seeding."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend import config
from backend.db import get_db

log = logging.getLogger("auth")
bearer = HTTPBearer(auto_error=False)

# Accounts shown on the login page in the "Evaluation environment" notice.
SEEDED_ACCOUNTS = [
    {"username": "analyst", "password": "Sentinel-Analyst#2026", "fullName": "Priya Raman",
     "department": "Security Operations", "role": "analyst"},
    {"username": "admin", "password": "Sentinel-Admin#2026", "fullName": "Marcus Hale",
     "department": "Security Operations", "role": "admin"},
]


def hash_password(plain: str) -> str:
    """Return a bcrypt hash (salted, cost 12)."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time bcrypt comparison."""
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except ValueError:
        return False


def seed_accounts() -> None:
    """Upsert the two seeded analyst accounts (idempotent; password hash set on insert only)."""
    users = get_db()["users"]
    for acc in SEEDED_ACCOUNTS:
        users.update_one(
            {"username": acc["username"]},
            {"$setOnInsert": {"passwordHash": hash_password(acc["password"])},
             "$set": {"fullName": acc["fullName"], "department": acc["department"], "role": acc["role"]}},
            upsert=True,
        )
    log.info("seeded accounts: %s", [a["username"] for a in SEEDED_ACCOUNTS])


def create_token(username: str, role: str) -> str:
    """Sign a JWT carrying username and role."""
    exp = datetime.now(timezone.utc) + timedelta(minutes=config.JWT_EXPIRE_MINUTES)
    return jwt.encode({"sub": username, "role": role, "exp": exp}, config.JWT_SECRET, algorithm="HS256")


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Return the user document if credentials are valid, else None."""
    user = next(get_db()["users"].aggregate([
        {"$match": {"username": username, "passwordHash": {"$exists": True}}}, {"$limit": 1}]), None)
    if user and verify_password(password, user["passwordHash"]):
        return user
    return None


def current_user(cred: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict[str, Any]:
    """FastAPI dependency: decode the bearer token or raise 401."""
    if cred is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in to continue.")
    try:
        payload = jwt.decode(cred.credentials, config.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Your session has expired. Sign in again.")
    return {"username": payload["sub"], "role": payload["role"]}
