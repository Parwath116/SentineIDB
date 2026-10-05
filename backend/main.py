"""SentinelDB API (FastAPI)."""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from backend import auth, benchmark, config, detector
from backend.analytics import CHAIN_WINDOW, lateral_chains
from backend.db import get_db
from backend.pipelines import describe_all, get as get_pipeline, p5_lateral_movement, p7_dashboard_facets, p8_log_search, p9_materialize, to_json
from backend.serialize import jsonable

log = logging.getLogger("api")


def refresh_summaries(hours: int = 3) -> None:
    """Re-materialise the most recent hourly rows and the daily roll-up (cheap, $merge is an upsert)."""
    db = get_db()
    since = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours)
    list(db["events"].aggregate(p9_materialize.hourly(since=since)))
    list(db["hourly_summary"].aggregate(p9_materialize.daily()))


async def summary_loop() -> None:
    """Background task: keep the materialised summaries fresh for live data."""
    while True:
        await asyncio.sleep(60)
        try:
            await asyncio.to_thread(refresh_summaries)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            log.error("summary refresh failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: seed accounts, build summaries, start the detector and the summary refresher."""
    await asyncio.to_thread(auth.seed_accounts)
    if get_db()["hourly_summary"].estimated_document_count() == 0 and get_db()["events"].estimated_document_count() > 0:
        await asyncio.to_thread(refresh_summaries, 24 * 365)
    _, stop = detector.start_background(asyncio.get_running_loop())
    task = asyncio.create_task(summary_loop())
    yield
    stop.set()
    task.cancel()


app = FastAPI(title="SentinelDB API", version=config.APP_VERSION, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])

public = APIRouter(prefix="/api")
secured = APIRouter(prefix="/api", dependencies=[Depends(auth.current_user)])


def since_days(days: int) -> datetime:
    """UTC timestamp `days` days ago."""
    return datetime.now(timezone.utc) - timedelta(days=days)


def wrap(data: Any, pipeline: list[dict], collection: str, **extra: Any) -> dict[str, Any]:
    """Standard envelope: result plus the exact aggregation that produced it (for the Query Explorer)."""
    return jsonable({"data": data, "pipeline": to_json(pipeline), "collection": collection, **extra})


# ----------------------------------------------------------------------------- public

@public.get("/health")
def health() -> dict[str, Any]:
    """Liveness plus database ping."""
    get_db().client.admin.command("ping")
    return {"status": "ok", "version": config.APP_VERSION}


class LoginBody(BaseModel):
    """Login payload."""

    username: str
    password: str


@public.post("/auth/login")
def login(body: LoginBody) -> dict[str, Any]:
    """Exchange credentials for a JWT."""
    user = auth.authenticate(body.username, body.password)
    if not user:
        raise HTTPException(401, "Incorrect username or password.")
    return {"token": auth.create_token(user["username"], user["role"]),
            "user": {"username": user["username"], "fullName": user["fullName"], "role": user["role"]}}


# ----------------------------------------------------------------------------- secured

@secured.get("/auth/me")
def me(user: dict = Depends(auth.current_user)) -> dict[str, Any]:
    """Return the signed-in user."""
    return user


@secured.get("/pipelines")
def pipelines() -> list[dict[str, Any]]:
    """Every named pipeline with its JSON and description."""
    return describe_all()


@secured.get("/pipelines/{name}")
def pipeline_by_name(name: str) -> dict[str, Any]:
    """One pipeline by name."""
    p = get_pipeline(name)
    if not p:
        raise HTTPException(404, "No pipeline with that name.")
    return p


@secured.get("/dashboard/kpis")
def kpis() -> dict[str, Any]:
    """KPI cards: last-24h totals from hourly_summary plus alert counts."""
    db = get_db()
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    pipe = [{"$match": {"hour": {"$gte": since}}},
            {"$group": {"_id": None, "events": {"$sum": "$total"}, "suspicious": {"$sum": "$suspicious"},
                        "authFail": {"$sum": "$authFail"}, "bytesOut": {"$sum": "$bytesOut"}}}]
    totals = next(db["hourly_summary"].aggregate(pipe), {"events": 0, "suspicious": 0, "authFail": 0, "bytesOut": 0})
    totals.pop("_id", None)
    alerts = next(db["alerts"].aggregate([{"$facet": {
        "open": [{"$match": {"status": "open"}}, {"$count": "n"}],
        "critical": [{"$match": {"status": "open", "severity": "critical"}}, {"$count": "n"}]}}]))
    risky = next(db["ip_state"].aggregate([{"$match": {"riskScore": {"$gte": 50}}}, {"$count": "n"}]), {"n": 0})
    return wrap({**totals, "openAlerts": (alerts["open"] or [{"n": 0}])[0]["n"],
                 "criticalAlerts": (alerts["critical"] or [{"n": 0}])[0]["n"], "highRiskIps": risky["n"]},
                pipe, "hourly_summary", extraPipelines={
                    "alerts": to_json([{"$facet": {"open": [{"$match": {"status": "open"}}, {"$count": "n"}],
                                                   "critical": [{"$match": {"status": "open", "severity": "critical"}}, {"$count": "n"}]}}]),
                    "highRiskIps": to_json([{"$match": {"riskScore": {"$gte": 50}}}, {"$count": "n"}])})


@secured.get("/dashboard/attacks-per-hour")
def attacks_per_hour(days: int = Query(7, ge=1, le=30)) -> dict[str, Any]:
    """Hourly suspicious-event counts, read from the materialised hourly_summary."""
    pipe = [{"$match": {"hour": {"$gte": since_days(days)}}}, {"$sort": {"hour": 1}},
            {"$project": {"_id": 0, "hour": 1, "suspicious": 1, "authFail": 1, "fwDeny": 1, "total": 1}}]
    return wrap(list(get_db()["hourly_summary"].aggregate(pipe)), pipe, "hourly_summary")


@secured.get("/dashboard/facets")
def facets(days: int = Query(7, ge=1, le=30)) -> dict[str, Any]:
    """Top attackers, targeted hosts, severity mix and time-of-day buckets ($facet / $bucket)."""
    pipe = p7_dashboard_facets.build(since=since_days(days))
    return wrap(next(get_db()["events"].aggregate(pipe, allowDiskUse=True)), pipe, "events")


@secured.get("/dashboard/alert-severity")
def alert_severity() -> dict[str, Any]:
    """Alert counts per severity."""
    pipe = [{"$group": {"_id": "$severity", "alerts": {"$sum": 1}}}, {"$sort": {"alerts": -1}}]
    return wrap(list(get_db()["alerts"].aggregate(pipe)), pipe, "alerts")


@secured.get("/alerts")
def list_alerts(status: str | None = None, severity: str | None = None, limit: int = Query(100, le=500)) -> dict[str, Any]:
    """Alerts, newest first (served by the status/severity/ts compound index)."""
    match: dict[str, Any] = {}
    if status:
        match["status"] = status
    if severity:
        match["severity"] = severity
    pipe = [{"$match": match}, {"$sort": {"ts": -1}}, {"$limit": limit}]
    return wrap(list(get_db()["alerts"].aggregate(pipe)), pipe, "alerts")


def _oid(value: str) -> ObjectId:
    try:
        return ObjectId(value)
    except InvalidId:
        raise HTTPException(400, "That alert id is not valid.")


@secured.post("/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: str, user: dict = Depends(auth.current_user)) -> dict[str, Any]:
    """Mark an open alert as acknowledged by the current analyst."""
    res = get_db()["alerts"].update_one({"_id": _oid(alert_id), "status": "open"},
                                        {"$set": {"status": "acknowledged", "acknowledgedBy": user["username"]}})
    if res.matched_count == 0:
        raise HTTPException(409, "Only open alerts can be acknowledged.")
    return {"ok": True}


class EscalateBody(BaseModel):
    """Optional incident title/notes."""

    title: str | None = None
    notes: str = ""


@secured.post("/alerts/{alert_id}/escalate")
def escalate(alert_id: str, body: EscalateBody, user: dict = Depends(auth.current_user)) -> dict[str, Any]:
    """Create an incident from an alert and link them."""
    db = get_db()
    alert = next(db["alerts"].aggregate([{"$match": {"_id": _oid(alert_id)}}]), None)
    if not alert:
        raise HTTPException(404, "Alert not found.")
    if alert["status"] == "escalated":
        raise HTTPException(409, "This alert is already part of an incident.")
    inc = {"createdAt": datetime.now(timezone.utc), "title": body.title or f"{alert['type']} from {alert['srcIp']}",
           "severity": alert["severity"], "status": "open", "alertIds": [alert["_id"]], "createdBy": user["username"],
           "notes": body.notes}
    inc_id = db["incidents"].insert_one(inc).inserted_id
    db["alerts"].update_one({"_id": alert["_id"]}, {"$set": {"status": "escalated", "incidentId": inc_id,
                                                              "acknowledgedBy": user["username"]}})
    return {"ok": True, "incidentId": str(inc_id)}


@secured.get("/incidents")
def incidents() -> dict[str, Any]:
    """Incidents with their linked alerts."""
    pipe = [{"$sort": {"createdAt": -1}}, {"$limit": 100},
            {"$lookup": {"from": "alerts", "localField": "alertIds", "foreignField": "_id", "as": "alerts"}},
            {"$project": {"alerts.evidence": 0}}]
    return wrap(list(get_db()["incidents"].aggregate(pipe)), pipe, "incidents")


@secured.get("/chains/origins")
def chain_origins() -> dict[str, Any]:
    """Hosts that opened remote-admin sessions, with chain depth (2+ hops is flagged)."""
    chains = lateral_chains(get_db())
    chains.sort(key=lambda c: (not c["flagged"], c["firstTs"]), reverse=False)
    return wrap(chains, p5_lateral_movement.candidate_origins(), "connections")


@secured.get("/chains/trace")
def chain_trace(host: str, since: datetime | None = None, window_minutes: int = Query(60, ge=1, le=1440)) -> dict[str, Any]:
    """Trace a lateral-movement chain from `host` with $graphLookup and return graph nodes + links."""
    db = get_db()
    if since is None:
        cand = next((c for c in db["connections"].aggregate(p5_lateral_movement.candidate_origins()) if c["host"] == host), None)
        since = (cand["firstTs"] if cand else datetime.now(timezone.utc)) - timedelta(minutes=1)
    until = since + timedelta(minutes=window_minutes)
    pipe = p5_lateral_movement.build(host, since, until)
    res = next(db["hosts"].aggregate(pipe), None)
    if res is None:
        raise HTTPException(404, "That host is not in the inventory.")
    edges = sorted(res["chain"], key=lambda e: (e["hop"], e["ts"]))
    names = {host} | {e["srcHost"] for e in edges} | {e["dstHost"] for e in edges}
    info = {h["hostname"]: h for h in db["hosts"].aggregate([{"$match": {"hostname": {"$in": list(names)}}}, {"$project": {"_id": 0}}])}
    hop_of = {host: 0}
    for e in edges:
        hop_of.setdefault(e["dstHost"], e["hop"] + 1)
    nodes = [{"id": n, "subnet": info.get(n, {}).get("subnet"), "criticality": info.get(n, {}).get("criticality"),
              "ip": info.get(n, {}).get("ip"), "hop": hop_of.get(n, 0), "origin": n == host} for n in names]
    links = [{"source": e["srcHost"], "target": e["dstHost"], "protocol": e["protocol"], "ts": e["ts"], "hop": e["hop"] + 1}
             for e in edges]
    return wrap({"nodes": nodes, "links": links, "origin": host, "hops": res["deepest"] if edges else 0,
                 "from": since, "until": until}, pipe, "hosts")


@secured.get("/search")
def search(q: str = Query(..., min_length=2), limit: int = Query(25, le=100)) -> dict[str, Any]:
    """Full-text search over raw log messages, ranked by text score and joined with events."""
    pipe = p8_log_search.build(q, limit)
    return wrap(list(get_db()["raw_logs"].aggregate(pipe)), pipe, "raw_logs")


@secured.get("/benchmarks")
def benchmarks_results() -> dict[str, Any]:
    """Latest saved benchmark results."""
    if not config.BENCHMARK_FILE.exists():
        raise HTTPException(404, "No benchmark has been run yet. Run one from this page.")
    return json.loads(config.BENCHMARK_FILE.read_text())


@secured.post("/benchmarks/run")
async def benchmarks_run() -> dict[str, Any]:
    """Run the benchmark suite (takes a minute) and save results."""
    return await asyncio.to_thread(benchmark.run_all)


@secured.get("/stream/counts")
def counts_snapshot() -> dict[str, Any]:
    """Snapshot of events in the last minute and open alerts (same figures the SSE stream pushes)."""
    return snapshot()


def snapshot() -> dict[str, Any]:
    """Events in the last 60 s, total events (estimated), and open alerts."""
    db = get_db()
    last = next(db["events"].aggregate([{"$match": {"ts": {"$gte": datetime.now(timezone.utc) - timedelta(seconds=60)}}},
                                        {"$count": "n"}]), {"n": 0})
    open_alerts = next(db["alerts"].aggregate([{"$match": {"status": "open"}}, {"$count": "n"}]), {"n": 0})
    return {"eventsLastMinute": last["n"], "openAlerts": open_alerts["n"],
            "totalEvents": db["events"].estimated_document_count(), "at": datetime.now(timezone.utc)}


app.include_router(public)
app.include_router(secured)


@app.get("/api/stream")
async def stream(token: str = Query(...)) -> EventSourceResponse:
    """Server-Sent Events: new alerts as they are created plus event counters every 3 s.

    EventSource cannot set headers, so the JWT is accepted as a query parameter on this endpoint only.
    """
    try:
        jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Your session has expired. Sign in again.")
    queue = detector.bus.subscribe()

    async def gen():
        try:
            yield {"event": "counts", "data": json.dumps(jsonable(await asyncio.to_thread(snapshot)))}
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=3)
                    yield {"event": msg["type"], "data": json.dumps(jsonable(msg["data"]))}
                except asyncio.TimeoutError:
                    yield {"event": "counts", "data": json.dumps(jsonable(await asyncio.to_thread(snapshot)))}
        finally:
            detector.bus.unsubscribe(queue)

    return EventSourceResponse(gen())


# Serve frontend SPA
dist_dir = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if dist_dir.exists():
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    assets_dir = dist_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404, "API endpoint not found")
        target = dist_dir / full_path
        if target.is_file():
            return FileResponse(target)
        return FileResponse(dist_dir / "index.html")

