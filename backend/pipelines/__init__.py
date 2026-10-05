"""Registry of the named aggregation pipelines exposed through /api/pipelines."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from bson import json_util
import json

from backend.pipelines import (p1_failed_login_velocity, p2_brute_force, p3_password_spraying, p4_port_scan,
                               p5_lateral_movement, p6_exfiltration, p7_dashboard_facets, p8_log_search,
                               p9_materialize, p10_login_velocity, p11_exfil_anomaly)

MODULES = [p2_brute_force, p3_password_spraying, p4_port_scan, p5_lateral_movement,
           p6_exfiltration, p7_dashboard_facets, p8_log_search, p9_materialize,
           p10_login_velocity, p11_exfil_anomaly]


def _example_args(mod: Any) -> dict[str, Any]:
    """Representative arguments used when rendering a pipeline for display."""
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    if mod is p5_lateral_movement:
        return {"start_host": "nwl-ws-12", "since": now, "until": now + timedelta(hours=1)}
    if mod is p8_log_search:
        return {"query": "failed password"}
    return {}


def to_json(pipeline: list[dict]) -> Any:
    """Convert a pipeline to plain JSON (dates become {"$date": ...})."""
    return json.loads(json_util.dumps(pipeline, json_options=json_util.RELAXED_JSON_OPTIONS))


def describe_all() -> list[dict[str, Any]]:
    """Return name/title/description/collection/MITRE/pipeline for every module."""
    out = []
    for m in MODULES:
        entry = {"name": m.NAME, "title": m.TITLE, "description": m.DESCRIPTION, "collection": m.COLLECTION,
                 "mitre": m.MITRE, "pipeline": to_json(m.build(**_example_args(m)))}
        if m is p9_materialize:
            entry["pipelineDaily"] = to_json(m.daily())
        if m is p5_lateral_movement:
            entry["pipelineCandidates"] = to_json(m.candidate_origins())
        out.append(entry)
    return out


def get(name: str) -> dict[str, Any] | None:
    """Return one pipeline description by name."""
    return next((d for d in describe_all() if d["name"] == name), None)
