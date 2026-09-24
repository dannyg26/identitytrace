"""IdentityTrace FastAPI application entrypoint.

Wires the JSON API (mounted under /api) and a separate server-rendered
dashboard (clean paths: /, /events, /rules). These are kept in distinct
path namespaces on purpose: the API and the dashboard both need a resource
called "events" (and, from here, "detections" and later "incidents") and
registering both a JSON route and an HTML route on the exact same path
means Starlette just matches whichever was added to the router first,
silently shadowing the other - which is what happened here in Phase 1
before this split (the /events dashboard page was unreachable dead code).
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.detections import get_loaded_rules, set_loaded_rules
from app.api.detections import router as detections_router
from app.api.evaluation import router as evaluation_router
from app.api.events import router as events_router
from app.api.identities import load_identity_context
from app.api.identities import router as identities_router
from app.api.incidents import (
    ALLOWED_STATUSES,
    set_loaded_correlation_rules,
)
from app.api.incidents import router as incidents_router
from app.correlation.loader import load_correlation_rules
from app.detections.loader import load_rules
from app.evaluation.harness import run_evaluation
from app.graph.build import build_incident_graph
from app.graph.svg import render_svg
from app.models.baseline import BaselineDeviationRecord
from app.models.db import SessionLocal, init_db
from app.models.detection import DetectionMatchRecord
from app.models.event import EventRecord
from app.models.incident import IncidentRecord

BASE_DIR = Path(__file__).resolve().parent.parent
# See app/detections/loader.py's _default_detections_dir() docstring: this
# relative path only resolves correctly when app/ sits in a source
# checkout (local run or editable install) - override for other layouts.
DASHBOARD_DIR = Path(os.environ.get("IDENTITYTRACE_DASHBOARD_DIR", str(BASE_DIR / "dashboard")))


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    set_loaded_rules(load_rules())
    set_loaded_correlation_rules(load_correlation_rules())
    yield


app = FastAPI(
    title="IdentityTrace",
    description="Cross-SaaS identity attack detection platform (research/lab build).",
    version="1.0.0",
    lifespan=_lifespan,
)

app.include_router(events_router, prefix="/api")
app.include_router(detections_router, prefix="/api")
app.include_router(identities_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(evaluation_router, prefix="/api")

if (DASHBOARD_DIR / "static").exists():
    app.mount(
        "/static", StaticFiles(directory=DASHBOARD_DIR / "static"), name="static"
    )

templates = Jinja2Templates(directory=DASHBOARD_DIR / "templates")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def overview(request: Request) -> Any:  # noqa: ANN401 - Jinja2 response type
    db: Session = SessionLocal()
    try:
        total = db.query(func.count(EventRecord.event_id)).scalar() or 0
        by_source = dict(
            db.query(EventRecord.source, func.count(EventRecord.event_id))
            .group_by(EventRecord.source)
            .all()
        )
        recent = (
            db.query(EventRecord)
            .order_by(EventRecord.timestamp.desc())
            .limit(10)
            .all()
        )
        recent_matches = (
            db.query(DetectionMatchRecord)
            .order_by(DetectionMatchRecord.timestamp.desc())
            .limit(10)
            .all()
        )
        recent_incidents = (
            db.query(IncidentRecord)
            .order_by(IncidentRecord.last_event_at.desc())
            .limit(10)
            .all()
        )
    finally:
        db.close()
    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "total": total,
            "by_source": by_source,
            "recent": [r.to_schema() for r in recent],
            "recent_matches": [m.to_dict() for m in recent_matches],
            "recent_incidents": [i.to_dict() for i in recent_incidents],
        },
    )


@app.get("/events")
def events_page(
    request: Request,
    source: str | None = None,
    actor_id: str | None = None,
) -> Any:  # noqa: ANN401 - Jinja2 response type
    db: Session = SessionLocal()
    try:
        query = db.query(EventRecord)
        if source:
            query = query.filter(EventRecord.source == source)
        if actor_id:
            query = query.filter(EventRecord.actor_id == actor_id)
        records = query.order_by(EventRecord.timestamp.desc()).limit(200).all()
        event_ids = [r.event_id for r in records]
        matches_by_event: dict[str, list[dict]] = {}
        deviations_by_event: dict[str, list[dict]] = {}
        if event_ids:
            for m in (
                db.query(DetectionMatchRecord)
                .filter(DetectionMatchRecord.event_id.in_(event_ids))
                .all()
            ):
                matches_by_event.setdefault(m.event_id, []).append(m.to_dict())
            for d in (
                db.query(BaselineDeviationRecord)
                .filter(BaselineDeviationRecord.event_id.in_(event_ids))
                .all()
            ):
                deviations_by_event.setdefault(d.event_id, []).append(d.to_dict())
    finally:
        db.close()
    return templates.TemplateResponse(
        request,
        "events.html",
        {
            "events": [r.to_schema() for r in records],
            "matches_by_event": matches_by_event,
            "deviations_by_event": deviations_by_event,
            "source": source or "",
            "actor_id": actor_id or "",
        },
    )


@app.get("/rules")
def rules_page(request: Request) -> Any:  # noqa: ANN401 - Jinja2 response type
    db: Session = SessionLocal()
    try:
        last_triggered = dict(
            db.query(
                DetectionMatchRecord.rule_id, func.max(DetectionMatchRecord.timestamp)
            ).group_by(DetectionMatchRecord.rule_id)
        )
    finally:
        db.close()
    rules = sorted(get_loaded_rules(), key=lambda r: r.id)
    return templates.TemplateResponse(
        request,
        "rules.html",
        {
            "rules": rules,
            "last_triggered": last_triggered,
        },
    )


@app.get("/identities")
def identities_page(request: Request) -> Any:  # noqa: ANN401 - Jinja2 response type
    db: Session = SessionLocal()
    try:
        rows = (
            db.query(
                EventRecord.actor_id,
                func.count(EventRecord.event_id),
                func.max(EventRecord.timestamp),
            )
            .group_by(EventRecord.actor_id)
            .order_by(func.max(EventRecord.timestamp).desc())
            .all()
        )
    finally:
        db.close()
    identities = [
        {"actor_id": actor_id, "event_count": count, "last_seen": last_seen}
        for actor_id, count, last_seen in rows
    ]
    return templates.TemplateResponse(
        request, "identities.html", {"identities": identities}
    )


@app.get("/identities/{actor_id}")
def identity_detail_page(request: Request, actor_id: str) -> Any:  # noqa: ANN401
    db: Session = SessionLocal()
    try:
        context = load_identity_context(db, actor_id)
    finally:
        db.close()
    if context is None:
        raise HTTPException(status_code=404, detail=f"identity '{actor_id}' not found")
    return templates.TemplateResponse(request, "identity_detail.html", context)


@app.get("/incidents")
def incidents_page(
    request: Request,
    severity: str | None = None,
    status: str | None = None,
) -> Any:  # noqa: ANN401 - Jinja2 response type
    db: Session = SessionLocal()
    try:
        query = db.query(IncidentRecord)
        if severity:
            query = query.filter(IncidentRecord.severity == severity)
        if status:
            query = query.filter(IncidentRecord.status == status)
        records = query.order_by(IncidentRecord.last_event_at.desc()).limit(200).all()
    finally:
        db.close()
    return templates.TemplateResponse(
        request,
        "incidents.html",
        {
            "incidents": [r.to_dict() for r in records],
            "severity": severity or "",
            "status": status or "",
        },
    )


@app.get("/incidents/{incident_id}")
def incident_detail_page(request: Request, incident_id: str) -> Any:  # noqa: ANN401
    db: Session = SessionLocal()
    try:
        record = db.get(IncidentRecord, incident_id)
        if record is None:
            raise HTTPException(
                status_code=404, detail=f"incident '{incident_id}' not found"
            )
        incident = record.to_dict()
        events_by_id = {
            e.event_id: e.to_schema()
            for e in db.query(EventRecord)
            .filter(EventRecord.event_id.in_(incident["evidence_ids"]))
            .all()
        }
        graph = build_incident_graph(db, incident)
        graph_svg = render_svg(graph)
    finally:
        db.close()
    timeline = [
        events_by_id[eid] for eid in incident["evidence_ids"] if eid in events_by_id
    ]
    return templates.TemplateResponse(
        request,
        "incident_detail.html",
        {
            "incident": incident,
            "timeline": timeline,
            "allowed_statuses": sorted(ALLOWED_STATUSES),
            "graph_svg": graph_svg,
        },
    )


@app.get("/evaluation")
def evaluation_page(
    request: Request,
    seed: int = 42,
    scenarios_per_type: int = 2,
) -> Any:  # noqa: ANN401 - Jinja2 response type
    # Runs synchronously against a throwaway in-memory DB (see
    # app/evaluation/harness.py) - fast at this dataset size, and never
    # touches the live database backing the rest of the dashboard.
    metrics = run_evaluation(seed=seed, scenarios_per_type=scenarios_per_type)
    return templates.TemplateResponse(
        request,
        "evaluation.html",
        {
            "metrics": metrics,
            "seed": seed,
            "scenarios_per_type": scenarios_per_type,
        },
    )


@app.get("/alerts")
def alerts_page(request: Request, actor_id: str | None = None) -> Any:  # noqa: ANN401
    """Phase 9 #9: high/critical atomic matches as their own queue,
    alongside (not instead of) /incidents - see app/api/detections.py's
    list_alerts() docstring."""
    db: Session = SessionLocal()
    try:
        query = db.query(DetectionMatchRecord).filter(
            DetectionMatchRecord.severity.in_(["high", "critical"])
        )
        if actor_id:
            query = query.filter(DetectionMatchRecord.actor_id == actor_id)
        records = query.order_by(DetectionMatchRecord.timestamp.desc()).limit(200).all()
    finally:
        db.close()
    return templates.TemplateResponse(
        request,
        "alerts.html",
        {"alerts": [r.to_dict() for r in records], "actor_id": actor_id or ""},
    )
