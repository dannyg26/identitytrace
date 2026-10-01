"""Bounded, authenticated and audited exports using the same filters as the queue."""

import csv
import io
from threading import BoundedSemaphore

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import Response

from app.incident_query import IncidentFilters, incident_query
from app.models.db import get_db
from app.models.event import EventRecord
from app.models.incident import IncidentRecord
from app.models.operations import AuditRecord
from app.reports import incident_report, summary_report

router = APIRouter(prefix="/reports", tags=["reports"])
_slot = BoundedSemaphore(2)
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _export(db, request, name, media_type, build, details):
    if not _slot.acquire(blocking=False):
        raise HTTPException(429, "Report capacity reached; retry shortly", headers={"Retry-After": "5"})
    try:
        content = build()
        db.add(AuditRecord(principal=request.state.principal.name, action="report.exported",
                           entity_id=name, after=details))
        db.commit()
        return Response(content, media_type=media_type,
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})
    finally:
        _slot.release()


@router.get("/summary.docx")
def export_summary(request: Request, filters: IncidentFilters = Depends(), db=Depends(get_db)):
    query = incident_query(db, filters)
    total = query.count()
    rows = [r.to_dict() for r in query.limit(100).all()]
    return _export(db, request, "identitytrace-incidents.docx", DOCX,
                   lambda: summary_report(rows, total, filters.model_dump(exclude_defaults=True)),
                   {"rows": len(rows), "matching": total})


@router.get("/incidents.csv")
def export_csv(request: Request, filters: IncidentFilters = Depends(), db=Depends(get_db)):
    query = incident_query(db, filters)
    if query.count() > 5000:
        raise HTTPException(422, "More than 5000 incidents match. Narrow the filters before exporting.")
    rows = query.limit(5000).all()

    def build():
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        fields = ("incident_id", "identity_id", "severity", "status", "last_event_at", "correlation_rule_title", "superseded_at")
        writer.writerow(fields)
        for row in rows:
            values = [str(getattr(row, field) or "") for field in fields]
            writer.writerow(["'" + v if v.lstrip().startswith(("=", "+", "-", "@")) or v.startswith(("\t", "\r", "\n")) else v for v in values])
        return stream.getvalue().encode("utf-8-sig")

    return _export(db, request, "identitytrace-incidents.csv", "text/csv", build, {"rows": len(rows)})


@router.get("/incidents/{incident_id}.docx")
def export_incident(incident_id: str, request: Request, db=Depends(get_db)):
    record = db.get(IncidentRecord, incident_id)
    if record is None:
        raise HTTPException(404, "Incident not found")
    if len(record.evidence_ids) > 500:
        raise HTTPException(422, "This incident exceeds the 500-event report limit")
    events = db.query(EventRecord).filter(EventRecord.event_id.in_(record.evidence_ids)).order_by(EventRecord.timestamp, EventRecord.event_id).all()
    data = [event.to_schema().model_dump(mode="json") for event in events]
    return _export(db, request, "identitytrace-incident.docx", DOCX,
                   lambda: incident_report(record.to_dict(), data), {"incident_id": incident_id, "events": len(data)})
