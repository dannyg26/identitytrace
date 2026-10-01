"""Administrative identity links and read-only change history."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.detections import get_loaded_rules
from app.api.incidents import get_loaded_correlation_rules
from app.models.db import get_db
from app.models.event import KNOWN_SOURCES
from app.models.operations import AuditRecord, IdentityLink
from app.pipeline import rebuild_evidence
from app.writes import write_lock

router = APIRouter(tags=["administration"])


class IdentityLinkRequest(BaseModel):
    source: str
    alias: str = Field(min_length=1, max_length=320)
    canonical_id: str = Field(min_length=1, max_length=320)

    @field_validator("source")
    @classmethod
    def known_source(cls, value):
        if value not in KNOWN_SOURCES:
            raise ValueError("Unknown source")
        return value

    @field_validator("alias", "canonical_id")
    @classmethod
    def nonblank(cls, value):
        if not value.strip() or value != value.strip():
            raise ValueError("Identity identifiers must be nonblank without surrounding whitespace")
        return value


@router.get("/identity-links")
def list_links(db: Session = Depends(get_db)):
    return [{"source": row.source, "alias": row.alias, "canonical_id": row.canonical_id}
            for row in db.query(IdentityLink).order_by(IdentityLink.source, IdentityLink.alias).all()]


@router.post("/identity-links", status_code=201)
def create_link(payload: IdentityLinkRequest, request: Request, db: Session = Depends(get_db)):
    with write_lock(db):
        try:
            existing = db.get(IdentityLink, (payload.source, payload.alias))
            if existing:
                if existing.canonical_id != payload.canonical_id:
                    raise HTTPException(status_code=409, detail="Alias is already linked to another identity")
                db.commit()
                return payload.model_dump()
            db.add(IdentityLink(**payload.model_dump()))
            db.flush()
            rebuild_evidence(db, get_loaded_rules(), get_loaded_correlation_rules())
            db.add(AuditRecord(principal=request.state.principal.name, action="identity.linked",
                               entity_id=f"{payload.source}:{payload.alias}", after=payload.model_dump()))
            db.commit()
            return payload.model_dump()
        except Exception:
            db.rollback()
            raise


@router.get("/audit")
def list_audit(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
               db: Session = Depends(get_db)):
    return [row.to_dict() for row in db.query(AuditRecord).order_by(
        AuditRecord.timestamp.desc(), AuditRecord.id
    ).offset(offset).limit(limit).all()]
