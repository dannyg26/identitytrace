"""Bound concurrent interactive benchmark work independently of ingestion."""

from threading import BoundedSemaphore

from fastapi import HTTPException

from app.evaluation.harness import run_evaluation

_slot = BoundedSemaphore(1)


def run_interactive_evaluation(**kwargs):
    if not _slot.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="An evaluation is already running", headers={"Retry-After": "10"})
    try:
        return run_evaluation(**kwargs)
    finally:
        _slot.release()
