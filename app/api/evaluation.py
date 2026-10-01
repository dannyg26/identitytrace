"""Evaluation harness API (blueprint §9.2: POST /evaluation/run).

Runs entirely against a throwaway in-memory database
(app/evaluation/harness.py) - never the live one - so calling this can
never pollute real SOC data with synthetic incidents.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.evaluation.service import run_interactive_evaluation

router = APIRouter(tags=["evaluation"])


class EvaluationRequest(BaseModel):
    seed: int = 42
    scenarios_per_type: int = Field(default=2, ge=1, le=10)
    num_benign_identities: int = Field(default=5, ge=1, le=20)


@router.post("/evaluation/run")
def evaluation_run(request: EvaluationRequest = EvaluationRequest()) -> dict:
    return run_interactive_evaluation(
        seed=request.seed,
        scenarios_per_type=request.scenarios_per_type,
        num_benign_identities=request.num_benign_identities,
    )
