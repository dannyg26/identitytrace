"""Evaluation harness API (blueprint §9.2: POST /evaluation/run).

Runs entirely against a throwaway in-memory database
(app/evaluation/harness.py) - never the live one - so calling this can
never pollute real SOC data with synthetic incidents.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.evaluation.harness import run_evaluation

router = APIRouter(tags=["evaluation"])


class EvaluationRequest(BaseModel):
    seed: int = 42
    scenarios_per_type: int = 2
    num_benign_identities: int = 5


@router.post("/evaluation/run")
def evaluation_run(request: EvaluationRequest = EvaluationRequest()) -> dict:
    return run_evaluation(
        seed=request.seed,
        scenarios_per_type=request.scenarios_per_type,
        num_benign_identities=request.num_benign_identities,
    )
