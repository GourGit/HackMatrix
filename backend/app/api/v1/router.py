"""V1 API router — aggregates all versioned endpoint sub-routers.

Import this module and include ``v1_router`` in the main FastAPI app to
mount every ``/v1/…`` route.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.assessments import router as assessments_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.findings import router as findings_router
from app.api.v1.indicators import router as indicators_router

v1_router = APIRouter(prefix="/v1")

v1_router.include_router(assessments_router)
v1_router.include_router(evidence_router)
v1_router.include_router(findings_router)
v1_router.include_router(indicators_router)
