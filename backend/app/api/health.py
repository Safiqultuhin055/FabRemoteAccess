"""Health endpoints. Readiness is reported only from a real database check, never assumed."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import DatabaseGateway, get_database

router = APIRouter(prefix="/health", tags=["health"])


class LiveResponse(BaseModel):
    status: Literal["ok"]


class ReadinessChecks(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    database: Literal["ok", "error", "not_configured"]
    schema_: Literal["ok", "mismatch", "unknown"] = Field(alias="schema")


class ReadyResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    checks: ReadinessChecks


@router.get("/live", response_model=LiveResponse, summary="Process is running (no dependency checks)")
def live() -> LiveResponse:
    return LiveResponse(status="ok")


@router.get("/ready", response_model=ReadyResponse, summary="Dependencies verified",
            responses={503: {"model": ReadyResponse, "description": "A dependency is not ready"}})
def ready(database: Annotated[DatabaseGateway, Depends(get_database)]) -> JSONResponse:
    result = database.check_readiness()
    body = ReadyResponse(status="ready" if result.ready else "not_ready",
                         checks=ReadinessChecks(database=result.database, schema=result.schema))
    return JSONResponse(body.model_dump(by_alias=True), status_code=200 if result.ready else 503)
