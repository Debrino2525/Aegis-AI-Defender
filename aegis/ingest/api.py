"""Telemetry ingestion API routes."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from aegis.ingest.manager import get_telemetry_manager

router = APIRouter()


class LogParseRequest(BaseModel):
    log_format: str = Field(..., description="Format type: cef, leef, json")
    raw_log: str = Field(..., description="Raw log string")


@router.post("/api/telemetry/parse")
async def parse_log(body: LogParseRequest):
    """Parse a log line using the specified format."""
    manager = get_telemetry_manager()
    result = manager.parse_log(body.log_format, body.raw_log)
    if result:
        return {"success": True, "event": result}
    raise HTTPException(status_code=400, detail="Failed to parse log")
