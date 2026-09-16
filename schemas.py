from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, field_validator


def _as_utc(dt: datetime) -> datetime:
    """SQLite has no real timezone-aware storage — even though our columns
    are declared DateTime(timezone=True), values round-trip as naive
    datetimes (confirmed: tzinfo is None after a DB round-trip). Since every
    timestamp in this app is written via SQLite's CURRENT_TIMESTAMP or
    Python's own UTC clock, a naive value here is always UTC in practice —
    so we tag it explicitly rather than leave it ambiguous. Without this,
    the JSON goes out as e.g. "2026-09-16T17:48:23" with no zone marker,
    and per the JS Date spec, a browser then parses that as LOCAL time —
    silently mislabeling a UTC clock reading as if it were already in the
    viewer's timezone. That's a real bug this fixes, not a display quirk."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class BlockCreate(BaseModel):
    source: str
    command: str
    entity: str
    params: dict[str, Any] = {}


class TamperRequest(BaseModel):
    offchain_command: str
    offchain_params: dict[str, Any] = {}


class BlockOut(BaseModel):
    id: int
    ts: datetime
    source: str
    command: str
    entity: str
    params: dict[str, Any]
    prev_hash: str
    onchain_hash: str
    preimage: str
    tx_hash: Optional[str] = None
    onchain_index: Optional[int] = None
    anchor_error: Optional[str] = None
    offchain_command: str
    offchain_params: dict[str, Any]
    offchain_hash: str
    tampered: bool

    model_config = {"from_attributes": True}

    @field_validator("ts")
    @classmethod
    def _tag_utc(cls, v: datetime) -> datetime:
        return _as_utc(v)


class VerifyResult(BaseModel):
    chain_length: int
    chain_verified: bool
    mismatches: list[int]


class TelemetryIn(BaseModel):
    source: str = "RTU-07 Reactor"
    entity: str = "REACTOR-01"
    pressure: float
    temp: float
    vibration: float


class TelemetryEval(BaseModel):
    physics_breach: list[str]
    ml_score: float
    is_anomaly: bool


class AnomalyOut(BaseModel):
    id: int
    ts: datetime
    block_id: Optional[int]
    severity: str
    title: str
    description: str
    technique: Optional[str]
    ml_score: Optional[float]

    model_config = {"from_attributes": True}

    @field_validator("ts")
    @classmethod
    def _tag_utc(cls, v: datetime) -> datetime:
        return _as_utc(v)


class ForensicStep(BaseModel):
    block_id: int
    ts: datetime
    title: str
    description: str
    flag: Optional[str] = None  # "tamper" | "root" | None

    @field_validator("ts")
    @classmethod
    def _tag_utc(cls, v: datetime) -> datetime:
        return _as_utc(v)


class ReconstructRequest(BaseModel):
    start_block_id: int


class AttributionOut(BaseModel):
    scores: dict[str, int]
    leader: Optional[str]
    tied_with: list[str] = []


class ReconstructResult(BaseModel):
    steps: list[ForensicStep]
    attribution: AttributionOut


class MitreTechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str
    hit: bool
