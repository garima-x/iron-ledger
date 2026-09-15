from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, Float
from sqlalchemy.sql import func

from .database import Base


class LedgerBlock(Base):
    """
    Mirrors the frontend's block shape, but here it's the source of truth.

    `onchain_*` fields are what was actually hashed and (if configured)
    anchored to Sepolia. `offchain_*` fields represent the mutable local
    historian record — the thing an attacker could rewrite after the fact.
    `offchain_hash` is recomputed on every read from whatever the offchain_*
    fields currently say; if it no longer matches `onchain_hash`, that block
    is flagged tampered. This mismatch is real, not a hardcoded flag.
    """
    __tablename__ = "ledger_blocks"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime(timezone=True), server_default=func.now())

    source = Column(String, nullable=False)
    command = Column(String, nullable=False)
    entity = Column(String, nullable=False)
    params_json = Column(Text, nullable=False)

    prev_hash = Column(String(64), nullable=False)
    onchain_hash = Column(String(64), nullable=False)
    preimage = Column(Text, nullable=False)

    tx_hash = Column(String(80), nullable=True)
    onchain_index = Column(Integer, nullable=True)
    anchor_error = Column(Text, nullable=True)

    offchain_command = Column(String, nullable=False)
    offchain_params_json = Column(Text, nullable=False)


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime(timezone=True), server_default=func.now())
    block_id = Column(Integer, nullable=True)
    severity = Column(String, nullable=False)  # critical | warning
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    technique = Column(String, nullable=True)  # MITRE ATT&CK for ICS technique id
    ml_score = Column(Float, nullable=True)
