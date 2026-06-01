"""Evidence Hash-Chain verification API.

Endpoint:
  GET /api/v1/evidence/{control_id}/verify-chain

Verifies that each Evidence record for a control_id correctly links
to the previous one via previous_hash (= content_hash of previous record).

Response:
  {"control_id": "CC6.1", "valid": true, "chain_length": 5, "broken_at": null}

Records without previous_hash (legacy or genesis) are treated as valid.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_auth
from database import get_db
from models import Evidence

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence-chain"])


@router.get("/{control_id}/verify-chain")
async def verify_evidence_chain(
    control_id: str,
    payload: dict = Depends(require_auth),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Verify the hash-chain integrity of evidence records for a control.

    Loads all Evidence for control_id sorted by created_at ASC, then
    walks the chain verifying each record links back to the previous one.

    Returns 404 if no evidence exists for the control.
    """
    stmt = (
        select(Evidence)
        .where(Evidence.control_id == control_id)
        .order_by(Evidence.created_at.asc())
    )
    result = await session.execute(stmt)
    records = result.scalars().all()

    chain_length = len(records)

    if chain_length == 0:
        raise HTTPException(
            status_code=404,
            detail=f"No evidence found for control_id={control_id!r}",
        )

    broken_at: Optional[str] = None
    prev_content_hash: Optional[str] = None

    for ev in records:
        if prev_content_hash is None:
            # Genesis block: first record in the chain, always valid
            prev_content_hash = ev.content_hash
            continue

        ev_prev_hash: Optional[str] = getattr(ev, "previous_hash", None)
        if ev_prev_hash is None:
            # Legacy record without previous_hash - treat as valid, continue chain
            prev_content_hash = ev.content_hash
            continue

        if ev_prev_hash != prev_content_hash:
            broken_at = ev.id
            log.warning(
                "Hash-chain broken for control_id=%s at evidence_id=%s: "
                "expected previous_hash=%s, got=%s",
                control_id,
                ev.id,
                prev_content_hash,
                ev_prev_hash,
            )
            break

        prev_content_hash = ev.content_hash

    return {
        "control_id": control_id,
        "valid": broken_at is None,
        "chain_length": chain_length,
        "broken_at": broken_at,
    }
