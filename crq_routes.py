"""
CRQ Routes — FastAPI router for Quantitative Risk (Monte Carlo) endpoints.

Register in ui_server.py:
    from crq_routes import router as crq_router
    app.include_router(crq_router)
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional

from auth import require_auth
from crq_engine import CRQEngine

router = APIRouter(prefix="/api/crq", tags=["crq"])

_engine = CRQEngine()


# ── Schemas ────────────────────────────────────────────────────────────────────

class SimulateRequest(BaseModel):
    asset_value: float = Field(..., gt=0, description="Dollar value of the asset")
    threat_freq_per_year: float = Field(
        ..., gt=0, description="Expected threat events per year (e.g. 0.5)"
    )
    vuln_factor: float = Field(
        ..., ge=0, le=1, description="Probability (0–1) that threat succeeds"
    )
    impact_min_pct: float = Field(
        ..., ge=0, le=1, description="Minimum impact as fraction of asset value"
    )
    impact_max_pct: float = Field(
        ..., ge=0, le=1, description="Maximum impact as fraction of asset value"
    )
    iterations: int = Field(
        default=10_000, ge=100, le=100_000, description="Monte Carlo iterations"
    )
    label: Optional[str] = Field(default=None, description="Optional label for the simulation")

    @model_validator(mode="after")
    def validate_impact_range(self) -> "SimulateRequest":
        if self.impact_max_pct < self.impact_min_pct:
            raise ValueError("impact_max_pct must be >= impact_min_pct")
        return self


class PortfolioRisk(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    asset_value: float = Field(..., gt=0)
    threat_freq_per_year: float = Field(..., gt=0)
    vuln_factor: float = Field(..., ge=0, le=1)
    impact_min_pct: float = Field(..., ge=0, le=1)
    impact_max_pct: float = Field(..., ge=0, le=1)
    iterations: Optional[int] = Field(default=None, ge=100, le=100_000)

    @model_validator(mode="after")
    def validate_impact_range(self) -> "PortfolioRisk":
        if self.impact_max_pct < self.impact_min_pct:
            raise ValueError("impact_max_pct must be >= impact_min_pct")
        return self


class PortfolioRequest(BaseModel):
    risks: list[PortfolioRisk] = Field(..., min_length=1)
    confidence: float = Field(default=0.95, ge=0.5, le=0.9999)
    iterations: int = Field(default=10_000, ge=100, le=100_000)


# ── Preset definitions ─────────────────────────────────────────────────────────

_PRESETS: list[dict] = [
    {
        "id": "ransomware",
        "name": "Ransomware Attack",
        "description": (
            "Ransomware encryption of critical systems. "
            "Includes recovery costs, ransom, and downtime."
        ),
        "asset_value": 5_000_000,
        "threat_freq_per_year": 0.3,
        "vuln_factor": 0.4,
        "impact_min_pct": 0.10,
        "impact_max_pct": 0.60,
        "iterations": 10_000,
    },
    {
        "id": "data_breach",
        "name": "Data Breach",
        "description": (
            "Unauthorized exfiltration of PII/sensitive data. "
            "Includes regulatory fines, legal costs, and notification expenses."
        ),
        "asset_value": 3_000_000,
        "threat_freq_per_year": 0.2,
        "vuln_factor": 0.35,
        "impact_min_pct": 0.15,
        "impact_max_pct": 0.80,
        "iterations": 10_000,
    },
    {
        "id": "ddos",
        "name": "DDoS Attack",
        "description": (
            "Distributed denial-of-service causing service unavailability. "
            "Includes revenue loss and mitigation costs."
        ),
        "asset_value": 1_000_000,
        "threat_freq_per_year": 1.5,
        "vuln_factor": 0.6,
        "impact_min_pct": 0.02,
        "impact_max_pct": 0.20,
        "iterations": 10_000,
    },
    {
        "id": "insider_threat",
        "name": "Insider Threat",
        "description": (
            "Malicious or negligent insider causing data loss or sabotage. "
            "Includes investigation, legal, and remediation costs."
        ),
        "asset_value": 2_000_000,
        "threat_freq_per_year": 0.15,
        "vuln_factor": 0.5,
        "impact_min_pct": 0.05,
        "impact_max_pct": 0.50,
        "iterations": 10_000,
    },
    {
        "id": "vendor_failure",
        "name": "Vendor/Supply Chain Failure",
        "description": (
            "Critical third-party vendor breach or service failure. "
            "Includes recovery, contractual penalties, and operational disruption."
        ),
        "asset_value": 4_000_000,
        "threat_freq_per_year": 0.25,
        "vuln_factor": 0.45,
        "impact_min_pct": 0.08,
        "impact_max_pct": 0.40,
        "iterations": 10_000,
    },
]


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.post("/simulate")
async def simulate_risk(
    body: SimulateRequest,
    payload: dict = Depends(require_auth),
) -> dict:
    """
    Run a single Monte Carlo risk simulation.

    Returns ALE, VaR 95/99, expected single-event loss, max loss,
    loss exceedance curve, and iteration count.
    """
    try:
        result = _engine.simulate(
            asset_value=body.asset_value,
            threat_freq_per_year=body.threat_freq_per_year,
            vuln_factor=body.vuln_factor,
            impact_min_pct=body.impact_min_pct,
            impact_max_pct=body.impact_max_pct,
            iterations=body.iterations,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Simulation error: {exc}") from exc

    if body.label:
        result["label"] = body.label

    return result


@router.post("/portfolio")
async def portfolio_var(
    body: PortfolioRequest,
    payload: dict = Depends(require_auth),
) -> dict:
    """
    Aggregate multiple risks and return portfolio-level VaR.

    Simulates each risk independently then combines annual loss distributions
    to produce a portfolio-level loss distribution.
    """
    risks_dicts = [r.model_dump() for r in body.risks]
    try:
        result = _engine.portfolio_var(
            risks=risks_dicts,
            confidence=body.confidence,
            iterations=body.iterations,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"Portfolio simulation error: {exc}"
        ) from exc

    return result


@router.get("/presets")
async def get_presets(
    payload: dict = Depends(require_auth),
) -> list[dict]:
    """
    Return 5 preset risk scenarios with pre-configured parameter values.

    Presets: ransomware, data_breach, ddos, insider_threat, vendor_failure.
    """
    return _PRESETS
