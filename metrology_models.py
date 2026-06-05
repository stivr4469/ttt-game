"""
SQLAlchemy ORM models for the Metrology Framework.

Replaces binary PASS/FAIL control measurements with continuous metrics
tracking (e.g., "% employees completed training: target 100%, current 87%").
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MetricDefinition(Base):
    """Defines a continuous compliance metric with a target value and direction."""

    __tablename__ = "metric_definitions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    unit: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "%", "hours", "count", "days"
    target_value: Mapped[float] = mapped_column(Float, nullable=False)
    target_direction: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # "min" (lower=better), "max" (higher=better), "exact"
    category: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # "training", "incident_response", "access", "vendor", "compliance", "operational"
    control_id: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # e.g., "CC7.2"
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class MetricInstance(Base):
    """A single recorded measurement for a MetricDefinition."""

    __tablename__ = "metric_instances"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    definition_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("metric_definitions.id"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    source: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )  # "manual", "github", "okta", "auto"
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
