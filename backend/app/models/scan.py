import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Float, DateTime, Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base
import enum


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    COLLECTING = "collecting"
    NORMALIZING = "normalizing"
    CORRELATING = "correlating"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanMode(str, enum.Enum):
    DEMO = "demo"
    LIVE = "live"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_domain: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.PENDING.value)
    mode: Mapped[str] = mapped_column(String(10), default=ScanMode.DEMO.value)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    progress_message: Mapped[str] = mapped_column(Text, default="")
    overall_risk_score: Mapped[float] = mapped_column(Float, nullable=True)
    overall_risk_level: Mapped[str] = mapped_column(String(20), nullable=True)
    total_findings: Mapped[int] = mapped_column(default=0)
    total_relationships: Mapped[int] = mapped_column(default=0)
    total_attack_paths: Mapped[int] = mapped_column(default=0)
    total_exposures: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    relationships_list = relationship("Relationship", back_populates="scan", cascade="all, delete-orphan")
    attack_paths = relationship("AttackPath", back_populates="scan", cascade="all, delete-orphan")
    risk_scores = relationship("RiskScore", back_populates="scan", cascade="all, delete-orphan")
    recommendations = relationship("Recommendation", back_populates="scan", cascade="all, delete-orphan")
