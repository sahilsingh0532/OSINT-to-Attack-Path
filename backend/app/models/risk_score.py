import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)

    # Four risk factors (0.0 to 10.0 each)
    exposure: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    exploitability: Mapped[float] = mapped_column(Float, default=0.0)
    impact: Mapped[float] = mapped_column(Float, default=0.0)

    # Composite score (0-100)
    composite_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(20), default="LOW")

    # Explanation
    rationale: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan = relationship("Scan", back_populates="risk_scores")
    finding = relationship("Finding", back_populates="risk_scores")

    @staticmethod
    def calculate_composite(exposure: float, confidence: float, exploitability: float, impact: float) -> float:
        """Calculate composite risk score: (E × C × Ex × I) / 100, normalized to 0-100."""
        raw = (exposure * confidence * exploitability * impact) / 100.0
        return min(max(round(raw, 1), 0.0), 100.0)

    @staticmethod
    def get_risk_level(score: float) -> str:
        """Map composite score to risk level."""
        if score <= 20:
            return "LOW"
        elif score <= 40:
            return "MEDIUM"
        elif score <= 60:
            return "HIGH"
        elif score <= 80:
            return "VERY HIGH"
        else:
            return "CRITICAL"
