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

    @property
    def likelihood(self) -> float:
        """NIST SP 800-30 Threat Event Likelihood (0.0 - 10.0 scale)."""
        return RiskScore.calculate_likelihood(self.exposure, self.confidence, self.exploitability)

    @staticmethod
    def calculate_likelihood(exposure: float, confidence: float, exploitability: float) -> float:
        """
        Calculate NIST SP 800-30 Rev. 1 Threat Event Likelihood (0.0 - 10.0 scale).
        Combines threat event initiation/exposure and exploitability predisposition,
        modulated by assessment confidence factor.
        """
        conf_val = float(confidence)
        if conf_val > 1.0:
            conf_val = min(1.0, conf_val / 10.0 if conf_val <= 10.0 else conf_val / 100.0)
        conf_factor = 0.70 + (0.30 * max(0.0, conf_val))

        exp = max(0.0, min(10.0, float(exposure)))
        expl = max(0.0, min(10.0, float(exploitability)))
        base_likelihood = (exp + expl) / 2.0
        return min(max(round(base_likelihood * conf_factor, 1), 0.0), 10.0)

    @staticmethod
    def calculate_composite(exposure: float, confidence: float, exploitability: float, impact: float) -> float:
        """
        Calculate NIST SP 800-30 Rev. 1 Risk Score (0.0 - 100.0 scale).
        Risk = Threat Event Likelihood (0-10) × Threat Event Impact (0-10).
        """
        likelihood = RiskScore.calculate_likelihood(exposure, confidence, exploitability)
        imp = max(0.0, min(10.0, float(impact)))
        nist_score = likelihood * imp
        return min(max(round(nist_score, 1), 0.0), 100.0)

    @staticmethod
    def get_risk_level(score: float) -> str:
        """
        Map composite score to NIST SP 800-30 standard semi-quantitative risk levels.
        - 0.0 - 20.0: LOW (NIST Very Low / Low)
        - 20.1 - 40.0: LOW
        - 40.1 - 60.0: MEDIUM (NIST Moderate)
        - 60.1 - 80.0: HIGH
        - 80.1 - 100.0: CRITICAL (NIST Very High)
        """
        if score <= 20.0:
            return "LOW"
        elif score <= 40.0:
            return "LOW"
        elif score <= 60.0:
            return "MEDIUM"
        elif score <= 80.0:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def calculate_nist_risk(exposure: float, confidence: float, exploitability: float, impact: float) -> dict:
        """Return complete NIST SP 800-30 Rev. 1 assessment breakdown."""
        likelihood = RiskScore.calculate_likelihood(exposure, confidence, exploitability)
        imp = max(0.0, min(10.0, float(impact)))
        score = min(max(round(likelihood * imp, 1), 0.0), 100.0)
        level = RiskScore.get_risk_level(score)
        return {
            "standard": "NIST SP 800-30 Rev. 1",
            "likelihood": likelihood,
            "impact": imp,
            "risk_score": score,
            "risk_level": level,
            "formula": "Risk = Likelihood (0-10) × Impact (0-10)",
        }
