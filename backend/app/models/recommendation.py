import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Recommendation(Base):
    __tablename__ = "recommendations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=True)
    attack_path_id: Mapped[str] = mapped_column(String(36), ForeignKey("attack_paths.id"), nullable=True)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    # Categories: access_control, monitoring, patching, configuration,
    #             secret_management, network_security, asset_management

    priority: Mapped[int] = mapped_column(Integer, default=3)  # 1=Critical, 2=High, 3=Medium, 4=Low
    effort: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high
    rationale: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan = relationship("Scan", back_populates="recommendations")
    finding = relationship("Finding", foreign_keys=[finding_id])
    attack_path = relationship("AttackPath", foreign_keys=[attack_path_id])
