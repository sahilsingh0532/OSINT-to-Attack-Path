import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)

    # Source info
    source: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "certificate_transparency"
    collection_method: Mapped[str] = mapped_column(String(50), default="passive")

    # Finding content
    finding_type: Mapped[str] = mapped_column(String(50), nullable=False)  # domain, subdomain, certificate, ip, technology, etc.
    value: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Evidence & classification
    confidence: Mapped[float] = mapped_column(Float, default=0.5)  # 0.0 to 1.0
    observation_type: Mapped[str] = mapped_column(String(20), default="observed")  # observed, inferred, hypothesized
    evidence: Mapped[str] = mapped_column(Text, nullable=True)  # Human-readable evidence description
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=True)  # Raw JSON from source

    # Metadata
    category: Mapped[str] = mapped_column(String(50), nullable=True)  # infrastructure, code, identity, threat
    tags: Mapped[str] = mapped_column(Text, nullable=True)  # Comma-separated tags
    external_url: Mapped[str] = mapped_column(Text, nullable=True)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    risk_scores = relationship("RiskScore", back_populates="finding", cascade="all, delete-orphan")
