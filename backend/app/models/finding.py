import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Float, DateTime, ForeignKey, JSON, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)

    # Primary source (for backwards compatibility; multi-source stored in sources JSON)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    collection_method: Mapped[str] = mapped_column(String(50), default="passive")

    # Finding content
    finding_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Evidence & classification
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    observation_type: Mapped[str] = mapped_column(String(20), default="observed")
    evidence: Mapped[str] = mapped_column(Text, nullable=True)
    raw_data: Mapped[dict] = mapped_column(JSON, nullable=True)

    # ── Multi-source fields (Phase 2 upgrade) ──────────────────────────────
    sources: Mapped[list] = mapped_column(JSON, nullable=True)           # ["crt.sh", "censys", "virustotal"]
    source_count: Mapped[int] = mapped_column(Integer, default=1)        # Number of agreeing sources
    source_agreement: Mapped[float] = mapped_column(Float, default=1.0)  # source_count / total_queried
    total_queried: Mapped[int] = mapped_column(Integer, default=1)       # Total providers queried for this type
    evidence_per_source: Mapped[list] = mapped_column(JSON, nullable=True)  # [{source, evidence, discovered_at, raw_data}]
    # ──────────────────────────────────────────────────────────────────────

    # Metadata
    category: Mapped[str] = mapped_column(String(50), nullable=True)
    tags: Mapped[str] = mapped_column(Text, nullable=True)
    external_url: Mapped[str] = mapped_column(Text, nullable=True)
    norm_value: Mapped[str] = mapped_column(Text, nullable=True)  # Normalized value for dedup

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # ORM Relationships
    scan = relationship("Scan", back_populates="findings")
    risk_scores = relationship("RiskScore", back_populates="finding", cascade="all, delete-orphan")
