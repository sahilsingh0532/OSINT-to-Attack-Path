import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Relationship(Base):
    __tablename__ = "relationships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)

    source_finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)
    target_finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=False)

    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # Types: has_subdomain, has_certificate, resolves_to, uses_technology,
    #        has_repository, developed_by, belongs_to_asn, references_threat,
    #        exposes, linked_to

    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan = relationship("Scan", back_populates="relationships_list")
    source_finding = relationship("Finding", foreign_keys=[source_finding_id])
    target_finding = relationship("Finding", foreign_keys=[target_finding_id])
