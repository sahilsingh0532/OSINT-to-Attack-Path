import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Float, Integer, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=True)  # Attack hypothesis text
    validation_note: Mapped[str] = mapped_column(Text, default="Requires authorized validation")

    # Risk
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(20), default="LOW")
    severity_order: Mapped[int] = mapped_column(Integer, default=0)  # For sorting

    # Path metadata
    entry_point: Mapped[str] = mapped_column(Text, nullable=True)
    target_asset: Mapped[str] = mapped_column(Text, nullable=True)
    path_data: Mapped[dict] = mapped_column(JSON, nullable=True)  # Ordered list of node IDs

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan = relationship("Scan", back_populates="attack_paths")
    nodes = relationship("AttackPathNode", back_populates="attack_path", cascade="all, delete-orphan",
                         order_by="AttackPathNode.step_order")


class AttackPathNode(Base):
    __tablename__ = "attack_path_nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    attack_path_id: Mapped[str] = mapped_column(String(36), ForeignKey("attack_paths.id"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id"), nullable=True)

    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    label: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    node_type: Mapped[str] = mapped_column(String(50), nullable=False)  # entry, asset, weakness, impact

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    attack_path = relationship("AttackPath", back_populates="nodes")
    finding = relationship("Finding", foreign_keys=[finding_id])
