"""Pydantic schemas for API request/response validation."""

from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime


# ── Scans ────────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    target_domain: str
    mode: str = "demo"  # "demo" or "live"


class ScanSummary(BaseModel):
    id: str
    target_domain: str
    mode: str
    status: str
    progress: Optional[float] = 0
    progress_message: Optional[str] = None
    overall_risk_score: Optional[float] = 0
    overall_risk_level: Optional[str] = "LOW"
    total_findings: Optional[int] = 0
    total_relationships: Optional[int] = 0
    total_attack_paths: Optional[int] = 0
    total_exposures: Optional[int] = 0
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Evidence per source ───────────────────────────────────────────────────────

class SourceEvidence(BaseModel):
    source: str
    evidence: str
    discovered_at: Optional[str] = None
    confidence: Optional[float] = None
    raw_data: Optional[Dict[str, Any]] = None


# ── Findings ─────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    id: str
    scan_id: str
    source: str
    finding_type: str
    value: str
    title: Optional[str] = None
    description: Optional[str] = None
    confidence: float
    observation_type: str
    evidence: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[str] = None
    external_url: Optional[str] = None
    # Multi-source fields
    sources: Optional[List[str]] = None
    source_count: Optional[int] = 1
    source_agreement: Optional[float] = 1.0
    total_queried: Optional[int] = 1
    evidence_per_source: Optional[List[SourceEvidence]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    discovered_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class FindingDetail(FindingOut):
    raw_data: Optional[Dict[str, Any]] = None
    norm_value: Optional[str] = None

    class Config:
        from_attributes = True


# ── Confidence Breakdown ──────────────────────────────────────────────────────

class ConfidenceBreakdown(BaseModel):
    final_confidence_pct: int
    confidence_label: str
    source_agreement: str
    source_count: int
    total_queried: int
    breakdown: Dict[str, int]
    note: str


# ── Graph ─────────────────────────────────────────────────────────────────────

class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str
    finding_id: Optional[str] = None
    confidence: Optional[float] = None
    observation_type: Optional[str] = None
    risk_level: Optional[str] = None
    source_count: Optional[int] = 1
    sources: Optional[List[str]] = None
    data: Optional[Dict[str, Any]] = None


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    confidence: Optional[float] = None
    label: Optional[str] = None


class GraphData(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


# ── Relationships ─────────────────────────────────────────────────────────────

class RelationshipOut(BaseModel):
    id: str
    scan_id: str
    source_finding_id: str
    target_finding_id: str
    relationship_type: str
    confidence: Optional[float] = None
    description: Optional[str] = None

    class Config:
        from_attributes = True


# ── Attack Paths ──────────────────────────────────────────────────────────────

class AttackPathNodeOut(BaseModel):
    id: str
    step_order: int
    label: str
    description: Optional[str] = None
    node_type: str
    finding_id: Optional[str] = None

    class Config:
        from_attributes = True


class AttackPathOut(BaseModel):
    id: str
    scan_id: str
    title: str
    description: Optional[str] = None
    hypothesis: Optional[str] = None
    validation_note: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    severity_order: Optional[int] = None
    entry_point: Optional[str] = None
    target_asset: Optional[str] = None
    created_at: Optional[datetime] = None
    nodes: List[AttackPathNodeOut] = []

    class Config:
        from_attributes = True


# ── Risk ──────────────────────────────────────────────────────────────────────

class RiskScoreOut(BaseModel):
    id: str
    scan_id: str
    finding_id: Optional[str] = None
    exposure: float
    confidence: float
    exploitability: float
    impact: float
    composite_score: float
    risk_level: str
    rationale: Optional[str] = None

    class Config:
        from_attributes = True


class RiskSummary(BaseModel):
    overall_score: float
    overall_level: str
    total_findings: int
    critical_count: int
    very_high_count: int
    high_count: int
    medium_count: int
    low_count: int
    by_category: Dict[str, float]


# ── Recommendations ───────────────────────────────────────────────────────────

class RecommendationOut(BaseModel):
    id: str
    scan_id: str
    finding_id: Optional[str] = None
    title: str
    description: str
    category: str
    priority: int
    effort: str
    rationale: Optional[str] = None

    class Config:
        from_attributes = True


# ── Timeline ──────────────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    id: str
    timestamp: datetime
    title: str
    description: str
    source: str
    finding_type: str
    category: Optional[str] = None
    confidence: float
    observation_type: str
    sources: Optional[List[str]] = None
    source_count: Optional[int] = 1


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    domains: int = 0
    subdomains: int = 0
    certificates: int = 0
    ip_asn: int = 0
    technologies: int = 0
    repositories: int = 0
    org_references: int = 0
    threat_indicators: int = 0
    exposure_points: int = 0
    attack_paths: int = 0
    emails: int = 0
    usernames: int = 0
    overall_risk_score: float = 0
    overall_risk_level: str = "LOW"
    avg_confidence: Optional[float] = None
    avg_source_count: Optional[float] = None


# ── Source Health ─────────────────────────────────────────────────────────────

class SourceStatus(BaseModel):
    name: str
    display_name: str
    status: str           # "ready" | "key_missing" | "demo" | "error"
    is_demo: bool
    description: str
    requires_key: Optional[bool] = False
    category: Optional[str] = None
    last_error: Optional[str] = None
    last_queried_at: Optional[str] = None


# ── Source Comparison ─────────────────────────────────────────────────────────

class SourceComparisonRow(BaseModel):
    source: str
    result: str      # "Found" | "Not found" | "N/A"
    status: str      # "found" | "not_found" | "na"
    confidence: Optional[float] = None
    discovered_at: Optional[str] = None


class SourceComparison(BaseModel):
    finding_id: str
    finding_value: str
    finding_type: str
    rows: List[SourceComparisonRow]
    source_count: int
    total_queried: int
    agreement_pct: int
    confidence_pct: int


# ── Report ────────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    format: str = "json"  # "json" | "pdf" | "csv"
    include_evidence: bool = True
    include_raw_data: bool = False
