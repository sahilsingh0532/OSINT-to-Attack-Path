from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# --- Scan Schemas ---
class ScanCreate(BaseModel):
    target_domain: str = Field(..., min_length=1, max_length=255)
    mode: str = Field(default="demo", pattern="^(demo|live)$")


class ScanSummary(BaseModel):
    id: str
    target_domain: str
    status: str
    mode: str
    progress: float
    progress_message: str
    overall_risk_score: Optional[float] = None
    overall_risk_level: Optional[str] = None
    total_findings: int
    total_relationships: int
    total_attack_paths: int
    total_exposures: int
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# --- Finding Schemas ---
class FindingOut(BaseModel):
    id: str
    scan_id: str
    source: str
    collection_method: str
    finding_type: str
    value: str
    title: Optional[str] = None
    description: Optional[str] = None
    confidence: float
    observation_type: str
    evidence: Optional[str] = None
    raw_data: Optional[dict] = None
    category: Optional[str] = None
    tags: Optional[str] = None
    external_url: Optional[str] = None
    discovered_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class FindingDetail(FindingOut):
    risk_scores: List["RiskScoreOut"] = []


# --- Relationship Schemas ---
class RelationshipOut(BaseModel):
    id: str
    scan_id: str
    source_finding_id: str
    target_finding_id: str
    relationship_type: str
    confidence: float
    description: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# --- Attack Path Schemas ---
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
    validation_note: str
    risk_score: float
    risk_level: str
    severity_order: int
    entry_point: Optional[str] = None
    target_asset: Optional[str] = None
    nodes: List[AttackPathNodeOut] = []
    created_at: datetime

    class Config:
        from_attributes = True


# --- Risk Score Schemas ---
class RiskScoreOut(BaseModel):
    id: str
    scan_id: str
    finding_id: str
    exposure: float
    confidence: float
    exploitability: float
    impact: float
    composite_score: float
    risk_level: str
    rationale: Optional[str] = None
    created_at: datetime

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
    by_category: dict


# --- Recommendation Schemas ---
class RecommendationOut(BaseModel):
    id: str
    scan_id: str
    finding_id: Optional[str] = None
    attack_path_id: Optional[str] = None
    title: str
    description: str
    category: str
    priority: int
    effort: str
    rationale: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# --- Graph Schemas ---
class GraphNode(BaseModel):
    id: str
    label: str
    node_type: str
    finding_id: Optional[str] = None
    confidence: float = 0.5
    observation_type: str = "observed"
    risk_level: Optional[str] = None
    data: Optional[dict] = None


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    confidence: float = 0.5
    label: Optional[str] = None


class GraphData(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


# --- Timeline Schemas ---
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


# --- Dashboard Stats ---
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
    overall_risk_score: float = 0.0
    overall_risk_level: str = "LOW"


# --- Source Status ---
class SourceStatus(BaseModel):
    name: str
    display_name: str
    status: str  # completed, pending, error, not_configured
    findings_count: int = 0
    confidence: str = "N/A"  # High, Medium, Low
    last_updated: Optional[datetime] = None
    is_demo: bool = True
    description: str = ""


# --- Report ---
class ReportRequest(BaseModel):
    scan_id: str
    include_sections: List[str] = Field(default_factory=lambda: [
        "executive_summary", "scope", "methodology", "sources",
        "findings", "attack_surface", "attack_paths", "risk",
        "evidence", "recommendations", "limitations", "conclusion"
    ])
    format: str = "json"  # json, html


# Forward reference resolution
FindingDetail.model_rebuild()
