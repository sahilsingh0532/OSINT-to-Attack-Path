"""
API routes for all scan, finding, graph, attack-path, risk, recommendation,
timeline, report, and settings endpoints.
"""

import asyncio
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional

from app.database import get_db, async_session
from app.models.scan import Scan, ScanStatus, ScanMode
from app.models.finding import Finding
from app.models.relationship import Relationship
from app.models.attack_path import AttackPath, AttackPathNode
from app.models.risk_score import RiskScore
from app.models.recommendation import Recommendation
from app.schemas import (
    ScanCreate, ScanSummary, FindingOut, FindingDetail,
    RelationshipOut, AttackPathOut, AttackPathNodeOut,
    RiskScoreOut, RiskSummary, RecommendationOut,
    GraphData, GraphNode, GraphEdge,
    TimelineEvent, DashboardStats, SourceStatus,
    ReportRequest,
)
from app.services.scan_orchestrator import run_scan
from app.services.reporter import generate_report
from app.collectors.collectors import ALL_COLLECTORS
from app.config import settings


router = APIRouter(prefix="/api")


# --- Background task runner ---
async def _run_scan_background(scan_id: str):
    """Run scan in background with its own DB session."""
    async with async_session() as db:
        await run_scan(scan_id, db)


# ====================== SCANS ======================

@router.post("/scans", response_model=ScanSummary)
async def create_scan(scan_data: ScanCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Start a new passive reconnaissance scan."""
    scan = Scan(
        target_domain=scan_data.target_domain,
        mode=scan_data.mode,
        status=ScanStatus.PENDING.value,
    )
    db.add(scan)
    await db.flush()
    await db.commit()
    await db.refresh(scan)

    # Run scan in background
    background_tasks.add_task(_run_scan_background, scan.id)

    return scan


@router.get("/scans", response_model=List[ScanSummary])
async def list_scans(db: AsyncSession = Depends(get_db)):
    """List all scans."""
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.get("/scans/{scan_id}", response_model=ScanSummary)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get scan status and summary."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ====================== DASHBOARD ======================

@router.get("/scans/{scan_id}/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get dashboard statistics for a scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Count findings by type
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    type_counts = {}
    for f in findings:
        ft = f.finding_type
        type_counts[ft] = type_counts.get(ft, 0) + 1

    return DashboardStats(
        domains=type_counts.get("domain", 0),
        subdomains=type_counts.get("subdomain", 0),
        certificates=type_counts.get("certificate", 0),
        ip_asn=type_counts.get("ip", 0) + type_counts.get("asn", 0),
        technologies=type_counts.get("technology", 0),
        repositories=type_counts.get("repository", 0),
        org_references=type_counts.get("organization", 0),
        threat_indicators=type_counts.get("threat_indicator", 0) + type_counts.get("darkweb_reference", 0),
        exposure_points=type_counts.get("exposure", 0),
        attack_paths=scan.total_attack_paths,
        overall_risk_score=scan.overall_risk_score or 0,
        overall_risk_level=scan.overall_risk_level or "LOW",
    )


# ====================== FINDINGS ======================

@router.get("/scans/{scan_id}/findings", response_model=List[FindingOut])
async def get_findings(
    scan_id: str,
    finding_type: Optional[str] = None,
    category: Optional[str] = None,
    observation_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List findings with optional filtering."""
    query = select(Finding).where(Finding.scan_id == scan_id)
    if finding_type:
        query = query.where(Finding.finding_type == finding_type)
    if category:
        query = query.where(Finding.category == category)
    if observation_type:
        query = query.where(Finding.observation_type == observation_type)
    query = query.order_by(Finding.discovered_at)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single finding with details."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


# ====================== GRAPH / CORRELATION ======================

@router.get("/scans/{scan_id}/graph", response_model=GraphData)
async def get_graph_data(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get Cytoscape.js-compatible graph data."""
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    relationships_result = await db.execute(select(Relationship).where(Relationship.scan_id == scan_id))
    relationships = relationships_result.scalars().all()

    # Risk scores for coloring
    risk_result = await db.execute(select(RiskScore).where(RiskScore.scan_id == scan_id))
    risk_scores = {rs.finding_id: rs for rs in risk_result.scalars().all()}

    # Build nodes — group by type, skip duplicates
    nodes = []
    seen_ids = set()
    for f in findings:
        if f.id not in seen_ids:
            rs = risk_scores.get(f.id)
            nodes.append(GraphNode(
                id=f.id,
                label=f.title or f.value[:50],
                node_type=f.finding_type,
                finding_id=f.id,
                confidence=f.confidence,
                observation_type=f.observation_type,
                risk_level=rs.risk_level if rs else None,
                data={
                    "value": f.value,
                    "source": f.source,
                    "category": f.category,
                    "evidence": f.evidence,
                }
            ))
            seen_ids.add(f.id)

    # Build edges
    edges = []
    for r in relationships:
        edges.append(GraphEdge(
            id=r.id,
            source=r.source_finding_id,
            target=r.target_finding_id,
            relationship_type=r.relationship_type,
            confidence=r.confidence,
            label=r.relationship_type.replace("_", " "),
        ))

    return GraphData(nodes=nodes, edges=edges)


@router.get("/scans/{scan_id}/relationships", response_model=List[RelationshipOut])
async def get_relationships(scan_id: str, db: AsyncSession = Depends(get_db)):
    """List all relationships for a scan."""
    result = await db.execute(select(Relationship).where(Relationship.scan_id == scan_id))
    return result.scalars().all()


# ====================== ATTACK PATHS ======================

@router.get("/scans/{scan_id}/attack-paths", response_model=List[AttackPathOut])
async def get_attack_paths(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get attack hypotheses ordered by risk."""
    result = await db.execute(
        select(AttackPath).where(AttackPath.scan_id == scan_id).order_by(AttackPath.risk_score.desc())
    )
    attack_paths = result.scalars().all()

    # Load nodes for each path
    response = []
    for ap in attack_paths:
        nodes_result = await db.execute(
            select(AttackPathNode).where(AttackPathNode.attack_path_id == ap.id).order_by(AttackPathNode.step_order)
        )
        nodes = nodes_result.scalars().all()
        ap_dict = AttackPathOut(
            id=ap.id,
            scan_id=ap.scan_id,
            title=ap.title,
            description=ap.description,
            hypothesis=ap.hypothesis,
            validation_note=ap.validation_note,
            risk_score=ap.risk_score,
            risk_level=ap.risk_level,
            severity_order=ap.severity_order,
            entry_point=ap.entry_point,
            target_asset=ap.target_asset,
            created_at=ap.created_at,
            nodes=[AttackPathNodeOut(
                id=n.id, step_order=n.step_order, label=n.label,
                description=n.description, node_type=n.node_type,
                finding_id=n.finding_id
            ) for n in nodes],
        )
        response.append(ap_dict)

    return response


# ====================== RISK ======================

@router.get("/scans/{scan_id}/risk", response_model=List[RiskScoreOut])
async def get_risk_scores(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get all risk scores for a scan."""
    result = await db.execute(
        select(RiskScore).where(RiskScore.scan_id == scan_id).order_by(RiskScore.composite_score.desc())
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/risk/summary", response_model=RiskSummary)
async def get_risk_summary(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get risk summary with distribution."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = await db.execute(select(RiskScore).where(RiskScore.scan_id == scan_id))
    scores = result.scalars().all()

    # Count by category via findings
    by_category = {}
    for rs in scores:
        finding = await db.get(Finding, rs.finding_id)
        if finding:
            cat = finding.category or "other"
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(rs.composite_score)

    return RiskSummary(
        overall_score=scan.overall_risk_score or 0,
        overall_level=scan.overall_risk_level or "LOW",
        total_findings=len(scores),
        critical_count=sum(1 for s in scores if s.risk_level == "CRITICAL"),
        very_high_count=sum(1 for s in scores if s.risk_level == "VERY HIGH"),
        high_count=sum(1 for s in scores if s.risk_level == "HIGH"),
        medium_count=sum(1 for s in scores if s.risk_level == "MEDIUM"),
        low_count=sum(1 for s in scores if s.risk_level == "LOW"),
        by_category={k: round(sum(v) / len(v), 1) for k, v in by_category.items()},
    )


# ====================== RECOMMENDATIONS ======================

@router.get("/scans/{scan_id}/recommendations", response_model=List[RecommendationOut])
async def get_recommendations(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get defensive recommendations."""
    result = await db.execute(
        select(Recommendation).where(Recommendation.scan_id == scan_id).order_by(Recommendation.priority)
    )
    return result.scalars().all()


# ====================== TIMELINE ======================

@router.get("/scans/{scan_id}/timeline", response_model=List[TimelineEvent])
async def get_timeline(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get chronological OSINT timeline."""
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.discovered_at)
    )
    findings = result.scalars().all()

    events = []
    for f in findings:
        events.append(TimelineEvent(
            id=f.id,
            timestamp=f.discovered_at,
            title=f.title or f.value[:80],
            description=f.description or "",
            source=f.source,
            finding_type=f.finding_type,
            category=f.category,
            confidence=f.confidence,
            observation_type=f.observation_type,
        ))

    return events


# ====================== REPORTS ======================

@router.post("/scans/{scan_id}/report")
async def create_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate a VAPT/OSINT report."""
    report = await generate_report(scan_id, db)
    return report


# ====================== SOURCES ======================

@router.get("/sources", response_model=List[SourceStatus])
async def get_sources():
    """Get status of all OSINT sources."""
    sources = []
    for CollectorClass in ALL_COLLECTORS:
        c = CollectorClass()
        c.is_demo = (settings.osint_mode == "demo")
        status = c.get_status()
        sources.append(SourceStatus(
            name=status["name"],
            display_name=status["display_name"],
            status="completed" if c.is_demo else status["status"],
            is_demo=c.is_demo,
            description=status["description"],
        ))
    return sources


# ====================== SETTINGS ======================

@router.get("/settings")
async def get_settings():
    """Get current application settings."""
    return {
        "mode": settings.osint_mode,
        "github_configured": bool(settings.github_token),
        "shodan_configured": bool(settings.shodan_api_key),
        "virustotal_configured": bool(settings.virustotal_api_key),
        "censys_configured": bool(settings.censys_api_id),
    }
