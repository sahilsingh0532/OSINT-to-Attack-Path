"""
API routes — all scan, finding, intelligence, graph, attack-path,
risk, recommendation, timeline, report, sources, and settings endpoints.
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
    ReportRequest, SourceComparison, SourceComparisonRow, ConfidenceBreakdown,
)
from app.services.scan_orchestrator import run_scan
from app.services.reporter import generate_report
from app.services.confidence import confidence_breakdown
from app.collectors.registry import get_all_providers, get_provider_health, PROVIDER_REGISTRY
from app.config import settings


router = APIRouter(prefix="/api")


# ── Background task runner ────────────────────────────────────────────────────
async def _run_scan_background(scan_id: str):
    async with async_session() as db:
        await run_scan(scan_id, db)


# ═══════════════════════════════ SCANS ═══════════════════════════════════════

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
    background_tasks.add_task(_run_scan_background, scan.id)
    return scan


@router.get("/scans", response_model=List[ScanSummary])
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.get("/scans/{scan_id}", response_model=ScanSummary)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ═══════════════════════════════ DASHBOARD ═══════════════════════════════════

@router.get("/scans/{scan_id}/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    type_counts = {}
    total_confidence = 0.0
    total_source_count = 0
    count = 0

    for f in findings:
        ft = f.finding_type
        type_counts[ft] = type_counts.get(ft, 0) + 1
        total_confidence += f.confidence or 0
        total_source_count += f.source_count or 1
        count += 1

    avg_confidence = round(total_confidence / count * 100) if count else 0
    avg_source_count = round(total_source_count / count, 1) if count else 1

    return DashboardStats(
        domains=type_counts.get("domain", 0),
        subdomains=type_counts.get("subdomain", 0),
        certificates=type_counts.get("certificate", 0),
        ip_asn=type_counts.get("ip", 0) + type_counts.get("asn", 0),
        technologies=type_counts.get("technology", 0),
        repositories=type_counts.get("repository", 0),
        org_references=type_counts.get("organization", 0) + type_counts.get("identity", 0),
        threat_indicators=type_counts.get("threat_indicator", 0) + type_counts.get("darkweb_reference", 0),
        exposure_points=type_counts.get("exposure", 0),
        attack_paths=scan.total_attack_paths or 0,
        emails=type_counts.get("email", 0),
        usernames=type_counts.get("identity", 0),
        overall_risk_score=scan.overall_risk_score or 0,
        overall_risk_level=scan.overall_risk_level or "LOW",
        avg_confidence=avg_confidence,
        avg_source_count=avg_source_count,
    )


# ═══════════════════════════════ FINDINGS ════════════════════════════════════

@router.get("/scans/{scan_id}/findings", response_model=List[FindingOut])
async def get_findings(
    scan_id: str,
    finding_type: Optional[str] = None,
    category: Optional[str] = None,
    observation_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(Finding).where(Finding.scan_id == scan_id)
    if finding_type:
        query = query.where(Finding.finding_type == finding_type)
    if category:
        query = query.where(Finding.category == category)
    if observation_type:
        query = query.where(Finding.observation_type == observation_type)
    query = query.order_by(Finding.source_count.desc(), Finding.confidence.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/findings/{finding_id}", response_model=FindingDetail)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


# ─── Typed finding endpoints ──────────────────────────────────────────────────

@router.get("/scans/{scan_id}/domains", response_model=List[FindingOut])
async def get_domains(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id, Finding.finding_type == "domain")
        .order_by(Finding.source_count.desc())
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/subdomains", response_model=List[FindingOut])
async def get_subdomains(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id, Finding.finding_type == "subdomain")
        .order_by(Finding.source_count.desc(), Finding.confidence.desc())
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/certificates", response_model=List[FindingOut])
async def get_certificates(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id, Finding.finding_type == "certificate")
        .order_by(Finding.source_count.desc())
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/ips", response_model=List[FindingOut])
async def get_ips(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.finding_type.in_(["ip", "asn"])
        ).order_by(Finding.source_count.desc())
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/emails", response_model=List[FindingOut])
async def get_emails(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id, Finding.finding_type == "email")
        .order_by(Finding.source_count.desc())
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/usernames", response_model=List[FindingOut])
async def get_usernames(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.finding_type.in_(["identity", "username"])
        ).order_by(Finding.source_count.desc())
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/technologies", response_model=List[FindingOut])
async def get_technologies(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id, Finding.finding_type == "technology")
        .order_by(Finding.source_count.desc())
    )
    return result.scalars().all()


# ─── Source comparison matrix ─────────────────────────────────────────────────

@router.get("/scans/{scan_id}/source-comparison", response_model=List[SourceComparison])
async def get_source_comparison(
    scan_id: str,
    finding_type: Optional[str] = "subdomain",
    limit: int = 20,
    db: AsyncSession = Depends(get_db)
):
    """Return per-finding source comparison matrix."""
    result = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.finding_type == finding_type,
        ).order_by(Finding.source_count.desc()).limit(limit)
    )
    findings = result.scalars().all()

    # Get all known sources for this category
    category_providers = []
    for cat, providers in PROVIDER_REGISTRY.items():
        for P in providers:
            p = P()
            category_providers.append(p.name)
    known_sources = list(dict.fromkeys(category_providers))[:8]

    comparisons = []
    for f in findings:
        sources_found = set(f.sources or [f.source])
        rows = []
        for src in known_sources:
            if src in sources_found:
                ev = next((e for e in (f.evidence_per_source or []) if e.get("source") == src), {})
                rows.append(SourceComparisonRow(
                    source=src, result="Found", status="found",
                    confidence=ev.get("confidence"),
                    discovered_at=ev.get("discovered_at"),
                ))
            else:
                rows.append(SourceComparisonRow(source=src, result="Not found", status="not_found"))

        sc = f.source_count or 1
        tq = f.total_queried or len(known_sources)
        comparisons.append(SourceComparison(
            finding_id=f.id,
            finding_value=f.value,
            finding_type=f.finding_type,
            rows=rows,
            source_count=sc,
            total_queried=tq,
            agreement_pct=round(sc / max(tq, 1) * 100),
            confidence_pct=round((f.confidence or 0) * 100),
        ))
    return comparisons


# ─── Confidence breakdown ──────────────────────────────────────────────────────

@router.get("/findings/{finding_id}/confidence", response_model=ConfidenceBreakdown)
async def get_confidence_breakdown(finding_id: str, db: AsyncSession = Depends(get_db)):
    f = await db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    sources_list = f.sources or [f.source]
    source_confidences = [e.get("confidence", f.confidence) for e in (f.evidence_per_source or [])]
    if not source_confidences:
        source_confidences = [f.confidence]
    breakdown = confidence_breakdown(
        source_confidences=source_confidences,
        source_count=f.source_count or 1,
        total_queried=f.total_queried or 1,
        first_seen=f.first_seen.isoformat() if f.first_seen else None,
    )
    return ConfidenceBreakdown(**breakdown)


# ═══════════════════════════════ GRAPH ═══════════════════════════════════════

@router.get("/scans/{scan_id}/graph", response_model=GraphData)
async def get_graph_data(scan_id: str, db: AsyncSession = Depends(get_db)):
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()
    relationships_result = await db.execute(select(Relationship).where(Relationship.scan_id == scan_id))
    relationships = relationships_result.scalars().all()
    risk_result = await db.execute(select(RiskScore).where(RiskScore.scan_id == scan_id))
    risk_scores = {rs.finding_id: rs for rs in risk_result.scalars().all()}

    nodes = []
    seen_ids = set()
    for f in findings:
        if f.id not in seen_ids:
            rs = risk_scores.get(f.id)
            nodes.append(GraphNode(
                id=f.id, label=f.title or f.value[:50],
                node_type=f.finding_type, finding_id=f.id,
                confidence=f.confidence, observation_type=f.observation_type,
                risk_level=rs.risk_level if rs else None,
                source_count=f.source_count or 1,
                sources=f.sources or [f.source],
                data={"value": f.value, "source": f.source, "category": f.category},
            ))
            seen_ids.add(f.id)

    edges = []
    for r in relationships:
        edges.append(GraphEdge(
            id=r.id, source=r.source_finding_id, target=r.target_finding_id,
            relationship_type=r.relationship_type, confidence=r.confidence,
            label=r.relationship_type.replace("_", " "),
        ))

    return GraphData(nodes=nodes, edges=edges)


@router.get("/scans/{scan_id}/relationships", response_model=List[RelationshipOut])
async def get_relationships(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Relationship).where(Relationship.scan_id == scan_id))
    return result.scalars().all()


# ═══════════════════════════════ ATTACK PATHS ═════════════════════════════════

@router.get("/scans/{scan_id}/attack-paths", response_model=List[AttackPathOut])
async def get_attack_paths(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AttackPath).where(AttackPath.scan_id == scan_id).order_by(AttackPath.risk_score.desc())
    )
    attack_paths = result.scalars().all()
    response = []
    for ap in attack_paths:
        nodes_result = await db.execute(
            select(AttackPathNode).where(AttackPathNode.attack_path_id == ap.id)
            .order_by(AttackPathNode.step_order)
        )
        nodes = nodes_result.scalars().all()
        response.append(AttackPathOut(
            id=ap.id, scan_id=ap.scan_id, title=ap.title,
            description=ap.description, hypothesis=ap.hypothesis,
            validation_note=ap.validation_note, risk_score=ap.risk_score,
            risk_level=ap.risk_level, severity_order=ap.severity_order,
            entry_point=ap.entry_point, target_asset=ap.target_asset,
            created_at=ap.created_at,
            nodes=[AttackPathNodeOut(
                id=n.id, step_order=n.step_order, label=n.label,
                description=n.description, node_type=n.node_type,
                finding_id=n.finding_id,
            ) for n in nodes],
        ))
    return response


# ═══════════════════════════════ RISK ════════════════════════════════════════

@router.get("/scans/{scan_id}/risk", response_model=List[RiskScoreOut])
async def get_risk_scores(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(RiskScore).where(RiskScore.scan_id == scan_id)
        .order_by(RiskScore.composite_score.desc())
    )
    return result.scalars().all()


@router.get("/scans/{scan_id}/risk/summary", response_model=RiskSummary)
async def get_risk_summary(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    result = await db.execute(select(RiskScore).where(RiskScore.scan_id == scan_id))
    scores = result.scalars().all()
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


# ═══════════════════════════════ RECOMMENDATIONS ══════════════════════════════

@router.get("/scans/{scan_id}/recommendations", response_model=List[RecommendationOut])
async def get_recommendations(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Recommendation).where(Recommendation.scan_id == scan_id)
        .order_by(Recommendation.priority)
    )
    return result.scalars().all()


# ═══════════════════════════════ TIMELINE ════════════════════════════════════

@router.get("/scans/{scan_id}/timeline", response_model=List[TimelineEvent])
async def get_timeline(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.discovered_at)
    )
    findings = result.scalars().all()
    return [
        TimelineEvent(
            id=f.id, timestamp=f.discovered_at,
            title=f.title or f.value[:80], description=f.description or "",
            source=f.source, finding_type=f.finding_type, category=f.category,
            confidence=f.confidence, observation_type=f.observation_type,
            sources=f.sources or [f.source], source_count=f.source_count or 1,
        )
        for f in findings
    ]


# ═══════════════════════════════ REPORTS ═════════════════════════════════════

@router.post("/scans/{scan_id}/report")
async def create_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    report = await generate_report(scan_id, db)
    return report


# ═══════════════════════════════ SOURCES / HEALTH ════════════════════════════

@router.get("/sources", response_model=List[SourceStatus])
async def get_sources():
    """Get status of all registered OSINT providers."""
    is_demo = (settings.osint_mode == "demo")
    health = get_provider_health(is_demo=is_demo)
    return [
        SourceStatus(
            name=h["name"],
            display_name=h["display_name"],
            status=h["status"],
            is_demo=h["is_demo"],
            description=h["description"],
            requires_key=h["requires_key"],
            category=h["category"],
            last_error=h.get("last_error"),
            last_queried_at=h.get("last_queried_at"),
        )
        for h in health
    ]


@router.get("/sources/health")
async def get_source_health():
    """Detailed source health for the Source Health Dashboard."""
    is_demo = (settings.osint_mode == "demo")
    return get_provider_health(is_demo=is_demo)


# ═══════════════════════════════ SETTINGS ════════════════════════════════════

@router.get("/settings")
async def get_settings():
    return {
        "mode": settings.osint_mode,
        "github_configured": bool(settings.github_token),
        "shodan_configured": bool(settings.shodan_api_key),
        "virustotal_configured": bool(settings.virustotal_api_key),
        "censys_configured": bool(settings.censys_api_id),
        "hunter_configured": bool(settings.hunter_api_key),
        "hibp_configured": bool(settings.hibp_api_key),
        "emailrep_configured": bool(settings.emailrep_api_key),
        "firebase_configured": bool(settings.firebase_project_id),
        "securitytrails_configured": bool(settings.securitytrails_api_key),
    }
