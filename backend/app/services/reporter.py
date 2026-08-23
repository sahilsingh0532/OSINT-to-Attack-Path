"""
Report generation service — produces VAPT/OSINT reports in JSON and HTML formats.
"""

from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.relationship import Relationship
from app.models.attack_path import AttackPath, AttackPathNode
from app.models.risk_score import RiskScore
from app.models.recommendation import Recommendation


async def generate_report(scan_id: str, db: AsyncSession, sections: list = None, fmt: str = "json") -> dict:
    """Generate a comprehensive VAPT/OSINT report."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        return {"error": "Scan not found"}

    # Fetch all data
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    relationships_result = await db.execute(select(Relationship).where(Relationship.scan_id == scan_id))
    relationships = relationships_result.scalars().all()

    attack_paths_result = await db.execute(
        select(AttackPath).where(AttackPath.scan_id == scan_id).order_by(AttackPath.risk_score.desc())
    )
    attack_paths = attack_paths_result.scalars().all()

    risk_scores_result = await db.execute(
        select(RiskScore).where(RiskScore.scan_id == scan_id).order_by(RiskScore.composite_score.desc())
    )
    risk_scores = risk_scores_result.scalars().all()

    recommendations_result = await db.execute(
        select(Recommendation).where(Recommendation.scan_id == scan_id).order_by(Recommendation.priority)
    )
    recommendations = recommendations_result.scalars().all()

    # Build report
    report = {
        "title": "OSINT-to-Attack-Path — Passive Reconnaissance Report",
        "subtitle": "Automated Passive Reconnaissance & Risk Prioritization Framework",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": "CONFIDENTIAL — Authorized Use Only",
        "disclaimer": "This report is generated for authorized security testing, academic research, and controlled laboratory environments only. It does not constitute an active penetration test. All findings are based on passive reconnaissance of publicly available information.",

        "executive_summary": {
            "target": scan.target_domain,
            "mode": scan.mode,
            "total_findings": scan.total_findings,
            "total_relationships": scan.total_relationships,
            "total_attack_paths": scan.total_attack_paths,
            "total_exposures": scan.total_exposures,
            "overall_risk_score": scan.overall_risk_score,
            "overall_risk_level": scan.overall_risk_level,
            "scan_duration": str(scan.completed_at - scan.created_at) if scan.completed_at else "N/A",
            "summary": f"Passive reconnaissance of {scan.target_domain} identified {scan.total_findings} OSINT records from multiple sources. Data correlation revealed {scan.total_relationships} relationships between assets, {scan.total_exposures} potential exposure points, and {scan.total_attack_paths} attack hypotheses. The overall OSINT risk score is {scan.overall_risk_score}/100 ({scan.overall_risk_level})."
        },

        "scope": {
            "target_domain": scan.target_domain,
            "methodology": "Passive OSINT Collection",
            "sources_used": list(set(f.source for f in findings)),
            "limitations": [
                "This assessment uses only passive reconnaissance techniques.",
                "No active scanning, exploitation, or authentication bypass was performed.",
                "Findings are based on publicly available information only.",
                "Risk scores are academic estimates and do not represent CVSS scores.",
                "Some findings may be outdated — active validation is required.",
            ]
        },

        "methodology": {
            "phases": [
                "Phase 1: Passive OSINT Collection from multiple sources",
                "Phase 2: Data Normalization and deduplication",
                "Phase 3: Cross-source correlation and relationship mapping",
                "Phase 4: Attack hypothesis generation from correlated data",
                "Phase 5: Risk scoring using 4-factor model (Exposure × Confidence × Exploitability × Impact)",
                "Phase 6: Defensive recommendation generation",
            ],
            "note": "This is an academic risk-prioritization model and is not CVSS."
        },

        "findings": [
            {
                "id": f.id,
                "source": f.source,
                "type": f.finding_type,
                "value": f.value,
                "title": f.title,
                "description": f.description,
                "confidence": f.confidence,
                "observation_type": f.observation_type,
                "evidence": f.evidence,
                "category": f.category,
                "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
            }
            for f in findings
        ],

        "attack_paths": [
            {
                "id": ap.id,
                "title": ap.title,
                "description": ap.description,
                "hypothesis": ap.hypothesis,
                "validation_note": ap.validation_note,
                "risk_score": ap.risk_score,
                "risk_level": ap.risk_level,
                "entry_point": ap.entry_point,
                "target_asset": ap.target_asset,
            }
            for ap in attack_paths
        ],

        "risk_analysis": {
            "scores": [
                {
                    "finding_id": rs.finding_id,
                    "exposure": rs.exposure,
                    "confidence": rs.confidence,
                    "exploitability": rs.exploitability,
                    "impact": rs.impact,
                    "composite_score": rs.composite_score,
                    "risk_level": rs.risk_level,
                    "rationale": rs.rationale,
                }
                for rs in risk_scores
            ],
            "distribution": {
                "CRITICAL": sum(1 for rs in risk_scores if rs.risk_level == "CRITICAL"),
                "VERY HIGH": sum(1 for rs in risk_scores if rs.risk_level == "VERY HIGH"),
                "HIGH": sum(1 for rs in risk_scores if rs.risk_level == "HIGH"),
                "MEDIUM": sum(1 for rs in risk_scores if rs.risk_level == "MEDIUM"),
                "LOW": sum(1 for rs in risk_scores if rs.risk_level == "LOW"),
            }
        },

        "recommendations": [
            {
                "title": rec.title,
                "description": rec.description,
                "category": rec.category,
                "priority": rec.priority,
                "effort": rec.effort,
                "rationale": rec.rationale,
            }
            for rec in recommendations
        ],

        "conclusion": f"The passive reconnaissance assessment of {scan.target_domain} reveals a {scan.overall_risk_level} risk posture based on publicly discoverable information. The most critical findings involve publicly accessible development infrastructure, exposed infrastructure-as-code repositories, and known vulnerable software versions. Immediate remediation is recommended for the {sum(1 for rs in risk_scores if rs.risk_level in ('CRITICAL', 'VERY HIGH'))} critical/very-high risk findings."
    }

    return report
