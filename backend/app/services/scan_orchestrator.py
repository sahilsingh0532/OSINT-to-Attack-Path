"""Scan orchestrator — coordinates the entire OSINT pipeline:
Collect → Normalize → Correlate → Attack Paths → Risk Scores → Recommendations
"""

import asyncio
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding
from app.models.relationship import Relationship
from app.models.attack_path import AttackPath, AttackPathNode
from app.models.risk_score import RiskScore
from app.models.recommendation import Recommendation
from app.collectors.collectors import ALL_COLLECTORS
from app.demo.apexnova_dataset import (
    ALL_FINDINGS, EXPOSURE_POINTS, ATTACK_PATHS,
    RECOMMENDATIONS as DEMO_RECOMMENDATIONS,
    RISK_SCORES as DEMO_RISK_SCORES,
)
from app.services.correlator import build_relationships
from app.services.risk_engine import calculate_risk_scores_for_findings
from app.services.defense_engine import generate_recommendations_for_findings


async def run_scan(scan_id: str, db: AsyncSession):
    """Execute the full OSINT pipeline for a scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        return

    try:
        is_demo_scan = (scan.mode == "demo")

        # Phase 1: Collection
        scan.status = ScanStatus.COLLECTING.value
        scan.progress = 0.1
        scan.progress_message = "Collecting OSINT data..."
        await db.commit()

        findings_data = []
        collector_classes = ALL_COLLECTORS
        for i, CollectorClass in enumerate(collector_classes):
            collector = CollectorClass()
            collector.is_demo = is_demo_scan
            try:
                results = await collector.collect(scan.target_domain)
                findings_data.extend(results)
            except Exception as ce:
                print(f"Collector {collector.name} error: {ce}")
            scan.progress = 0.1 + (0.3 * (i + 1) / len(collector_classes))
            scan.progress_message = f"Collecting from {collector.display_name}..."
            await db.commit()

        # Phase 2: Normalization — store findings in DB
        scan.status = ScanStatus.NORMALIZING.value
        scan.progress = 0.4
        scan.progress_message = "Normalizing collected data..."
        await db.commit()

        finding_map = {}  # title/value → Finding object (for linking)
        inserted_findings = []
        for fd in findings_data:
            disc_at = datetime.now(timezone.utc)
            if fd.get("discovered_at"):
                try:
                    disc_at = datetime.fromisoformat(fd["discovered_at"])
                except Exception:
                    pass

            finding = Finding(
                scan_id=scan_id,
                source=fd["source"],
                collection_method=fd.get("collection_method", "passive"),
                finding_type=fd["finding_type"],
                value=fd["value"],
                title=fd.get("title"),
                description=fd.get("description"),
                confidence=fd.get("confidence", 0.5),
                observation_type=fd.get("observation_type", "observed"),
                evidence=fd.get("evidence"),
                raw_data=fd.get("raw_data"),
                category=fd.get("category"),
                tags=fd.get("tags"),
                external_url=fd.get("external_url"),
                discovered_at=disc_at,
            )
            db.add(finding)
            await db.flush()
            inserted_findings.append(finding)
            finding_map[fd["value"]] = finding
            if fd.get("title"):
                finding_map[fd["title"]] = finding

        scan.total_findings = len(findings_data)
        await db.commit()

        # Phase 3: Correlation
        scan.status = ScanStatus.CORRELATING.value
        scan.progress = 0.55
        scan.progress_message = "Building correlation graph..."
        await db.commit()

        relationships = build_relationships(finding_map, findings_data)
        for rel in relationships:
            src = finding_map.get(rel["source_ref"])
            tgt = finding_map.get(rel["target_ref"])
            if src and tgt:
                r = Relationship(
                    scan_id=scan_id,
                    source_finding_id=src.id,
                    target_finding_id=tgt.id,
                    relationship_type=rel["relationship_type"],
                    confidence=rel["confidence"],
                    description=rel.get("description"),
                )
                db.add(r)

        scan.total_relationships = len(relationships)
        await db.commit()

        # Phase 4: Attack Path Generation
        scan.status = ScanStatus.ANALYZING.value
        scan.progress = 0.7
        scan.progress_message = "Generating attack hypotheses..."
        await db.commit()

        attack_paths_to_create = []
        if is_demo_scan:
            attack_paths_to_create = ATTACK_PATHS
        else:
            # Dynamic attack path generation for Live Mode
            subdomains = [f.value for f in inserted_findings if f.finding_type == "subdomain"]
            techs = [f.value for f in inserted_findings if f.finding_type == "technology"]
            repos = [f.value for f in inserted_findings if f.finding_type == "repository"]
            threats = [f.value for f in inserted_findings if f.finding_type == "threat_indicator"]

            # Path 1: Infrastructure & Subdomain Attack Vector
            entry_sub = subdomains[0] if subdomains else scan.target_domain
            attack_paths_to_create.append({
                "title": f"External Surface Reconnaissance → {scan.target_domain}",
                "description": f"Public exposure of infrastructure subdomains on {scan.target_domain} enables target profiling.",
                "hypothesis": f"An attacker could map active subdomains, discover version headers, and probe for unpatched external endpoints on {entry_sub}.",
                "validation_note": "Requires authorized security verification.",
                "risk_score": 65.0,
                "risk_level": "HIGH",
                "entry_point": entry_sub,
                "target_asset": "Corporate Infrastructure",
                "nodes": [
                    {"step_order": 1, "label": "Passive OSINT Discovery", "description": "Target domain enumerated via public sources", "node_type": "entry"},
                    {"step_order": 2, "label": entry_sub, "description": "Active endpoint identified", "node_type": "asset"},
                    {"step_order": 3, "label": techs[0] if techs else "Web Stack", "description": "Technology fingerprinted", "node_type": "asset"},
                    {"step_order": 4, "label": "Exposure Vector", "description": "Unnecessary information disclosure", "node_type": "weakness"},
                    {"step_order": 5, "label": "Target Access", "description": "Potential initial access path", "node_type": "impact"},
                ]
            })

            # Path 2: Code Repository Exposure (if repos found)
            if repos:
                attack_paths_to_create.append({
                    "title": f"GitHub Repository → Code Exposure",
                    "description": "Public GitHub repositories may expose sensitive developer comments, API endpoints, or configurations.",
                    "hypothesis": "An attacker analyzing public repos could locate exposed endpoints or staging environment configurations.",
                    "validation_note": "Perform automated secret scanning on public repositories.",
                    "risk_score": 70.0,
                    "risk_level": "HIGH",
                    "entry_point": repos[0],
                    "target_asset": "Source Code & Configs",
                    "nodes": [
                        {"step_order": 1, "label": "GitHub Discovery", "description": "Public repository found", "node_type": "entry"},
                        {"step_order": 2, "label": repos[0], "description": "Target code repository", "node_type": "asset"},
                        {"step_order": 3, "label": "Config Exposure", "description": "Hardcoded config references", "node_type": "weakness"},
                        {"step_order": 4, "label": "Data Exposure", "description": "Source code disclosure", "node_type": "impact"},
                    ]
                })

            # Path 3: Threat Intelligence Exposure (if threats found)
            if threats:
                attack_paths_to_create.append({
                    "title": f"Threat Intelligence Flag → Reputation Risk",
                    "description": "Domain or associated IP flagged in threat intelligence feeds.",
                    "hypothesis": "Blacklisted domain or reputation warning flags target for security scrutiny.",
                    "validation_note": "Audit threat feeds and blacklist entries.",
                    "risk_score": 75.0,
                    "risk_level": "VERY HIGH",
                    "entry_point": scan.target_domain,
                    "target_asset": "Domain Reputation",
                    "nodes": [
                        {"step_order": 1, "label": "Threat Feed Alert", "description": "Domain flagged in threat database", "node_type": "entry"},
                        {"step_order": 2, "label": threats[0], "description": "Threat indicator match", "node_type": "weakness"},
                        {"step_order": 3, "label": "Reputation Impact", "description": "Domain blacklisting / warning", "node_type": "impact"},
                    ]
                })

        for ap_data in attack_paths_to_create:
            ap = AttackPath(
                scan_id=scan_id,
                title=ap_data["title"],
                description=ap_data["description"],
                hypothesis=ap_data["hypothesis"],
                validation_note=ap_data["validation_note"],
                risk_score=ap_data["risk_score"],
                risk_level=ap_data["risk_level"],
                entry_point=ap_data["entry_point"],
                target_asset=ap_data["target_asset"],
            )
            db.add(ap)
            await db.flush()

            for node_data in ap_data["nodes"]:
                node = AttackPathNode(
                    attack_path_id=ap.id,
                    step_order=node_data["step_order"],
                    label=node_data["label"],
                    description=node_data.get("description"),
                    node_type=node_data["node_type"],
                )
                db.add(node)

        scan.total_attack_paths = len(attack_paths_to_create)
        await db.commit()

        # Phase 5: Risk Scoring
        scan.progress = 0.8
        scan.progress_message = "Calculating risk scores..."
        await db.commit()

        exposure_count = 0
        if is_demo_scan:
            for rs_data in DEMO_RISK_SCORES:
                finding = finding_map.get(rs_data["finding_ref"])
                if finding:
                    composite = RiskScore.calculate_composite(
                        rs_data["exposure"], rs_data["confidence"],
                        rs_data["exploitability"], rs_data["impact"]
                    )
                    rs = RiskScore(
                        scan_id=scan_id,
                        finding_id=finding.id,
                        exposure=rs_data["exposure"],
                        confidence=rs_data["confidence"],
                        exploitability=rs_data["exploitability"],
                        impact=rs_data["impact"],
                        composite_score=composite,
                        risk_level=RiskScore.get_risk_level(composite),
                        rationale=rs_data["rationale"],
                    )
                    db.add(rs)
                    exposure_count += 1
        else:
            # Calculate dynamic risk scores for all inserted live findings
            calculated_scores = calculate_risk_scores_for_findings(inserted_findings)
            for cs in calculated_scores:
                rs = RiskScore(
                    scan_id=scan_id,
                    finding_id=cs["finding_id"],
                    exposure=cs["exposure"],
                    confidence=cs["confidence"],
                    exploitability=cs["exploitability"],
                    impact=cs["impact"],
                    composite_score=cs["composite_score"],
                    risk_level=cs["risk_level"],
                    rationale=cs["rationale"],
                )
                db.add(rs)
                exposure_count += 1

        scan.total_exposures = exposure_count
        await db.commit()

        # Phase 6: Defensive Recommendations
        scan.progress = 0.9
        scan.progress_message = "Generating defensive recommendations..."
        await db.commit()

        if is_demo_scan:
            for rec_data in DEMO_RECOMMENDATIONS:
                finding = finding_map.get(rec_data.get("finding_ref"))
                rec = Recommendation(
                    scan_id=scan_id,
                    finding_id=finding.id if finding else None,
                    title=rec_data["title"],
                    description=rec_data["description"],
                    category=rec_data["category"],
                    priority=rec_data["priority"],
                    effort=rec_data["effort"],
                    rationale=rec_data.get("rationale"),
                )
                db.add(rec)
        else:
            recs = generate_recommendations_for_findings(inserted_findings, scan.target_domain)
            for rec_data in recs:
                rec = Recommendation(
                    scan_id=scan_id,
                    title=rec_data["title"],
                    description=rec_data["description"],
                    category=rec_data["category"],
                    priority=rec_data["priority"],
                    effort=rec_data["effort"],
                    rationale=rec_data.get("rationale"),
                )
                db.add(rec)

        await db.commit()

        # Phase 7: Calculate overall risk score
        scan.progress = 0.95
        scan.progress_message = "Finalizing analysis..."
        await db.commit()

        result = await db.execute(
            select(RiskScore).where(RiskScore.scan_id == scan_id)
        )
        all_risk_scores = result.scalars().all()
        if all_risk_scores:
            scores = [rs.composite_score for rs in all_risk_scores]
            scan.overall_risk_score = round(sum(scores) / len(scores) * 1.15, 1)  # Weighted average
            scan.overall_risk_score = min(scan.overall_risk_score, 100.0)
            scan.overall_risk_level = RiskScore.get_risk_level(scan.overall_risk_score)
        else:
            scan.overall_risk_score = 0.0
            scan.overall_risk_level = "LOW"

        # Complete
        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 1.0
        scan.progress_message = "Scan completed successfully."
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()

    except Exception as e:
        scan.status = ScanStatus.FAILED.value
        scan.progress_message = f"Error: {str(e)}"
        await db.commit()
        raise
