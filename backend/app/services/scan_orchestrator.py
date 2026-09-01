"""
Scan Orchestrator v2 — coordinates the full OSINT pipeline using the modular
provider registry and multi-source merger:

  Providers run concurrently → raw results → merge → correlate → attack paths → risk → recommendations
"""

import asyncio
from datetime import datetime, timezone
from collections import defaultdict
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding
from app.models.relationship import Relationship
from app.models.attack_path import AttackPath, AttackPathNode
from app.models.risk_score import RiskScore
from app.models.recommendation import Recommendation

from app.collectors.registry import get_domain_scan_providers, PROVIDER_REGISTRY
from app.services.merger import merge_results, compute_source_agreement
from app.services.correlator import build_relationships
from app.services.risk_engine import calculate_risk_scores_for_findings
from app.services.defense_engine import generate_recommendations_for_findings
from app.services.confidence import confidence_breakdown

from app.demo.apexnova_dataset import (
    ALL_FINDINGS, ATTACK_PATHS,
    RECOMMENDATIONS as DEMO_RECOMMENDATIONS,
    RISK_SCORES as DEMO_RISK_SCORES,
)


async def _run_provider(provider, target: str) -> list:
    """Run a single provider and return results, catching all errors."""
    try:
        return await provider.collect(target)
    except Exception as e:
        print(f"[Provider Error] {provider.name}: {e}")
        return []


async def run_scan(scan_id: str, db: AsyncSession):
    """Execute the full OSINT pipeline for a scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        return

    try:
        is_demo = (scan.mode == "demo")

        # ── Phase 1: Concurrent Provider Collection ────────────────────────
        scan.status = ScanStatus.COLLECTING.value
        scan.progress = 0.05
        scan.progress_message = "Initialising OSINT providers..."
        await db.commit()

        if is_demo:
            raw_results = ALL_FINDINGS
            await db.commit()
        else:
            providers = get_domain_scan_providers()
            total_providers = len(providers)

            # Run all providers concurrently (asyncio.gather)
            scan.progress_message = f"Running {total_providers} OSINT providers concurrently..."
            await db.commit()

            tasks = []
            for ProviderClass in providers:
                p = ProviderClass()
                p.is_demo = False
                tasks.append(_run_provider(p, scan.target_domain))

            results_per_provider = await asyncio.gather(*tasks, return_exceptions=False)
            raw_results = []
            for provider_results in results_per_provider:
                if isinstance(provider_results, list):
                    raw_results.extend(provider_results)

        scan.progress = 0.30
        scan.progress_message = f"Collected {len(raw_results)} raw intelligence items..."
        await db.commit()

        # ── Phase 2: Multi-Source Merging ──────────────────────────────────
        scan.status = ScanStatus.NORMALIZING.value
        scan.progress_message = "Merging multi-source results..."
        await db.commit()

        if is_demo:
            # Demo data is pre-structured — wrap as merged findings
            merged_findings = raw_results
        else:
            merged_findings = merge_results(raw_results)

            # Calculate total providers queried per type
            total_queried_per_type: dict = defaultdict(int)
            for cat, providers_list in PROVIDER_REGISTRY.items():
                if cat in ("domain", "dns", "certificate", "ip", "technology", "github", "threat_intel"):
                    for ProviderClass in providers_list:
                        p = ProviderClass()
                        p.is_demo = False
                        if p._has_api_key() or not p.requires_key:
                            for ft in _category_to_finding_types(cat):
                                total_queried_per_type[ft] += 1

            # Refine source_agreement with actual provider counts
            merged_findings = compute_source_agreement(merged_findings, dict(total_queried_per_type))

        scan.progress = 0.45
        scan.progress_message = f"Merged to {len(merged_findings)} unique findings..."
        await db.commit()

        # ── Phase 3: Persist Findings to DB ───────────────────────────────
        finding_map = {}
        inserted_findings = []

        for fd in merged_findings:
            disc_at = datetime.now(timezone.utc)
            if fd.get("discovered_at"):
                try:
                    disc_at = datetime.fromisoformat(fd["discovered_at"].replace("Z", "+00:00"))
                except Exception:
                    pass

            first_seen = None
            if fd.get("first_seen"):
                try:
                    first_seen = datetime.fromisoformat(fd["first_seen"].replace("Z", "+00:00"))
                except Exception:
                    pass

            last_seen = None
            if fd.get("last_seen"):
                try:
                    last_seen = datetime.fromisoformat(fd["last_seen"].replace("Z", "+00:00"))
                except Exception:
                    pass

            # Determine primary source
            sources_list = fd.get("sources", [fd.get("source", "unknown")])
            primary_source = sources_list[0] if sources_list else fd.get("source", "unknown")

            finding = Finding(
                scan_id=scan_id,
                source=primary_source,
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
                # Multi-source fields
                sources=sources_list,
                source_count=fd.get("source_count", 1),
                source_agreement=fd.get("source_agreement", 1.0),
                total_queried=fd.get("total_queried", 1),
                evidence_per_source=fd.get("evidence_per_source", []),
                norm_value=fd.get("norm_value", ""),
                first_seen=first_seen,
                last_seen=last_seen,
            )
            db.add(finding)
            await db.flush()
            inserted_findings.append(finding)
            finding_map[fd["value"]] = finding
            if fd.get("title"):
                finding_map[fd["title"]] = finding
            if fd.get("norm_value"):
                finding_map[fd["norm_value"]] = finding

        scan.total_findings = len(merged_findings)
        await db.commit()

        # ── Phase 4: Correlation ───────────────────────────────────────────
        scan.status = ScanStatus.CORRELATING.value
        scan.progress = 0.60
        scan.progress_message = "Building correlation graph..."
        await db.commit()

        relationships = build_relationships(finding_map, merged_findings)
        for rel in relationships:
            src = finding_map.get(rel["source_ref"])
            tgt = finding_map.get(rel["target_ref"])
            if src and tgt and src.id != tgt.id:
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

        # ── Phase 5: Attack Paths ──────────────────────────────────────────
        scan.status = ScanStatus.ANALYZING.value
        scan.progress = 0.72
        scan.progress_message = "Generating evidence-backed attack hypotheses..."
        await db.commit()

        attack_paths_data = ATTACK_PATHS if is_demo else _generate_attack_paths(inserted_findings, scan)
        for ap_data in attack_paths_data:
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
            for node_data in ap_data.get("nodes", []):
                db.add(AttackPathNode(
                    attack_path_id=ap.id,
                    step_order=node_data["step_order"],
                    label=node_data["label"],
                    description=node_data.get("description"),
                    node_type=node_data["node_type"],
                ))

        scan.total_attack_paths = len(attack_paths_data)
        await db.commit()

        # ── Phase 6: Risk Scoring ──────────────────────────────────────────
        scan.progress = 0.82
        scan.progress_message = "Calculating risk scores..."
        await db.commit()

        exposure_count = 0
        if is_demo:
            for rs_data in DEMO_RISK_SCORES:
                finding = finding_map.get(rs_data.get("finding_ref", ""))
                if finding:
                    composite = RiskScore.calculate_composite(
                        rs_data["exposure"], rs_data["confidence"],
                        rs_data["exploitability"], rs_data["impact"]
                    )
                    db.add(RiskScore(
                        scan_id=scan_id, finding_id=finding.id,
                        exposure=rs_data["exposure"], confidence=rs_data["confidence"],
                        exploitability=rs_data["exploitability"], impact=rs_data["impact"],
                        composite_score=composite, risk_level=RiskScore.get_risk_level(composite),
                        rationale=rs_data["rationale"],
                    ))
                    exposure_count += 1
        else:
            calculated = calculate_risk_scores_for_findings(inserted_findings)
            for cs in calculated:
                db.add(RiskScore(
                    scan_id=scan_id, finding_id=cs["finding_id"],
                    exposure=cs["exposure"], confidence=cs["confidence"],
                    exploitability=cs["exploitability"], impact=cs["impact"],
                    composite_score=cs["composite_score"], risk_level=cs["risk_level"],
                    rationale=cs["rationale"],
                ))
                exposure_count += 1

        scan.total_exposures = exposure_count
        await db.commit()

        # ── Phase 7: Recommendations ───────────────────────────────────────
        scan.progress = 0.92
        scan.progress_message = "Generating defensive recommendations..."
        await db.commit()

        if is_demo:
            for rec_data in DEMO_RECOMMENDATIONS:
                finding = finding_map.get(rec_data.get("finding_ref"))
                db.add(Recommendation(
                    scan_id=scan_id,
                    finding_id=finding.id if finding else None,
                    title=rec_data["title"], description=rec_data["description"],
                    category=rec_data["category"], priority=rec_data["priority"],
                    effort=rec_data["effort"], rationale=rec_data.get("rationale"),
                ))
        else:
            for rec_data in generate_recommendations_for_findings(inserted_findings, scan.target_domain):
                db.add(Recommendation(
                    scan_id=scan_id, title=rec_data["title"],
                    description=rec_data["description"], category=rec_data["category"],
                    priority=rec_data["priority"], effort=rec_data["effort"],
                    rationale=rec_data.get("rationale"),
                ))

        await db.commit()

        # ── Phase 8: Overall Risk Score ────────────────────────────────────
        scan.progress = 0.97
        scan.progress_message = "Finalising analysis..."
        await db.commit()

        result = await db.execute(select(RiskScore).where(RiskScore.scan_id == scan_id))
        all_risk_scores = result.scalars().all()
        if all_risk_scores:
            scores = [rs.composite_score for rs in all_risk_scores]
            scan.overall_risk_score = round(min(sum(scores) / len(scores) * 1.15, 100.0), 1)
            scan.overall_risk_level = RiskScore.get_risk_level(scan.overall_risk_score)
        else:
            scan.overall_risk_score = 0.0
            scan.overall_risk_level = "LOW"

        scan.status = ScanStatus.COMPLETED.value
        scan.progress = 1.0
        scan.progress_message = "Scan completed successfully."
        scan.completed_at = datetime.now(timezone.utc)
        await db.commit()

    except Exception as e:
        await db.rollback()
        try:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED.value
                scan.progress_message = f"Error: {str(e)}"
                await db.commit()
        except Exception:
            pass
        raise


def _category_to_finding_types(category: str) -> list:
    """Map provider category to finding types for agreement calculation."""
    mapping = {
        "domain": ["domain", "subdomain"],
        "dns": ["ip", "subdomain"],
        "certificate": ["certificate"],
        "ip": ["ip", "asn"],
        "technology": ["technology", "exposure"],
        "github": ["repository", "identity", "exposure"],
        "email": ["email"],
        "username": ["identity"],
        "threat_intel": ["threat_indicator", "darkweb_reference"],
    }
    return mapping.get(category, [category])


def _generate_attack_paths(findings: list, scan) -> list:
    """Generate evidence-backed attack paths from live findings."""
    subdomains = [f for f in findings if f.finding_type == "subdomain"]
    techs = [f for f in findings if f.finding_type == "technology"]
    repos = [f for f in findings if f.finding_type == "repository"]
    threats = [f for f in findings if f.finding_type == "threat_indicator"]
    exposures = [f for f in findings if f.finding_type == "exposure"]
    ips = [f for f in findings if f.finding_type == "ip"]

    paths = []
    target = scan.target_domain

    # Path 1: External Surface Reconnaissance
    entry = subdomains[0].value if subdomains else target
    multi_source_subs = [f for f in subdomains if (f.source_count or 1) > 1]
    evidence_points = []
    if subdomains:
        evidence_points.append(f"✓ {len(subdomains)} subdomains discovered via passive DNS")
    if multi_source_subs:
        evidence_points.append(f"✓ {len(multi_source_subs)} confirmed by multiple independent sources")
    if ips:
        evidence_points.append(f"✓ {len(ips)} IP addresses identified via passive resolution")

    paths.append({
        "title": f"External Surface Reconnaissance → {target}",
        "description": f"Passive OSINT reveals {len(subdomains)} subdomains and {len(ips)} IPs for {target}.",
        "hypothesis": (
            f"An attacker conducting passive reconnaissance could discover {len(subdomains)} subdomains "
            f"without any active scanning. High-confidence subdomains (confirmed by multiple sources) "
            f"provide reliable targets for further authorized assessment."
        ),
        "validation_note": "Requires authorized active VAPT to validate exploitability.",
        "risk_score": min(55.0 + len(subdomains) * 0.5, 85.0),
        "risk_level": "HIGH" if len(subdomains) > 5 else "MEDIUM",
        "entry_point": entry,
        "target_asset": f"External Attack Surface ({target})",
        "nodes": [
            {"step_order": 1, "label": "Passive OSINT", "description": "Multiple sources queried passively", "node_type": "entry"},
            {"step_order": 2, "label": f"{len(subdomains)} Subdomains", "description": "Discovered via CT logs, passive DNS", "node_type": "asset"},
            {"step_order": 3, "label": f"{len(ips)} IP Addresses", "description": "Resolved via passive DNS", "node_type": "asset"},
            {"step_order": 4, "label": "Potential Attack Surface", "description": "External-facing infrastructure identified", "node_type": "impact"},
        ],
    })

    # Path 2: Technology Exposure
    if techs:
        paths.append({
            "title": f"Technology Fingerprinting → Potential Security Relevance",
            "description": f"{len(techs)} technology indicators observed across multiple passive sources.",
            "hypothesis": (
                f"Identified technologies may have publicly known security considerations. "
                f"Version disclosure via HTTP headers provides reconnaissance value. "
                f"Security relevance: potential. Validation requires authorized testing."
            ),
            "validation_note": "Technology identification does not imply vulnerability. Authorized assessment required.",
            "risk_score": 55.0,
            "risk_level": "MEDIUM",
            "entry_point": techs[0].value if techs else target,
            "target_asset": "Technology Stack",
            "nodes": [
                {"step_order": 1, "label": "HTTP Fingerprint", "description": "Headers analyzed passively", "node_type": "entry"},
                {"step_order": 2, "label": techs[0].value[:40] if techs else "Technology", "description": "Technology identified", "node_type": "asset"},
                {"step_order": 3, "label": "Security Relevance", "description": "Potential attack surface — requires authorized validation", "node_type": "weakness"},
            ],
        })

    # Path 3: Code Repository Exposure
    if repos:
        paths.append({
            "title": "GitHub Repository → Code Intelligence",
            "description": f"{len(repos)} public repositories reference target. Code intelligence potential.",
            "hypothesis": (
                "Public repositories may expose infrastructure references, development endpoints, "
                "or configuration patterns. Secret exposure detected in code search requires "
                "immediate credential rotation and repository audit."
            ),
            "validation_note": "Review all flagged files. Rotate any potentially exposed credentials immediately.",
            "risk_score": 70.0,
            "risk_level": "HIGH",
            "entry_point": repos[0].value,
            "target_asset": "Source Code & Configuration",
            "nodes": [
                {"step_order": 1, "label": "GitHub Discovery", "description": "Public repositories found", "node_type": "entry"},
                {"step_order": 2, "label": f"{len(repos)} Repositories", "description": "Code references identified", "node_type": "asset"},
                {"step_order": 3, "label": "Potential Exposure", "description": "Credentials/config may be exposed", "node_type": "weakness"},
                {"step_order": 4, "label": "Recommended Action", "description": "Rotate credentials. Audit repository history.", "node_type": "impact"},
            ],
        })

    # Path 4: Threat Intelligence Flag
    if threats:
        paths.append({
            "title": "Threat Intelligence → Domain Risk",
            "description": f"Domain flagged in {len(threats)} threat intelligence sources.",
            "hypothesis": (
                f"{target} appears in open threat intelligence feeds. This may indicate prior "
                "compromise, phishing associations, or malware distribution. Reputation impact "
                "requires immediate investigation."
            ),
            "validation_note": "Investigate threat feed entries. Contact threat intelligence provider for details.",
            "risk_score": 78.0,
            "risk_level": "VERY HIGH",
            "entry_point": target,
            "target_asset": "Domain Reputation",
            "nodes": [
                {"step_order": 1, "label": "Threat Feed Alert", "description": "Domain referenced in threat intelligence", "node_type": "entry"},
                {"step_order": 2, "label": f"{len(threats)} Threat Indicators", "description": "Multi-source threat confirmation", "node_type": "weakness"},
                {"step_order": 3, "label": "Reputation Risk", "description": "Domain reputation affected", "node_type": "impact"},
            ],
        })

    return paths
