"""
Multi-Source Merger — the core intelligence engine.

Merges raw provider results into unified findings.
If multiple independent sources discover the same entity (normalized value),
they are merged into ONE finding with a sources list and source agreement score.

This is the primary research novelty: cross-source validation → higher confidence.
"""

from typing import List, Dict, Any, Tuple
from collections import defaultdict
from datetime import datetime, timezone
import re

from app.services.confidence import calculate_confidence


def normalize_value(finding_type: str, value: str) -> str:
    """
    Normalize a finding value for deduplication.
    Different sources may represent the same entity with minor formatting differences.
    """
    value = value.strip().lower()

    if finding_type in ("domain", "subdomain"):
        # Remove trailing dots, strip www prefix for comparison
        value = value.rstrip(".")
        return value

    if finding_type == "ip":
        # Strip IPv6 brackets
        value = value.strip("[]")
        return value

    if finding_type == "certificate":
        # cert values have format "cert:ID:target" or similar — keep as-is
        return value

    if finding_type == "technology":
        # Normalize tech names: "Web Server: nginx/1.x" → "web server: nginx"
        # Remove version numbers for deduplication
        value = re.sub(r'\s+\d+[\d.]+\w*', '', value)
        return value.strip()

    if finding_type == "email":
        return value.strip().lower()

    if finding_type == "asn":
        # "AS12345 (Example)" → normalize by ASN number
        match = re.search(r'AS(\d+)', value, re.IGNORECASE)
        if match:
            return f"as{match.group(1)}"
        return value

    return value


def merge_results(raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Merge raw provider results into deduplicated, multi-source findings.

    Algorithm:
    1. Group results by (finding_type, normalized_value)
    2. For each group, merge sources into a single finding
    3. Calculate confidence based on number of agreeing sources
    4. Track first_seen / last_seen across all sources

    Returns merged finding list — each finding has:
    - sources: list of source names
    - source_count: number of unique sources
    - source_agreement: fraction (e.g. 0.75 = 3/4 sources agreed)
    - confidence: calculated from multi-source engine
    """
    # Group by (finding_type, normalized_value)
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

    for result in raw_results:
        ft = result.get("finding_type", "unknown")
        val = result.get("value", "")
        norm_val = normalize_value(ft, val)
        key = (ft, norm_val)
        groups[key].append(result)

    merged = []
    for (finding_type, norm_val), group in groups.items():
        if not group:
            continue

        # Collect unique sources
        sources = list(dict.fromkeys(r["source"] for r in group))  # ordered unique
        source_count = len(sources)

        # Pick the primary result (highest confidence)
        primary = max(group, key=lambda r: r.get("confidence", 0))

        # Merge evidence from all sources
        evidences = [r.get("evidence", "") for r in group if r.get("evidence")]
        merged_evidence = " | ".join(dict.fromkeys(evidences))  # deduplicated

        # First/last seen across all sources
        dates = []
        for r in group:
            for df in ["first_seen", "discovered_at", "last_seen"]:
                d = r.get(df)
                if d:
                    try:
                        dates.append(datetime.fromisoformat(d.replace("Z", "+00:00")))
                    except Exception:
                        pass
        first_seen = min(dates).isoformat() if dates else None
        last_seen = max(dates).isoformat() if dates else None

        # Source agreement: all providers that were queried for this type vs. sources that found it
        # We use source_count / max_possible as a proxy
        # (full accuracy would need total_queried_providers per type — handled in orchestrator)
        source_agreement = 1.0  # Will be refined by orchestrator with total_queried count

        # Calculate multi-source confidence
        base_confidences = [r.get("confidence", 0.5) for r in group]
        confidence = calculate_confidence(
            source_confidences=base_confidences,
            source_count=source_count,
            first_seen=first_seen,
        )

        # Determine observation type (use the most certain type)
        obs_types = [r.get("observation_type", "hypothesized") for r in group]
        obs_priority = {"observed": 0, "inferred": 1, "hypothesized": 2}
        observation_type = min(obs_types, key=lambda t: obs_priority.get(t, 99))

        # Merge raw_data from all sources for evidence panel
        all_raw = {}
        for r in group:
            src = r["source"]
            all_raw[src] = r.get("raw_data", {})

        # Build the merged finding
        merged_finding = {
            **primary,
            # Multi-source fields
            "sources": sources,
            "source_count": source_count,
            "source_agreement": source_agreement,
            "confidence": confidence,
            # Evidence
            "evidence": merged_evidence,
            "evidence_per_source": [
                {
                    "source": r["source"],
                    "evidence": r.get("evidence", ""),
                    "discovered_at": r.get("discovered_at", ""),
                    "confidence": r.get("confidence", 0.5),
                    "raw_data": r.get("raw_data", {}),
                }
                for r in group
            ],
            # Timestamps
            "first_seen": first_seen,
            "last_seen": last_seen,
            # Classification
            "observation_type": observation_type,
            # Normalized key for later lookups
            "norm_value": norm_val,
        }
        merged.append(merged_finding)

    return merged


def compute_source_agreement(
    merged_findings: List[Dict[str, Any]],
    total_queried_per_type: Dict[str, int],
) -> List[Dict[str, Any]]:
    """
    Refine source_agreement after knowing how many providers were queried per type.

    total_queried_per_type: {"domain": 4, "subdomain": 4, "certificate": 2, ...}
    """
    for finding in merged_findings:
        ft = finding.get("finding_type", "")
        total = total_queried_per_type.get(ft, finding.get("source_count", 1))
        source_count = finding.get("source_count", 1)
        finding["source_agreement"] = round(source_count / max(total, 1), 2)
        finding["total_queried"] = total
    return merged_findings
