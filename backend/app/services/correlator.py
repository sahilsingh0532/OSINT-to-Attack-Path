"""
Correlation Engine — builds relationships between OSINT findings.
This is the core intelligence component that connects individually harmless
discoveries into meaningful attack surface maps.
"""

from typing import List, Dict, Any


def build_relationships(finding_map: dict, findings_data: list) -> List[Dict[str, Any]]:
    """Build relationships between findings based on correlation rules.

    Args:
        finding_map: Dict mapping finding value/title to Finding ORM objects
        findings_data: Raw finding dictionaries from collectors

    Returns:
        List of relationship dictionaries with source_ref, target_ref, type, confidence
    """
    relationships = []

    # Index findings by type for efficient lookup
    by_type = {}
    for fd in findings_data:
        ft = fd["finding_type"]
        if ft not in by_type:
            by_type[ft] = []
        by_type[ft].append(fd)

    domains = by_type.get("domain", [])
    subdomains = by_type.get("subdomain", [])
    certificates = by_type.get("certificate", [])
    ips = [f for f in by_type.get("ip", [])]
    asns = by_type.get("asn", [])
    technologies = by_type.get("technology", [])
    repositories = by_type.get("repository", [])
    identities = by_type.get("identity", [])
    threats = by_type.get("threat_indicator", [])
    darkweb = by_type.get("darkweb_reference", [])
    orgs = by_type.get("organization", [])
    exposures = by_type.get("exposure", [])

    # Rule 1: Domain → Subdomain
    for domain in domains:
        for sub in subdomains:
            if sub["value"].endswith("." + domain["value"]) or domain["value"] in sub["value"]:
                relationships.append({
                    "source_ref": domain["value"],
                    "target_ref": sub["value"],
                    "relationship_type": "has_subdomain",
                    "confidence": min(domain["confidence"], sub["confidence"]),
                    "description": f"Subdomain of {domain['value']}"
                })

    # Rule 2: Subdomain → Certificate (match by subdomain name in cert CN/SAN)
    for sub in subdomains:
        for cert in certificates:
            cert_value = cert["value"].lower()
            sub_name = sub["value"].lower()
            if sub_name in cert_value or (cert.get("raw_data", {}).get("san") and
                                           any(sub_name in s.lower() for s in cert["raw_data"].get("san", []))):
                relationships.append({
                    "source_ref": sub["value"],
                    "target_ref": cert["value"],
                    "relationship_type": "has_certificate",
                    "confidence": min(sub["confidence"], cert["confidence"]),
                    "description": f"Certificate issued for {sub['value']}"
                })

    # Rule 3: Subdomain → IP (from raw_data)
    for sub in subdomains:
        ip_value = sub.get("raw_data", {}).get("ip")
        if ip_value:
            for ip in ips:
                if ip["value"] == ip_value:
                    relationships.append({
                        "source_ref": sub["value"],
                        "target_ref": ip["value"],
                        "relationship_type": "resolves_to",
                        "confidence": min(sub["confidence"], ip["confidence"]),
                        "description": f"{sub['value']} resolves to {ip['value']}"
                    })

    # Rule 4: IP → ASN
    for ip in ips:
        ip_asn = ip.get("raw_data", {}).get("asn")
        if ip_asn:
            for asn in asns:
                if ip_asn in asn["value"]:
                    relationships.append({
                        "source_ref": ip["value"],
                        "target_ref": asn["value"],
                        "relationship_type": "belongs_to_asn",
                        "confidence": min(ip["confidence"], asn["confidence"]),
                        "description": f"IP belongs to {asn['value']}"
                    })

    # Rule 5: Technology → Subdomain (detected_on field)
    for tech in technologies:
        detected_on = tech.get("raw_data", {}).get("detected_on", "")
        for sub in subdomains:
            if sub["value"] == detected_on:
                relationships.append({
                    "source_ref": sub["value"],
                    "target_ref": tech["value"],
                    "relationship_type": "uses_technology",
                    "confidence": min(sub["confidence"], tech["confidence"]),
                    "description": f"{sub['value']} runs {tech['value']}"
                })

    # Rule 6: Repository → Identity (contributors)
    for repo in repositories:
        contributors = repo.get("raw_data", {}).get("contributors", [])
        for identity in identities:
            username = identity.get("raw_data", {}).get("username", "")
            if username in contributors:
                relationships.append({
                    "source_ref": repo["value"],
                    "target_ref": identity["value"],
                    "relationship_type": "developed_by",
                    "confidence": min(repo["confidence"], identity["confidence"]),
                    "description": f"Repository has contributor {username}"
                })

    # Rule 7: Repository → Technology (via language/topics)
    for repo in repositories:
        topics = repo.get("raw_data", {}).get("topics", [])
        language = repo.get("raw_data", {}).get("language", "").lower()
        for tech in technologies:
            tech_name = tech["value"].lower()
            if any(t.lower() in tech_name for t in topics) or language in tech_name:
                relationships.append({
                    "source_ref": repo["value"],
                    "target_ref": tech["value"],
                    "relationship_type": "uses_technology",
                    "confidence": 0.6,
                    "description": f"Repository uses technology related to {tech['value']}"
                })

    # Rule 8: Domain → Threat indicator
    for domain in domains:
        for threat in threats:
            if domain["value"] in threat["value"]:
                relationships.append({
                    "source_ref": domain["value"],
                    "target_ref": threat["value"],
                    "relationship_type": "references_threat",
                    "confidence": threat["confidence"],
                    "description": f"Threat intelligence references {domain['value']}"
                })

    # Rule 9: Technology → Threat indicator (CVE matching)
    for tech in technologies:
        known_cves = tech.get("raw_data", {}).get("known_cves", [])
        for threat in threats:
            if any(cve in threat["value"] for cve in known_cves):
                relationships.append({
                    "source_ref": tech["value"],
                    "target_ref": threat["value"],
                    "relationship_type": "has_vulnerability",
                    "confidence": min(tech["confidence"], threat["confidence"]),
                    "description": f"Technology has known vulnerability"
                })

    # Rule 10: Exposure → related findings
    for exp in exposures:
        related = exp.get("raw_data", {}).get("related_findings", [])
        for ref in related:
            if ref in finding_map and exp["value"] in finding_map:
                relationships.append({
                    "source_ref": exp["value"],
                    "target_ref": ref,
                    "relationship_type": "exposes",
                    "confidence": exp["confidence"],
                    "description": f"Exposure linked to {ref}"
                })

    # Rule 11: Organization → Domain
    for org in orgs:
        for domain in domains:
            relationships.append({
                "source_ref": org["value"],
                "target_ref": domain["value"],
                "relationship_type": "owns_domain",
                "confidence": 0.85,
                "description": f"Organization owns {domain['value']}"
            })

    # Rule 12: Dark web → Domain/Organization
    for dw in darkweb:
        for domain in domains:
            if domain["value"] in dw["value"]:
                relationships.append({
                    "source_ref": dw["value"],
                    "target_ref": domain["value"],
                    "relationship_type": "references",
                    "confidence": dw["confidence"],
                    "description": f"Dark web reference to {domain['value']}"
                })

    return relationships
