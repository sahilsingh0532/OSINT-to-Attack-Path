"""Defense recommendation engine — generates defensive recommendations based on OSINT findings."""

from typing import List, Dict, Any


def generate_recommendations_for_findings(findings_list: list, target_domain: str) -> List[dict]:
    """Generate defensive security recommendations tailored to collected findings."""
    recommendations = []
    types_found = set(f.finding_type if hasattr(f, "finding_type") else f.get("finding_type") for f in findings_list)

    if "subdomain" in types_found or "certificate" in types_found:
        recommendations.append({
            "title": "Subdomain & Attack Surface Monitoring",
            "description": f"Implement automated Certificate Transparency log monitoring for *.{target_domain} to detect unauthorized subdomains or shadow IT assets.",
            "category": "attack_surface_management",
            "priority": 1,
            "effort": "LOW",
            "rationale": "Unmonitored subdomains often host outdated software or internal-only services exposed publicly."
        })

    if "technology" in types_found:
        recommendations.append({
            "title": "Harden Web Headers & Tech Stack Exposure",
            "description": f"Disable verbose server banners (Server, X-Powered-By, X-ASPNet-Version) on {target_domain} and enforce HSTS, CSP, and X-Frame-Options headers.",
            "category": "configuration",
            "priority": 2,
            "effort": "LOW",
            "rationale": "Information disclosure headers allow adversaries to target specific software versions and known vulnerabilities."
        })

    if "repository" in types_found or "developer" in types_found:
        recommendations.append({
            "title": "Automate Code Secret Scanning & Repo Governance",
            "description": "Deploy GitHub Secret Scanning or Trufflehog across all organization repositories and developer accounts to prevent secret credential leaks.",
            "category": "code_security",
            "priority": 1,
            "effort": "MEDIUM",
            "rationale": "Hardcoded API keys, tokens, or private credentials in public repositories provide immediate entry points."
        })

    if "threat_indicator" in types_found or "darkweb_reference" in types_found:
        recommendations.append({
            "title": "Threat Intelligence & Compromised Credential Monitoring",
            "description": f"Set up continuous dark web intelligence alerts for domain {target_domain} and enforce mandatory MFA for all corporate accounts.",
            "category": "identity_security",
            "priority": 1,
            "effort": "MEDIUM",
            "rationale": "Exposed employee credentials on dark web marketplaces enable credential stuffing and initial access."
        })

    if "exposure" in types_found or "ip" in types_found:
        recommendations.append({
            "title": "Restrict Public Service Exposure & Apply Network ACLs",
            "description": f"Audit all public IP addresses and open ports associated with {target_domain}. Place administrative interfaces behind VPN/ZTNA.",
            "category": "network_security",
            "priority": 2,
            "effort": "MEDIUM",
            "rationale": "Exposing management or database ports directly to the internet dramatically increases attack surface."
        })

    # Default baseline recommendation
    if not recommendations:
        recommendations.append({
            "title": "Continuous OSINT Reconnaissance & Asset Inventory",
            "description": f"Maintain an updated asset inventory for {target_domain} and perform regular passive OSINT scans.",
            "category": "governance",
            "priority": 3,
            "effort": "LOW",
            "rationale": "Proactive asset management prevents unauthorized external infrastructure expansion."
        })

    return recommendations
