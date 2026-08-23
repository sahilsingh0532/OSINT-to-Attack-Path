"""Risk scoring engine — calculates composite OSINT risk scores based on findings."""

from typing import List, Dict, Any
from app.models.risk_score import RiskScore


# Severity weighting rules for OSINT finding types & categories
SEVERITY_RULES = {
    "darkweb_reference": {"exposure": 8.5, "exploitability": 7.0, "impact": 8.0, "rationale": "Target domain or credentials referenced in dark web indices."},
    "threat_indicator": {"exposure": 8.0, "exploitability": 7.5, "impact": 8.5, "rationale": "Flagged by threat intelligence databases or security vendors."},
    "exposure": {"exposure": 7.5, "exploitability": 8.0, "impact": 7.5, "rationale": "Publicly exposed sensitive endpoint, configuration, or secret key."},
    "repository": {"exposure": 6.5, "exploitability": 6.0, "impact": 7.0, "rationale": "Public code repository potentially exposing internal code or infrastructure references."},
    "developer": {"exposure": 5.5, "exploitability": 5.0, "impact": 6.0, "rationale": "Public developer profile associated with target organization."},
    "technology": {"exposure": 5.0, "exploitability": 6.0, "impact": 5.5, "rationale": "Fingerprinted technology stack with potential version disclosure or missing security headers."},
    "certificate": {"exposure": 4.5, "exploitability": 4.0, "impact": 5.0, "rationale": "SSL/TLS certificate record revealing subdomains or expiration timeline."},
    "ip": {"exposure": 4.0, "exploitability": 5.0, "impact": 5.0, "rationale": "Public IP address associated with target domain infrastructure."},
    "asn": {"exposure": 3.0, "exploitability": 3.0, "impact": 4.0, "rationale": "Autonomous System Network routing information."},
    "subdomain": {"exposure": 3.5, "exploitability": 4.0, "impact": 4.5, "rationale": "Discovered active or historical subdomain."},
    "domain": {"exposure": 2.5, "exploitability": 2.0, "impact": 3.5, "rationale": "Target domain entry point."},
    "organization": {"exposure": 2.0, "exploitability": 2.0, "impact": 3.0, "rationale": "Corporate entity metadata."},
}


def calculate_risk_scores_for_findings(findings_list: list) -> List[dict]:
    """Calculate risk scores for a list of Finding objects or dicts."""
    risk_scores_data = []

    for f in findings_list:
        ftype = f.finding_type if hasattr(f, "finding_type") else f.get("finding_type", "domain")
        confidence = f.confidence if hasattr(f, "confidence") else f.get("confidence", 0.8)
        fid = f.id if hasattr(f, "id") else f.get("id")

        rule = SEVERITY_RULES.get(ftype, {
            "exposure": 4.0,
            "exploitability": 4.0,
            "impact": 4.0,
            "rationale": f"OSINT finding of type {ftype}."
        })

        exp = rule["exposure"]
        expl = rule["exploitability"]
        imp = rule["impact"]
        conf = float(confidence)

        composite = RiskScore.calculate_composite(exp, conf, expl, imp)
        level = RiskScore.get_risk_level(composite)

        risk_scores_data.append({
            "finding_id": fid,
            "exposure": exp,
            "confidence": conf,
            "exploitability": expl,
            "impact": imp,
            "composite_score": composite,
            "risk_level": level,
            "rationale": rule["rationale"],
        })

    return risk_scores_data
