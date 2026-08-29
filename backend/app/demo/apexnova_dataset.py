"""
Complete demo dataset for the fictional company ApexNova Technologies.
127 OSINT records covering domains, subdomains, certificates, IPs, technologies,
repositories, developers, threat intelligence, and dark-web references.

All data is entirely fictional. No real people, organizations, or infrastructure.

Phase 2 upgrade: every finding now includes multi-source fields:
  sources, source_count, source_agreement, evidence_per_source, first_seen, last_seen
This demonstrates the core research novelty: multi-source OSINT correlation.
"""

from datetime import datetime, timezone, timedelta

BASE_DATE = datetime(2026, 7, 1, tzinfo=timezone.utc)


def _dt(days_offset: int) -> str:
    return (BASE_DATE + timedelta(days=days_offset)).isoformat()


# ── Multi-source enrichment map ──────────────────────────────────────────────
# Defines which demo findings are confirmed by multiple fictional OSINT sources.
# Format: {finding_value: [source_names]}
_MULTI_SOURCE_MAP = {
    "apexnova.example":        ["rdap", "crt.sh", "virustotal", "hackertarget"],
    "apexnova-cloud.example":  ["rdap", "crt.sh", "virustotal"],
    "apexnova-internal.example": ["rdap", "crt.sh"],
    "apexnovatech.example":    ["rdap", "virustotal"],
    # Subdomains
    "dev.apexnova.example":    ["crt.sh", "virustotal", "hackertarget", "dns_query"],
    "api.apexnova.example":    ["crt.sh", "virustotal", "hackertarget"],
    "admin.apexnova.example":  ["crt.sh", "virustotal"],
    "staging.apexnova.example": ["crt.sh", "virustotal", "dns_query"],
    "mail.apexnova.example":   ["dns_query", "virustotal"],
    "vpn.apexnova.example":    ["crt.sh", "hackertarget"],
    "portal.apexnova.example": ["crt.sh", "virustotal", "hackertarget"],
    "jenkins.apexnova.example": ["crt.sh", "virustotal"],
    "gitlab.apexnova.example": ["crt.sh", "hackertarget"],
    "cloud.apexnova.example":  ["crt.sh", "virustotal", "hackertarget", "dns_query"],
    "db.apexnova.example":     ["crt.sh", "virustotal"],
    "backup.apexnova.example": ["crt.sh"],
    # IPs
    "203.0.113.10":  ["shodan", "virustotal", "rdap"],
    "203.0.113.45":  ["shodan", "virustotal"],
    "198.51.100.72": ["shodan", "virustotal", "rdap"],
    "198.51.100.88": ["shodan"],
    "192.0.2.155":   ["shodan", "virustotal"],
    "192.0.2.200":   ["shodan"],
    # Technologies
    "Nginx 1.24.0":  ["shodan", "virustotal", "http_fingerprint"],
    "React.js":      ["http_fingerprint", "virustotal"],
    "Node.js":       ["shodan", "http_fingerprint"],
    "PostgreSQL":    ["shodan", "virustotal"],
    "Docker":        ["shodan", "http_fingerprint"],
    "Kubernetes":    ["shodan"],
    # Emails (demo)
    "priya.sharma@apexnova.example":   ["hunter.io", "github"],
    "john.doe@apexnova.example":       ["hunter.io"],
    "dev-team@apexnova.example":       ["hunter.io", "github", "emailrep.io"],
    "security@apexnova.example":       ["hunter.io", "emailrep.io"],
}

# Total demo providers queried per type (for agreement calculation)
_TOTAL_QUERIED = {
    "domain": 4,
    "subdomain": 4,
    "certificate": 2,
    "ip": 3,
    "asn": 2,
    "technology": 3,
    "repository": 1,
    "identity": 2,
    "email": 3,
    "threat_indicator": 3,
    "darkweb_reference": 1,
    "exposure": 2,
    "organization": 2,
}


def _enrich_with_sources(finding: dict) -> dict:
    """Inject multi-source metadata into a demo finding."""
    value = finding.get("value", "")
    # Look up by exact value or by a key contained in the value
    sources = None
    for key, srcs in _MULTI_SOURCE_MAP.items():
        if key == value or (len(key) > 6 and key in value):
            sources = srcs
            break
    if sources is None:
        sources = [finding.get("source", "crt.sh")]

    ft = finding.get("finding_type", "unknown")
    total_q = _TOTAL_QUERIED.get(ft, 2)
    sc = len(sources)
    agreement = round(sc / max(total_q, 1), 2)

    # Build per-source evidence list
    base_conf = finding.get("confidence", 0.85)
    base_evidence = finding.get("evidence", "")
    disc_at = finding.get("discovered_at", _dt(0))

    evidence_per_source = []
    for i, src in enumerate(sources):
        ev_conf = max(0.70, base_conf - 0.03 * i)  # slight variation per source
        evidence_per_source.append({
            "source": src,
            "evidence": f"{base_evidence} (confirmed by {src})",
            "discovered_at": _dt(i),  # slight time offset
            "confidence": round(ev_conf, 2),
            "raw_data": {"source": src, "method": "passive"},
        })

    # Recalculate confidence with multi-source bonus
    source_bonus = min((sc - 1) * 0.08, 0.30)
    new_confidence = min(base_conf + source_bonus, 0.97)

    return {
        **finding,
        "sources": sources,
        "source_count": sc,
        "source_agreement": agreement,
        "total_queried": total_q,
        "confidence": round(new_confidence, 3),
        "evidence_per_source": evidence_per_source,
        "first_seen": finding.get("first_seen", disc_at),
        "last_seen": finding.get("last_seen", _dt(58)),
    }


DEMO_TARGET = "apexnova.example"
DEMO_ORG = "ApexNova Technologies"

# ============================================================================
# DOMAINS (4)
# ============================================================================
DOMAINS = [
    {
        "source": "dns_rdap",
        "finding_type": "domain",
        "value": "apexnova.example",
        "title": "Primary Domain",
        "description": "Main corporate domain for ApexNova Technologies.",
        "confidence": 0.99,
        "observation_type": "observed",
        "evidence": "RDAP registration record",
        "category": "infrastructure",
        "tags": "primary,corporate",
        "discovered_at": _dt(0),
        "raw_data": {
            "registrar": "ExampleRegistrar Inc.",
            "created": "2019-03-15",
            "expires": "2027-03-15",
            "nameservers": ["ns1.cloudhost.example", "ns2.cloudhost.example"],
            "status": "active"
        }
    },
    {
        "source": "dns_rdap",
        "finding_type": "domain",
        "value": "apexnova-cloud.example",
        "title": "Cloud Services Domain",
        "description": "Secondary domain used for cloud service infrastructure.",
        "confidence": 0.95,
        "observation_type": "observed",
        "evidence": "RDAP record linked via registrant organization match",
        "category": "infrastructure",
        "tags": "cloud,secondary",
        "discovered_at": _dt(2),
        "raw_data": {
            "registrar": "ExampleRegistrar Inc.",
            "created": "2021-06-20",
            "expires": "2027-06-20",
            "nameservers": ["ns1.cloudhost.example", "ns2.cloudhost.example"],
            "status": "active"
        }
    },
    {
        "source": "dns_rdap",
        "finding_type": "domain",
        "value": "apexnova-internal.example",
        "title": "Internal Tools Domain",
        "description": "Domain used for internal tooling and development environments.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "Certificate Transparency cross-reference",
        "category": "infrastructure",
        "tags": "internal,development",
        "discovered_at": _dt(5),
        "raw_data": {
            "registrar": "ExampleRegistrar Inc.",
            "created": "2022-01-10",
            "expires": "2027-01-10",
            "nameservers": ["ns1.cloudhost.example"],
            "status": "active"
        }
    },
    {
        "source": "dns_rdap",
        "finding_type": "domain",
        "value": "apexnovatech.example",
        "title": "Brand Variant Domain",
        "description": "Alternative brand domain registered by ApexNova Technologies.",
        "confidence": 0.85,
        "observation_type": "inferred",
        "evidence": "Registrant organization name match",
        "category": "infrastructure",
        "tags": "brand,variant",
        "discovered_at": _dt(3),
        "raw_data": {
            "registrar": "DomainShield Ltd.",
            "created": "2020-08-01",
            "expires": "2026-08-01",
            "nameservers": ["ns1.domainshield.example"],
            "status": "active"
        }
    },
]

# ============================================================================
# SUBDOMAINS (18)
# ============================================================================
SUBDOMAINS = [
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "www.apexnova.example",
        "title": "Main Website",
        "description": "Primary public-facing website.",
        "confidence": 0.99,
        "observation_type": "observed",
        "evidence": "CT log entry + passive DNS confirmation",
        "category": "infrastructure",
        "tags": "web,public",
        "discovered_at": _dt(0),
        "raw_data": {"ct_log": "Google Argon 2026", "ip": "203.0.113.10"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "dev.apexnova.example",
        "title": "Development Environment",
        "description": "Development server — potentially sensitive if publicly accessible.",
        "confidence": 0.95,
        "observation_type": "observed",
        "evidence": "CT log entry from Let's Encrypt certificate",
        "category": "infrastructure",
        "tags": "development,sensitive",
        "discovered_at": _dt(3),
        "raw_data": {"ct_log": "Let's Encrypt Oak 2026", "ip": "203.0.113.50"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "staging.apexnova.example",
        "title": "Staging Environment",
        "description": "Pre-production staging server.",
        "confidence": 0.95,
        "observation_type": "observed",
        "evidence": "CT log entry",
        "category": "infrastructure",
        "tags": "staging,pre-production",
        "discovered_at": _dt(4),
        "raw_data": {"ct_log": "Google Argon 2026", "ip": "203.0.113.51"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "api.apexnova.example",
        "title": "API Gateway",
        "description": "Public API endpoint.",
        "confidence": 0.98,
        "observation_type": "observed",
        "evidence": "CT log entry + technology fingerprint",
        "category": "infrastructure",
        "tags": "api,public",
        "discovered_at": _dt(1),
        "raw_data": {"ct_log": "DigiCert Yeti 2026", "ip": "203.0.113.20"}
    },
    {
        "source": "passive_dns",
        "finding_type": "subdomain",
        "value": "mail.apexnova.example",
        "title": "Mail Server",
        "description": "Corporate email server.",
        "confidence": 0.97,
        "observation_type": "observed",
        "evidence": "MX record in passive DNS data",
        "category": "infrastructure",
        "tags": "mail,corporate",
        "discovered_at": _dt(0),
        "raw_data": {"record_type": "MX", "ip": "203.0.113.25", "priority": 10}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "vpn.apexnova.example",
        "title": "VPN Gateway",
        "description": "Remote access VPN endpoint.",
        "confidence": 0.96,
        "observation_type": "observed",
        "evidence": "CT log entry",
        "category": "infrastructure",
        "tags": "vpn,remote-access",
        "discovered_at": _dt(2),
        "raw_data": {"ct_log": "Google Argon 2026", "ip": "203.0.113.30"}
    },
    {
        "source": "passive_dns",
        "finding_type": "subdomain",
        "value": "cdn.apexnova.example",
        "title": "CDN Endpoint",
        "description": "Content delivery network subdomain.",
        "confidence": 0.93,
        "observation_type": "observed",
        "evidence": "CNAME to CDN provider in passive DNS",
        "category": "infrastructure",
        "tags": "cdn,content",
        "discovered_at": _dt(1),
        "raw_data": {"record_type": "CNAME", "target": "apexnova.cdn-provider.example"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "admin.apexnova.example",
        "title": "Admin Panel",
        "description": "Administrative interface — high-value target if exposed.",
        "confidence": 0.92,
        "observation_type": "observed",
        "evidence": "CT log entry from internal CA certificate",
        "category": "infrastructure",
        "tags": "admin,sensitive,high-value",
        "discovered_at": _dt(6),
        "raw_data": {"ct_log": "Internal CA", "ip": "203.0.113.55"}
    },
    {
        "source": "passive_dns",
        "finding_type": "subdomain",
        "value": "db-admin.apexnova.example",
        "title": "Database Admin Interface",
        "description": "Database administration tool — critical if externally accessible.",
        "confidence": 0.88,
        "observation_type": "observed",
        "evidence": "Passive DNS A record",
        "category": "infrastructure",
        "tags": "database,admin,critical",
        "discovered_at": _dt(8),
        "raw_data": {"record_type": "A", "ip": "203.0.113.56"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "jenkins.apexnova.example",
        "title": "CI/CD Server",
        "description": "Jenkins continuous integration server.",
        "confidence": 0.91,
        "observation_type": "observed",
        "evidence": "CT log entry with Jenkins-specific certificate",
        "category": "infrastructure",
        "tags": "cicd,jenkins,development",
        "discovered_at": _dt(7),
        "raw_data": {"ct_log": "Let's Encrypt Oak 2026", "ip": "203.0.113.57"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "grafana.apexnova.example",
        "title": "Monitoring Dashboard",
        "description": "Grafana monitoring and observability dashboard.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "CT log entry",
        "category": "infrastructure",
        "tags": "monitoring,grafana",
        "discovered_at": _dt(5),
        "raw_data": {"ct_log": "Google Argon 2026", "ip": "203.0.113.58"}
    },
    {
        "source": "passive_dns",
        "finding_type": "subdomain",
        "value": "git.apexnova.example",
        "title": "Self-Hosted Git",
        "description": "Self-hosted Git server (Gitea/GitLab).",
        "confidence": 0.89,
        "observation_type": "observed",
        "evidence": "Passive DNS record",
        "category": "infrastructure",
        "tags": "git,source-code",
        "discovered_at": _dt(9),
        "raw_data": {"record_type": "A", "ip": "203.0.113.59"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "portal.apexnova.example",
        "title": "Customer Portal",
        "description": "Customer-facing portal application.",
        "confidence": 0.97,
        "observation_type": "observed",
        "evidence": "CT log entry",
        "category": "infrastructure",
        "tags": "portal,customer",
        "discovered_at": _dt(1),
        "raw_data": {"ct_log": "DigiCert Yeti 2026", "ip": "203.0.113.21"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "docs.apexnova.example",
        "title": "Documentation Site",
        "description": "Public API and product documentation.",
        "confidence": 0.96,
        "observation_type": "observed",
        "evidence": "CT log entry",
        "category": "infrastructure",
        "tags": "docs,public",
        "discovered_at": _dt(2),
        "raw_data": {"ct_log": "Google Argon 2026", "ip": "203.0.113.22"}
    },
    {
        "source": "passive_dns",
        "finding_type": "subdomain",
        "value": "status.apexnova.example",
        "title": "Status Page",
        "description": "Public service status page.",
        "confidence": 0.94,
        "observation_type": "observed",
        "evidence": "CNAME record in passive DNS",
        "category": "infrastructure",
        "tags": "status,public",
        "discovered_at": _dt(1),
        "raw_data": {"record_type": "CNAME", "target": "apexnova.statuspage.example"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "test.apexnova.example",
        "title": "Test Environment",
        "description": "QA testing environment.",
        "confidence": 0.87,
        "observation_type": "observed",
        "evidence": "CT log entry from Let's Encrypt",
        "category": "infrastructure",
        "tags": "test,qa",
        "discovered_at": _dt(10),
        "raw_data": {"ct_log": "Let's Encrypt Oak 2026", "ip": "203.0.113.60"}
    },
    {
        "source": "passive_dns",
        "finding_type": "subdomain",
        "value": "legacy.apexnova.example",
        "title": "Legacy Application",
        "description": "Legacy application server — may run outdated software.",
        "confidence": 0.82,
        "observation_type": "observed",
        "evidence": "Passive DNS historical record",
        "category": "infrastructure",
        "tags": "legacy,outdated",
        "discovered_at": _dt(12),
        "raw_data": {"record_type": "A", "ip": "203.0.113.61", "first_seen": "2022-05-01"}
    },
    {
        "source": "certificate_transparency",
        "finding_type": "subdomain",
        "value": "beta.apexnova-cloud.example",
        "title": "Cloud Beta Service",
        "description": "Beta cloud service endpoint.",
        "confidence": 0.88,
        "observation_type": "observed",
        "evidence": "CT log entry for cloud domain",
        "category": "infrastructure",
        "tags": "beta,cloud",
        "discovered_at": _dt(11),
        "raw_data": {"ct_log": "Google Argon 2026", "ip": "198.51.100.10"}
    },
]

# ============================================================================
# CERTIFICATES (12)
# ============================================================================
CERTIFICATES = [
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=apexnova.example, SAN=www.apexnova.example",
        "title": "Primary Wildcard Certificate",
        "description": "Main TLS certificate for the primary domain.",
        "confidence": 0.99,
        "observation_type": "observed",
        "evidence": "CT log: Google Argon 2026",
        "category": "infrastructure",
        "tags": "tls,primary",
        "discovered_at": _dt(0),
        "raw_data": {
            "issuer": "DigiCert Global G3",
            "serial": "0A:1B:2C:3D:4E:5F",
            "not_before": "2026-01-15",
            "not_after": "2027-01-15",
            "san": ["apexnova.example", "www.apexnova.example"],
            "key_algorithm": "RSA 2048"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=*.apexnova.example (Wildcard)",
        "title": "Wildcard Certificate",
        "description": "Wildcard certificate covering all subdomains.",
        "confidence": 0.98,
        "observation_type": "observed",
        "evidence": "CT log: DigiCert Yeti 2026",
        "category": "infrastructure",
        "tags": "tls,wildcard",
        "discovered_at": _dt(0),
        "raw_data": {
            "issuer": "DigiCert Global G3",
            "serial": "1A:2B:3C:4D:5E:6F",
            "not_before": "2026-02-01",
            "not_after": "2027-02-01",
            "san": ["*.apexnova.example"],
            "key_algorithm": "ECDSA P-256"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=dev.apexnova.example (Let's Encrypt)",
        "title": "Dev Environment Certificate",
        "description": "Let's Encrypt certificate for development server — indicates public accessibility.",
        "confidence": 0.95,
        "observation_type": "observed",
        "evidence": "CT log: Let's Encrypt Oak 2026",
        "category": "infrastructure",
        "tags": "tls,development,letsencrypt",
        "discovered_at": _dt(3),
        "raw_data": {
            "issuer": "Let's Encrypt Authority X4",
            "serial": "2A:3B:4C:5D:6E:7F",
            "not_before": "2026-06-01",
            "not_after": "2026-08-30",
            "san": ["dev.apexnova.example"],
            "key_algorithm": "ECDSA P-256"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=staging.apexnova.example",
        "title": "Staging Certificate",
        "description": "Certificate for staging environment.",
        "confidence": 0.94,
        "observation_type": "observed",
        "evidence": "CT log: Let's Encrypt Oak 2026",
        "category": "infrastructure",
        "tags": "tls,staging",
        "discovered_at": _dt(4),
        "raw_data": {
            "issuer": "Let's Encrypt Authority X4",
            "serial": "3A:4B:5C:6D:7E:8F",
            "not_before": "2026-06-15",
            "not_after": "2026-09-13",
            "san": ["staging.apexnova.example"],
            "key_algorithm": "ECDSA P-256"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=api.apexnova.example",
        "title": "API Certificate",
        "description": "TLS certificate for the API gateway.",
        "confidence": 0.98,
        "observation_type": "observed",
        "evidence": "CT log: DigiCert Yeti 2026",
        "category": "infrastructure",
        "tags": "tls,api",
        "discovered_at": _dt(1),
        "raw_data": {
            "issuer": "DigiCert Global G3",
            "serial": "4A:5B:6C:7D:8E:9F",
            "not_before": "2026-03-01",
            "not_after": "2027-03-01",
            "san": ["api.apexnova.example"],
            "key_algorithm": "RSA 2048"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=admin.apexnova.example (Internal CA)",
        "title": "Admin Panel Certificate — Internal CA",
        "description": "Self-signed or internal CA certificate for admin panel — unusual for public-facing service.",
        "confidence": 0.92,
        "observation_type": "observed",
        "evidence": "CT log: Internal CA submission",
        "category": "infrastructure",
        "tags": "tls,admin,internal-ca,anomaly",
        "discovered_at": _dt(6),
        "raw_data": {
            "issuer": "ApexNova Internal CA",
            "serial": "5A:6B:7C:8D:9E:AF",
            "not_before": "2025-01-01",
            "not_after": "2028-01-01",
            "san": ["admin.apexnova.example"],
            "key_algorithm": "RSA 4096",
            "self_signed": False,
            "internal_ca": True
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=jenkins.apexnova.example",
        "title": "Jenkins Certificate",
        "description": "Let's Encrypt certificate for CI/CD server.",
        "confidence": 0.91,
        "observation_type": "observed",
        "evidence": "CT log: Let's Encrypt Oak 2026",
        "category": "infrastructure",
        "tags": "tls,jenkins,cicd",
        "discovered_at": _dt(7),
        "raw_data": {
            "issuer": "Let's Encrypt Authority X4",
            "serial": "6A:7B:8C:9D:AE:BF",
            "not_before": "2026-07-01",
            "not_after": "2026-09-29",
            "san": ["jenkins.apexnova.example"],
            "key_algorithm": "ECDSA P-256"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=portal.apexnova.example",
        "title": "Portal Certificate",
        "description": "DigiCert certificate for customer portal.",
        "confidence": 0.97,
        "observation_type": "observed",
        "evidence": "CT log: DigiCert Yeti 2026",
        "category": "infrastructure",
        "tags": "tls,portal",
        "discovered_at": _dt(1),
        "raw_data": {
            "issuer": "DigiCert Global G3",
            "serial": "7A:8B:9C:AD:BE:CF",
            "not_before": "2026-02-15",
            "not_after": "2027-02-15",
            "san": ["portal.apexnova.example"],
            "key_algorithm": "RSA 2048"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=grafana.apexnova.example",
        "title": "Grafana Certificate",
        "description": "Certificate for monitoring dashboard.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "CT log: Let's Encrypt Oak 2026",
        "category": "infrastructure",
        "tags": "tls,grafana,monitoring",
        "discovered_at": _dt(5),
        "raw_data": {
            "issuer": "Let's Encrypt Authority X4",
            "serial": "8A:9B:AC:BD:CE:DF",
            "not_before": "2026-05-15",
            "not_after": "2026-08-13",
            "san": ["grafana.apexnova.example"],
            "key_algorithm": "ECDSA P-256"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=*.apexnova-cloud.example",
        "title": "Cloud Wildcard Certificate",
        "description": "Wildcard certificate for cloud services domain.",
        "confidence": 0.95,
        "observation_type": "observed",
        "evidence": "CT log: Google Argon 2026",
        "category": "infrastructure",
        "tags": "tls,cloud,wildcard",
        "discovered_at": _dt(2),
        "raw_data": {
            "issuer": "Amazon Trust Services",
            "serial": "9A:AB:BC:CD:DE:EF",
            "not_before": "2026-04-01",
            "not_after": "2027-04-01",
            "san": ["*.apexnova-cloud.example", "apexnova-cloud.example"],
            "key_algorithm": "RSA 2048"
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=test.apexnova.example (expired)",
        "title": "Expired Test Certificate",
        "description": "Expired certificate for test environment — may indicate abandoned or neglected infrastructure.",
        "confidence": 0.87,
        "observation_type": "observed",
        "evidence": "CT log historical entry",
        "category": "infrastructure",
        "tags": "tls,test,expired,anomaly",
        "discovered_at": _dt(10),
        "raw_data": {
            "issuer": "Let's Encrypt Authority X3",
            "serial": "AA:BB:CC:DD:EE:FF",
            "not_before": "2025-06-01",
            "not_after": "2025-08-30",
            "san": ["test.apexnova.example"],
            "key_algorithm": "RSA 2048",
            "expired": True
        }
    },
    {
        "source": "certificate_transparency",
        "finding_type": "certificate",
        "value": "CN=legacy.apexnova.example (SHA-1)",
        "title": "Legacy Certificate with SHA-1",
        "description": "Legacy certificate using deprecated SHA-1 — indicates outdated infrastructure.",
        "confidence": 0.82,
        "observation_type": "observed",
        "evidence": "CT log historical entry",
        "category": "infrastructure",
        "tags": "tls,legacy,sha1,deprecated,anomaly",
        "discovered_at": _dt(12),
        "raw_data": {
            "issuer": "GeoTrust Global CA",
            "serial": "BB:CC:DD:EE:FF:00",
            "not_before": "2022-01-01",
            "not_after": "2025-01-01",
            "san": ["legacy.apexnova.example"],
            "key_algorithm": "RSA 2048",
            "signature_algorithm": "SHA-1 with RSA",
            "deprecated": True
        }
    },
]

# ============================================================================
# IP / ASN (6)
# ============================================================================
IP_ASN = [
    {
        "source": "passive_dns",
        "finding_type": "ip",
        "value": "203.0.113.10",
        "title": "Primary Web Server IP",
        "description": "IP address hosting the primary website.",
        "confidence": 0.97,
        "observation_type": "observed",
        "evidence": "A record for www.apexnova.example",
        "category": "infrastructure",
        "tags": "ip,webserver",
        "discovered_at": _dt(0),
        "raw_data": {"asn": "AS64500", "org": "CloudHost Global Inc.", "country": "US", "hosting": "cloud"}
    },
    {
        "source": "passive_dns",
        "finding_type": "ip",
        "value": "203.0.113.20",
        "title": "API Server IP",
        "description": "IP address hosting the API gateway.",
        "confidence": 0.96,
        "observation_type": "observed",
        "evidence": "A record for api.apexnova.example",
        "category": "infrastructure",
        "tags": "ip,api",
        "discovered_at": _dt(1),
        "raw_data": {"asn": "AS64500", "org": "CloudHost Global Inc.", "country": "US", "hosting": "cloud"}
    },
    {
        "source": "passive_dns",
        "finding_type": "ip",
        "value": "203.0.113.50",
        "title": "Development Server IP",
        "description": "IP address of the development server — same hosting provider as production.",
        "confidence": 0.93,
        "observation_type": "observed",
        "evidence": "A record for dev.apexnova.example",
        "category": "infrastructure",
        "tags": "ip,development",
        "discovered_at": _dt(3),
        "raw_data": {"asn": "AS64500", "org": "CloudHost Global Inc.", "country": "US", "hosting": "cloud"}
    },
    {
        "source": "infrastructure",
        "finding_type": "asn",
        "value": "AS64500 — CloudHost Global Inc.",
        "title": "Primary Hosting Provider ASN",
        "description": "Most infrastructure is hosted on CloudHost Global (AS64500).",
        "confidence": 0.95,
        "observation_type": "observed",
        "evidence": "Multiple A records resolve to this ASN",
        "category": "infrastructure",
        "tags": "asn,hosting,cloud",
        "discovered_at": _dt(0),
        "raw_data": {"asn": "AS64500", "name": "CloudHost Global Inc.", "ip_count": 5, "country": "US"}
    },
    {
        "source": "infrastructure",
        "finding_type": "ip",
        "value": "198.51.100.10",
        "title": "Cloud Services IP",
        "description": "IP address for cloud services domain — different hosting provider.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "A record for beta.apexnova-cloud.example",
        "category": "infrastructure",
        "tags": "ip,cloud",
        "discovered_at": _dt(11),
        "raw_data": {"asn": "AS16509", "org": "Amazon Web Services", "country": "US", "hosting": "aws"}
    },
    {
        "source": "infrastructure",
        "finding_type": "asn",
        "value": "AS16509 — Amazon Web Services",
        "title": "Secondary Hosting Provider ASN",
        "description": "Cloud services are hosted on AWS.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "Cloud domain A records resolve to AWS",
        "category": "infrastructure",
        "tags": "asn,aws,cloud",
        "discovered_at": _dt(11),
        "raw_data": {"asn": "AS16509", "name": "Amazon Web Services", "ip_count": 1, "country": "US"}
    },
]

# ============================================================================
# TECHNOLOGIES (7)
# ============================================================================
TECHNOLOGIES = [
    {
        "source": "technology_fingerprint",
        "finding_type": "technology",
        "value": "Apache HTTP Server 2.4.49",
        "title": "Apache 2.4.49 Detected",
        "description": "Apache HTTP Server version 2.4.49 detected — this version has known path traversal vulnerability (CVE-2021-41773).",
        "confidence": 0.88,
        "observation_type": "observed",
        "evidence": "HTTP Server header from passive scan data",
        "category": "technology",
        "tags": "webserver,apache,outdated,cve",
        "discovered_at": _dt(14),
        "raw_data": {
            "product": "Apache HTTP Server",
            "version": "2.4.49",
            "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            "known_cves": ["CVE-2021-41773", "CVE-2021-42013"],
            "detected_on": "legacy.apexnova.example"
        }
    },
    {
        "source": "technology_fingerprint",
        "finding_type": "technology",
        "value": "Node.js 16.x (Express Framework)",
        "title": "Node.js 16.x with Express",
        "description": "Node.js 16 runtime detected — this is an EOL (End of Life) version.",
        "confidence": 0.85,
        "observation_type": "observed",
        "evidence": "X-Powered-By header and response characteristics",
        "category": "technology",
        "tags": "nodejs,express,eol",
        "discovered_at": _dt(14),
        "raw_data": {
            "product": "Node.js",
            "version": "16.x",
            "framework": "Express 4.18",
            "eol": True,
            "detected_on": "api.apexnova.example"
        }
    },
    {
        "source": "technology_fingerprint",
        "finding_type": "technology",
        "value": "WordPress 5.8.3",
        "title": "WordPress 5.8.3 Detected",
        "description": "WordPress 5.8.3 — multiple versions behind current release.",
        "confidence": 0.92,
        "observation_type": "observed",
        "evidence": "HTML meta generator tag and wp-content paths",
        "category": "technology",
        "tags": "wordpress,cms,outdated",
        "discovered_at": _dt(15),
        "raw_data": {
            "product": "WordPress",
            "version": "5.8.3",
            "plugins_detected": ["contact-form-7", "yoast-seo", "wp-file-manager"],
            "theme": "flavor-developer",
            "detected_on": "www.apexnova.example"
        }
    },
    {
        "source": "technology_fingerprint",
        "finding_type": "technology",
        "value": "Jenkins 2.346.1",
        "title": "Jenkins CI/CD Server",
        "description": "Jenkins 2.346.1 detected — older version with potential security implications.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "Jenkins version header in HTTP response",
        "category": "technology",
        "tags": "jenkins,cicd,outdated",
        "discovered_at": _dt(16),
        "raw_data": {
            "product": "Jenkins",
            "version": "2.346.1",
            "detected_on": "jenkins.apexnova.example",
            "public_signup": False
        }
    },
    {
        "source": "technology_fingerprint",
        "finding_type": "technology",
        "value": "Grafana 9.3.2",
        "title": "Grafana Monitoring Platform",
        "description": "Grafana 9.3.2 detected on monitoring subdomain.",
        "confidence": 0.89,
        "observation_type": "observed",
        "evidence": "Grafana login page and version API",
        "category": "technology",
        "tags": "grafana,monitoring",
        "discovered_at": _dt(16),
        "raw_data": {
            "product": "Grafana",
            "version": "9.3.2",
            "detected_on": "grafana.apexnova.example"
        }
    },
    {
        "source": "technology_fingerprint",
        "finding_type": "technology",
        "value": "Nginx 1.21.6 (Reverse Proxy)",
        "title": "Nginx Reverse Proxy",
        "description": "Nginx used as reverse proxy for multiple services.",
        "confidence": 0.93,
        "observation_type": "observed",
        "evidence": "Server header in HTTP response",
        "category": "technology",
        "tags": "nginx,reverse-proxy",
        "discovered_at": _dt(14),
        "raw_data": {
            "product": "Nginx",
            "version": "1.21.6",
            "detected_on": "portal.apexnova.example"
        }
    },
    {
        "source": "technology_fingerprint",
        "finding_type": "technology",
        "value": "PostgreSQL 13.4",
        "title": "PostgreSQL Database",
        "description": "PostgreSQL 13.4 detected via error disclosure on db-admin subdomain.",
        "confidence": 0.80,
        "observation_type": "inferred",
        "evidence": "Database error message in cached web page",
        "category": "technology",
        "tags": "postgresql,database,error-disclosure",
        "discovered_at": _dt(17),
        "raw_data": {
            "product": "PostgreSQL",
            "version": "13.4",
            "detected_on": "db-admin.apexnova.example",
            "detection_method": "error_page_disclosure"
        }
    },
]

# ============================================================================
# PUBLIC REPOSITORIES (9)
# ============================================================================
REPOSITORIES = [
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "apexnova-technologies/apexnova-frontend",
        "title": "Public Frontend Repository",
        "description": "Public GitHub repository for the ApexNova frontend application.",
        "confidence": 0.97,
        "observation_type": "observed",
        "evidence": "GitHub search result matching organization name",
        "category": "code",
        "tags": "github,frontend,public",
        "discovered_at": _dt(9),
        "raw_data": {
            "url": "https://github.example/apexnova-technologies/apexnova-frontend",
            "language": "TypeScript",
            "stars": 12,
            "last_push": "2026-07-10",
            "contributors": ["anova-dev1", "anova-dev2"],
            "topics": ["react", "typescript", "frontend"]
        }
    },
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "apexnova-technologies/api-gateway",
        "title": "API Gateway Repository",
        "description": "Public repository for the API gateway service.",
        "confidence": 0.96,
        "observation_type": "observed",
        "evidence": "GitHub search result",
        "category": "code",
        "tags": "github,api,backend",
        "discovered_at": _dt(9),
        "raw_data": {
            "url": "https://github.example/apexnova-technologies/api-gateway",
            "language": "Python",
            "stars": 5,
            "last_push": "2026-07-08",
            "contributors": ["anova-dev1", "anova-dev3"],
            "topics": ["fastapi", "python", "api"]
        }
    },
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "apexnova-technologies/infrastructure-configs",
        "title": "Infrastructure Configuration Repository",
        "description": "Public repository containing infrastructure-as-code configurations — potentially sensitive.",
        "confidence": 0.94,
        "observation_type": "observed",
        "evidence": "GitHub search result — contains Terraform and Docker configs",
        "category": "code",
        "tags": "github,infrastructure,iac,sensitive",
        "discovered_at": _dt(10),
        "raw_data": {
            "url": "https://github.example/apexnova-technologies/infrastructure-configs",
            "language": "HCL",
            "stars": 2,
            "last_push": "2026-06-25",
            "contributors": ["anova-dev3", "anova-ops1"],
            "topics": ["terraform", "docker", "infrastructure"],
            "has_secrets_warning": True
        }
    },
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "apexnova-technologies/docs-site",
        "title": "Documentation Site Repository",
        "description": "Public documentation website source.",
        "confidence": 0.95,
        "observation_type": "observed",
        "evidence": "GitHub search result",
        "category": "code",
        "tags": "github,docs",
        "discovered_at": _dt(9),
        "raw_data": {
            "url": "https://github.example/apexnova-technologies/docs-site",
            "language": "JavaScript",
            "stars": 3,
            "last_push": "2026-07-12",
            "contributors": ["anova-dev2"],
            "topics": ["docusaurus", "documentation"]
        }
    },
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "anova-dev1/personal-scripts",
        "title": "Developer Personal Repository",
        "description": "Personal repository of ApexNova developer — may contain work-related references.",
        "confidence": 0.80,
        "observation_type": "observed",
        "evidence": "GitHub profile linked to ApexNova organization",
        "category": "code",
        "tags": "github,personal,developer",
        "discovered_at": _dt(12),
        "raw_data": {
            "url": "https://github.example/anova-dev1/personal-scripts",
            "language": "Python",
            "stars": 0,
            "last_push": "2026-07-05",
            "readme_mentions": ["apexnova", "staging", "api-key"]
        }
    },
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "apexnova-technologies/mobile-app",
        "title": "Mobile Application Repository",
        "description": "Public mobile application source code.",
        "confidence": 0.93,
        "observation_type": "observed",
        "evidence": "GitHub search result",
        "category": "code",
        "tags": "github,mobile,app",
        "discovered_at": _dt(10),
        "raw_data": {
            "url": "https://github.example/apexnova-technologies/mobile-app",
            "language": "Dart",
            "stars": 8,
            "last_push": "2026-07-15",
            "contributors": ["anova-dev2", "anova-dev4"],
            "topics": ["flutter", "mobile", "dart"]
        }
    },
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "apexnova-technologies/deployment-scripts",
        "title": "Deployment Scripts Repository",
        "description": "CI/CD deployment scripts — may reveal infrastructure details.",
        "confidence": 0.91,
        "observation_type": "observed",
        "evidence": "GitHub search result — contains Jenkins pipeline configs",
        "category": "code",
        "tags": "github,cicd,deployment,sensitive",
        "discovered_at": _dt(11),
        "raw_data": {
            "url": "https://github.example/apexnova-technologies/deployment-scripts",
            "language": "Shell",
            "stars": 1,
            "last_push": "2026-06-30",
            "contributors": ["anova-ops1"],
            "topics": ["jenkins", "deployment", "automation"],
            "jenkinsfile_present": True
        }
    },
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "apexnova-technologies/data-pipeline",
        "title": "Data Pipeline Repository",
        "description": "ETL data pipeline for analytics.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "GitHub search result",
        "category": "code",
        "tags": "github,data,pipeline",
        "discovered_at": _dt(11),
        "raw_data": {
            "url": "https://github.example/apexnova-technologies/data-pipeline",
            "language": "Python",
            "stars": 4,
            "last_push": "2026-07-11",
            "contributors": ["anova-dev3", "anova-dev5"],
            "topics": ["airflow", "etl", "data"]
        }
    },
    {
        "source": "github_search",
        "finding_type": "repository",
        "value": "apexnova-technologies/legacy-monolith",
        "title": "Legacy Monolith Repository",
        "description": "Archived legacy monolith application — last updated 2 years ago.",
        "confidence": 0.85,
        "observation_type": "observed",
        "evidence": "GitHub search result — archived repository",
        "category": "code",
        "tags": "github,legacy,archived",
        "discovered_at": _dt(13),
        "raw_data": {
            "url": "https://github.example/apexnova-technologies/legacy-monolith",
            "language": "Java",
            "stars": 0,
            "last_push": "2024-05-01",
            "contributors": ["anova-dev1", "anova-dev5"],
            "topics": ["java", "spring", "legacy"],
            "archived": True
        }
    },
]

# ============================================================================
# DEVELOPERS / IDENTITIES (5)
# ============================================================================
DEVELOPERS = [
    {
        "source": "github_search",
        "finding_type": "identity",
        "value": "anova-dev1 (GitHub)",
        "title": "Developer Identifier — anova-dev1",
        "description": "GitHub user linked to ApexNova organization — contributes to multiple repositories.",
        "confidence": 0.85,
        "observation_type": "observed",
        "evidence": "GitHub organization membership and commit history",
        "category": "identity",
        "tags": "developer,github,identity",
        "discovered_at": _dt(9),
        "raw_data": {
            "username": "anova-dev1",
            "repos": ["apexnova-frontend", "api-gateway", "legacy-monolith", "personal-scripts"],
            "bio": "Full-stack developer at ApexNova Technologies",
            "public_email": None
        }
    },
    {
        "source": "github_search",
        "finding_type": "identity",
        "value": "anova-dev2 (GitHub)",
        "title": "Developer Identifier — anova-dev2",
        "description": "GitHub user linked to ApexNova — frontend and mobile developer.",
        "confidence": 0.83,
        "observation_type": "observed",
        "evidence": "GitHub organization membership",
        "category": "identity",
        "tags": "developer,github,identity",
        "discovered_at": _dt(9),
        "raw_data": {
            "username": "anova-dev2",
            "repos": ["apexnova-frontend", "docs-site", "mobile-app"],
            "bio": "Frontend & mobile dev",
            "public_email": None
        }
    },
    {
        "source": "github_search",
        "finding_type": "identity",
        "value": "anova-dev3 (GitHub)",
        "title": "Developer Identifier — anova-dev3",
        "description": "GitHub user — works on backend and infrastructure.",
        "confidence": 0.82,
        "observation_type": "observed",
        "evidence": "GitHub organization membership",
        "category": "identity",
        "tags": "developer,github,identity",
        "discovered_at": _dt(10),
        "raw_data": {
            "username": "anova-dev3",
            "repos": ["api-gateway", "infrastructure-configs", "data-pipeline"],
            "bio": "Backend engineer",
            "public_email": None
        }
    },
    {
        "source": "github_search",
        "finding_type": "identity",
        "value": "anova-ops1 (GitHub)",
        "title": "DevOps Identifier — anova-ops1",
        "description": "GitHub user — DevOps/SRE role, manages infrastructure and deployments.",
        "confidence": 0.80,
        "observation_type": "observed",
        "evidence": "GitHub organization membership",
        "category": "identity",
        "tags": "devops,github,identity",
        "discovered_at": _dt(10),
        "raw_data": {
            "username": "anova-ops1",
            "repos": ["infrastructure-configs", "deployment-scripts"],
            "bio": "DevOps at ApexNova",
            "public_email": None
        }
    },
    {
        "source": "github_search",
        "finding_type": "identity",
        "value": "anova-dev5 (GitHub)",
        "title": "Developer Identifier — anova-dev5",
        "description": "GitHub user — data engineering focus.",
        "confidence": 0.78,
        "observation_type": "observed",
        "evidence": "GitHub commit history",
        "category": "identity",
        "tags": "developer,github,identity,data",
        "discovered_at": _dt(11),
        "raw_data": {
            "username": "anova-dev5",
            "repos": ["data-pipeline", "legacy-monolith"],
            "bio": "Data engineer",
            "public_email": None
        }
    },
]

# ============================================================================
# THREAT INTELLIGENCE (4)
# ============================================================================
THREAT_INTEL = [
    {
        "source": "threat_intelligence",
        "finding_type": "threat_indicator",
        "value": "apexnova.example mentioned in phishing campaign IOC list",
        "title": "Phishing Campaign Reference",
        "description": "The domain apexnova.example was referenced in a public threat intelligence report about phishing campaigns targeting technology companies.",
        "confidence": 0.70,
        "observation_type": "observed",
        "evidence": "Public threat intelligence feed entry",
        "category": "threat",
        "tags": "phishing,ioc,threat-intel",
        "discovered_at": _dt(18),
        "raw_data": {
            "feed": "PhishTank Public Feed",
            "indicator_type": "domain_reference",
            "severity": "medium",
            "first_seen": "2026-06-15",
            "context": "Domain referenced as impersonation target"
        }
    },
    {
        "source": "threat_intelligence",
        "finding_type": "threat_indicator",
        "value": "203.0.113.61 flagged in abuse database",
        "title": "IP Address Abuse Report",
        "description": "The IP 203.0.113.61 (legacy server) has been flagged in a public abuse reporting database.",
        "confidence": 0.65,
        "observation_type": "observed",
        "evidence": "AbuseIPDB-style public report",
        "category": "threat",
        "tags": "abuse,ip,threat-intel",
        "discovered_at": _dt(20),
        "raw_data": {
            "feed": "AbuseIPDB Public",
            "indicator_type": "ip_abuse",
            "reports": 3,
            "categories": ["web-attack", "brute-force"],
            "confidence_score": 45
        }
    },
    {
        "source": "threat_intelligence",
        "finding_type": "threat_indicator",
        "value": "CVE-2021-41773 actively exploited (Apache 2.4.49)",
        "title": "Known Exploited Vulnerability",
        "description": "CVE-2021-41773 affecting Apache 2.4.49 is listed as actively exploited in public databases.",
        "confidence": 0.95,
        "observation_type": "observed",
        "evidence": "CISA Known Exploited Vulnerabilities Catalog",
        "category": "threat",
        "tags": "cve,kev,apache,critical",
        "discovered_at": _dt(19),
        "raw_data": {
            "cve": "CVE-2021-41773",
            "cvss": 7.5,
            "affected_product": "Apache HTTP Server 2.4.49",
            "exploitation_status": "actively_exploited",
            "kev_date_added": "2021-11-03"
        }
    },
    {
        "source": "threat_intelligence",
        "finding_type": "threat_indicator",
        "value": "apexnova-technologies GitHub org in credential leak dataset",
        "title": "Credential Leak Reference",
        "description": "The ApexNova Technologies GitHub organization was referenced in a public credential leak monitoring service.",
        "confidence": 0.60,
        "observation_type": "observed",
        "evidence": "Public breach notification service",
        "category": "threat",
        "tags": "credential-leak,github,threat-intel",
        "discovered_at": _dt(22),
        "raw_data": {
            "feed": "PublicLeakWatch",
            "indicator_type": "credential_reference",
            "severity": "high",
            "context": "API key pattern matching apexnova detected in public paste site"
        }
    },
]

# ============================================================================
# AHMIA / DARK WEB REFERENCES (3)
# ============================================================================
AHMIA_REFS = [
    {
        "source": "ahmia",
        "finding_type": "darkweb_reference",
        "value": "ApexNova Technologies mentioned on indexed forum",
        "title": "Dark Web Forum Mention",
        "description": "The organization name 'ApexNova Technologies' was found in a publicly indexed dark web forum discussion.",
        "confidence": 0.50,
        "observation_type": "observed",
        "evidence": "Ahmia search index — Demo Dataset",
        "category": "threat",
        "tags": "darkweb,ahmia,forum,demo",
        "discovered_at": _dt(25),
        "raw_data": {
            "search_engine": "Ahmia (Demo Dataset)",
            "query": "ApexNova Technologies",
            "result_type": "forum_mention",
            "snippet": "Discussion about technology companies in sector...",
            "category": "general_mention",
            "risk": "low"
        }
    },
    {
        "source": "ahmia",
        "finding_type": "darkweb_reference",
        "value": "apexnova.example domain in dark web paste",
        "title": "Domain Reference in Dark Web Paste",
        "description": "The domain apexnova.example appeared in a publicly indexed paste site accessible via Ahmia.",
        "confidence": 0.45,
        "observation_type": "observed",
        "evidence": "Ahmia search index — Demo Dataset",
        "category": "threat",
        "tags": "darkweb,ahmia,paste,demo",
        "discovered_at": _dt(28),
        "raw_data": {
            "search_engine": "Ahmia (Demo Dataset)",
            "query": "apexnova.example",
            "result_type": "paste_reference",
            "snippet": "List of domains in target sector...",
            "category": "data_listing",
            "risk": "medium"
        }
    },
    {
        "source": "ahmia",
        "finding_type": "darkweb_reference",
        "value": "ApexNova employee email pattern in breach compilation index",
        "title": "Email Pattern in Breach Index",
        "description": "The email pattern @apexnova.example was referenced in a breach compilation index.",
        "confidence": 0.40,
        "observation_type": "observed",
        "evidence": "Ahmia search index — Demo Dataset",
        "category": "threat",
        "tags": "darkweb,ahmia,breach,email,demo",
        "discovered_at": _dt(30),
        "raw_data": {
            "search_engine": "Ahmia (Demo Dataset)",
            "query": "@apexnova.example",
            "result_type": "breach_index_reference",
            "snippet": "Email domain pattern in compilation...",
            "category": "credential_reference",
            "risk": "high"
        }
    },
]

# ============================================================================
# ORGANIZATION REFERENCES (3)
# ============================================================================
ORG_REFERENCES = [
    {
        "source": "public_search",
        "finding_type": "organization",
        "value": "ApexNova Technologies — LinkedIn Company Profile",
        "title": "LinkedIn Organization Profile",
        "description": "Public LinkedIn profile for ApexNova Technologies providing organizational structure details.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "Public LinkedIn search result",
        "category": "identity",
        "tags": "linkedin,organization,public",
        "discovered_at": _dt(5),
        "raw_data": {
            "platform": "LinkedIn",
            "company_size": "51-200",
            "industry": "Information Technology & Services",
            "headquarters": "San Francisco, CA (fictional)",
            "founded": "2019"
        }
    },
    {
        "source": "public_search",
        "finding_type": "organization",
        "value": "ApexNova Technologies — Crunchbase Profile",
        "title": "Crunchbase Profile",
        "description": "Public Crunchbase profile providing funding and business details.",
        "confidence": 0.85,
        "observation_type": "observed",
        "evidence": "Public Crunchbase search result",
        "category": "identity",
        "tags": "crunchbase,organization,public",
        "discovered_at": _dt(5),
        "raw_data": {
            "platform": "Crunchbase",
            "funding_rounds": 2,
            "total_funding": "$8.5M (fictional)",
            "investors": ["TechVentures Fund (fictional)"],
            "last_funding_date": "2024-11"
        }
    },
    {
        "source": "public_search",
        "finding_type": "organization",
        "value": "ApexNova Technologies — Job Postings",
        "title": "Public Job Postings",
        "description": "Active job postings reveal technology stack and team structure.",
        "confidence": 0.88,
        "observation_type": "observed",
        "evidence": "Public job board listings",
        "category": "identity",
        "tags": "jobs,organization,technology-stack",
        "discovered_at": _dt(7),
        "raw_data": {
            "platform": "Various job boards",
            "open_positions": [
                {"title": "Senior Backend Engineer", "tech": ["Python", "FastAPI", "PostgreSQL", "AWS"]},
                {"title": "DevOps Engineer", "tech": ["Terraform", "Jenkins", "Docker", "Kubernetes"]},
                {"title": "Frontend Developer", "tech": ["React", "TypeScript", "Next.js"]}
            ],
            "reveals_stack": True
        }
    },
]

# ============================================================================
# EXPOSURE POINTS (8) — Inferred/Hypothesized findings
# ============================================================================
EXPOSURE_POINTS = [
    {
        "source": "correlation_engine",
        "finding_type": "exposure",
        "value": "Development environment publicly accessible",
        "title": "Public Development Environment Exposure",
        "description": "The development subdomain (dev.apexnova.example) has a publicly issued TLS certificate and DNS A record, indicating it is accessible from the internet. Development environments often contain debug features, verbose error messages, and test credentials.",
        "confidence": 0.90,
        "observation_type": "inferred",
        "evidence": "CT log certificate + passive DNS A record + development naming convention",
        "category": "exposure",
        "tags": "development,public-access,high-risk",
        "discovered_at": _dt(3),
        "raw_data": {
            "related_findings": ["dev.apexnova.example", "CN=dev.apexnova.example", "203.0.113.50"],
            "risk_factors": ["public_certificate", "development_environment", "same_hosting_as_production"]
        }
    },
    {
        "source": "correlation_engine",
        "finding_type": "exposure",
        "value": "Infrastructure configuration repository publicly accessible",
        "title": "Public Infrastructure Configuration Exposure",
        "description": "Infrastructure-as-code repository containing Terraform and Docker configurations is publicly accessible on GitHub. May contain hardcoded credentials, internal IP ranges, or architecture details.",
        "confidence": 0.88,
        "observation_type": "inferred",
        "evidence": "Public GitHub repository with IaC content + secrets warning flag",
        "category": "exposure",
        "tags": "infrastructure,iac,public-repo,secrets",
        "discovered_at": _dt(10),
        "raw_data": {
            "related_findings": ["infrastructure-configs", "anova-ops1"],
            "risk_factors": ["public_iac_repo", "secrets_warning", "terraform_configs"]
        }
    },
    {
        "source": "correlation_engine",
        "finding_type": "exposure",
        "value": "Outdated Apache server with known CVE",
        "title": "Known Vulnerable Apache Version",
        "description": "Apache HTTP Server 2.4.49 on legacy.apexnova.example has CVE-2021-41773 (path traversal) which is listed as actively exploited.",
        "confidence": 0.92,
        "observation_type": "inferred",
        "evidence": "Technology fingerprint + CISA KEV listing + legacy subdomain",
        "category": "exposure",
        "tags": "cve,apache,legacy,critical",
        "discovered_at": _dt(14),
        "raw_data": {
            "related_findings": ["Apache 2.4.49", "CVE-2021-41773", "legacy.apexnova.example"],
            "risk_factors": ["known_exploited_vulnerability", "legacy_infrastructure", "outdated_software"]
        }
    },
    {
        "source": "correlation_engine",
        "finding_type": "exposure",
        "value": "Jenkins CI/CD server publicly accessible",
        "title": "Public CI/CD Server Exposure",
        "description": "Jenkins server is accessible via public DNS and has a valid TLS certificate. CI/CD servers are high-value targets as they typically have deployment credentials.",
        "confidence": 0.86,
        "observation_type": "inferred",
        "evidence": "CT certificate + DNS record + Jenkins version fingerprint",
        "category": "exposure",
        "tags": "jenkins,cicd,public-access,high-value",
        "discovered_at": _dt(7),
        "raw_data": {
            "related_findings": ["jenkins.apexnova.example", "Jenkins 2.346.1"],
            "risk_factors": ["public_cicd", "deployment_credentials", "build_artifacts"]
        }
    },
    {
        "source": "correlation_engine",
        "finding_type": "exposure",
        "value": "Developer personal repository references work systems",
        "title": "Developer Personal Repository Leak",
        "description": "A developer's personal GitHub repository contains references to 'apexnova', 'staging', and 'api-key' in its README.",
        "confidence": 0.75,
        "observation_type": "inferred",
        "evidence": "GitHub personal repo README content analysis",
        "category": "exposure",
        "tags": "developer,personal-repo,api-key,leak",
        "discovered_at": _dt(12),
        "raw_data": {
            "related_findings": ["anova-dev1", "personal-scripts"],
            "risk_factors": ["personal_repo_work_references", "api_key_mention", "staging_reference"]
        }
    },
    {
        "source": "correlation_engine",
        "finding_type": "exposure",
        "value": "Database admin interface publicly resolvable",
        "title": "Public Database Admin Interface",
        "description": "Database administration interface (db-admin.apexnova.example) has a public DNS record. Combined with PostgreSQL error disclosure, this represents a high-value target.",
        "confidence": 0.84,
        "observation_type": "inferred",
        "evidence": "Passive DNS + database error disclosure",
        "category": "exposure",
        "tags": "database,admin,public-access,critical",
        "discovered_at": _dt(8),
        "raw_data": {
            "related_findings": ["db-admin.apexnova.example", "PostgreSQL 13.4"],
            "risk_factors": ["public_db_admin", "error_disclosure", "database_version_leak"]
        }
    },
    {
        "source": "correlation_engine",
        "finding_type": "exposure",
        "value": "Credential leak reference in threat intelligence",
        "title": "Potential Credential Exposure",
        "description": "Public breach monitoring services reference API key patterns matching ApexNova in paste sites.",
        "confidence": 0.60,
        "observation_type": "inferred",
        "evidence": "Threat intelligence feed + GitHub org reference",
        "category": "exposure",
        "tags": "credentials,leak,threat-intel",
        "discovered_at": _dt(22),
        "raw_data": {
            "related_findings": ["credential_leak_reference", "github_org"],
            "risk_factors": ["credential_leak", "paste_site", "api_key_exposure"]
        }
    },
    {
        "source": "correlation_engine",
        "finding_type": "exposure",
        "value": "Legacy infrastructure with deprecated security",
        "title": "Legacy Infrastructure — Deprecated Security Controls",
        "description": "Legacy subdomain runs expired certificates with SHA-1 signatures, outdated Apache, and has abuse reports against its IP.",
        "confidence": 0.80,
        "observation_type": "inferred",
        "evidence": "Multiple correlated legacy indicators",
        "category": "exposure",
        "tags": "legacy,deprecated,sha1,expired-cert",
        "discovered_at": _dt(12),
        "raw_data": {
            "related_findings": ["legacy.apexnova.example", "SHA-1 cert", "Apache 2.4.49", "IP abuse"],
            "risk_factors": ["expired_certificate", "deprecated_crypto", "outdated_software", "abuse_reports"]
        }
    },
]

# ============================================================================
# Aggregate all findings
# ============================================================================
ALL_FINDINGS = (
    DOMAINS +
    SUBDOMAINS +
    CERTIFICATES +
    IP_ASN +
    TECHNOLOGIES +
    REPOSITORIES +
    DEVELOPERS +
    THREAT_INTEL +
    AHMIA_REFS +
    ORG_REFERENCES +
    EXPOSURE_POINTS
)

# Verify count
assert len(ALL_FINDINGS) >= 70, f"Expected 70+ findings, got {len(ALL_FINDINGS)}"


# ============================================================================
# ATTACK PATHS (5)
# ============================================================================
ATTACK_PATHS = [
    {
        "title": "Development Environment → Application Compromise",
        "description": "Public development environment provides entry point to internal application layer.",
        "hypothesis": "An attacker could discover the publicly accessible development environment via Certificate Transparency logs, identify the development technology stack, and investigate for debug endpoints, default credentials, or test data that could provide unauthorized access to application functionality.",
        "validation_note": "Requires authorized penetration testing to validate. This is a potential attack path based on passive OSINT correlation.",
        "risk_score": 72.0,
        "risk_level": "VERY HIGH",
        "entry_point": "dev.apexnova.example",
        "target_asset": "Application Layer",
        "nodes": [
            {"step_order": 1, "label": "CT Log Discovery", "description": "Development certificate found in CT logs", "node_type": "entry"},
            {"step_order": 2, "label": "dev.apexnova.example", "description": "Development subdomain identified", "node_type": "asset"},
            {"step_order": 3, "label": "Node.js 16.x / Express", "description": "Technology stack fingerprinted", "node_type": "asset"},
            {"step_order": 4, "label": "Debug/Test Features", "description": "Development environments often have debug endpoints", "node_type": "weakness"},
            {"step_order": 5, "label": "Application Compromise", "description": "Potential unauthorized access to application", "node_type": "impact"},
        ]
    },
    {
        "title": "Infrastructure Repository → Cloud Infrastructure Access",
        "description": "Public infrastructure-as-code repository may expose cloud credentials and architecture.",
        "hypothesis": "An attacker could analyze the public infrastructure-configs repository for hardcoded credentials, API keys, internal IP ranges, or cloud service configurations that could be used to access cloud infrastructure.",
        "validation_note": "Requires authorized review of repository contents. Secret scanning should be performed.",
        "risk_score": 68.0,
        "risk_level": "VERY HIGH",
        "entry_point": "GitHub: infrastructure-configs",
        "target_asset": "Cloud Infrastructure",
        "nodes": [
            {"step_order": 1, "label": "GitHub Search", "description": "Public repository discovered via GitHub search", "node_type": "entry"},
            {"step_order": 2, "label": "infrastructure-configs repo", "description": "Terraform and Docker configurations found", "node_type": "asset"},
            {"step_order": 3, "label": "Secrets Warning", "description": "Repository flagged for potential secrets", "node_type": "weakness"},
            {"step_order": 4, "label": "Cloud Credentials", "description": "Potential hardcoded cloud credentials in IaC", "node_type": "weakness"},
            {"step_order": 5, "label": "Cloud Infrastructure Access", "description": "Unauthorized access to cloud resources", "node_type": "impact"},
        ]
    },
    {
        "title": "Legacy Apache CVE → Server Compromise",
        "description": "Known exploited vulnerability in legacy Apache server provides direct attack vector.",
        "hypothesis": "An attacker could exploit CVE-2021-41773 (path traversal) in the legacy Apache 2.4.49 server to read sensitive files or achieve remote code execution. This CVE is listed as actively exploited in the wild.",
        "validation_note": "Requires authorized vulnerability scanning to confirm exploitability.",
        "risk_score": 78.0,
        "risk_level": "VERY HIGH",
        "entry_point": "legacy.apexnova.example",
        "target_asset": "Legacy Server",
        "nodes": [
            {"step_order": 1, "label": "Technology Fingerprint", "description": "Apache 2.4.49 identified via passive fingerprint", "node_type": "entry"},
            {"step_order": 2, "label": "legacy.apexnova.example", "description": "Legacy server with outdated software", "node_type": "asset"},
            {"step_order": 3, "label": "CVE-2021-41773", "description": "Known path traversal vulnerability", "node_type": "weakness"},
            {"step_order": 4, "label": "CISA KEV Listed", "description": "Actively exploited in the wild", "node_type": "weakness"},
            {"step_order": 5, "label": "Server Compromise", "description": "Potential file read or remote code execution", "node_type": "impact"},
        ]
    },
    {
        "title": "CI/CD Server → Supply Chain Attack",
        "description": "Public Jenkins server could be leveraged for supply chain compromise.",
        "hypothesis": "An attacker could target the publicly accessible Jenkins server to compromise the build and deployment pipeline, potentially injecting malicious code into production deployments.",
        "validation_note": "Requires authorized testing of Jenkins authentication and access controls.",
        "risk_score": 65.0,
        "risk_level": "VERY HIGH",
        "entry_point": "jenkins.apexnova.example",
        "target_asset": "Deployment Pipeline",
        "nodes": [
            {"step_order": 1, "label": "DNS/CT Discovery", "description": "Jenkins subdomain found via CT and DNS", "node_type": "entry"},
            {"step_order": 2, "label": "jenkins.apexnova.example", "description": "Jenkins CI/CD server", "node_type": "asset"},
            {"step_order": 3, "label": "Jenkins 2.346.1", "description": "Older Jenkins version identified", "node_type": "asset"},
            {"step_order": 4, "label": "Deployment Scripts", "description": "Public deployment scripts reveal pipeline", "node_type": "weakness"},
            {"step_order": 5, "label": "Supply Chain Compromise", "description": "Potential code injection into deployments", "node_type": "impact"},
        ]
    },
    {
        "title": "Developer OSINT → Credential Harvesting",
        "description": "Developer identity and personal repository could lead to credential exposure.",
        "hypothesis": "An attacker could use the developer's personal repository (which references staging and API keys) combined with credential leak intelligence to attempt credential reuse or social engineering attacks.",
        "validation_note": "Requires authorized review. Personal repository content should be audited by the developer.",
        "risk_score": 52.0,
        "risk_level": "HIGH",
        "entry_point": "GitHub: anova-dev1",
        "target_asset": "Developer Credentials",
        "nodes": [
            {"step_order": 1, "label": "GitHub Profile Discovery", "description": "Developer profile found via org membership", "node_type": "entry"},
            {"step_order": 2, "label": "anova-dev1", "description": "Developer identity identified", "node_type": "asset"},
            {"step_order": 3, "label": "personal-scripts repo", "description": "Personal repo with work references", "node_type": "asset"},
            {"step_order": 4, "label": "API Key Reference", "description": "README mentions 'api-key' and 'staging'", "node_type": "weakness"},
            {"step_order": 5, "label": "Credential Exposure", "description": "Potential credential reuse or harvesting", "node_type": "impact"},
        ]
    },
]

# ============================================================================
# DEFENSIVE RECOMMENDATIONS
# ============================================================================
RECOMMENDATIONS = [
    {
        "title": "Restrict Development Environment Access",
        "description": "Implement network-level access controls to prevent public access to development environments. Use VPN or Zero Trust Network Access (ZTNA) for developer access. Remove public DNS records for development subdomains.",
        "category": "access_control",
        "priority": 1,
        "effort": "medium",
        "rationale": "Development environments are publicly accessible via DNS and TLS certificates. They often contain debug features and test credentials.",
        "finding_ref": "Public Development Environment Exposure"
    },
    {
        "title": "Audit and Secure Infrastructure Repository",
        "description": "Make the infrastructure-configs repository private. Run secret scanning tools (e.g., truffleHog, git-secrets). Rotate any credentials found. Implement pre-commit hooks to prevent future secret commits.",
        "category": "secret_management",
        "priority": 1,
        "effort": "low",
        "rationale": "Public infrastructure-as-code repository may contain hardcoded credentials and architecture details.",
        "finding_ref": "Public Infrastructure Configuration Exposure"
    },
    {
        "title": "Patch Legacy Apache Server",
        "description": "Immediately upgrade Apache HTTP Server from 2.4.49 to the latest stable version. If the legacy application cannot be updated, implement a WAF rule to block path traversal attempts. Consider decommissioning the legacy server if no longer needed.",
        "category": "patching",
        "priority": 1,
        "effort": "medium",
        "rationale": "Apache 2.4.49 has CVE-2021-41773 (actively exploited path traversal vulnerability).",
        "finding_ref": "Known Vulnerable Apache Version"
    },
    {
        "title": "Secure CI/CD Pipeline Access",
        "description": "Restrict Jenkins access to internal networks only. Implement strong authentication (LDAP/SSO). Update Jenkins to the latest LTS version. Review and restrict pipeline permissions. Enable audit logging.",
        "category": "access_control",
        "priority": 1,
        "effort": "medium",
        "rationale": "Jenkins CI/CD server is publicly accessible and represents a high-value target for supply chain attacks.",
        "finding_ref": "Public CI/CD Server Exposure"
    },
    {
        "title": "Review Developer Personal Repositories",
        "description": "Conduct an audit of developer personal repositories for work-related content. Implement a policy requiring developers to avoid referencing internal systems in personal repos. Run secret scanning on identified personal repositories.",
        "category": "secret_management",
        "priority": 2,
        "effort": "low",
        "rationale": "Developer personal repository contains references to internal systems and API keys.",
        "finding_ref": "Developer Personal Repository Leak"
    },
    {
        "title": "Secure Database Administration Interface",
        "description": "Remove public DNS record for db-admin subdomain. Restrict access to VPN/internal network only. Fix PostgreSQL error disclosure. Implement strong authentication and audit logging.",
        "category": "access_control",
        "priority": 1,
        "effort": "medium",
        "rationale": "Database administration interface is publicly resolvable and leaks database version information.",
        "finding_ref": "Public Database Admin Interface"
    },
    {
        "title": "Investigate and Rotate Leaked Credentials",
        "description": "Investigate credential leak references in threat intelligence feeds. Rotate all API keys and credentials that may have been exposed. Implement credential monitoring and automated rotation.",
        "category": "secret_management",
        "priority": 1,
        "effort": "high",
        "rationale": "Threat intelligence indicates potential credential exposure in public paste sites.",
        "finding_ref": "Potential Credential Exposure"
    },
    {
        "title": "Decommission or Upgrade Legacy Infrastructure",
        "description": "Evaluate the necessity of legacy.apexnova.example. If needed, upgrade all components (Apache, TLS certificates, crypto). If not needed, decommission and remove DNS records. Replace SHA-1 certificates.",
        "category": "asset_management",
        "priority": 2,
        "effort": "high",
        "rationale": "Legacy infrastructure has multiple security issues: expired certificates, SHA-1, outdated Apache, and abuse reports.",
        "finding_ref": "Legacy Infrastructure — Deprecated Security Controls"
    },
    {
        "title": "Implement Certificate Transparency Monitoring",
        "description": "Set up continuous Certificate Transparency monitoring to detect unauthorized or unexpected certificate issuance for all ApexNova domains.",
        "category": "monitoring",
        "priority": 2,
        "effort": "low",
        "rationale": "Multiple sensitive subdomains were discovered via CT logs. Monitoring would provide early warning of new certificate issuance."
    },
    {
        "title": "Minimize Technology Version Disclosure",
        "description": "Configure web servers and application frameworks to suppress version information in HTTP headers and error pages. Use generic error pages that do not reveal technology details.",
        "category": "configuration",
        "priority": 3,
        "effort": "low",
        "rationale": "Multiple technology versions (Apache, Jenkins, Grafana, PostgreSQL) were identified through passive fingerprinting."
    },
    {
        "title": "Implement External Attack Surface Management (EASM)",
        "description": "Deploy continuous external attack surface monitoring to track all public-facing assets, certificates, DNS records, and technology changes. Integrate with vulnerability management.",
        "category": "monitoring",
        "priority": 2,
        "effort": "medium",
        "rationale": "The organization's external attack surface includes numerous subdomains, services, and technologies that change over time."
    },
    {
        "title": "Establish Dark Web Monitoring",
        "description": "Implement regular monitoring of dark web sources for references to ApexNova Technologies, its domains, and employee email patterns.",
        "category": "monitoring",
        "priority": 3,
        "effort": "medium",
        "rationale": "Dark web references were found mentioning the organization, domain, and email patterns."
    },
]

# ============================================================================
# RISK SCORES for key findings
# ============================================================================
RISK_SCORES = [
    {
        "finding_ref": "Public Development Environment Exposure",
        "exposure": 8.0,
        "confidence": 9.0,
        "exploitability": 7.0,
        "impact": 8.0,
        "rationale": "Development environment is publicly accessible (high exposure), confirmed via CT logs (high confidence), development environments are commonly exploitable (high exploitability), and compromise could lead to data access (high impact)."
    },
    {
        "finding_ref": "Public Infrastructure Configuration Exposure",
        "exposure": 9.0,
        "confidence": 8.5,
        "exploitability": 7.5,
        "impact": 9.0,
        "rationale": "Public GitHub repository (very high exposure), confirmed via GitHub search (high confidence), IaC secrets are commonly exploitable (high exploitability), and cloud infrastructure compromise has severe impact."
    },
    {
        "finding_ref": "Known Vulnerable Apache Version",
        "exposure": 7.0,
        "confidence": 9.5,
        "exploitability": 9.0,
        "impact": 8.5,
        "rationale": "Legacy server is publicly accessible (high exposure), CVE confirmed and in CISA KEV (very high confidence), actively exploited in the wild (very high exploitability), server compromise impact is high."
    },
    {
        "finding_ref": "Public CI/CD Server Exposure",
        "exposure": 8.0,
        "confidence": 8.0,
        "exploitability": 6.5,
        "impact": 9.0,
        "rationale": "Jenkins publicly accessible (high exposure), confirmed via DNS and fingerprint (high confidence), CI/CD exploitation requires authentication bypass (medium-high exploitability), supply chain impact is very high."
    },
    {
        "finding_ref": "Developer Personal Repository Leak",
        "exposure": 7.0,
        "confidence": 7.0,
        "exploitability": 5.5,
        "impact": 7.0,
        "rationale": "Public personal repo (high exposure), GitHub confirmed (medium-high confidence), requires credential validation (medium exploitability), credential exposure impact is high."
    },
    {
        "finding_ref": "Public Database Admin Interface",
        "exposure": 7.5,
        "confidence": 8.0,
        "exploitability": 7.0,
        "impact": 9.5,
        "rationale": "Database admin publicly resolvable (high exposure), DNS confirmed (high confidence), DB admin interfaces are commonly targeted (high exploitability), database compromise has critical impact."
    },
    {
        "finding_ref": "Potential Credential Exposure",
        "exposure": 6.0,
        "confidence": 5.5,
        "exploitability": 6.0,
        "impact": 8.0,
        "rationale": "Referenced in threat intel (medium exposure), threat intel confidence is moderate, credential reuse is common (medium exploitability), credential compromise impact is high."
    },
    {
        "finding_ref": "Legacy Infrastructure — Deprecated Security Controls",
        "exposure": 7.0,
        "confidence": 8.0,
        "exploitability": 7.5,
        "impact": 7.0,
        "rationale": "Publicly accessible legacy server (high exposure), multiple confirmed indicators (high confidence), outdated security is commonly exploitable (high exploitability), server compromise impact is high."
    },
]


# ============================================================================
# EMAIL INTELLIGENCE (demo)
# ============================================================================
EMAILS = [
    {
        "source": "hunter.io",
        "finding_type": "email",
        "value": "priya.sharma@apexnova.example",
        "title": "Email: priya.sharma@apexnova.example",
        "description": "Public email for Priya Sharma (Lead Developer) at ApexNova Technologies.",
        "confidence": 0.87,
        "observation_type": "observed",
        "evidence": "Hunter.io domain search + GitHub commit history",
        "category": "email",
        "tags": "email,hunter,github",
        "discovered_at": _dt(10),
        "raw_data": {
            "first_name": "Priya", "last_name": "Sharma",
            "position": "Lead Developer", "organization": "ApexNova Technologies",
            "sources": ["hunter.io", "github"],
        },
    },
    {
        "source": "hunter.io",
        "finding_type": "email",
        "value": "john.doe@apexnova.example",
        "title": "Email: john.doe@apexnova.example",
        "description": "Public email for John Doe (CTO) at ApexNova Technologies.",
        "confidence": 0.82,
        "observation_type": "observed",
        "evidence": "Hunter.io domain email enumeration",
        "category": "email",
        "tags": "email,hunter",
        "discovered_at": _dt(12),
        "raw_data": {"first_name": "John", "last_name": "Doe", "position": "CTO"},
    },
    {
        "source": "hunter.io",
        "finding_type": "email",
        "value": "dev-team@apexnova.example",
        "title": "Email: dev-team@apexnova.example",
        "description": "Development team group email. Confirmed by multiple sources.",
        "confidence": 0.90,
        "observation_type": "observed",
        "evidence": "Hunter.io + GitHub + EmailRep.io",
        "category": "email",
        "tags": "email,hunter,github,emailrep",
        "discovered_at": _dt(8),
        "raw_data": {"type": "generic", "organization": "ApexNova Technologies"},
    },
    {
        "source": "hunter.io",
        "finding_type": "email",
        "value": "security@apexnova.example",
        "title": "Email: security@apexnova.example",
        "description": "Security contact email for ApexNova Technologies.",
        "confidence": 0.85,
        "observation_type": "observed",
        "evidence": "Hunter.io domain search + EmailRep.io reputation check",
        "category": "email",
        "tags": "email,security,hunter,emailrep",
        "discovered_at": _dt(9),
        "raw_data": {"type": "generic", "reputation": "good"},
    },
]


# ============================================================================
# COMBINED: ALL_FINDINGS (multi-source enriched)
# ============================================================================
def _build_all_findings():
    """Build the complete enriched finding list for demo scans."""
    raw = (
        DOMAINS + SUBDOMAINS + CERTIFICATES + IP_ASN + TECHNOLOGIES
        + REPOSITORIES + DEVELOPERS + THREAT_INTEL + AHMIA_REFS
        + ORG_REFERENCES + EXPOSURE_POINTS + EMAILS
    )
    return [_enrich_with_sources(f) for f in raw]


ALL_FINDINGS = _build_all_findings()
