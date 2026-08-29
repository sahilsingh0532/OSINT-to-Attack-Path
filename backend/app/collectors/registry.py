"""
Provider Registry — the central registry of all OSINT providers.

Replaces the old ALL_COLLECTORS list with a categorized, modular registry.
Each provider is grouped by category.
"""

from typing import List, Type, Dict
from app.collectors.base import BaseCollector

# Domain providers
from app.collectors.domain.crtsh import CrtShDomainCollector
from app.collectors.domain.virustotal import VirusTotalDomainCollector
from app.collectors.domain.hackertarget import HackerTargetDomainCollector
from app.collectors.domain.rdap import RdapDomainCollector

# Certificate providers
from app.collectors.certificate.crtsh import CrtShCertCollector
from app.collectors.certificate.virustotal import VirusTotalCertCollector

# IP providers
from app.collectors.ip.shodan import ShodanIpCollector
from app.collectors.ip.virustotal import VirusTotalIpCollector
from app.collectors.ip.rdap import RdapIpCollector

# DNS providers
from app.collectors.dns.dns_query import DnsQueryCollector
from app.collectors.dns.alienvault import AlienVaultDnsCollector
from app.collectors.dns.virustotal import VirusTotalDnsCollector
from app.collectors.dns.securitytrails import SecurityTrailsDnsCollector

# Email providers
from app.collectors.email.hunter import HunterEmailCollector
from app.collectors.email.emailrep import EmailRepCollector
from app.collectors.email.github import GithubEmailCollector
from app.collectors.email.hibp import HibpEmailCollector

# Username providers
from app.collectors.username.github import GithubUsernameCollector

# Technology providers
from app.collectors.technology.http_fingerprint import HttpFingerprintCollector
from app.collectors.technology.shodan import ShodanTechCollector
from app.collectors.technology.virustotal import VirusTotalTechCollector

# Threat Intel providers
from app.collectors.threat_intel.virustotal import VirusTotalThreatCollector
from app.collectors.threat_intel.alienvault import AlienVaultThreatCollector
from app.collectors.threat_intel.ahmia import AhmiaThreatCollector

# GitHub intelligence
from app.collectors.github.github import GithubIntelCollector


# ================================================================
# REGISTRY — ordered by category for the scan pipeline
# ================================================================

PROVIDER_REGISTRY: Dict[str, List[Type[BaseCollector]]] = {
    "domain": [
        CrtShDomainCollector,
        VirusTotalDomainCollector,
        HackerTargetDomainCollector,
        RdapDomainCollector,
    ],
    "dns": [
        DnsQueryCollector,
        AlienVaultDnsCollector,
        VirusTotalDnsCollector,
        SecurityTrailsDnsCollector,
    ],
    "certificate": [
        CrtShCertCollector,
        VirusTotalCertCollector,
    ],
    "ip": [
        ShodanIpCollector,
        VirusTotalIpCollector,
        RdapIpCollector,
    ],
    "technology": [
        HttpFingerprintCollector,
        ShodanTechCollector,
        VirusTotalTechCollector,
    ],
    "github": [
        GithubIntelCollector,
    ],
    "email": [
        GithubEmailCollector,
        HunterEmailCollector,
        HibpEmailCollector,
        # EmailRepCollector — only for direct email queries, not domain scans
    ],
    "username": [
        GithubUsernameCollector,
    ],
    "threat_intel": [
        VirusTotalThreatCollector,
        AlienVaultThreatCollector,
        AhmiaThreatCollector,
    ],
}

# Flat list of all providers (for backwards compatibility and health checks)
ALL_PROVIDERS: List[Type[BaseCollector]] = [
    provider
    for providers in PROVIDER_REGISTRY.values()
    for provider in providers
]

# Providers that run on a domain scan (excludes email/username which need separate input)
DOMAIN_SCAN_CATEGORIES = ["domain", "dns", "certificate", "ip", "technology", "github", "threat_intel"]


def get_all_providers() -> List[Type[BaseCollector]]:
    """Return all registered provider classes."""
    return ALL_PROVIDERS


def get_providers_by_category(category: str) -> List[Type[BaseCollector]]:
    """Return providers for a specific category."""
    return PROVIDER_REGISTRY.get(category, [])


def get_domain_scan_providers() -> List[Type[BaseCollector]]:
    """Return providers that run during a domain scan."""
    result = []
    for cat in DOMAIN_SCAN_CATEGORIES:
        result.extend(PROVIDER_REGISTRY.get(cat, []))
    return result


def get_provider_health(is_demo: bool = False) -> List[dict]:
    """Return health status of all providers."""
    statuses = []
    seen = set()  # Track (name, category) pairs to avoid duplicates in health view
    for cat, providers in PROVIDER_REGISTRY.items():
        for ProviderClass in providers:
            p = ProviderClass()
            p.is_demo = is_demo
            status = p.get_status()
            key = f"{status['name']}:{cat}"
            if key not in seen:
                seen.add(key)
                statuses.append(status)
    return statuses
