"""DNS providers — SecurityTrails passive DNS (requires API key)."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class SecurityTrailsDnsCollector(BaseCollector):
    name = "securitytrails"
    display_name = "SecurityTrails (Passive DNS)"
    description = "Passive DNS records, subdomains, and historical DNS from SecurityTrails API. API key required."
    provider_category = "dns"
    requires_key = True

    def _has_api_key(self) -> bool:
        return bool(settings.securitytrails_api_key)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not settings.securitytrails_api_key:
            return []

        results = []
        headers = {"apikey": settings.securitytrails_api_key}

        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. Subdomain enumeration
                r = await client.get(
                    f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
                    headers=headers,
                )
                if r.status_code == 200:
                    data = r.json()
                    subdomains = data.get("subdomains", [])
                    for sub in subdomains[:40]:
                        fqdn = f"{sub}.{target}"
                        results.append(make_result(
                            source=self.name,
                            finding_type="subdomain",
                            value=fqdn,
                            target=target,
                            confidence=0.90,
                            evidence=f"SecurityTrails subdomain enumeration for {target}",
                            title=f"Subdomain: {fqdn}",
                            description=f"Subdomain {fqdn} discovered via SecurityTrails passive DNS database.",
                            observation_type="observed",
                            category="infrastructure",
                            tags="subdomain,securitytrails,passive_dns",
                            raw_data={"subdomain": sub, "fqdn": fqdn},
                        ))

                # 2. Historical DNS records
                r2 = await client.get(
                    f"https://api.securitytrails.com/v1/history/{target}/dns/a",
                    headers=headers,
                )
                if r2.status_code == 200:
                    hist = r2.json()
                    records = hist.get("records", [])
                    seen_ips = set()
                    for record in records[:10]:
                        for value in record.get("values", []):
                            ip = value.get("ip", "")
                            if ip and ip not in seen_ips:
                                seen_ips.add(ip)
                                first_seen = record.get("first_seen", "")
                                last_seen = record.get("last_seen", "")
                                results.append(make_result(
                                    source=self.name,
                                    finding_type="ip",
                                    value=ip,
                                    target=target,
                                    confidence=0.85,
                                    evidence=f"SecurityTrails historical A record for {target}",
                                    title=f"Historical IP: {ip}",
                                    description=(
                                        f"IP {ip} was historically associated with {target}. "
                                        f"First seen: {first_seen}, Last seen: {last_seen}."
                                    ),
                                    observation_type="observed",
                                    category="infrastructure",
                                    tags="ip,historical_dns,securitytrails",
                                    raw_data={"ip": ip, "first_seen": first_seen, "last_seen": last_seen},
                                    first_seen=first_seen,
                                    last_seen=last_seen,
                                ))

        except Exception as e:
            self._record_error(str(e))

        return results
