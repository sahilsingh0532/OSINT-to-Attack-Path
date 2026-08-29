"""IP providers — VirusTotal IP relationship data."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings
import dns.asyncresolver


class VirusTotalIpCollector(BaseCollector):
    name = "virustotal"
    display_name = "VirusTotal (IP Intelligence)"
    description = "IP reputation and relationship data from VirusTotal. Requires API key."
    provider_category = "ip"
    requires_key = True

    def _has_api_key(self) -> bool:
        return bool(settings.virustotal_api_key)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not self._has_api_key():
            return []
        results = []
        resolved_ips = []
        try:
            resolver = dns.asyncresolver.Resolver()
            a = await resolver.resolve(target, 'A')
            resolved_ips = [str(r) for r in a]
        except Exception:
            pass

        try:
            self._record_query()
            headers = {"x-apikey": settings.virustotal_api_key}
            async with httpx.AsyncClient(timeout=10.0) as client:
                for ip in resolved_ips[:2]:
                    r = await client.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers=headers,
                    )
                    if r.status_code == 200:
                        attrs = r.json().get("data", {}).get("attributes", {})
                        asn = attrs.get("asn", "")
                        asn_owner = attrs.get("as_owner", "")
                        country = attrs.get("country", "")
                        reputation = attrs.get("reputation", 0)
                        stats = attrs.get("last_analysis_stats", {})

                        results.append(make_result(
                            source=self.name,
                            finding_type="ip",
                            value=ip,
                            target=target,
                            confidence=0.92,
                            evidence=f"VirusTotal IP analysis for {ip}",
                            title=f"IP: {ip} (VT)",
                            description=f"IP {ip} in {country}. ASN: AS{asn} ({asn_owner}). Reputation: {reputation}",
                            observation_type="observed",
                            category="infrastructure",
                            tags="ip,virustotal,asn",
                            raw_data={
                                "ip": ip,
                                "asn": asn,
                                "as_owner": asn_owner,
                                "country": country,
                                "reputation": reputation,
                                "last_analysis_stats": stats,
                            },
                        ))
                        if asn:
                            results.append(make_result(
                                source=self.name,
                                finding_type="asn",
                                value=f"AS{asn} ({asn_owner})",
                                target=target,
                                confidence=0.90,
                                evidence=f"VirusTotal ASN data for {ip}",
                                title=f"ASN: AS{asn}",
                                description=f"IP {ip} belongs to AS{asn} ({asn_owner}) in {country}",
                                observation_type="observed",
                                category="infrastructure",
                                tags="asn,virustotal",
                                raw_data={"asn": asn, "owner": asn_owner, "ip": ip},
                            ))
        except Exception as e:
            self._record_error(str(e))
        return results
