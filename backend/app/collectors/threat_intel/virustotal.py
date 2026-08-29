"""Threat Intel providers — VirusTotal domain/IP reputation."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class VirusTotalThreatCollector(BaseCollector):
    name = "virustotal"
    display_name = "VirusTotal (Threat Intelligence)"
    description = "Domain/IP threat intelligence from VirusTotal multi-vendor analysis. Requires API key."
    provider_category = "threat_intel"
    requires_key = True

    def _has_api_key(self) -> bool:
        return bool(settings.virustotal_api_key)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not self._has_api_key():
            return []
        results = []
        try:
            self._record_query()
            headers = {"x-apikey": settings.virustotal_api_key}
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}",
                    headers=headers,
                )
                if r.status_code == 200:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    reputation = attrs.get("reputation", 0)
                    total = sum(stats.values()) or 1

                    confidence = 0.92 if (malicious + suspicious) > 0 else 0.85
                    results.append(make_result(
                        source=self.name,
                        finding_type="threat_indicator",
                        value=f"VT:{target}:malicious={malicious}/suspicious={suspicious}",
                        target=target,
                        confidence=confidence,
                        evidence=f"VirusTotal multi-vendor analysis: {malicious} malicious, {suspicious} suspicious out of {total} engines",
                        title=f"Threat Intel: {target} (VT)",
                        description=(
                            f"VirusTotal analysis — Malicious: {malicious}, Suspicious: {suspicious}, "
                            f"Harmless: {harmless}. Reputation score: {reputation}."
                        ),
                        observation_type="observed",
                        category="threat_intel",
                        tags=f"virustotal,threat,{'malicious' if malicious > 0 else 'clean'}",
                        raw_data={
                            "stats": stats,
                            "reputation": reputation,
                            "total_engines": total,
                            "malicious": malicious,
                            "suspicious": suspicious,
                        },
                    ))

                    # Get communicating files/URLs if any threat found
                    if malicious > 0:
                        r2 = await client.get(
                            f"https://www.virustotal.com/api/v3/domains/{target}/urls?limit=5",
                            headers=headers,
                        )
                        if r2.status_code == 200:
                            for url_item in r2.json().get("data", [])[:5]:
                                url_attrs = url_item.get("attributes", {})
                                url_val = url_attrs.get("url", "")
                                url_stats = url_attrs.get("last_analysis_stats", {})
                                if url_val:
                                    results.append(make_result(
                                        source=self.name,
                                        finding_type="threat_indicator",
                                        value=f"malicious_url:{url_val[:80]}",
                                        target=target,
                                        confidence=0.85,
                                        evidence=f"VirusTotal reported malicious URL under {target}",
                                        title=f"Malicious URL: {url_val[:60]}",
                                        description=f"URL flagged by VirusTotal vendors. Stats: {url_stats}",
                                        observation_type="observed",
                                        category="threat_intel",
                                        tags="virustotal,threat,url,malicious",
                                        raw_data={"url": url_val, "stats": url_stats},
                                    ))
        except Exception as e:
            self._record_error(str(e))
        return results
