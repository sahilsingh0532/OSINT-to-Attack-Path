"""Domain providers — VirusTotal passive DNS subdomains."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class VirusTotalDomainCollector(BaseCollector):
    name = "virustotal"
    display_name = "VirusTotal (Passive DNS)"
    description = "Subdomain discovery via VirusTotal passive DNS API. Requires API key."
    provider_category = "domain"
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
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
                # Get subdomains
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}/subdomains?limit=40",
                    headers=headers,
                )
                if r.status_code == 200:
                    items = r.json().get("data", [])
                    for item in items:
                        sub = item.get("id", "")
                        if sub and target in sub:
                            attrs = item.get("attributes", {})
                            results.append(make_result(
                                source=self.name,
                                finding_type="subdomain",
                                value=sub,
                                target=target,
                                confidence=0.90,
                                evidence=f"VirusTotal passive DNS records for {target}",
                                title=f"Subdomain: {sub}",
                                description=f"Subdomain {sub} found in VirusTotal passive DNS database.",
                                observation_type="observed",
                                category="infrastructure",
                                tags="subdomain,virustotal,passive_dns",
                                raw_data={
                                    "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                                    "reputation": attrs.get("reputation", 0),
                                    "last_seen": attrs.get("last_modification_date"),
                                },
                                last_seen=str(attrs.get("last_modification_date", "")),
                            ))
                elif r.status_code == 401 or r.status_code == 403:
                    self._record_error("VirusTotal API Key Invalid or Unauthorized (401/403)", status_code=r.status_code)
                    return []
                elif r.status_code == 429:
                    self._record_error("VirusTotal API Rate Limit Exceeded (429)", status_code=429)
                    return []
                elif r.status_code != 404:
                    self._record_error(f"VirusTotal subdomain query returned HTTP {r.status_code}", status_code=r.status_code)

                # Also get domain info (categories, reputation)
                r2 = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}",
                    headers=headers,
                )
                if r2.status_code == 200:
                    attrs = r2.json().get("data", {}).get("attributes", {})
                    results.append(make_result(
                        source=self.name,
                        finding_type="domain",
                        value=target,
                        target=target,
                        confidence=0.95,
                        evidence="VirusTotal domain analysis report",
                        title=f"Domain: {target}",
                        description=f"Domain analyzed by VirusTotal. Reputation: {attrs.get('reputation', 0)}",
                        observation_type="observed",
                        category="infrastructure",
                        tags="domain,virustotal",
                        raw_data={
                            "reputation": attrs.get("reputation", 0),
                            "categories": attrs.get("categories", {}),
                            "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                            "registrar": attrs.get("registrar", ""),
                            "creation_date": attrs.get("creation_date"),
                        },
                    ))
                self._record_success(len(results))
        except httpx.TimeoutException:
            self._record_error("VirusTotal request timed out (12s limit)")
        except Exception as e:
            self._record_error(str(e))
        return results
