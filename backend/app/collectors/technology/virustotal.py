"""Technology providers — VirusTotal web categories and tech data."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class VirusTotalTechCollector(BaseCollector):
    name = "virustotal"
    display_name = "VirusTotal (Technology Categories)"
    description = "Web technology categories from VirusTotal domain analysis. Requires API key."
    provider_category = "technology"
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
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}",
                    headers=headers,
                )
                if r.status_code == 200:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    categories = attrs.get("categories", {})
                    tags = attrs.get("tags", [])

                    for vendor, category in categories.items():
                        results.append(make_result(
                            source=self.name,
                            finding_type="technology",
                            value=f"Category: {category}",
                            target=target,
                            confidence=0.80,
                            evidence=f"VirusTotal category classification by {vendor}",
                            title=f"Web Category: {category}",
                            description=f"Domain {target} categorized as '{category}' by {vendor}",
                            observation_type="observed",
                            category="technology",
                            tags=f"category,virustotal,{category.lower().replace(' ', '_')}",
                            raw_data={"vendor": vendor, "category": category},
                        ))

                    for tag in tags:
                        results.append(make_result(
                            source=self.name,
                            finding_type="technology",
                            value=f"VT Tag: {tag}",
                            target=target,
                            confidence=0.78,
                            evidence=f"VirusTotal domain tag for {target}",
                            title=f"VT Tag: {tag}",
                            description=f"VirusTotal tagged domain {target} as '{tag}'",
                            observation_type="inferred",
                            category="technology",
                            tags=f"tag,virustotal,{tag.lower()}",
                            raw_data={"tag": tag},
                        ))
                    self._record_success(len(results))
                elif r.status_code == 401 or r.status_code == 403:
                    self._record_error("VirusTotal API Key Invalid or Unauthorized (401/403)", status_code=r.status_code)
                elif r.status_code == 429:
                    self._record_error("VirusTotal API Rate Limit Exceeded (429)", status_code=429)
                elif r.status_code != 404:
                    self._record_error(f"VirusTotal categories returned HTTP {r.status_code}", status_code=r.status_code)
        except httpx.TimeoutException:
            self._record_error("VirusTotal categories query timed out (10s limit)")
        except Exception as e:
            self._record_error(str(e))
        return results
