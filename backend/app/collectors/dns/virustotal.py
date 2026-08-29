"""DNS providers — VirusTotal passive DNS resolution records."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class VirusTotalDnsCollector(BaseCollector):
    name = "virustotal"
    display_name = "VirusTotal (DNS Records)"
    description = "Passive DNS resolutions from VirusTotal. Requires API key."
    provider_category = "dns"
    requires_key = True

    def _has_api_key(self) -> bool:
        return bool(settings.virustotal_api_key)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not self._has_api_key():
            return []
        results = []
        seen = set()
        try:
            self._record_query()
            headers = {"x-apikey": settings.virustotal_api_key}
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}/resolutions?limit=20",
                    headers=headers,
                )
                if r.status_code == 200:
                    items = r.json().get("data", [])
                    for item in items:
                        attrs = item.get("attributes", {})
                        ip = attrs.get("ip_address", "")
                        date = attrs.get("date", "")
                        resolver = attrs.get("resolver", "")
                        if ip and ip not in seen:
                            seen.add(ip)
                            results.append(make_result(
                                source=self.name, finding_type="ip", value=ip,
                                target=target, confidence=0.88,
                                evidence=f"VirusTotal passive DNS resolution for {target}",
                                title=f"Passive DNS: {target} → {ip}",
                                description=f"VirusTotal recorded {target} resolving to {ip} (resolver: {resolver})",
                                observation_type="observed", category="infrastructure",
                                tags="ip,dns,passive_dns,virustotal",
                                raw_data={"ip": ip, "date": date, "resolver": resolver},
                                last_seen=str(date),
                            ))
        except Exception as e:
            self._record_error(str(e))
        return results
