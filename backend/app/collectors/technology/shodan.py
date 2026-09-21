"""Technology providers — Shodan service/tech banners."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings
import dns.asyncresolver


class ShodanTechCollector(BaseCollector):
    name = "shodan"
    display_name = "Shodan (Technology Banners)"
    description = "Technology and service banners from Shodan host data. Requires API key."
    provider_category = "technology"
    requires_key = True

    def _has_api_key(self) -> bool:
        return bool(settings.shodan_api_key)

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
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                for ip in resolved_ips[:2]:
                    r = await client.get(
                        f"https://api.shodan.io/shodan/host/{ip}?key={settings.shodan_api_key}"
                    )
                    if r.status_code == 200:
                        data = r.json()
                        for service in data.get("data", [])[:10]:
                            product = service.get("product", "")
                            version = service.get("version", "")
                            transport = service.get("transport", "tcp")
                            port = service.get("port", "")
                            if product:
                                tech_val = f"{product} {version}".strip()
                                results.append(make_result(
                                    source=self.name,
                                    finding_type="technology",
                                    value=tech_val,
                                    target=target,
                                    confidence=0.88,
                                    evidence=f"Shodan service banner on {ip}:{port}/{transport}",
                                    title=f"Tech: {tech_val} (:{port})",
                                    description=f"Shodan observed {tech_val} on {ip}:{port}/{transport}",
                                    observation_type="observed",
                                    category="technology",
                                    tags=f"technology,shodan,{product.lower().replace(' ', '_')}",
                                    raw_data={
                                        "product": product,
                                        "version": version,
                                        "port": port,
                                        "transport": transport,
                                        "ip": ip,
                                    },
                                ))
                    elif r.status_code == 401 or r.status_code == 403:
                        self._record_error("Shodan API Key Invalid or Unauthorized (401/403)", status_code=r.status_code)
                        return results
                    elif r.status_code == 429:
                        self._record_error("Shodan API Rate Limit Exceeded (429)", status_code=429)
                        return results
                    elif r.status_code != 404:
                        self._record_error(f"Shodan tech query returned HTTP {r.status_code}", status_code=r.status_code)
                self._record_success(len(results))
        except httpx.TimeoutException:
            self._record_error("Shodan tech query timed out (10s limit)")
        except Exception as e:
            self._record_error(str(e))
        return results
