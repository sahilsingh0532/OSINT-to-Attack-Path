"""Email providers — Hunter.io domain email enumeration."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class HunterEmailCollector(BaseCollector):
    name = "hunter.io"
    display_name = "Hunter.io (Email Discovery)"
    description = "Email address discovery via Hunter.io domain search API. Requires API key (free tier: 25/month)."
    provider_category = "email"
    requires_key = True

    def _has_api_key(self) -> bool:
        return bool(settings.hunter_api_key)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not self._has_api_key():
            return []
        results = []
        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"https://api.hunter.io/v2/domain-search?domain={target}&api_key={settings.hunter_api_key}&limit=20"
                )
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    org = data.get("organization", target)
                    emails = data.get("emails", [])
                    pattern = data.get("pattern", "")

                    for em in emails[:20]:
                        email_addr = em.get("value", "")
                        em_type = em.get("type", "")
                        confidence = em.get("confidence", 50) / 100.0
                        first_name = em.get("first_name", "")
                        last_name = em.get("last_name", "")
                        position = em.get("position", "")
                        sources_list = [s.get("uri", "") for s in em.get("sources", [])[:3]]

                        results.append(make_result(
                            source=self.name,
                            finding_type="email",
                            value=email_addr,
                            target=target,
                            confidence=min(confidence + 0.1, 1.0),
                            evidence=f"Hunter.io domain search for {target}",
                            title=f"Email: {email_addr}",
                            description=f"Public email for {first_name} {last_name} ({position}) at {org}. Type: {em_type}",
                            observation_type="observed",
                            category="email",
                            tags=f"email,hunter,{em_type}",
                            raw_data={
                                "email": email_addr,
                                "type": em_type,
                                "first_name": first_name,
                                "last_name": last_name,
                                "position": position,
                                "organization": org,
                                "sources": sources_list,
                                "pattern": pattern,
                            },
                        ))
        except Exception as e:
            self._record_error(str(e))
        return results
