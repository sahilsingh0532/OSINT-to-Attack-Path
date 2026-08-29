"""Email providers — Have I Been Pwned (HIBP) breach lookup (API key required)."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class HibpEmailCollector(BaseCollector):
    name = "hibp"
    display_name = "Have I Been Pwned (HIBP)"
    description = "Checks domain email addresses against the HIBP breach database. Paid API key required."
    provider_category = "email"
    requires_key = True

    def _has_api_key(self) -> bool:
        return bool(settings.hibp_api_key)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        target: domain name (e.g. 'example.com').
        Queries HIBP for all email breaches associated with the domain.
        """
        if not settings.hibp_api_key:
            return []

        results = []
        headers = {
            "hibp-api-key": settings.hibp_api_key,
            "User-Agent": "OSINT-to-Attack-Path/2.0",
        }

        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=12.0) as client:
                # Query HIBP for all breached accounts on the domain
                r = await client.get(
                    f"https://haveibeenpwned.com/api/v3/breacheddomain/{target}",
                    headers=headers,
                )

                if r.status_code == 200:
                    # Returns a dict of { "username": ["BreachName1", "BreachName2"] }
                    breach_map = r.json()
                    for username, breaches in list(breach_map.items())[:20]:
                        email = f"{username}@{target}"
                        breach_list = ", ".join(breaches[:5])
                        results.append(make_result(
                            source=self.name,
                            finding_type="email",
                            value=email,
                            target=target,
                            confidence=0.95,
                            evidence=f"HIBP breach database: {len(breaches)} breach(es) — {breach_list}",
                            title=f"Breached Account: {email}",
                            description=(
                                f"Email address {email} was found in {len(breaches)} known data breach(es): "
                                f"{breach_list}. Immediate credential rotation recommended."
                            ),
                            observation_type="observed",
                            category="email",
                            tags=f"email,hibp,breach,{'high_risk' if len(breaches) > 2 else 'breach'}",
                            raw_data={
                                "email": email,
                                "username": username,
                                "breach_count": len(breaches),
                                "breaches": breaches,
                            },
                        ))

                elif r.status_code == 404:
                    # Domain not in any breach — still report as a clean finding
                    results.append(make_result(
                        source=self.name,
                        finding_type="email",
                        value=f"@{target} (no breaches found)",
                        target=target,
                        confidence=0.90,
                        evidence="HIBP domain breach search returned no results",
                        title=f"HIBP: No Breaches Found for @{target}",
                        description=f"Domain {target} was not found in any HIBP breach database records.",
                        observation_type="observed",
                        category="email",
                        tags="email,hibp,no_breach",
                        raw_data={"domain": target, "breached": False},
                    ))

        except Exception as e:
            self._record_error(str(e))

        return results
