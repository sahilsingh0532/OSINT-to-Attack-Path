"""Email providers — XposedOrNot (XON) breach intelligence (Free, no key required)."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class XposedOrNotEmailCollector(BaseCollector):
    name = "xposedornot"
    display_name = "XposedOrNot (Breach Intelligence)"
    description = "Checks email addresses against the XposedOrNot breach database for data leaks, compromised credentials, and exposure metrics."
    provider_category = "email"
    requires_key = False  # Free keyless API, optional API key for higher rate limits

    def _has_api_key(self) -> bool:
        return bool(settings.xposedornot_api_key)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        target: email address (e.g. 'user@example.com') or domain name.
        Queries XposedOrNot for data breaches associated with the target email.
        """
        results = []
        # Support email target or domain target test fallback
        query_email = target if "@" in target else f"test@{target}"

        headers = {
            "User-Agent": "OSINT-to-Attack-Path/2.0",
        }
        if settings.xposedornot_api_key:
            headers["x-api-key"] = settings.xposedornot_api_key

        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
                # Primary query: detailed breach analytics
                r = await client.get(
                    f"https://api.xposedornot.com/v1/breach-analytics?email={query_email}",
                    headers=headers,
                )

                if r.status_code == 200:
                    data = r.json()
                    exposed = data.get("ExposedBreaches") or {}
                    breaches_details = exposed.get("breaches_details") if isinstance(exposed, dict) else []
                    summary = data.get("BreachesSummary") or {}
                    site_str = summary.get("site", "") if isinstance(summary, dict) else ""

                    if breaches_details:
                        breach_names = [b.get("breach", "Unknown") for b in breaches_details]
                        breach_list_str = ", ".join(breach_names[:6])
                        all_xposed_fields = set()
                        for b in breaches_details:
                            fields = b.get("xposed_data", "")
                            if fields:
                                for f in fields.split(";"):
                                    if f.strip():
                                        all_xposed_fields.add(f.strip())

                        results.append(make_result(
                            source=self.name,
                            finding_type="email",
                            value=target,
                            target=target,
                            confidence=0.95,
                            evidence=f"XposedOrNot breach database: {len(breaches_details)} breach(es) — {breach_list_str}",
                            title=f"Breached Account: {target}",
                            description=(
                                f"Email address {target} was detected in {len(breaches_details)} data breach(es): "
                                f"{breach_list_str}. Exposed data types: {', '.join(sorted(all_xposed_fields)[:8]) or 'Credentials'}."
                            ),
                            observation_type="observed",
                            category="email",
                            tags=f"email,xposedornot,breach,{'high_risk' if len(breaches_details) > 2 else 'breach'}",
                            raw_data={
                                "email": target,
                                "breached": True,
                                "breach_count": len(breaches_details),
                                "breaches": breaches_details,
                                "exposed_data_fields": list(all_xposed_fields),
                            },
                        ))
                        self._record_success(len(results))

                    elif site_str:
                        # Fallback list of breach names from summary
                        site_list = [s.strip() for s in site_str.split(";") if s.strip()]
                        results.append(make_result(
                            source=self.name,
                            finding_type="email",
                            value=target,
                            target=target,
                            confidence=0.90,
                            evidence=f"XposedOrNot breach catalog: {len(site_list)} breach exposure(s)",
                            title=f"Breached Account: {target}",
                            description=f"Email address {target} was found in {len(site_list)} breach(es): {', '.join(site_list[:5])}.",
                            observation_type="observed",
                            category="email",
                            tags="email,xposedornot,breach",
                            raw_data={
                                "email": target,
                                "breached": True,
                                "breach_count": len(site_list),
                                "breaches": [{"breach": name} for name in site_list],
                            },
                        ))
                        self._record_success(len(results))

                    else:
                        # Clean finding — 0 breaches
                        results.append(make_result(
                            source=self.name,
                            finding_type="email",
                            value=f"{target} (clean / no breaches)",
                            target=target,
                            confidence=0.90,
                            evidence="XposedOrNot breach check returned no exposures",
                            title=f"XposedOrNot: Clean Status for {target}",
                            description=f"Email {target} was not found in any indexed XposedOrNot breach databases.",
                            observation_type="observed",
                            category="email",
                            tags="email,xposedornot,clean",
                            raw_data={"email": target, "breached": False, "breach_count": 0},
                        ))
                        self._record_success(len(results))

                elif r.status_code == 404:
                    # Clean finding
                    results.append(make_result(
                        source=self.name,
                        finding_type="email",
                        value=f"{target} (clean / no breaches)",
                        target=target,
                        confidence=0.90,
                        evidence="XposedOrNot returned no breach records (404)",
                        title=f"XposedOrNot: No Breaches for {target}",
                        description=f"Email {target} was not detected in any known XposedOrNot data breaches.",
                        observation_type="observed",
                        category="email",
                        tags="email,xposedornot,clean",
                        raw_data={"email": target, "breached": False, "breach_count": 0},
                    ))
                    self._record_success(len(results))

                elif r.status_code == 429:
                    self._record_error("XposedOrNot API rate limit exceeded (429)", status_code=429)
                else:
                    self._record_error(f"XposedOrNot returned HTTP {r.status_code}", status_code=r.status_code)

        except httpx.TimeoutException:
            self._record_error("XposedOrNot query timed out (12s limit)")
        except Exception as e:
            self._record_error(str(e))

        return results
