"""Threat Intel providers — Ahmia dark web index search (safe, public references only)."""

import httpx
import re
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class AhmiaThreatCollector(BaseCollector):
    name = "ahmia"
    display_name = "Ahmia (Dark Web Index)"
    description = (
        "Safe publicly-indexed dark web reference search via Ahmia. "
        "Only returns count of mentions — no illegal content, no credentials."
    )
    provider_category = "threat_intel"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.get(
                    f"https://ahmia.fi/search/?q={target}",
                    headers={"User-Agent": "Mozilla/5.0 (OSINT Academic Research)"},
                )
                if r.status_code == 200:
                    count = len(re.findall(r'<li class="result">', r.text))
                    if count > 0:
                        results.append(make_result(
                            source=self.name,
                            finding_type="darkweb_reference",
                            value=f"ahmia:{target}:count={count}",
                            target=target,
                            confidence=0.72,
                            evidence=f"Ahmia search index returned {count} results for {target}",
                            title=f"Dark Web Mentions: {count} results",
                            description=(
                                f"Domain {target} was found in {count} publicly indexed dark web pages via Ahmia. "
                                "This is a passive count only — no illegal content was accessed or stored."
                            ),
                            observation_type="inferred",
                            category="darkweb",
                            tags="ahmia,darkweb,tor,reference",
                            raw_data={"match_count": count, "query": target},
                        ))
        except Exception as e:
            self._record_error(str(e))
        return results
