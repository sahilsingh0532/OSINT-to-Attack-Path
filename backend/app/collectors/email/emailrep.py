"""Email providers — EmailRep.io email reputation (safe metadata only)."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class EmailRepCollector(BaseCollector):
    name = "emailrep.io"
    display_name = "EmailRep.io (Email Reputation)"
    description = "Email reputation and metadata via EmailRep.io. Free tier: 100 req/day."
    provider_category = "email"
    requires_key = False  # Key optional for higher quota

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        For domain-level recon, query EmailRep for any discovered emails.
        For direct email queries, call with target = email address.
        """
        results = []
        # Only run if target looks like an email
        if "@" not in target and "." in target:
            # Domain mode — we can't enumerate emails without Hunter, skip
            return []

        try:
            self._record_query()
            headers = {"Key": settings.emailrep_api_key} if settings.emailrep_api_key else {}
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.get(
                    f"https://emailrep.io/{target}",
                    headers={**headers, "User-Agent": "OSINT-Academic-Research/1.0"},
                )
                if r.status_code == 200:
                    data = r.json()
                    reputation = data.get("reputation", "none")
                    suspicious = data.get("suspicious", False)
                    references = data.get("references", 0)
                    details = data.get("details", {})
                    profiles = details.get("profiles", [])
                    deliverable = details.get("deliverable", None)
                    days_since_seen = details.get("days_since_domain_creation", None)

                    results.append(make_result(
                        source=self.name,
                        finding_type="email",
                        value=target,
                        target=target,
                        confidence=0.85,
                        evidence=f"EmailRep.io analysis for {target}",
                        title=f"Email Reputation: {target}",
                        description=(
                            f"Email reputation: {reputation}. Suspicious: {suspicious}. "
                            f"Public references: {references}. Profiles: {', '.join(profiles[:5])}"
                        ),
                        observation_type="observed",
                        category="email",
                        tags=f"email,reputation,emailrep,{'suspicious' if suspicious else 'clean'}",
                        raw_data={
                            "email": target,
                            "reputation": reputation,
                            "suspicious": suspicious,
                            "references": references,
                            "profiles": profiles,
                            "deliverable": deliverable,
                            "days_since_domain_creation": days_since_seen,
                            # Never include passwords or private data
                        },
                    ))
        except Exception as e:
            self._record_error(str(e))
        return results
