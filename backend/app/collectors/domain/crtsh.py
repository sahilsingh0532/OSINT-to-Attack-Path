"""Domain providers — crt.sh Certificate Transparency subdomain enumeration."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result, now_iso


class CrtShDomainCollector(BaseCollector):
    name = "crt.sh"
    display_name = "crt.sh (Certificate Transparency)"
    description = "Subdomain discovery via Certificate Transparency logs. Free, no API key required."
    provider_category = "domain"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        found = set()
        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"https://crt.sh/?q=%.{target}&output=json",
                    headers={"Accept": "application/json"},
                )
                if r.status_code == 200:
                    entries = r.json()
                    for entry in entries[:200]:
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            if name.startswith("*."):
                                name = name[2:]
                            if name and target in name and name not in found:
                                found.add(name)
                                ftype = "domain" if name == target else "subdomain"
                                results.append(make_result(
                                    source=self.name,
                                    finding_type=ftype,
                                    value=name,
                                    target=target,
                                    confidence=0.92,
                                    evidence=f"Certificate Transparency log entry in crt.sh for {target}",
                                    title=f"{'Domain' if ftype == 'domain' else 'Subdomain'}: {name}",
                                    description=f"Discovered via Certificate Transparency logs. Cert ID: {entry.get('id')}",
                                    observation_type="observed",
                                    category="infrastructure",
                                    tags="subdomain,ct,crtsh",
                                    raw_data={
                                        "cert_id": entry.get("id"),
                                        "issuer": entry.get("issuer_name", "")[:80],
                                        "logged_at": entry.get("entry_timestamp"),
                                        "not_before": entry.get("not_before"),
                                        "not_after": entry.get("not_after"),
                                    },
                                    first_seen=entry.get("not_before"),
                                    last_seen=entry.get("not_after"),
                                ))
        except Exception as e:
            self._record_error(str(e))
        return results
