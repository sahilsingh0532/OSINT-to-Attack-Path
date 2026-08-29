"""Certificate providers — crt.sh Certificate Transparency records."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class CrtShCertCollector(BaseCollector):
    name = "crt.sh"
    display_name = "crt.sh (Certificate Records)"
    description = "SSL/TLS certificate details from Certificate Transparency logs. Free, no key."
    provider_category = "certificate"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        seen_ids = set()
        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"https://crt.sh/?q={target}&output=json",
                    headers={"Accept": "application/json"},
                )
                if r.status_code == 200:
                    entries = r.json()
                    for entry in entries[:30]:
                        cert_id = str(entry.get("id", ""))
                        if cert_id in seen_ids:
                            continue
                        seen_ids.add(cert_id)
                        issuer = entry.get("issuer_name", "Unknown Issuer")
                        name_val = entry.get("name_value", target)
                        san_list = [s.strip() for s in name_val.split("\n") if s.strip()]
                        logged_at = entry.get("entry_timestamp", "")

                        results.append(make_result(
                            source=self.name,
                            finding_type="certificate",
                            value=f"cert:{cert_id}:{target}",
                            target=target,
                            confidence=0.95,
                            evidence=f"Certificate Transparency log — crt.sh record #{cert_id}",
                            title=f"TLS Cert #{cert_id[:8]}: {san_list[0] if san_list else target}",
                            description=f"Certificate issued by {issuer[:80]} covering {len(san_list)} domain(s).",
                            observation_type="observed",
                            category="security",
                            tags="certificate,tls,ssl,ct",
                            raw_data={
                                "cert_id": cert_id,
                                "issuer": issuer,
                                "san": san_list,
                                "logged_at": logged_at,
                                "not_before": entry.get("not_before"),
                                "not_after": entry.get("not_after"),
                                "serial": entry.get("serial_number", ""),
                            },
                            first_seen=entry.get("not_before"),
                            last_seen=entry.get("not_after"),
                        ))
        except Exception as e:
            self._record_error(str(e))
        return results
