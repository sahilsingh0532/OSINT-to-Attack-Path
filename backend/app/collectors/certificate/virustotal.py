"""Certificate providers — VirusTotal certificate intelligence."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class VirusTotalCertCollector(BaseCollector):
    name = "virustotal"
    display_name = "VirusTotal (Certificate Intel)"
    description = "Certificate data from VirusTotal domain analysis. Requires API key."
    provider_category = "certificate"
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
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}/historical_ssl_certificates?limit=10",
                    headers=headers,
                )
                if r.status_code == 200:
                    items = r.json().get("data", [])
                    for item in items:
                        attrs = item.get("attributes", {})
                        subject = attrs.get("subject", {})
                        issuer = attrs.get("issuer", {})
                        validity = attrs.get("validity", {})
                        san = attrs.get("extensions", {}).get("subject_alternative_name", [])
                        cert_id = item.get("id", "")

                        cn = subject.get("CN", target)
                        issuer_cn = issuer.get("CN", "Unknown CA")

                        results.append(make_result(
                            source=self.name,
                            finding_type="certificate",
                            value=f"cert:vt:{cert_id[:16]}:{cn}",
                            target=target,
                            confidence=0.92,
                            evidence=f"VirusTotal historical SSL certificate record for {target}",
                            title=f"TLS Cert (VT): {cn}",
                            description=f"Certificate issued by {issuer_cn} for {cn}. SANs: {len(san)} domain(s).",
                            observation_type="observed",
                            category="security",
                            tags="certificate,tls,ssl,virustotal",
                            raw_data={
                                "cert_id": cert_id[:32],
                                "subject_cn": cn,
                                "issuer_cn": issuer_cn,
                                "san": san[:20],
                                "not_before": validity.get("not_before"),
                                "not_after": validity.get("not_after"),
                                "serial": attrs.get("serial_number", ""),
                                "thumbprint": attrs.get("thumbprint", ""),
                            },
                            first_seen=validity.get("not_before"),
                            last_seen=validity.get("not_after"),
                        ))
        except Exception as e:
            self._record_error(str(e))
        return results
