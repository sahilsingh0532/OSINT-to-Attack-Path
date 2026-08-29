"""DNS providers — AlienVault OTX passive DNS (free, no key)."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class AlienVaultDnsCollector(BaseCollector):
    name = "alienvault_otx"
    display_name = "AlienVault OTX (Passive DNS)"
    description = "Passive DNS records from AlienVault OTX public API. Free, no key."
    provider_category = "dns"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        seen = set()
        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
                )
                if r.status_code == 200:
                    data = r.json()
                    for record in data.get("passive_dns", [])[:30]:
                        hostname = record.get("hostname", "").lower()
                        address = record.get("address", "")
                        record_type = record.get("record_type", "")
                        first = record.get("first", "")
                        last = record.get("last", "")

                        if hostname and hostname not in seen:
                            seen.add(hostname)
                            ftype = "subdomain" if target in hostname and hostname != target else "ip"
                            if address and record_type == "A":
                                ftype = "ip"
                                val = address
                            else:
                                val = hostname

                            if val not in seen:
                                seen.add(val)
                                results.append(make_result(
                                    source=self.name, finding_type=ftype, value=val,
                                    target=target, confidence=0.85,
                                    evidence=f"AlienVault OTX passive DNS for {target}",
                                    title=f"Passive DNS: {val}",
                                    description=f"Passive DNS record: {hostname} → {address} ({record_type})",
                                    observation_type="observed", category="infrastructure",
                                    tags=f"passive_dns,alienvault,{record_type.lower()}",
                                    raw_data={"hostname": hostname, "address": address, "type": record_type},
                                    first_seen=first, last_seen=last,
                                ))
        except Exception as e:
            self._record_error(str(e))
        return results
