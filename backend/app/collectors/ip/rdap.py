"""IP providers — RDAP IP lookup (free, no key)."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
import dns.asyncresolver


class RdapIpCollector(BaseCollector):
    name = "rdap"
    display_name = "RDAP (IP Registration)"
    description = "IP registration and ASN data via RDAP protocol. Free, no API key."
    provider_category = "ip"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
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
            async with httpx.AsyncClient(timeout=6.0) as client:
                for ip in resolved_ips[:2]:
                    r = await client.get(f"https://rdap.org/ip/{ip}")
                    if r.status_code == 200:
                        data = r.json()
                        name = data.get("name", "")
                        handle = data.get("handle", "")
                        country = data.get("country", "")
                        start_addr = data.get("startAddress", "")
                        end_addr = data.get("endAddress", "")

                        results.append(make_result(
                            source=self.name,
                            finding_type="ip",
                            value=ip,
                            target=target,
                            confidence=0.90,
                            evidence=f"RDAP IP registration record for {ip}",
                            title=f"IP Block: {ip} ({name})",
                            description=f"IP {ip} in block {start_addr}–{end_addr}. Handle: {handle}. Country: {country}",
                            observation_type="observed",
                            category="infrastructure",
                            tags="ip,rdap,registration",
                            raw_data={
                                "ip": ip,
                                "name": name,
                                "handle": handle,
                                "country": country,
                                "start": start_addr,
                                "end": end_addr,
                            },
                        ))
        except Exception as e:
            self._record_error(str(e))
        return results
