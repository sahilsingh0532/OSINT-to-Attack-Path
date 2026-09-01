"""IP providers — Shodan InternetDB (completely free, no API key required).

internetdb.shodan.io is a free, unauthenticated endpoint that returns:
- Open TCP ports
- Hostnames
- CPE software identifiers
- CVE IDs (known vulnerabilities)
- Tags (e.g. "self-signed", "cloud", "honeypot")
"""

import httpx
import asyncio
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class ShodanInternetDbCollector(BaseCollector):
    name = "shodan_internetdb"
    display_name = "Shodan InternetDB (Free)"
    description = (
        "Open ports, hostnames, CPEs, CVEs, and tags via Shodan's free InternetDB API. "
        "No API key required."
    )
    provider_category = "ip"
    requires_key = False

    async def _resolve_ips(self, target: str) -> List[str]:
        """Resolve domain to IPv4 addresses using DNS."""
        try:
            import socket
            infos = await asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.getaddrinfo(target, None, socket.AF_INET)
            )
            return list({i[4][0] for i in infos})[:3]
        except Exception:
            return []

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        ips = await self._resolve_ips(target)

        for ip in ips:
            try:
                self._record_query()
                async with httpx.AsyncClient(timeout=8.0) as client:
                    r = await client.get(f"https://internetdb.shodan.io/{ip}")

                if r.status_code == 200:
                    data = r.json()
                    ports = data.get("ports", [])
                    hostnames = data.get("hostnames", [])
                    cpes = data.get("cpes", [])
                    tags = data.get("tags", [])
                    vulns = data.get("vulns", [])

                    if ports or vulns:
                        results.append(make_result(
                            source=self.name,
                            finding_type="ip",
                            value=ip,
                            target=target,
                            confidence=0.92,
                            evidence=(
                                f"Shodan InternetDB: {len(ports)} open ports, "
                                f"{len(vulns)} CVEs, tags: {', '.join(tags) or 'none'}"
                            ),
                            title=f"IP Intelligence: {ip}",
                            description=(
                                f"IP {ip} has {len(ports)} open ports: {ports[:10]}. "
                                f"Hostnames: {hostnames[:3]}. "
                                f"Known CVEs: {len(vulns)}. "
                                f"Tags: {tags}."
                            ),
                            observation_type="observed",
                            category="infrastructure",
                            tags=f"ip,shodan_free,ports,{','.join(tags[:3])}",
                            raw_data={
                                "ip": ip,
                                "ports": ports,
                                "hostnames": hostnames,
                                "cpes": cpes,
                                "tags": tags,
                                "vulns": vulns,
                            },
                        ))

                    # Each open port = an exposure finding
                    for port in ports[:8]:
                        results.append(make_result(
                            source=self.name,
                            finding_type="exposure",
                            value=f"{ip}:{port}",
                            target=target,
                            confidence=0.90,
                            evidence=f"Shodan InternetDB passive scan — port {port}/tcp confirmed open",
                            title=f"Open Port {port}/tcp on {ip}",
                            description=(
                                f"Port {port}/tcp is exposed on {ip}. "
                                f"Discovered passively via Shodan InternetDB."
                            ),
                            observation_type="observed",
                            category="exposure",
                            tags=f"port,exposure,{port}",
                            raw_data={"ip": ip, "port": port},
                        ))

                    # Each CVE = its own threat indicator
                    for cve in vulns[:5]:
                        results.append(make_result(
                            source=self.name,
                            finding_type="threat_indicator",
                            value=cve,
                            target=target,
                            confidence=0.88,
                            evidence=f"Shodan InternetDB: {cve} found on {ip}",
                            title=f"CVE: {cve} on {ip}",
                            description=(
                                f"Known vulnerability {cve} identified on {ip} "
                                f"via Shodan InternetDB. Immediate patching recommended."
                            ),
                            observation_type="observed",
                            category="threat_intel",
                            tags=f"cve,vulnerability,shodan_free",
                            raw_data={"ip": ip, "cve": cve},
                        ))

            except Exception as e:
                self._record_error(str(e))

        return results
