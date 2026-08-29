"""IP providers — Shodan host intelligence."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result
from app.config import settings


class ShodanIpCollector(BaseCollector):
    name = "shodan"
    display_name = "Shodan (Host Intelligence)"
    description = "IP/ASN host information from Shodan. Requires API key."
    provider_category = "ip"
    requires_key = True

    def _has_api_key(self) -> bool:
        return bool(settings.shodan_api_key)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not self._has_api_key():
            return []
        results = []
        import dns.asyncresolver
        resolved_ips = []
        try:
            resolver = dns.asyncresolver.Resolver()
            a = await resolver.resolve(target, 'A')
            resolved_ips = [str(r) for r in a]
        except Exception:
            pass

        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=10.0) as client:
                for ip in resolved_ips[:3]:
                    r = await client.get(
                        f"https://api.shodan.io/shodan/host/{ip}?key={settings.shodan_api_key}"
                    )
                    if r.status_code == 200:
                        data = r.json()
                        org = data.get("org", "Unknown Org")
                        asn = data.get("asn", "")
                        country = data.get("country_name", "")
                        isp = data.get("isp", "")
                        ports = data.get("ports", [])
                        hostnames = data.get("hostnames", [])
                        os_info = data.get("os", "")

                        results.append(make_result(
                            source=self.name,
                            finding_type="ip",
                            value=ip,
                            target=target,
                            confidence=0.95,
                            evidence=f"Shodan host lookup for IP {ip} associated with {target}",
                            title=f"IP: {ip} ({org})",
                            description=f"Host {ip} in {country}. ASN: {asn}. ISP: {isp}. Observed ports: {ports[:8]}",
                            observation_type="observed",
                            category="infrastructure",
                            tags="ip,shodan,asn,host",
                            raw_data={
                                "ip": ip,
                                "org": org,
                                "asn": asn,
                                "isp": isp,
                                "country": country,
                                "ports": ports[:15],
                                "hostnames": hostnames[:10],
                                "os": os_info,
                                "tags": data.get("tags", []),
                            },
                        ))

                        if asn:
                            results.append(make_result(
                                source=self.name,
                                finding_type="asn",
                                value=f"{asn} ({org})",
                                target=target,
                                confidence=0.93,
                                evidence=f"Shodan ASN data for {ip}",
                                title=f"ASN: {asn}",
                                description=f"IP {ip} belongs to {org} ({asn}) in {country}",
                                observation_type="observed",
                                category="infrastructure",
                                tags="asn,shodan",
                                raw_data={"asn": asn, "org": org, "ip": ip},
                            ))

                        for port in ports[:10]:
                            results.append(make_result(
                                source=self.name,
                                finding_type="exposure",
                                value=f"{ip}:{port}",
                                target=target,
                                confidence=0.90,
                                evidence=f"Shodan observed open port {port}/tcp on {ip}",
                                title=f"Open Port: {port}/tcp on {ip}",
                                description=f"Shodan passive scan observed port {port} open on {ip}.",
                                observation_type="observed",
                                category="exposure",
                                tags=f"port,shodan,{port}",
                                raw_data={"ip": ip, "port": port},
                            ))
        except Exception as e:
            self._record_error(str(e))
        return results
