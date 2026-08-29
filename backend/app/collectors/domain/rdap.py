"""Domain providers — RDAP/WHOIS domain registration data (no API key)."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class RdapDomainCollector(BaseCollector):
    name = "rdap"
    display_name = "RDAP / WHOIS"
    description = "Domain registration metadata via RDAP protocol. Free, no API key required."
    provider_category = "domain"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=6.0) as client:
                r = await client.get(f"https://rdap.org/domain/{target}")
                if r.status_code == 200:
                    data = r.json()
                    handle = data.get("handle", "")
                    status = data.get("status", [])
                    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
                    registrar = ""
                    for entity in data.get("entities", []):
                        if "registrar" in entity.get("roles", []):
                            vcard = entity.get("vcardArray", [None, []])[1]
                            for field in vcard:
                                if field[0] == "fn":
                                    registrar = field[3]

                    results.append(make_result(
                        source=self.name,
                        finding_type="domain",
                        value=target,
                        target=target,
                        confidence=0.95,
                        evidence=f"RDAP registration record for {target} via rdap.org",
                        title=f"Domain Registration: {target}",
                        description=f"Domain registered. Handle: {handle}. Status: {', '.join(status)}. Registrar: {registrar}",
                        observation_type="observed",
                        category="infrastructure",
                        tags="domain,rdap,whois,registration",
                        raw_data={
                            "handle": handle,
                            "status": status,
                            "registrar": registrar,
                            "registration": events.get("registration"),
                            "expiration": events.get("expiration"),
                            "last_changed": events.get("last changed"),
                        },
                        first_seen=events.get("registration"),
                        last_seen=events.get("last changed"),
                    ))

                    # Name servers as subdomains
                    for ns in data.get("nameservers", []):
                        ns_name = ns.get("ldhName", "").lower().rstrip(".")
                        if ns_name:
                            results.append(make_result(
                                source=self.name,
                                finding_type="subdomain",
                                value=ns_name,
                                target=target,
                                confidence=0.88,
                                evidence=f"RDAP nameserver record for {target}",
                                title=f"Nameserver: {ns_name}",
                                description=f"Authoritative nameserver for {target}",
                                observation_type="observed",
                                category="infrastructure",
                                tags="nameserver,rdap,dns",
                                raw_data={"nameserver": ns_name},
                            ))
        except Exception as e:
            self._record_error(str(e))
        return results
