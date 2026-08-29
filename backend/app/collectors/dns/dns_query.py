"""DNS providers — direct DNS query (A, MX, NS, TXT, AAAA). No API key."""

import dns.asyncresolver
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class DnsQueryCollector(BaseCollector):
    name = "dns_query"
    display_name = "DNS Query (A/MX/NS/TXT)"
    description = "Direct DNS record lookups via system resolver. No API key required."
    provider_category = "dns"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        try:
            self._record_query()
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 5.0

            # A Records
            try:
                a_records = await resolver.resolve(target, 'A')
                for rdata in a_records:
                    ip = str(rdata)
                    results.append(make_result(
                        source=self.name, finding_type="ip", value=ip, target=target,
                        confidence=0.97, evidence=f"DNS A record for {target}",
                        title=f"A Record: {ip}", description=f"{target} resolves to {ip}",
                        observation_type="observed", category="infrastructure", tags="ip,dns,a_record",
                        raw_data={"record_type": "A", "ip": ip},
                    ))
            except Exception:
                pass

            # AAAA Records
            try:
                aaaa_records = await resolver.resolve(target, 'AAAA')
                for rdata in aaaa_records:
                    ip6 = str(rdata)
                    results.append(make_result(
                        source=self.name, finding_type="ip", value=ip6, target=target,
                        confidence=0.97, evidence=f"DNS AAAA record for {target}",
                        title=f"AAAA Record: {ip6}", description=f"{target} resolves to IPv6 {ip6}",
                        observation_type="observed", category="infrastructure", tags="ip,dns,aaaa_record",
                        raw_data={"record_type": "AAAA", "ip6": ip6},
                    ))
            except Exception:
                pass

            # NS Records
            try:
                ns_records = await resolver.resolve(target, 'NS')
                for rdata in ns_records:
                    ns = str(rdata).rstrip('.')
                    results.append(make_result(
                        source=self.name, finding_type="subdomain", value=ns, target=target,
                        confidence=0.90, evidence=f"DNS NS record for {target}",
                        title=f"Nameserver: {ns}", description=f"Authoritative nameserver for {target}",
                        observation_type="observed", category="infrastructure", tags="nameserver,dns,ns_record",
                        raw_data={"record_type": "NS", "nameserver": ns},
                    ))
            except Exception:
                pass

            # MX Records
            try:
                mx_records = await resolver.resolve(target, 'MX')
                for rdata in mx_records:
                    mx = str(rdata.exchange).rstrip('.')
                    results.append(make_result(
                        source=self.name, finding_type="subdomain", value=mx, target=target,
                        confidence=0.90, evidence=f"DNS MX record for {target}",
                        title=f"Mail Server: {mx}", description=f"MX mail exchange for {target} (priority {rdata.preference})",
                        observation_type="observed", category="infrastructure", tags="mail,mx,dns",
                        raw_data={"record_type": "MX", "mx": mx, "priority": rdata.preference},
                    ))
            except Exception:
                pass

            # TXT Records
            try:
                txt_records = await resolver.resolve(target, 'TXT')
                for rdata in txt_records:
                    txt = str(rdata).strip('"')
                    tag = "spf" if "v=spf" in txt.lower() else "dmarc" if "v=dmarc" in txt.lower() else "txt"
                    results.append(make_result(
                        source=self.name, finding_type="exposure", value=f"TXT:{txt[:80]}",
                        target=target, confidence=0.88, evidence=f"DNS TXT record for {target}",
                        title=f"TXT Record: {txt[:50]}",
                        description=f"DNS TXT record may reveal email security configuration or service verification.",
                        observation_type="observed", category="email_security", tags=f"txt,dns,{tag}",
                        raw_data={"record_type": "TXT", "value": txt},
                    ))
            except Exception:
                pass

        except Exception as e:
            self._record_error(str(e))
        return results
