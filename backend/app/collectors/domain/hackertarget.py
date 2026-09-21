"""Domain providers — HackerTarget passive subdomain enumeration (free, no key)."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class HackerTargetDomainCollector(BaseCollector):
    name = "hackertarget"
    display_name = "HackerTarget (Passive Subdomain)"
    description = "Free passive subdomain enumeration via HackerTarget API. No API key required."
    provider_category = "domain"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        found = set()
        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                r = await client.get(
                    f"https://api.hackertarget.com/hostsearch/?q={target}",
                    headers={"User-Agent": "Mozilla/5.0 (OSINT Research)"}
                )
                if r.status_code == 200:
                    text = r.text.strip()
                    if "api count exceeded" in text.lower():
                        self._record_error("HackerTarget rate limit exceeded (50 free req/day)", status_code=429)
                        return []
                    elif "error" in text.lower()[:50] and "no records" not in text.lower():
                        self._record_error(f"HackerTarget API response: {text[:100]}")
                        return []

                    for line in text.split("\n"):
                        parts = line.split(",")
                        if len(parts) >= 1:
                            hostname = parts[0].strip().lower()
                            ip = parts[1].strip() if len(parts) > 1 else None
                            if hostname and target in hostname and hostname not in found:
                                found.add(hostname)
                                ftype = "domain" if hostname == target else "subdomain"
                                results.append(make_result(
                                    source=self.name,
                                    finding_type=ftype,
                                    value=hostname,
                                    target=target,
                                    confidence=0.85,
                                    evidence=f"HackerTarget passive DNS search for {target}",
                                    title=f"Subdomain: {hostname}",
                                    description=f"Passive DNS entry found via HackerTarget for {target}",
                                    observation_type="observed",
                                    category="infrastructure",
                                    tags="subdomain,hackertarget,passive_dns",
                                    raw_data={"hostname": hostname, "ip": ip},
                                ))
                    self._record_success(len(results))
                else:
                    self._record_error(f"HackerTarget returned HTTP {r.status_code}", status_code=r.status_code)
        except httpx.TimeoutException:
            self._record_error("HackerTarget request timed out (10s limit)")
        except Exception as e:
            self._record_error(str(e))
        return results
