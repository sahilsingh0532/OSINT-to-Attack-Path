"""Technology providers — HTTP header fingerprinting."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class HttpFingerprintCollector(BaseCollector):
    name = "http_fingerprint"
    display_name = "HTTP Header Fingerprint"
    description = "Technology identification via HTTP response headers and content. No API key."
    provider_category = "technology"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        try:
            self._record_query()
            for scheme in ["https", "http"]:
                url = f"{scheme}://{target}"
                try:
                    async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False) as client:
                        r = await client.get(url)
                        headers = {k.lower(): v for k, v in r.headers.items()}

                        server = headers.get("server", "")
                        powered_by = headers.get("x-powered-by", "")
                        content_type = headers.get("content-type", "")
                        cf = headers.get("cf-ray", "")  # Cloudflare
                        via = headers.get("via", "")

                        if server:
                            results.append(make_result(
                                source=self.name, finding_type="technology", value=f"Server: {server}",
                                target=target, confidence=0.90,
                                evidence=f"HTTP Server header from {url}",
                                title=f"Web Server: {server}",
                                description=f"Server header discloses: {server}",
                                observation_type="observed", category="technology", tags="web_server,header",
                                raw_data={"header": "Server", "value": server, "url": url},
                            ))

                        if powered_by:
                            results.append(make_result(
                                source=self.name, finding_type="technology", value=f"X-Powered-By: {powered_by}",
                                target=target, confidence=0.90,
                                evidence=f"X-Powered-By header from {url}",
                                title=f"Tech Stack: {powered_by}",
                                description=f"X-Powered-By header discloses: {powered_by}",
                                observation_type="observed", category="technology", tags="tech_stack,header",
                                raw_data={"header": "X-Powered-By", "value": powered_by, "url": url},
                            ))

                        if cf:
                            results.append(make_result(
                                source=self.name, finding_type="technology", value="CDN: Cloudflare",
                                target=target, confidence=0.92,
                                evidence=f"Cloudflare CF-Ray header detected from {url}",
                                title="CDN: Cloudflare",
                                description=f"Cloudflare CDN/WAF detected via CF-Ray header",
                                observation_type="observed", category="technology", tags="cdn,cloudflare",
                                raw_data={"cf_ray": cf, "url": url},
                            ))

                        # Missing security headers
                        sec_headers = {
                            "strict-transport-security": "HSTS",
                            "content-security-policy": "CSP",
                            "x-frame-options": "X-Frame-Options",
                            "x-content-type-options": "X-Content-Type-Options",
                            "referrer-policy": "Referrer-Policy",
                        }
                        missing = [v for k, v in sec_headers.items() if k not in headers]
                        if missing:
                            results.append(make_result(
                                source=self.name, finding_type="exposure",
                                value=f"Missing Headers: {', '.join(missing)}",
                                target=target, confidence=0.85,
                                evidence=f"HTTP headers audit on {url}",
                                title="Missing Security Headers",
                                description=f"Recommended headers not present: {', '.join(missing)}",
                                observation_type="observed", category="configuration", tags="security_headers,misconfiguration",
                                raw_data={"missing_headers": missing, "url": url},
                            ))
                        break
                except Exception:
                    continue
        except Exception as e:
            self._record_error(str(e))
        return results
