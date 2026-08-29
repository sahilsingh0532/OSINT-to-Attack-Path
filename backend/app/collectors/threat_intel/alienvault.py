"""Threat Intel providers — AlienVault OTX pulse feed."""

import httpx
from typing import List, Dict, Any
from app.collectors.base import BaseCollector, make_result


class AlienVaultThreatCollector(BaseCollector):
    name = "alienvault_otx"
    display_name = "AlienVault OTX (Threat Feed)"
    description = "Open threat intelligence pulses from AlienVault OTX. Free, no key required."
    provider_category = "threat_intel"
    requires_key = False

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        results = []
        try:
            self._record_query()
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/general"
                )
                if r.status_code == 200:
                    data = r.json()
                    pulse_info = data.get("pulse_info", {})
                    pulse_count = pulse_info.get("count", 0)
                    pulses = pulse_info.get("pulses", [])[:5]

                    for pulse in pulses:
                        results.append(make_result(
                            source=self.name,
                            finding_type="threat_indicator",
                            value=f"otx_pulse:{pulse.get('id', '')}",
                            target=target,
                            confidence=0.83,
                            evidence=f"AlienVault OTX threat pulse: {pulse.get('name', '')}",
                            title=f"OTX Threat Pulse: {pulse.get('name', '')[:60]}",
                            description=(
                                f"Domain {target} referenced in OTX threat pulse '{pulse.get('name', '')}'. "
                                f"Tags: {', '.join(pulse.get('tags', [])[:5])}"
                            ),
                            observation_type="observed",
                            category="threat_intel",
                            tags=f"alienvault,otx,threat,{','.join(pulse.get('tags', [])[:3])}",
                            raw_data={
                                "pulse_id": pulse.get("id", ""),
                                "pulse_name": pulse.get("name", ""),
                                "tags": pulse.get("tags", []),
                                "created": pulse.get("created", ""),
                                "modified": pulse.get("modified", ""),
                                "tlp": pulse.get("tlp", ""),
                            },
                            first_seen=pulse.get("created"),
                            last_seen=pulse.get("modified"),
                        ))

                    if pulse_count > 0 and not pulses:
                        results.append(make_result(
                            source=self.name,
                            finding_type="threat_indicator",
                            value=f"otx:{target}:pulses={pulse_count}",
                            target=target,
                            confidence=0.80,
                            evidence=f"AlienVault OTX: {pulse_count} pulses reference {target}",
                            title=f"OTX: {pulse_count} Threat Pulses",
                            description=f"Domain {target} is referenced in {pulse_count} AlienVault OTX threat intelligence pulses.",
                            observation_type="observed",
                            category="threat_intel",
                            tags="alienvault,otx,threat",
                            raw_data={"pulse_count": pulse_count},
                        ))
        except Exception as e:
            self._record_error(str(e))
        return results
