"""
Base collector interface for all OSINT data collectors.
Every provider returns standardized OsintResult dictionaries.

Standardized result format:
{
    "source":           str,   # provider name e.g. "crt.sh"
    "category":         str,   # "domain" | "certificate" | "ip" | "email" | ...
    "finding_type":     str,   # "domain" | "subdomain" | "certificate" | "ip" | "technology" | ...
    "value":            str,   # the discovered entity value
    "target":           str,   # the queried target
    "confidence":       float, # 0.0 – 1.0 (single-source confidence)
    "observation_type": str,   # "observed" | "inferred" | "hypothesized"
    "evidence":         str,   # human-readable evidence description
    "title":            str,   # short display title
    "description":      str,   # longer description
    "tags":             str,   # comma-separated tags
    "discovered_at":    str,   # ISO timestamp
    "first_seen":       str,   # ISO timestamp (may be None)
    "last_seen":        str,   # ISO timestamp (may be None)
    "raw_data":         dict,  # raw API/source response data
    "external_url":     str,   # optional external link
}
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


def now_iso() -> str:
    """Return current UTC time as ISO string."""
    return datetime.now(timezone.utc).isoformat()


def make_result(
    source: str,
    finding_type: str,
    value: str,
    target: str,
    confidence: float,
    evidence: str,
    title: str = "",
    description: str = "",
    observation_type: str = "observed",
    category: str = "",
    tags: str = "",
    raw_data: Optional[dict] = None,
    external_url: Optional[str] = None,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a standardized OSINT result dictionary.
    Use this factory in every provider to ensure a consistent schema.
    """
    ts = now_iso()
    return {
        "source": source,
        "category": category or finding_type,
        "finding_type": finding_type,
        "value": value,
        "target": target,
        "confidence": max(0.0, min(1.0, confidence)),
        "observation_type": observation_type,
        "evidence": evidence,
        "title": title or f"{finding_type.title()}: {value}",
        "description": description,
        "tags": tags,
        "discovered_at": ts,
        "first_seen": first_seen,
        "last_seen": last_seen or ts,
        "raw_data": raw_data or {},
        "external_url": external_url,
    }


class BaseCollector(ABC):
    """Abstract base class for OSINT collectors."""

    name: str = "base"
    display_name: str = "Base Collector"
    description: str = ""
    provider_category: str = "general"  # domain, certificate, ip, email, username, technology, threat_intel, github
    requires_key: bool = False

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.is_demo = True
        self._last_error: Optional[str] = None
        self._last_queried_at: Optional[str] = None

    @abstractmethod
    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        Collect OSINT data for the given target.
        Returns a list of standardized result dictionaries (use make_result()).
        Must NOT raise exceptions — catch internally and return partial results.
        """
        pass

    def get_status(self) -> dict:
        """Return the current status of this provider."""
        if self.is_demo:
            status = "demo"
        elif self.requires_key and not self._has_api_key():
            status = "key_missing"
        else:
            status = "ready"

        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.provider_category,
            "status": status,
            "requires_key": self.requires_key,
            "is_demo": self.is_demo,
            "last_error": self._last_error,
            "last_queried_at": self._last_queried_at,
        }

    def _has_api_key(self) -> bool:
        """Override in providers that require API keys."""
        return False

    def _record_query(self):
        """Call this when a real API query is made."""
        self._last_queried_at = now_iso()

    def _record_error(self, error: str):
        """Record the last error for the health dashboard."""
        self._last_error = str(error)[:200]
