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

import time
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


# ==============================================================================
# GLOBAL PROVIDER HEALTH & DIAGNOSTICS TRACKER
# ==============================================================================

class ProviderHealthTracker:
    """
    In-memory singleton tracker that records real-time execution health,
    latencies, errors, and stats across all collector runs.
    """
    def __init__(self):
        self._records: Dict[str, Dict[str, Any]] = {}

    def _key(self, name: str, category: str) -> str:
        return f"{name}:{category}"

    def record_query_start(self, name: str, category: str):
        key = self._key(name, category)
        rec = self._records.setdefault(key, {
            "name": name,
            "category": category,
            "total_queries": 0,
            "total_errors": 0,
            "total_findings": 0,
            "last_error": None,
            "last_status": "ready",
            "last_queried_at": None,
            "last_latency_ms": None,
            "last_findings_count": 0,
        })
        rec["total_queries"] += 1
        rec["last_queried_at"] = now_iso()

    def record_query_success(self, name: str, category: str, findings_count: int, latency_ms: float):
        key = self._key(name, category)
        rec = self._records.setdefault(key, {
            "name": name,
            "category": category,
            "total_queries": 1,
            "total_errors": 0,
            "total_findings": 0,
        })
        rec["last_error"] = None
        rec["last_status"] = "ready"
        rec["last_latency_ms"] = round(latency_ms, 1)
        rec["last_findings_count"] = findings_count
        rec["total_findings"] = rec.get("total_findings", 0) + findings_count

    def record_query_error(self, name: str, category: str, error_msg: str, status_code: Optional[int] = None, latency_ms: Optional[float] = None):
        key = self._key(name, category)
        rec = self._records.setdefault(key, {
            "name": name,
            "category": category,
            "total_queries": 1,
            "total_errors": 0,
            "total_findings": 0,
        })
        rec["total_errors"] += 1
        rec["last_error"] = str(error_msg)[:300]
        if status_code == 401 or status_code == 403:
            rec["last_status"] = "auth_failed"
        elif status_code == 429:
            rec["last_status"] = "rate_limited"
        elif "timeout" in str(error_msg).lower():
            rec["last_status"] = "timeout"
        else:
            rec["last_status"] = "error"

        if latency_ms is not None:
            rec["last_latency_ms"] = round(latency_ms, 1)

    def get_record(self, name: str, category: str) -> Optional[Dict[str, Any]]:
        return self._records.get(self._key(name, category))


GLOBAL_TRACKER = ProviderHealthTracker()


# ==============================================================================
# BASE COLLECTOR
# ==============================================================================

class BaseCollector(ABC):
    """Abstract base class for OSINT collectors."""

    name: str = "base"
    display_name: str = "Base Collector"
    description: str = ""
    provider_category: str = "general"  # domain, certificate, ip, email, username, technology, threat_intel, github
    requires_key: bool = False

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.is_demo = False
        self._query_start_time: Optional[float] = None

    @abstractmethod
    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        Collect OSINT data for the given target.
        Returns a list of standardized result dictionaries (use make_result()).
        Must NOT raise exceptions — catch internally and return partial results.
        """
        pass

    async def test_connection(self, target: str = "example.com") -> Dict[str, Any]:
        """
        Perform a live health check on this provider.
        Returns a dictionary with status, latency_ms, findings_count, and error.
        """
        if self.requires_key and not self._has_api_key():
            return {
                "name": self.name,
                "display_name": self.display_name,
                "category": self.provider_category,
                "status": "key_missing",
                "ok": False,
                "message": "API key is not configured in backend/.env",
                "latency_ms": 0,
                "findings_count": 0,
            }

        start = time.time()
        try:
            results = await self.collect(target)
            latency = round((time.time() - start) * 1000, 1)
            rec = GLOBAL_TRACKER.get_record(self.name, self.provider_category)
            err = rec.get("last_error") if rec else None
            status = rec.get("last_status", "ready") if rec else "ready"
            
            # If an error was logged during collect
            if err:
                return {
                    "name": self.name,
                    "display_name": self.display_name,
                    "category": self.provider_category,
                    "status": status,
                    "ok": False,
                    "message": err,
                    "latency_ms": latency,
                    "findings_count": len(results),
                }

            return {
                "name": self.name,
                "display_name": self.display_name,
                "category": self.provider_category,
                "status": "ready",
                "ok": True,
                "message": f"Successfully queried ({len(results)} items found)",
                "latency_ms": latency,
                "findings_count": len(results),
            }
        except Exception as e:
            latency = round((time.time() - start) * 1000, 1)
            self._record_error(str(e), latency_ms=latency)
            return {
                "name": self.name,
                "display_name": self.display_name,
                "category": self.provider_category,
                "status": "error",
                "ok": False,
                "message": str(e),
                "latency_ms": latency,
                "findings_count": 0,
            }

    def get_status(self) -> dict:
        """Return the current status of this provider, merging persistent health stats."""
        rec = GLOBAL_TRACKER.get_record(self.name, self.provider_category)

        if self.is_demo:
            status = "demo"
        elif self.requires_key and not self._has_api_key():
            status = "key_missing"
        elif rec and rec.get("last_status"):
            status = rec["last_status"]
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
            "last_error": rec.get("last_error") if rec else None,
            "last_queried_at": rec.get("last_queried_at") if rec else None,
            "last_latency_ms": rec.get("last_latency_ms") if rec else None,
            "last_findings_count": rec.get("last_findings_count", 0) if rec else 0,
            "total_queries": rec.get("total_queries", 0) if rec else 0,
            "total_errors": rec.get("total_errors", 0) if rec else 0,
        }

    def _has_api_key(self) -> bool:
        """Override in providers that require API keys."""
        return False

    def _record_query(self):
        """Call this when an API query starts."""
        self._query_start_time = time.time()
        GLOBAL_TRACKER.record_query_start(self.name, self.provider_category)

    def _record_success(self, findings_count: int = 0):
        """Call this when a query finishes successfully."""
        latency_ms = (time.time() - self._query_start_time) * 1000 if self._query_start_time else 0.0
        GLOBAL_TRACKER.record_query_success(self.name, self.provider_category, findings_count, latency_ms)

    def _record_error(self, error: str, status_code: Optional[int] = None, latency_ms: Optional[float] = None):
        """Record an error for this provider in global tracking."""
        if latency_ms is None and self._query_start_time:
            latency_ms = (time.time() - self._query_start_time) * 1000
        GLOBAL_TRACKER.record_query_error(self.name, self.provider_category, str(error), status_code, latency_ms)
