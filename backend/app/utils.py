"""Utility functions for domain normalization and robust timezone-aware datetime parsing."""

import re
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse


def clean_domain_target(target: str) -> str:
    """
    Clean and sanitize target input into a valid domain, hostname, or IP string.
    Strips protocols (http://, https://), ports (:8080), paths, query strings,
    URL fragments (#), whitespace, and trailing dots/slashes.
    """
    if not target:
        return ""
    
    target = target.strip()
    
    # If the user pasted a full URL or protocol-relative URL
    if re.match(r'^[a-zA-Z]+://', target) or target.startswith("//"):
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            host = parsed.hostname or parsed.netloc or ""
            target = host
        except Exception:
            pass

    # Strip any remaining path, query string, or fragment
    target = target.split("/")[0].split("?")[0].split("#")[0]
    
    # Strip port if present (and not IPv6)
    if ":" in target and not target.startswith("["):
        target = target.split(":")[0]

    # Clean whitespace, trailing dots, and lowercase
    target = target.strip().rstrip(".").lower()
    return target


def is_valid_domain(target: str) -> bool:
    """
    Validate whether a cleaned target string is a plausible domain, hostname, or IP.
    """
    if not target or len(target) > 253:
        return False
    # Allow standard domains (including subdomains/tlds), IPs, or internal hostnames
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    simple_host_pattern = r'^[a-zA-Z0-9\-_]{1,63}$'
    
    return bool(
        re.match(domain_pattern, target) or 
        re.match(ip_pattern, target) or 
        re.match(simple_host_pattern, target)
    )


def to_utc_datetime(val: Any) -> Optional[datetime]:
    """
    Safely parse any datetime string, timestamp integer/float, or existing datetime
    into a timezone-aware UTC datetime.
    Returns None if parsing fails.
    """
    if val is None:
        return None

    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc)

    # Handle numeric timestamps (e.g. 1710763200 or "1710763200")
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except Exception:
            return None

    if isinstance(val, str):
        val = val.strip()
        if not val:
            return None

        # Check if numeric string
        if val.isdigit():
            try:
                return datetime.fromtimestamp(int(val), tz=timezone.utc)
            except Exception:
                pass

        # Normalize ISO representation
        iso_str = val.replace("Z", "+00:00")
        
        # Try standard ISO parser
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # Common date format fallbacks
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
            "%d/%m/%Y",
            "%m/%d/%Y",
            "%b %d %Y",
            "%d %b %Y",
            "%Y/%m/%d",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(val[:19], fmt)
                return dt.replace(tzinfo=timezone.utc)
            except Exception:
                continue

    return None


def to_utc_iso(val: Any) -> Optional[str]:
    """Convert any date/timestamp into an ISO 8601 string in UTC."""
    dt = to_utc_datetime(val)
    return dt.isoformat() if dt else None
