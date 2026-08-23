"""
Base collector interface for all OSINT data collectors.
Each collector returns standardized finding dictionaries.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class BaseCollector(ABC):
    """Abstract base class for OSINT collectors."""

    name: str = "base"
    display_name: str = "Base Collector"
    description: str = ""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.is_demo = True

    @abstractmethod
    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Collect OSINT data for the given target domain.

        Returns a list of standardized finding dictionaries.
        """
        pass

    def get_status(self) -> dict:
        """Return the current status of this collector."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "status": "not_configured" if not self.is_demo and not self._has_api_key() else "ready",
            "is_demo": self.is_demo,
            "description": self.description,
        }

    def _has_api_key(self) -> bool:
        """Check if required API keys are configured."""
        return False
