import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Application
    app_name: str = "OSINT-to-Attack-Path"
    app_version: str = "2.0.0"
    osint_mode: str = "demo"  # "demo" or "live"

    # Database (local SQLite)
    database_url: str = "sqlite+aiosqlite:///./osint_attack_path.db"

    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    frontend_url: str = "http://localhost:5173"

    # ── Existing API Keys ──────────────────────────────────────────────────
    github_token: Optional[str] = None
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None

    # ── New API Keys (Phase 2 upgrade) ────────────────────────────────────
    # Email Intelligence
    hunter_api_key: Optional[str] = None          # Hunter.io — 25 req/month free
    hibp_api_key: Optional[str] = None            # Have I Been Pwned — paid API
    emailrep_api_key: Optional[str] = None        # EmailRep.io — 100 req/day free

    # DNS / Subdomain
    securitytrails_api_key: Optional[str] = None  # SecurityTrails — optional
    dnsdumpster_api_key: Optional[str] = None     # DNSDumpster — optional

    # Threat Intel
    ahmia_api_key: Optional[str] = None           # Ahmia — no key needed for basic search

    # ── Firebase (optional sync layer) ────────────────────────────────────
    firebase_api_key: Optional[str] = None
    firebase_auth_domain: Optional[str] = None
    firebase_project_id: Optional[str] = None
    firebase_storage_bucket: Optional[str] = None
    firebase_messaging_sender_id: Optional[str] = None
    firebase_app_id: Optional[str] = None
    firebase_measurement_id: Optional[str] = None
    firebase_service_account_path: Optional[str] = None  # Path to service account JSON

    # ── Confidence scoring parameters (configurable) ──────────────────────
    confidence_source_bonus: float = 0.08    # Bonus per additional agreeing source
    confidence_max_bonus: float = 0.30       # Maximum bonus from agreement
    confidence_freshness_days: int = 30      # Days for freshness bonus
    confidence_freshness_bonus: float = 0.05 # Bonus for recent data

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()
