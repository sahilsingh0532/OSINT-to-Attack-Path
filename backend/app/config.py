import os
import tempfile
from pydantic_settings import BaseSettings
from typing import Optional


def get_default_db_url() -> str:
    if os.environ.get("VERCEL") or not os.access(".", os.W_OK):
        db_file = os.path.join(tempfile.gettempdir(), "osint_attack_path.db")
        return f"sqlite+aiosqlite:///{db_file}"
    return "sqlite+aiosqlite:///./osint_attack_path.db"


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Application
    app_name: str = "OSINT-to-Attack-Path"
    app_version: str = "1.0.0"
    osint_mode: str = "demo"  # "demo" or "live"

    # Database
    database_url: str = get_default_db_url()

    # Server
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    frontend_url: str = "http://localhost:5173"

    # API Keys (optional — only for live mode)
    github_token: Optional[str] = None
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

