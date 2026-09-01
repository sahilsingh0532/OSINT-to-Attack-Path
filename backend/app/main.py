"""
OSINT-to-Attack-Path — FastAPI Application Entry Point
Automated Passive Reconnaissance & Risk Prioritization Framework
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.routers.api import router

# Import models to ensure they're registered with SQLAlchemy
import app.models  # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle."""
    # Startup: create database tables
    await init_db()
    yield
    # Shutdown: cleanup if needed


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Automated Passive Reconnaissance & Risk Prioritization Framework. "
        "This framework is intended for authorized security testing, "
        "academic research, and controlled laboratory environments only."
    ),
    lifespan=lifespan,
)

# CORS — allow frontend dev server, Vercel, GitHub Pages, and Render
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        settings.frontend_url,
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"https://(.*\.(vercel\.app|github\.io|onrender\.com|web\.app|firebaseapp\.com))",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router)


@app.get("/")
async def root():
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "mode": settings.osint_mode,
        "disclaimer": (
            "This framework is intended for authorized security testing, "
            "academic research, and controlled laboratory environments only."
        ),
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}
