"""ARGUS FastAPI Application.

Main entry point for the ARGUS REST API. Initializes the database,
configures logging, and registers all route modules.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from argus.database.database import init_db
from argus.utils.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup
    setup_logging()
    init_db()
    yield
    # Shutdown (nothing to clean up currently)


app = FastAPI(
    title="ARGUS API",
    description=(
        "AI-Driven Network Guard & Unified Security — "
        "REST API for security event ingestion, storage, and analysis."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Register routes
from argus.api.routes.health import router as health_router
from argus.api.routes.events import router as events_router

app.include_router(health_router)
app.include_router(events_router)


@app.get("/")
async def root():
    """API root — redirects to docs."""
    return {
        "service": "ARGUS API",
        "version": "0.1.0",
        "docs": "/docs",
        "health": "/health",
    }
