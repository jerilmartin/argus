"""ARGUS Health Check Route."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Health check endpoint.

    Returns a simple status indicator. Future versions may
    include database connectivity and service health.
    """
    return {
        "status": "ok",
        "service": "argus-api",
        "version": "0.1.0",
    }
