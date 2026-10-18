"""Version 1 API router."""

from fastapi import APIRouter

from app.api.v1 import admin_invitations, auth, connections, devices

API_PREFIX = "/api/v1"

router = APIRouter(prefix=API_PREFIX)
router.include_router(auth.router)
router.include_router(admin_invitations.router)
router.include_router(devices.router)
router.include_router(connections.requests_router)
router.include_router(connections.sessions_router)
