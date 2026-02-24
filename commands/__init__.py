"""
Commands package – aggregates all command routers into a single top-level router.
"""

import logging

from aiogram import Router

logger = logging.getLogger(__name__)

router = Router()

try:
    from commands.start import router as start_router
    router.include_router(start_router)
    logger.debug("Registered start_router.")
except Exception:
    logger.exception("Failed to register start_router.")

try:
    from commands.co import router as co_router
    router.include_router(co_router)
    logger.debug("Registered co_router.")
except Exception:
    logger.exception("Failed to register co_router.")
