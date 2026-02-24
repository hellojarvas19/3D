"""
Commands package – aggregates all command handlers into the Dispatcher.
"""

import logging

from aiogram.dispatcher import Dispatcher

logger = logging.getLogger(__name__)

# Create a global dispatcher that handlers will register with
dp = Dispatcher

try:
    from commands.start import register_start_handlers
    register_start_handlers(dp)
    logger.debug("Registered start handlers.")
except Exception:
    logger.exception("Failed to register start handlers.")

try:
    from commands.co import register_co_handlers
    register_co_handlers(dp)
    logger.debug("Registered co handlers.")
except Exception:
    logger.exception("Failed to register co handlers.")
