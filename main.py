"""
Bot entry-point – sets up logging, registers routers, and starts polling.
"""

import asyncio
import logging
import signal
import sys

from aiogram import Bot, Dispatcher
from config import BOT_TOKEN, setup_logging

logger = logging.getLogger(__name__)


async def main() -> None:
    """Initialise the bot, wire up routers, and start long-polling."""
    setup_logging()

    if not BOT_TOKEN:
        logger.critical("BOT_TOKEN is empty – cannot start.")
        sys.exit(1)

    bot = Bot(token=BOT_TOKEN)
    dp = Dispatcher(bot=bot)

    # Late import so logging is already configured when modules load
    from commands import router
    dp.include_router(router)

    logger.info("Bot starting – polling for updates …")

    try:
        await dp.start_polling(bot, skip_updates=True)
    except asyncio.CancelledError:
        logger.info("Polling cancelled.")
    except Exception:
        logger.exception("Unexpected error during polling.")
    finally:
        await _cleanup()
        logger.info("Bot stopped.")


async def _cleanup() -> None:
    """Close any long-lived aiohttp sessions gracefully."""
    try:
        from functions.charge_functions import close_session as close_charge_session
        await close_charge_session()
    except Exception:
        logger.debug("charge_functions session cleanup skipped.", exc_info=True)

    try:
        from commands.co import close_session as close_co_session
        await close_co_session()
    except Exception:
        logger.debug("co session cleanup skipped.", exc_info=True)


def _handle_signal(sig: signal.Signals) -> None:
    """Log the received signal and let asyncio's default handler cancel tasks."""
    logger.info("Received signal %s – shutting down …", sig.name)


if __name__ == "__main__":
    # Register friendly signal handlers (Unix only)
    loop = asyncio.new_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig)
        except NotImplementedError:
            pass  # Windows doesn't support add_signal_handler

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt – exiting.")
    finally:
        loop.close()
