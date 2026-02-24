"""
Configuration module for the bot.
Loads sensitive values from environment variables with fallback defaults.
"""

import os
import logging

logger = logging.getLogger(__name__)

# ─── Bot Configuration ───────────────────────────────────────────────
BOT_TOKEN = os.environ.get("BOT_TOKEN", "8244354469:AAE4O7pcdY1gj_Ntq9uKRt_T8J7P_C9mVx8")

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN is not set. Set it via the BOT_TOKEN environment variable.")

# ─── Access Control ──────────────────────────────────────────────────
ALLOWED_GROUP: int = int(os.environ.get("ALLOWED_GROUP", "-1003368032522"))
OWNER_ID: int = int(os.environ.get("OWNER_ID", "6320782528"))

# ─── File Paths ──────────────────────────────────────────────────────
PROXY_FILE: str = os.environ.get("PROXY_FILE", "proxies.json")

# ─── HTTP Defaults ───────────────────────────────────────────────────
DEFAULT_HEADERS: dict = {
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded",
    "origin": "https://checkout.stripe.com",
    "referer": "https://checkout.stripe.com/",
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}

# ─── Limits ──────────────────────────────────────────────────────────
MAX_PROXIES_PER_USER: int = 50
MAX_CARDS_PER_REQUEST: int = 100
SESSION_TIMEOUT_TOTAL: int = 20
SESSION_TIMEOUT_CONNECT: int = 5
SESSION_CONNECTOR_LIMIT: int = 100
PROXY_CHECK_THREADS: int = 10
PROXY_CHECK_TIMEOUT: int = 10

# ─── Logging Configuration ───────────────────────────────────────────
LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")
LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"


def setup_logging() -> None:
    """Configure the root logger with a consistent format."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format=LOG_FORMAT,
    )
    # Reduce noise from third-party libraries
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("aiogram").setLevel(logging.WARNING)
