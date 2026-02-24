"""
/start and /help command handlers.
"""

import logging

from aiogram import Router
from aiogram.types import Message
from aiogram.filters import Command
from aiogram.enums import ParseMode

from config import ALLOWED_GROUP, OWNER_ID

logger = logging.getLogger(__name__)

router = Router()


# ─── Helpers ──────────────────────────────────────────────────────────

def check_access(msg: Message) -> bool:
    """Return *True* if the user/chat is allowed to interact with the bot."""
    if msg.from_user and msg.from_user.id == OWNER_ID:
        return True
    return msg.chat.id == ALLOWED_GROUP


ACCESS_DENIED_TEXT = (
    "<blockquote><code>𝗔𝗰𝗰𝗲𝘀𝘀 𝗗𝗲𝗻𝗶𝗲𝗱 ❌</code></blockquote>\n\n"
    "<blockquote>「❃」 𝗝𝗼𝗶𝗻 𝘁𝗼 𝘂𝘀𝗲 : "
    "<code>https://t.me/+9B031Lv7m982MTc0</code></blockquote>"
)


# ─── Handlers ─────────────────────────────────────────────────────────

@router.message(Command("start"))
async def start_handler(msg: Message) -> None:
    """Send the welcome / overview message."""
    if not check_access(msg):
        await msg.answer(ACCESS_DENIED_TEXT, parse_mode=ParseMode.HTML)
        return

    welcome = (
        "<blockquote><code>Kamal Hitter ⚡</code></blockquote>\n\n"
        "<blockquote>「❃」 𝗖𝗵𝗲𝗰𝗸𝗼𝘂𝘁 𝗣𝗮𝗿𝘀𝗲𝗿\n"
        "    • <code>/co url</code> - Parse Stripe Checkout\n"
        "    • <code>/co url cc|mm|yy|cvv</code> - Charge Card</blockquote>\n\n"
        "<blockquote>「❃」 𝗦𝘂𝗽𝗽𝗼𝗿𝘁𝗲𝗱 𝗨𝗥𝗟𝘀\n"
        "    • <code>checkout.stripe.com</code>\n"
        "    • <code>buy.stripe.com</code></blockquote>\n\n"
        "<blockquote>「❃」 𝗖𝗼𝗻𝘁𝗮𝗰𝘁 : <code>@Mod_By_Kamal</code></blockquote>"
    )

    try:
        await msg.answer(welcome, parse_mode=ParseMode.HTML)
    except Exception:
        logger.exception("Failed to send /start reply to user %s", msg.from_user.id if msg.from_user else "?")


@router.message(Command("help"))
async def help_handler(msg: Message) -> None:
    """Send the help / commands message."""
    if not check_access(msg):
        await msg.answer(ACCESS_DENIED_TEXT, parse_mode=ParseMode.HTML)
        return

    help_text = (
        "<blockquote><code>𝗖𝗼𝗺𝗺𝗮𝗻𝗱𝘀 📋</code></blockquote>\n\n"
        "<blockquote>「❃」 <code>/start</code> - Show welcome message\n"
        "「❃」 <code>/help</code> - Show this help\n"
        "「❃」 <code>/co url</code> - Parse checkout info\n"
        "「❃」 <code>/co url cards</code> - Charge cards</blockquote>\n\n"
        "<blockquote>「❃」 𝗖𝗮𝗿𝗱 𝗙𝗼𝗿𝗺𝗮𝘁 : <code>cc|mm|yy|cvv</code>\n"
        "「❃」 𝗘𝘅𝗮𝗺𝗽𝗹𝗲 : <code>4242424242424242|12|25|123</code></blockquote>"
    )

    try:
        await msg.answer(help_text, parse_mode=ParseMode.HTML)
    except Exception:
        logger.exception("Failed to send /help reply to user %s", msg.from_user.id if msg.from_user else "?")
