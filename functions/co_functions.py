"""
Stripe checkout URL parsing and formatting utilities.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Optional
from urllib.parse import unquote

import aiohttp

from config import DEFAULT_HEADERS

logger = logging.getLogger(__name__)


# ─── Currency helpers ─────────────────────────────────────────────────

_CURRENCY_SYMBOLS: dict[str, str] = {
    "USD": "$", "EUR": "€", "GBP": "£", "INR": "₹", "JPY": "¥",
    "CNY": "¥", "KRW": "₩", "RUB": "₽", "BRL": "R$", "CAD": "C$",
    "AUD": "A$", "MXN": "MX$", "SGD": "S$", "HKD": "HK$", "THB": "฿",
    "VND": "₫", "PHP": "₱", "IDR": "Rp", "MYR": "RM", "ZAR": "R",
    "CHF": "CHF", "SEK": "kr", "NOK": "kr", "DKK": "kr", "PLN": "zł",
    "TRY": "₺", "AED": "د.إ", "SAR": "﷼", "ILS": "₪", "TWD": "NT$",
}


def get_currency_symbol(currency: str) -> str:
    """Return the symbol for *currency* (ISO code), or ``""``."""
    return _CURRENCY_SYMBOLS.get(currency.upper(), "")


# ─── Markdown helpers ─────────────────────────────────────────────────

def escape_md(text: str) -> str:
    """Escape MarkdownV2 special characters."""
    if not text:
        return ""
    for ch in r"_*[]()~`>#+-=|{}.!":
        text = text.replace(ch, f"\\{ch}")
    return text


def add_blockquote(text: str) -> str:
    """Prefix every line with ``>`` for Telegram blockquote formatting."""
    return "\n".join(f">{line}" for line in text.split("\n"))


# ─── URL extraction ───────────────────────────────────────────────────

_CHECKOUT_URL_PATTERNS: list[re.Pattern] = [
    re.compile(
        r"https?://checkout\.stripe\.com/c/pay/cs_[A-Za-z0-9_\-]+#[A-Za-z0-9%\-_=]+",
        re.IGNORECASE,
    ),
    re.compile(
        r"https?://checkout\.stripe\.com/c/pay/cs_[A-Za-z0-9_\-]+",
        re.IGNORECASE,
    ),
    re.compile(
        r'https?://checkout\.stripe\.com/[^\s"\'<>)]+',
        re.IGNORECASE,
    ),
    re.compile(
        r'https?://buy\.stripe\.com/[^\s"\'<>)]+',
        re.IGNORECASE,
    ),
]


def extract_checkout_url(text: str) -> Optional[str]:
    """
    Extract the first Stripe checkout URL from *text*.

    Returns ``None`` if no valid URL is found.
    """
    for pattern in _CHECKOUT_URL_PATTERNS:
        match = pattern.search(text)
        if match:
            url = match.group(0)

            # Trim trailing card data that may have been pasted alongside
            card_match = re.search(r"\d{13,19}\|", url)
            if card_match:
                url = url[: card_match.start()]

            return url.rstrip(".,;:")
    return None


# ─── PK / CS decoding ────────────────────────────────────────────────

def decode_pk_from_url(url: str) -> dict:
    """
    Extract PK and CS from a Stripe checkout URL's hash fragment
    using the XOR-5 decode scheme.

    Returns a dict with keys ``pk``, ``cs``, ``site`` (any may be ``None``).
    """
    result: dict = {"pk": None, "cs": None, "site": None}

    try:
        cs_match = re.search(r"cs_(live|test)_[A-Za-z0-9]+", url)
        if cs_match:
            result["cs"] = cs_match.group(0)

        if "#" not in url:
            return result

        hash_part = url.split("#", 1)[1]
        hash_decoded = unquote(hash_part)

        decoded_bytes = base64.b64decode(hash_decoded)
        xored = "".join(chr(b ^ 5) for b in decoded_bytes)

        pk_match = re.search(r"pk_(live|test)_[A-Za-z0-9]+", xored)
        if pk_match:
            result["pk"] = pk_match.group(0)

        site_match = re.search(r'https?://[^\s"\'<>]+', xored)
        if site_match:
            result["site"] = site_match.group(0)

    except (ValueError, base64.binascii.Error) as exc:
        logger.debug("Base64 decode failed for URL hash: %s", exc)
    except Exception:
        logger.exception("Unexpected error decoding PK from URL.")

    return result


# ─── Checkout info fetcher ────────────────────────────────────────────

async def parse_stripe_checkout(url: str) -> dict:
    """
    Fetch and parse checkout metadata (merchant, product, price, …).

    Returns a dict that always contains an ``error`` key (``None`` on success).
    """
    result: dict = {
        "url": url,
        "pk": None,
        "cs": None,
        "merchant": None,
        "price": None,
        "currency": None,
        "product": None,
        "error": None,
    }

    try:
        decoded = decode_pk_from_url(url)
        result["pk"] = decoded.get("pk")
        result["cs"] = decoded.get("cs")

        if not result["pk"] or not result["cs"]:
            result["error"] = "Could not decode PK/CS from URL"
            return result

        timeout = aiohttp.ClientTimeout(total=15, connect=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            body = f"key={result['pk']}&eid=NA&browser_locale=en-US&redirect_type=url"
            async with session.post(
                f"https://api.stripe.com/v1/payment_pages/{result['cs']}/init",
                headers=DEFAULT_HEADERS,
                data=body,
            ) as resp:
                if resp.status != 200:
                    result["error"] = f"Stripe returned HTTP {resp.status}"
                    return result
                init_data = await resp.json()

            if "error" in init_data:
                result["error"] = (
                    init_data.get("error", {}).get("message", "Init failed")
                )
                return result

            acc = init_data.get("account_settings", {})
            result["merchant"] = acc.get("display_name") or acc.get("business_name")

            lig = init_data.get("line_item_group")
            inv = init_data.get("invoice")
            if lig:
                result["price"] = lig.get("total", 0) / 100
                result["currency"] = lig.get("currency", "").upper()
                if lig.get("line_items"):
                    result["product"] = lig["line_items"][0].get("name")
            elif inv:
                result["price"] = inv.get("total", 0) / 100
                result["currency"] = inv.get("currency", "").upper()

    except aiohttp.ClientError as exc:
        logger.warning("HTTP error parsing checkout: %s", exc)
        result["error"] = f"HTTP error: {exc}"
    except Exception as exc:
        logger.exception("Unexpected error parsing checkout.")
        result["error"] = str(exc)

    return result


def format_checkout_md(data: dict) -> str:
    """Format checkout data as MarkdownV2 for Telegram."""
    if data.get("error"):
        return f"❌ `{escape_md(str(data['error']))}`"

    lines = ["⚡ *Stripe Checkout*", ""]

    if data.get("merchant"):
        lines.append(f"🏪 *Merchant:* `{escape_md(data['merchant'])}`")

    if data.get("product"):
        lines.append(f"📦 *Product:* `{escape_md(data['product'][:50])}`")

    if data.get("price") is not None:
        sym = get_currency_symbol(data.get("currency", ""))
        lines.append(
            f"💰 *Price:* `{sym}{data['price']:.2f} {data.get('currency', '')}`"
        )

    lines.append("")

    if data.get("pk"):
        lines.append(f"🔑 *PK:* `{escape_md(data['pk'][:30])}...`")
    if data.get("cs"):
        lines.append(f"🎫 *CS:* `{escape_md(data['cs'][:30])}...`")

    return "\n".join(lines)
