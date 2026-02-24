"""
Stripe card-charging logic (session management, payment method creation, confirm).
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import aiohttp

from config import (
    DEFAULT_HEADERS,
    SESSION_CONNECTOR_LIMIT,
    SESSION_TIMEOUT_CONNECT,
    SESSION_TIMEOUT_TOTAL,
)

logger = logging.getLogger(__name__)

# ─── Module-level session ─────────────────────────────────────────────

_session: Optional[aiohttp.ClientSession] = None


async def get_session() -> aiohttp.ClientSession:
    """Return (and lazily create) a shared :class:`aiohttp.ClientSession`."""
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                limit=SESSION_CONNECTOR_LIMIT,
                ttl_dns_cache=300,
            ),
            timeout=aiohttp.ClientTimeout(
                total=SESSION_TIMEOUT_TOTAL,
                connect=SESSION_TIMEOUT_CONNECT,
            ),
        )
        logger.debug("Created new aiohttp session (charge_functions).")
    return _session


async def close_session() -> None:
    """Gracefully close the module-level session if it is open."""
    global _session
    if _session and not _session.closed:
        await _session.close()
        logger.debug("Closed aiohttp session (charge_functions).")
    _session = None


# ─── Stripe helpers ───────────────────────────────────────────────────

async def init_checkout(pk: str, cs: str) -> dict:
    """
    Call Stripe's checkout init endpoint.

    Returns the parsed JSON response.
    Raises on HTTP / network failures.
    """
    session = await get_session()
    body = f"key={pk}&eid=NA&browser_locale=en-US&redirect_type=url"

    async with session.post(
        f"https://api.stripe.com/v1/payment_pages/{cs}/init",
        headers=DEFAULT_HEADERS,
        data=body,
    ) as resp:
        if resp.status != 200:
            logger.warning("init_checkout got HTTP %d for cs=%s", resp.status, cs[:20])
        return await resp.json()


async def charge_card_fast(
    card: dict,
    pk: str,
    cs: str,
    init_data: dict,
) -> dict:
    """
    Create a payment method and confirm the payment in one go.

    *card* must have keys ``cc``, ``month``, ``year``, ``cvv``.
    Returns a result dict with ``card``, ``status``, ``response``, ``time``.
    """
    card_str = f"{card['cc']}|{card['month']}|{card['year']}|{card['cvv']}"
    start = time.perf_counter()
    result: dict = {"card": card_str, "status": None, "response": None, "time": 0}

    try:
        session = await get_session()

        # ── Billing details ──
        email = init_data.get("customer_email") or "john@example.com"
        checksum = init_data.get("init_checksum", "")

        lig = init_data.get("line_item_group")
        inv = init_data.get("invoice")
        if lig:
            total = lig.get("total", 0)
            subtotal = lig.get("subtotal", 0)
        elif inv:
            total = inv.get("total", 0)
            subtotal = inv.get("subtotal", 0)
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

        # ── Create payment method ──
        pm_body = (
            f"type=card"
            f"&card[number]={card['cc']}"
            f"&card[cvc]={card['cvv']}"
            f"&card[exp_month]={card['month']}"
            f"&card[exp_year]={card['year']}"
            f"&billing_details[name]={name}"
            f"&billing_details[email]={email}"
            f"&billing_details[address][country]={country}"
            f"&billing_details[address][line1]={line1}"
            f"&billing_details[address][city]={city}"
            f"&billing_details[address][postal_code]={zip_code}"
            f"&billing_details[address][state]={state}"
            f"&key={pk}"
        )

        async with session.post(
            "https://api.stripe.com/v1/payment_methods",
            headers=DEFAULT_HEADERS,
            data=pm_body,
        ) as resp:
            pm = await resp.json()

        if "error" in pm:
            err_msg = pm["error"].get("message", "Card error")
            result["status"] = "DECLINED"
            result["response"] = err_msg
            result["time"] = round(time.perf_counter() - start, 2)
            return result

        pm_id = pm.get("id")
        if not pm_id:
            result["status"] = "FAILED"
            result["response"] = "No payment-method ID returned"
            result["time"] = round(time.perf_counter() - start, 2)
            return result

        # ── Confirm payment ──
        conf_body = (
            f"eid=NA"
            f"&payment_method={pm_id}"
            f"&expected_amount={total}"
            f"&last_displayed_line_item_group_details[subtotal]={subtotal}"
            f"&last_displayed_line_item_group_details[total_exclusive_tax]=0"
            f"&last_displayed_line_item_group_details[total_inclusive_tax]=0"
            f"&last_displayed_line_item_group_details[total_discount_amount]=0"
            f"&last_displayed_line_item_group_details[shipping_rate_amount]=0"
            f"&expected_payment_method_type=card"
            f"&key={pk}"
            f"&init_checksum={checksum}"
        )

        async with session.post(
            f"https://api.stripe.com/v1/payment_pages/{cs}/confirm",
            headers=DEFAULT_HEADERS,
            data=conf_body,
        ) as resp:
            conf = await resp.json()

        if "error" in conf:
            err = conf["error"]
            dc = err.get("decline_code", "")
            msg = err.get("message", "Failed")
            result["status"] = "DECLINED"
            result["response"] = f"{dc.upper()}: {msg}" if dc else msg
        else:
            pi = conf.get("payment_intent") or {}
            status = pi.get("status", "") or conf.get("status", "")
            if status == "succeeded":
                result["status"] = "CHARGED"
                result["response"] = "Charged"
            elif status == "requires_action":
                result["status"] = "3DS"
                result["response"] = "3DS Required"
            elif status == "requires_payment_method":
                result["status"] = "DECLINED"
                result["response"] = "Declined"
            else:
                result["status"] = "UNKNOWN"
                result["response"] = status or "Unknown"

    except aiohttp.ClientError as exc:
        logger.warning("HTTP error charging card %s…: %s", card["cc"][:6], exc)
        result["status"] = "ERROR"
        result["response"] = f"HTTP error: {str(exc)[:40]}"
    except Exception as exc:
        logger.exception("Unexpected error charging card %s…", card["cc"][:6])
        result["status"] = "ERROR"
        result["response"] = str(exc)[:40]

    result["time"] = round(time.perf_counter() - start, 2)
    return result


async def charge_card(card: dict, checkout_data: dict) -> dict:
    """
    High-level charge: initialise checkout, then charge.

    *checkout_data* must contain ``pk`` and ``cs``.
    """
    card_str = f"{card['cc']}|{card['month']}|{card['year']}|{card['cvv']}"
    pk = checkout_data.get("pk")
    cs = checkout_data.get("cs")

    if not pk or not cs:
        return {"card": card_str, "status": "FAILED", "response": "No PK/CS", "time": 0}

    try:
        init_data = await init_checkout(pk, cs)
    except Exception as exc:
        logger.warning("init_checkout failed: %s", exc)
        return {"card": card_str, "status": "FAILED", "response": f"Init error: {str(exc)[:40]}", "time": 0}

    if "error" in init_data:
        err_msg = init_data["error"].get("message", "Init failed") if isinstance(init_data["error"], dict) else str(init_data["error"])
        return {"card": card_str, "status": "FAILED", "response": err_msg, "time": 0}

    return await charge_card_fast(card, pk, cs, init_data)
