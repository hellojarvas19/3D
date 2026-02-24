"""
Card parsing and formatting utilities.

All card dicts use the keys: cc, month, year, cvv
  - month : two-digit string ("01"–"12")
  - year  : two-digit string (last two digits)
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

CARD_PATTERN = re.compile(
    r"(\d{15,19})\s*[|:/\\\-\s]\s*(\d{1,2})\s*[|:/\\\-\s]\s*(\d{2,4})\s*[|:/\\\-\s]\s*(\d{3,4})"
)


def parse_card(text: str) -> Optional[dict]:
    """
    Parse a single card string into a normalised dict.

    Accepts formats like:
        4242424242424242|12|25|123
        4242424242424242/12/2025/123
        4242424242424242:12:25:123

    Returns ``None`` if the input is invalid.
    """
    text = text.strip()
    if not text:
        return None

    # Try compiled regex first
    match = CARD_PATTERN.search(text)
    if match:
        cc, mm, yy, cvv = match.groups()
    else:
        # Fallback: split on common delimiters
        parts = re.split(r"[|:/\\\-\s]+", text)
        if len(parts) < 4:
            return None
        cc = re.sub(r"\D", "", parts[0])
        mm = parts[1].strip()
        yy = parts[2].strip()
        cvv = re.sub(r"\D", "", parts[3])

    # ── Validate CC length ──
    cc = re.sub(r"\D", "", cc)
    if not 15 <= len(cc) <= 19:
        return None

    # ── Normalise & validate month ──
    mm = mm.zfill(2)
    if not (mm.isdigit() and 1 <= int(mm) <= 12):
        return None

    # ── Normalise year to 2-digit ──
    if len(yy) == 4:
        yy = yy[2:]
    if len(yy) != 2 or not yy.isdigit():
        return None

    # ── Validate CVV ──
    cvv = re.sub(r"\D", "", cvv)
    if not 3 <= len(cvv) <= 4:
        return None

    return {"cc": cc, "month": mm, "year": yy, "cvv": cvv}


def parse_cards(text: str) -> list[dict]:
    """
    Extract all valid cards from *text* (one or more per line).

    Returns a list of card dicts (may be empty).
    """
    cards: list[dict] = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        # Try to find multiple cards on a single line
        matches = CARD_PATTERN.findall(line)
        if matches:
            for raw_match in matches:
                reconstructed = "|".join(raw_match)
                card = parse_card(reconstructed)
                if card:
                    cards.append(card)
        else:
            card = parse_card(line)
            if card:
                cards.append(card)
    return cards


def format_card(card: dict) -> str:
    """Return a ``cc|mm|yy|cvv`` representation of *card*."""
    return f"{card['cc']}|{card['month']}|{card['year']}|{card['cvv']}"


def mask_card(card: dict) -> str:
    """Return a masked display like ``424242****4242``."""
    cc = card["cc"]
    if len(cc) >= 10:
        return f"{cc[:6]}****{cc[-4:]}"
    return cc
