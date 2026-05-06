"""
notifier.py – Telegram bot notifications.

Features:
- Sends formatted alert messages via the Telegram Bot API.
- Exponential back-off on 429 / 5xx.
- Configurable via TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars.
- No-op (log-only) mode when credentials are absent, so the rest of the
  pipeline can run without a Telegram setup.
"""

from __future__ import annotations

import logging
import os
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
MAX_RETRIES = int(os.getenv("NOTIFIER_MAX_RETRIES", "4"))
BACKOFF_BASE = float(os.getenv("NOTIFIER_BACKOFF_BASE", "2.0"))


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=BACKOFF_BASE,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"Accept": "application/json"})
    return session


_SESSION: requests.Session | None = None


def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        _SESSION = _build_session()
    return _SESSION


# ---------------------------------------------------------------------------
# Message formatting
# ---------------------------------------------------------------------------

def _format_alert(
    token_address: str,
    name: str,
    symbol: str,
    score: float,
    reason: str,
    metrics: dict,
) -> str:
    """Build a Telegram MarkdownV2-compatible alert message."""
    liq = metrics.get("liq_usd") or 0
    vol = metrics.get("vol_5m_usd") or 0
    buys = metrics.get("buys_5m") or 0
    sells = metrics.get("sells_5m") or 0
    fdv = metrics.get("fdv") or 0
    buy_ratio = metrics.get("buy_ratio") or 0
    price = metrics.get("price_usd") or 0
    security_score = metrics.get("security_score") or 0

    # Escape special chars for MarkdownV2
    def _esc(s: str) -> str:
        for c in r"\_*[]()~`>#+-=|{}.!":
            s = s.replace(c, f"\\{c}")
        return s

    lines = [
        "🚨 *GEM ALERT* 🚨",
        "",
        f"*Token:* {_esc(symbol)} \\({_esc(name)}\\)",
        f"*Address:* `{token_address}`",
        "",
        f"*Security Score:* {security_score:.1f}/100",
        f"*Gem Score:* {score:.1f}/100",
        "",
        f"*Price USD:* ${price:.8f}" if price else "",
        f"*Liquidity:* ${liq:,.0f}",
        f"*Volume 5m:* ${vol:,.0f}",
        f"*Buys/Sells 5m:* {buys}/{sells} \\({buy_ratio:.0%} buy pressure\\)",
        f"*FDV:* ${fdv:,.0f}" if fdv else "",
        "",
        f"*Reason:* {_esc(reason)}",
    ]

    # Remove empty lines at end
    while lines and lines[-1] == "":
        lines.pop()

    return "\n".join(line for line in lines if line != "")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_alert(
    token_address: str,
    name: str,
    symbol: str,
    score: float,
    reason: str,
    metrics: dict,
) -> bool:
    """
    Send a Telegram alert.

    Returns True on success.
    If credentials are not configured, logs the alert and returns True (no-op).
    Returns False on delivery failure (after retries).
    """
    message = _format_alert(token_address, name, symbol, score, reason, metrics)

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning(
            "Telegram credentials not configured – alert not sent (logged only):\n%s",
            message,
        )
        return True  # treat as "sent" so pipeline doesn't stall

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "MarkdownV2",
        "disable_web_page_preview": True,
    }

    session = _get_session()
    attempt = 0
    while attempt <= MAX_RETRIES:
        try:
            resp = session.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("Telegram request error (attempt %d): %s", attempt, exc)
            attempt += 1
            time.sleep(BACKOFF_BASE ** attempt)
            continue

        if resp.status_code == 429:
            retry_after = int(resp.json().get("parameters", {}).get("retry_after", BACKOFF_BASE ** (attempt + 1)))
            logger.warning("Telegram rate-limited; sleeping %ss", retry_after)
            time.sleep(retry_after)
            attempt += 1
            continue

        if resp.ok:
            logger.info("Telegram alert sent for %s", token_address)
            return True

        logger.warning(
            "Telegram non-OK response %s (attempt %d): %s",
            resp.status_code,
            attempt,
            resp.text[:200],
        )
        attempt += 1
        time.sleep(BACKOFF_BASE ** attempt)

    logger.error("Failed to send Telegram alert for %s after %d attempts", token_address, MAX_RETRIES)
    return False
