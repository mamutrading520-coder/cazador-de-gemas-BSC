"""
security.py – Security gate using GoPlus Security API + Honeypot.is.

Design principles:
- Fail-closed: any API failure / timeout / rate-limit → treat token as UNSAFE.
- Returns (ok: bool, score: float 0-100, raw: dict).
- Exponential back-off on 429 / 5xx responses.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GOPLUS_BASE = "https://api.gopluslabs.io/api/v1"
HONEYPOT_BASE = "https://api.honeypot.is/v2"

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
MAX_RETRIES = int(os.getenv("SECURITY_MAX_RETRIES", "3"))
BACKOFF_BASE = float(os.getenv("SECURITY_BACKOFF_BASE", "1.5"))

BSC_CHAIN_ID_GOPLUS = "56"  # GoPlus uses numeric chain IDs

# ---------------------------------------------------------------------------
# Shared session
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=MAX_RETRIES,
        backoff_factor=BACKOFF_BASE,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"],
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
# GoPlus
# ---------------------------------------------------------------------------

def _check_goplus(token_address: str) -> dict[str, Any]:
    """
    Call GoPlus token security endpoint.
    Returns parsed result dict for the token, or {} on any failure.
    Fail-closed: errors return {}.
    """
    url = f"{GOPLUS_BASE}/token_security/{BSC_CHAIN_ID_GOPLUS}"
    params = {"contract_addresses": token_address.lower()}

    session = _get_session()
    attempt = 0
    while attempt <= MAX_RETRIES:
        try:
            resp = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("GoPlus request error (attempt %d): %s", attempt, exc)
            return {}

        if resp.status_code == 429:
            wait = BACKOFF_BASE ** (attempt + 1)
            logger.warning("GoPlus rate-limited; sleeping %.1fs", wait)
            time.sleep(wait)
            attempt += 1
            continue

        if not resp.ok:
            logger.warning("GoPlus non-OK %s for %s", resp.status_code, token_address)
            return {}

        try:
            data = resp.json()
        except ValueError:
            logger.warning("GoPlus JSON decode error for %s", token_address)
            return {}

        result = (data.get("result") or {})
        token_data = result.get(token_address.lower()) or result.get(token_address) or {}
        return token_data

    logger.warning("GoPlus max retries exceeded for %s", token_address)
    return {}


def _score_goplus(gp: dict) -> tuple[bool, float]:
    """
    Derive (ok, score 0-100) from GoPlus token security fields.

    Hard-fail on critical flags; deduct points for soft flags.
    Returns (False, 0.0) if any hard-fail flag is set or data is empty.
    """
    if not gp:
        return False, 0.0

    # --- Hard-fail flags (any True → unsafe) ---
    hard_fail_keys = [
        "is_honeypot",
        "is_blacklisted",
        "is_whitelisted",  # whitelist can be used to trap; treat as suspicious
        "hidden_owner",
        "can_take_back_ownership",
        "owner_change_balance",
        "selfdestruct",
        "external_call",
        "is_anti_whale",  # Some anti-whale mechanisms block sells
    ]
    for key in hard_fail_keys:
        if str(gp.get(key, "0")) == "1":
            logger.debug("GoPlus hard-fail flag '%s' for token", key)
            return False, 0.0

    # Honeypot: buy/sell tax > 50% is effectively a honeypot
    try:
        buy_tax = float(gp.get("buy_tax", 0))
        sell_tax = float(gp.get("sell_tax", 0))
    except (TypeError, ValueError):
        buy_tax = sell_tax = 0.0

    if buy_tax > 0.5 or sell_tax > 0.5:
        logger.debug("GoPlus high tax flags: buy=%.2f sell=%.2f", buy_tax, sell_tax)
        return False, 0.0

    # Source code must be verified
    if str(gp.get("is_open_source", "1")) == "0":
        return False, 0.0

    # --- Scoring (start at 100, deduct) ---
    score = 100.0

    if str(gp.get("is_mintable", "0")) == "1":
        score -= 20
    if str(gp.get("can_take_back_ownership", "0")) == "1":
        score -= 20
    if buy_tax > 0.1:
        score -= 10
    if sell_tax > 0.1:
        score -= 10
    if str(gp.get("trading_cooldown", "0")) == "1":
        score -= 10
    if str(gp.get("transfer_pausable", "0")) == "1":
        score -= 15

    lp_holders = gp.get("lp_holders") or []
    # Check if any LP holder is not locked (locked = 1)
    total_lp_pct = 0.0
    locked_lp_pct = 0.0
    for holder in lp_holders:
        pct = float(holder.get("percent", 0))
        total_lp_pct += pct
        if str(holder.get("is_locked", "0")) == "1":
            locked_lp_pct += pct
    if total_lp_pct > 0 and (locked_lp_pct / total_lp_pct) < 0.5:
        score -= 25  # Less than 50% LP locked

    return True, max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Honeypot.is
# ---------------------------------------------------------------------------

def _check_honeypot(token_address: str) -> dict[str, Any]:
    """
    Call Honeypot.is API for BSC (chainID=4).
    Returns parsed dict or {} on any failure.
    """
    # chainID 4 = BSC on honeypot.is  (1=ETH, 4=BSC)
    url = f"{HONEYPOT_BASE}/IsHoneypot"
    params = {"address": token_address.lower(), "chainID": "56"}

    session = _get_session()
    attempt = 0
    while attempt <= MAX_RETRIES:
        try:
            resp = session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("Honeypot.is request error (attempt %d): %s", attempt, exc)
            return {}

        if resp.status_code == 429:
            wait = BACKOFF_BASE ** (attempt + 1)
            logger.warning("Honeypot.is rate-limited; sleeping %.1fs", wait)
            time.sleep(wait)
            attempt += 1
            continue

        if not resp.ok:
            logger.warning("Honeypot.is non-OK %s for %s", resp.status_code, token_address)
            return {}

        try:
            return resp.json()
        except ValueError:
            logger.warning("Honeypot.is JSON decode error for %s", token_address)
            return {}

    logger.warning("Honeypot.is max retries exceeded for %s", token_address)
    return {}


def _score_honeypot(hp: dict) -> tuple[bool, float]:
    """
    Derive (ok, score 0-100) from Honeypot.is response.
    Fail-closed: empty response → (False, 0.0).
    """
    if not hp:
        return False, 0.0

    # Honeypot.is v2: top-level isHoneypot bool
    if hp.get("isHoneypot", True):
        return False, 0.0

    simulation = hp.get("simulationResult") or {}
    buy_tax = float(simulation.get("buyTax", 0) or 0)
    sell_tax = float(simulation.get("sellTax", 0) or 0)

    if buy_tax > 50 or sell_tax > 50:
        return False, 0.0

    score = 100.0
    if buy_tax > 10:
        score -= 10
    if sell_tax > 10:
        score -= 10

    contract_code = hp.get("contractCode") or {}
    if not contract_code.get("isVerified", True):
        return False, 0.0

    return True, max(0.0, min(100.0, score))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_token_security(token_address: str) -> tuple[bool, float, dict]:
    """
    Run GoPlus + Honeypot.is checks on a BSC token.

    Returns:
        ok    – True only if BOTH checks pass (fail-closed).
        score – Combined security score 0–100.
        raw   – Dict with raw API responses for storage.
    """
    token_address = token_address.lower().strip()
    logger.info("Security check: %s", token_address)

    gp_raw = _check_goplus(token_address)
    hp_raw = _check_honeypot(token_address)

    gp_ok, gp_score = _score_goplus(gp_raw)
    hp_ok, hp_score = _score_honeypot(hp_raw)

    ok = gp_ok and hp_ok
    # Average of both scores; if either failed outright the whole thing is 0
    combined_score = ((gp_score + hp_score) / 2.0) if ok else 0.0

    raw = {
        "goplus": gp_raw,
        "honeypot": hp_raw,
        "goplus_ok": gp_ok,
        "honeypot_ok": hp_ok,
        "goplus_score": gp_score,
        "honeypot_score": hp_score,
    }

    logger.info(
        "Security result for %s: ok=%s score=%.1f (gp=%s/%.1f hp=%s/%.1f)",
        token_address,
        ok,
        combined_score,
        gp_ok,
        gp_score,
        hp_ok,
        hp_score,
    )
    return ok, combined_score, raw
