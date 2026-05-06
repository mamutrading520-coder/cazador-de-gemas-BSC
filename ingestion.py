"""
ingestion.py – Poll DexScreener for new BSC PancakeSwap v2/v3 pairs.

Discovers recently-added pairs filtered to PancakeSwap v2/v3 on BSC,
extracts key metrics and returns a list of normalised dicts.
Poll interval is 10–20 s (configurable via POLL_INTERVAL_SECONDS env var).
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
DEXSCREENER_BASE = "https://api.dexscreener.com"
# /latest/dex/search supports chainId + dexId filters via query params
# The "new pairs" endpoint returns recently listed pairs across all chains.
NEW_PAIRS_URL = f"{DEXSCREENER_BASE}/latest/dex/search"
# DexScreener also exposes /latest/dex/tokens/{tokenAddress} and
# /latest/dex/pairs/bsc/{pairAddress} – used for enrichment below.

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))

PANCAKESWAP_DEX_IDS = {"pancakeswap", "pancakeswapv3", "pancakeswap-v2", "pancakeswap-v3"}
BSC_CHAIN_ID = "bsc"

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))

# ---------------------------------------------------------------------------
# Session with retry / back-off
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[429, 500, 502, 503, 504],
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
# Helpers
# ---------------------------------------------------------------------------

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalise_pair(pair: dict) -> dict | None:
    """Extract and normalise the fields we care about from a DexScreener pair object."""
    chain_id = (pair.get("chainId") or "").lower()
    dex_id = (pair.get("dexId") or "").lower()

    if chain_id != BSC_CHAIN_ID:
        return None
    # DexScreener uses "pancakeswap", "pancakeswap-v2", "pancakeswap-v3" etc.
    # All PancakeSwap variants share the "pancakeswap" prefix.
    if not dex_id.startswith("pancakeswap"):
        return None

    base_token = pair.get("baseToken") or {}
    quote_token = pair.get("quoteToken") or {}

    liquidity = pair.get("liquidity") or {}
    volume = pair.get("volume") or {}
    txns = pair.get("txns") or {}
    txns_m5 = txns.get("m5") or {}

    fdv = _safe_float(pair.get("fdv"))
    liq_usd = _safe_float(liquidity.get("usd"))
    vol_5m = _safe_float(volume.get("m5"))
    buys_5m = _safe_int(txns_m5.get("buys"))
    sells_5m = _safe_int(txns_m5.get("sells"))
    price_usd = _safe_float(pair.get("priceUsd"))

    pair_created_at = pair.get("pairCreatedAt")  # epoch ms

    return {
        "chain_id": chain_id,
        "dex_id": dex_id,
        "pair_address": (pair.get("pairAddress") or "").lower(),
        "base_token_address": (base_token.get("address") or "").lower(),
        "base_token_name": base_token.get("name") or "",
        "base_token_symbol": base_token.get("symbol") or "",
        "quote_token_address": (quote_token.get("address") or "").lower(),
        "quote_token_symbol": quote_token.get("symbol") or "",
        "price_usd": price_usd,
        "liq_usd": liq_usd,
        "vol_5m_usd": vol_5m,
        "buys_5m": buys_5m,
        "sells_5m": sells_5m,
        "fdv": fdv,
        "pair_created_at_ms": pair_created_at,
        "url": pair.get("url") or "",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fetch_new_bsc_pairs() -> list[dict]:
    """
    Query DexScreener for recently listed BSC PancakeSwap pairs.

    Returns a (possibly empty) list of normalised pair dicts.
    On any error, logs and returns [].
    """
    session = _get_session()

    # DexScreener /latest/dex/search?q=<query> returns pairs matching the query.
    # Using a broad BSC-specific query.  The "new pairs" page uses the same
    # endpoint with chainId filtering applied client-side.
    params = {"q": "BSC"}
    try:
        resp = session.get(NEW_PAIRS_URL, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("DexScreener request failed: %s", exc)
        return []

    if resp.status_code == 429:
        retry_after = int(resp.headers.get("Retry-After", "30"))
        logger.warning("DexScreener rate-limited; sleeping %ss", retry_after)
        time.sleep(retry_after)
        return []

    if not resp.ok:
        logger.warning("DexScreener non-OK response: %s", resp.status_code)
        return []

    try:
        data = resp.json()
    except ValueError as exc:
        logger.error("DexScreener JSON decode error: %s", exc)
        return []

    raw_pairs = data.get("pairs") or []
    results: list[dict] = []
    for raw in raw_pairs:
        normalised = _normalise_pair(raw)
        if normalised is not None:
            results.append(normalised)

    logger.info("DexScreener returned %d BSC PancakeSwap pair(s)", len(results))
    return results


# ---------------------------------------------------------------------------
# Polling loop (used by main.py)
# ---------------------------------------------------------------------------

def run_ingestion_loop(callback, stop_event=None):
    """
    Continuously poll DexScreener every POLL_INTERVAL_SECONDS seconds.

    :param callback: callable(pairs: list[dict]) invoked with each batch.
    :param stop_event: optional threading.Event; loop exits when set.
    """
    logger.info("Ingestion loop started (interval=%ss)", POLL_INTERVAL_SECONDS)
    while True:
        if stop_event and stop_event.is_set():
            logger.info("Ingestion loop stopping.")
            break
        pairs = fetch_new_bsc_pairs()
        if pairs:
            callback(pairs)
        time.sleep(POLL_INTERVAL_SECONDS)
