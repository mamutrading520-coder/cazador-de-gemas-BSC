"""
ingestion.py – Poll DexScreener for new BSC PancakeSwap v2/v3 pairs.

Discovers recently-added pairs filtered to PancakeSwap v2/v3 on BSC,
extracts key metrics and returns a list of normalised dicts.
Poll interval is 10–20 s (configurable via POLL_INTERVAL_SECONDS env var).

Discovery strategy
------------------
We use the DexScreener REST endpoint /latest/dex/search?q=BSC (no scraping).
This returns a broad mix of BSC pairs; we apply two layers of client-side
filtering:

  1. chainId == "bsc"          (BSC only)
  2. dexId in PANCAKESWAP_DEX_IDS  (explicit PancakeSwap v2/v3 allowlist)

Limitation: the search endpoint ranks pairs by relevance, not creation time,
so we may miss brand-new pairs that haven't accumulated enough activity yet.
The PANCAKESWAP_DEX_IDS allowlist ensures we never ingest pairs from other
DEXes regardless of how the search endpoint evolves.
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

# Primary discovery endpoint.
# /latest/dex/search?q=BSC returns BSC-related pairs ranked by relevance.
# Client-side filtering by chainId + PANCAKESWAP_DEX_IDS is applied afterwards.
SEARCH_URL = f"{DEXSCREENER_BASE}/latest/dex/search"

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))

# Explicit allowlist of DexScreener dexId values that correspond to
# PancakeSwap v2 or v3 on BSC.  Any pair whose dexId is NOT in this set
# is silently dropped, regardless of what the search endpoint returns.
PANCAKESWAP_DEX_IDS: frozenset[str] = frozenset({
    "pancakeswap",       # PancakeSwap v2 (canonical id used by DexScreener)
    "pancakeswap-v2",    # alternate hyphenated form observed in API responses
    "pancakeswapv2",     # alternate non-hyphenated form
    "pancakeswap-v3",    # PancakeSwap v3
    "pancakeswapv3",     # alternate non-hyphenated form
})

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
    # Strict allowlist: only accept the exact dexId values we know correspond
    # to PancakeSwap v2 or v3 on BSC.  This prevents pairs from other DEXes
    # (e.g. Biswap, ApeSwap) from slipping through even if a future search
    # result includes them.
    if dex_id not in PANCAKESWAP_DEX_IDS:
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

    Uses /latest/dex/search?q=BSC then applies client-side filtering:
      - chainId must be "bsc"
      - dexId must be in PANCAKESWAP_DEX_IDS (explicit v2/v3 allowlist)

    Returns a (possibly empty) list of normalised pair dicts.
    On any error, logs and returns [] (fail-safe for callers).
    """
    session = _get_session()

    params = {"q": "BSC"}
    try:
        resp = session.get(SEARCH_URL, params=params, timeout=REQUEST_TIMEOUT)
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
    logger.debug("DexScreener raw pairs returned by search: %d", len(raw_pairs))

    results: list[dict] = []
    skipped_chain = 0
    skipped_dex = 0
    for raw in raw_pairs:
        chain_id = (raw.get("chainId") or "").lower()
        dex_id = (raw.get("dexId") or "").lower()
        if chain_id != BSC_CHAIN_ID:
            skipped_chain += 1
            continue
        if dex_id not in PANCAKESWAP_DEX_IDS:
            skipped_dex += 1
            continue
        normalised = _normalise_pair(raw)
        if normalised is not None:
            results.append(normalised)

    logger.info(
        "DexScreener discovery: raw=%d bsc_pancakeswap=%d skipped_chain=%d skipped_dex=%d",
        len(raw_pairs),
        len(results),
        skipped_chain,
        skipped_dex,
    )
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
