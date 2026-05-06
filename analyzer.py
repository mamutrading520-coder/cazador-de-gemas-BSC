"""
analyzer.py – Heuristic quantitative scoring of the first secure snapshot.

Thresholds are configurable via environment variables (see DEFAULTS below).
Returns an AnalysisResult dataclass with score, signal flag, and reason.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configurable thresholds (all overridable via env)
# ---------------------------------------------------------------------------

MIN_LIQ_USD: float = float(os.getenv("MIN_LIQ_USD", "12000"))
MIN_VOL5_USD: float = float(os.getenv("MIN_VOL5_USD", "25000"))
MIN_BUY_RATIO: float = float(os.getenv("MIN_BUY_RATIO", "0.65"))
MAX_FDV_TO_LIQ: float = float(os.getenv("MAX_FDV_TO_LIQ", "250"))

# Security score floor required before analysis is considered meaningful
MIN_SECURITY_SCORE: float = float(os.getenv("MIN_SECURITY_SCORE", "60"))


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    token_address: str
    signal: bool            # True = "gem candidate", False = no signal
    score: float            # 0–100 heuristic score
    reason: str             # Human-readable explanation
    metrics: dict[str, Any] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------

def analyse_snapshot(
    token_address: str,
    security_score: float,
    liq_usd: float | None,
    vol_5m_usd: float | None,
    buys_5m: int | None,
    sells_5m: int | None,
    fdv: float | None,
    price_usd: float | None = None,
) -> AnalysisResult:
    """
    Evaluate a single snapshot for gem-candidate signals.

    Scoring rubric (each criterion contributes up to a weight; signal requires
    all hard thresholds to pass):

    Hard thresholds (fail any → no signal):
      1. liq_usd   >= MIN_LIQ_USD
      2. vol_5m    >= MIN_VOL5_USD
      3. buy_ratio >= MIN_BUY_RATIO   (buys / (buys + sells))
      4. fdv / liq <= MAX_FDV_TO_LIQ  (if both are present)

    Soft score (0–100):
      - Liquidity strength      (25 pts)
      - Volume strength         (25 pts)
      - Buy pressure            (25 pts)
      - FDV sanity              (25 pts)
    """
    metrics: dict[str, Any] = {
        "token_address": token_address,
        "security_score": security_score,
        "liq_usd": liq_usd,
        "vol_5m_usd": vol_5m_usd,
        "buys_5m": buys_5m,
        "sells_5m": sells_5m,
        "fdv": fdv,
        "price_usd": price_usd,
    }

    failures: list[str] = []

    # --- Safe coercion ---
    liq = float(liq_usd or 0)
    vol = float(vol_5m_usd or 0)
    buys = int(buys_5m or 0)
    sells = int(sells_5m or 0)
    fdv_val = float(fdv or 0)

    total_txns = buys + sells
    buy_ratio = (buys / total_txns) if total_txns > 0 else 0.0
    metrics["buy_ratio"] = buy_ratio

    fdv_to_liq = (fdv_val / liq) if liq > 0 and fdv_val > 0 else None
    metrics["fdv_to_liq"] = fdv_to_liq

    # --- Hard threshold checks ---
    if liq < MIN_LIQ_USD:
        failures.append(f"liq_usd={liq:.0f} < MIN_LIQ_USD={MIN_LIQ_USD:.0f}")

    if vol < MIN_VOL5_USD:
        failures.append(f"vol_5m={vol:.0f} < MIN_VOL5_USD={MIN_VOL5_USD:.0f}")

    if total_txns == 0 or buy_ratio < MIN_BUY_RATIO:
        failures.append(
            f"buy_ratio={buy_ratio:.2f} < MIN_BUY_RATIO={MIN_BUY_RATIO:.2f}"
            + (" (no txns)" if total_txns == 0 else "")
        )

    if fdv_to_liq is not None and fdv_to_liq > MAX_FDV_TO_LIQ:
        failures.append(
            f"fdv_to_liq={fdv_to_liq:.1f} > MAX_FDV_TO_LIQ={MAX_FDV_TO_LIQ:.0f}"
        )

    signal = len(failures) == 0

    # --- Soft score (always computed, useful for ranking) ---
    score_parts: list[float] = []

    # Liquidity (25 pts): full marks at 3× minimum
    liq_pts = min(25.0, 25.0 * (liq / (MIN_LIQ_USD * 3))) if liq > 0 else 0.0
    score_parts.append(liq_pts)

    # Volume 5m (25 pts): full marks at 3× minimum
    vol_pts = min(25.0, 25.0 * (vol / (MIN_VOL5_USD * 3))) if vol > 0 else 0.0
    score_parts.append(vol_pts)

    # Buy ratio (25 pts): linear from MIN_BUY_RATIO to 1.0
    if total_txns > 0:
        buy_pts = max(
            0.0,
            min(25.0, 25.0 * (buy_ratio - MIN_BUY_RATIO) / (1.0 - MIN_BUY_RATIO)),
        )
    else:
        buy_pts = 0.0
    score_parts.append(buy_pts)

    # FDV/Liq ratio (25 pts): lower is better; 0 pts when at max threshold
    if fdv_to_liq is not None:
        fdv_pts = max(
            0.0, min(25.0, 25.0 * (1.0 - fdv_to_liq / MAX_FDV_TO_LIQ))
        )
    else:
        # No FDV data – give half marks (data absence is neither good nor bad)
        fdv_pts = 12.5
    score_parts.append(fdv_pts)

    raw_score = sum(score_parts)
    metrics["score_parts"] = {
        "liq_pts": liq_pts,
        "vol_pts": vol_pts,
        "buy_pts": buy_pts,
        "fdv_pts": fdv_pts,
    }

    if signal:
        reason = (
            f"SIGNAL: liq=${liq:,.0f} vol5m=${vol:,.0f} "
            f"buy_ratio={buy_ratio:.0%} fdv_liq={fdv_to_liq:.1f}x"
            if fdv_to_liq is not None
            else f"SIGNAL: liq=${liq:,.0f} vol5m=${vol:,.0f} buy_ratio={buy_ratio:.0%}"
        )
    else:
        reason = "NO SIGNAL: " + "; ".join(failures)

    logger.info(
        "Analysis %s → signal=%s score=%.1f | %s",
        token_address,
        signal,
        raw_score,
        reason,
    )

    return AnalysisResult(
        token_address=token_address,
        signal=signal,
        score=raw_score,
        reason=reason,
        metrics=metrics,
        failures=failures,
    )
