"""
main.py – Orchestrator: ingest → security → persist → analyse → alert.

Run with:
    python main.py

Env vars (see .env.example):
    TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DB_PATH, POLL_INTERVAL_SECONDS, ...
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from types import FrameType

from dotenv import load_dotenv

load_dotenv()

# Module imports (after dotenv so env vars are loaded before module-level reads)
import analyzer
import database
import ingestion
import notifier
import security

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("main")

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
_stop = threading.Event()


def _handle_signal(signum: int, frame: FrameType | None) -> None:
    logger.info("Received signal %s – shutting down gracefully…", signum)
    _stop.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ---------------------------------------------------------------------------
# Core processing logic
# ---------------------------------------------------------------------------

def _process_pairs(conn, pairs: list[dict]) -> None:
    """
    For each pair discovered by the ingestion layer:
      1. Ensure the token is in the DB.
      2. If not yet security-checked, run the security gate (fail-closed).
      3. Always persist a snapshot (even for unsafe tokens – kept for analysis).
      4. Skip analysis/alert if security did not pass.
      5. On the first secure snapshot, run the analyser.
      6. If signal fires and no prior alert → send Telegram + persist alert.
    """
    for pair in pairs:
        if _stop.is_set():
            break

        token_address = pair["base_token_address"]
        if not token_address:
            continue

        # --- 1. Upsert token ---
        database.upsert_token(
            conn,
            address=token_address,
            name=pair["base_token_name"],
            symbol=pair["base_token_symbol"],
            chain_id=pair["chain_id"],
        )

        token_row = database.get_token(conn, token_address)

        # --- 2. Security gate (fail-closed) ---
        if not token_row["security_checked_at"]:
            ok, score, raw = security.check_token_security(token_address)
            database.update_token_security(conn, token_address, ok, score, raw)
            token_row = database.get_token(conn, token_address)
            logger.info(
                "security_result token=%s ok=%s score=%.1f",
                token_address,
                bool(token_row["security_ok"]),
                float(token_row["security_score"]),
            )

        # --- 3. Always persist snapshot (safe and unsafe tokens alike) ---
        # Unsafe-token snapshots are kept in the DB for later offline analysis.
        snap_id = database.insert_snapshot(
            conn,
            token_address=token_address,
            pair_address=pair["pair_address"],
            dex_id=pair["dex_id"],
            price_usd=pair["price_usd"] or None,
            liq_usd=pair["liq_usd"] or None,
            vol_5m_usd=pair["vol_5m_usd"] or None,
            buys_5m=pair["buys_5m"] or None,
            sells_5m=pair["sells_5m"] or None,
            fdv=pair["fdv"] or None,
            pair_url=pair["url"],
        )
        logger.info(
            "snapshot_insert id=%s token=%s pair=%s security_ok=%s liq=%.0f vol5m=%.0f",
            snap_id,
            token_address,
            pair["pair_address"],
            bool(token_row["security_ok"]),
            pair["liq_usd"] or 0,
            pair["vol_5m_usd"] or 0,
        )

        # --- 4. Skip analysis for unsafe tokens ---
        if not token_row["security_ok"]:
            logger.debug(
                "token=%s security_ok=False – snapshot stored, analysis skipped",
                token_address,
            )
            continue

        # --- 5. Analyse first secure snapshot ---
        # Only analyse once (when no alert exists yet)
        if database.has_alert(conn, token_address):
            logger.debug("alert_dedupe token=%s – already alerted, skipping", token_address)
            continue

        snap = database.get_first_secure_snapshot(conn, token_address)
        if snap is None:
            continue

        result = analyzer.analyse_snapshot(
            token_address=token_address,
            security_score=float(token_row["security_score"]),
            liq_usd=snap["liq_usd"],
            vol_5m_usd=snap["vol_5m_usd"],
            buys_5m=snap["buys_5m"],
            sells_5m=snap["sells_5m"],
            fdv=snap["fdv"],
            price_usd=snap["price_usd"],
        )
        logger.info(
            "signal_eval token=%s signal=%s score=%.1f reason=%s",
            token_address,
            result.signal,
            result.score,
            result.reason,
        )

        if not result.signal:
            continue

        # --- 6. Alert ---
        inserted = database.insert_alert(
            conn,
            token_address=token_address,
            score=result.score,
            reason=result.reason,
            metrics=result.metrics,
        )

        if not inserted:
            # Another run already alerted – skip Telegram
            logger.info("alert_dedupe token=%s – concurrent insert lost race, skipping notify", token_address)
            continue

        logger.info(
            "alert_triggered token=%s score=%.1f reason=%s",
            token_address,
            result.score,
            result.reason,
        )
        notifier.send_alert(
            token_address=token_address,
            name=token_row["name"],
            symbol=token_row["symbol"],
            score=result.score,
            reason=result.reason,
            metrics=result.metrics,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    logger.info("=== Cazador de Gemas BSC starting ===")

    db_path = os.getenv("DB_PATH", "gems.db")
    conn = database.init_db(db_path)

    def _ingestion_callback(pairs: list[dict]) -> None:
        logger.info("ingestion_batch pairs_discovered=%d", len(pairs))
        try:
            _process_pairs(conn, pairs)
        except Exception as exc:
            logger.exception("Unhandled error in processing loop: %s", exc)

    logger.info("Entering ingestion loop…")
    try:
        ingestion.run_ingestion_loop(_ingestion_callback, stop_event=_stop)
    finally:
        conn.close()
        logger.info("DB connection closed. Bye.")


if __name__ == "__main__":
    main()
