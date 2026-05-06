"""
database.py – SQLite persistence layer.

Schema designed for easy migration to PostgreSQL later:
- tokens      : one row per unique base token discovered
- snapshots   : market-data snapshot per token per poll cycle
- alerts      : de-duplicated signal alerts (one per token)

All timestamps are stored as ISO-8601 UTC strings for portability.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "gems.db")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = [
    """
    CREATE TABLE IF NOT EXISTS tokens (
        address         TEXT PRIMARY KEY,
        name            TEXT NOT NULL DEFAULT '',
        symbol          TEXT NOT NULL DEFAULT '',
        chain_id        TEXT NOT NULL DEFAULT 'bsc',
        first_seen_at   TEXT NOT NULL,
        security_ok     INTEGER NOT NULL DEFAULT 0,
        security_score  REAL NOT NULL DEFAULT 0.0,
        security_raw    TEXT,
        security_checked_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS snapshots (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        token_address   TEXT NOT NULL REFERENCES tokens(address),
        pair_address    TEXT NOT NULL DEFAULT '',
        dex_id          TEXT NOT NULL DEFAULT '',
        captured_at     TEXT NOT NULL,
        price_usd       REAL,
        liq_usd         REAL,
        vol_5m_usd      REAL,
        buys_5m         INTEGER,
        sells_5m        INTEGER,
        fdv             REAL,
        pair_url        TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        token_address   TEXT NOT NULL UNIQUE REFERENCES tokens(address),
        alerted_at      TEXT NOT NULL,
        score           REAL NOT NULL DEFAULT 0.0,
        reason          TEXT,
        metrics_json    TEXT
    )
    """,
    # Indexes for common lookups
    "CREATE INDEX IF NOT EXISTS idx_snapshots_token ON snapshots(token_address)",
    "CREATE INDEX IF NOT EXISTS idx_snapshots_captured ON snapshots(captured_at)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_token ON alerts(token_address)",
]


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """
    Open a SQLite connection.

    Note: check_same_thread=False is safe here because the pipeline is
    single-threaded (one orchestrator loop, no concurrent writers).
    WAL mode provides additional safety for potential read-only queries
    from other processes. If you add multi-threading, add explicit
    locking or use a connection-per-thread pattern.
    """
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _tx(conn: sqlite3.Connection):
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Initialise the database, run DDL, and return the connection."""
    logger.info("Initialising DB at %s", db_path)
    conn = get_connection(db_path)
    with _tx(conn):
        for stmt in _DDL:
            conn.execute(stmt)
    logger.info("DB schema ready.")
    return conn


# ---------------------------------------------------------------------------
# Token operations
# ---------------------------------------------------------------------------

def upsert_token(
    conn: sqlite3.Connection,
    address: str,
    name: str,
    symbol: str,
    chain_id: str = "bsc",
) -> None:
    """Insert token if not present; ignore if already exists."""
    now = _now()
    with _tx(conn):
        conn.execute(
            """
            INSERT INTO tokens (address, name, symbol, chain_id, first_seen_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(address) DO NOTHING
            """,
            (address.lower(), name, symbol, chain_id, now),
        )


def update_token_security(
    conn: sqlite3.Connection,
    address: str,
    ok: bool,
    score: float,
    raw: dict,
) -> None:
    now = _now()
    with _tx(conn):
        conn.execute(
            """
            UPDATE tokens
            SET security_ok=?, security_score=?, security_raw=?, security_checked_at=?
            WHERE address=?
            """,
            (int(ok), score, json.dumps(raw), now, address.lower()),
        )


def get_token(conn: sqlite3.Connection, address: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM tokens WHERE address=?", (address.lower(),)
    ).fetchone()


# ---------------------------------------------------------------------------
# Snapshot operations
# ---------------------------------------------------------------------------

def insert_snapshot(
    conn: sqlite3.Connection,
    token_address: str,
    pair_address: str,
    dex_id: str,
    price_usd: float | None,
    liq_usd: float | None,
    vol_5m_usd: float | None,
    buys_5m: int | None,
    sells_5m: int | None,
    fdv: float | None,
    pair_url: str = "",
) -> int:
    """Insert a market-data snapshot; returns the new row id."""
    now = _now()
    with _tx(conn):
        cur = conn.execute(
            """
            INSERT INTO snapshots
                (token_address, pair_address, dex_id, captured_at,
                 price_usd, liq_usd, vol_5m_usd, buys_5m, sells_5m, fdv, pair_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token_address.lower(),
                pair_address.lower(),
                dex_id,
                now,
                price_usd,
                liq_usd,
                vol_5m_usd,
                buys_5m,
                sells_5m,
                fdv,
                pair_url,
            ),
        )
    return cur.lastrowid


def get_first_secure_snapshot(
    conn: sqlite3.Connection, token_address: str
) -> sqlite3.Row | None:
    """
    Return the earliest snapshot for a token that was captured after security
    was confirmed (i.e. after the token's security_checked_at timestamp).
    """
    token = get_token(conn, token_address)
    if not token or not token["security_checked_at"]:
        return None
    return conn.execute(
        """
        SELECT s.*
        FROM snapshots s
        WHERE s.token_address = ?
          AND s.captured_at >= ?
        ORDER BY s.captured_at ASC
        LIMIT 1
        """,
        (token_address.lower(), token["security_checked_at"]),
    ).fetchone()


# ---------------------------------------------------------------------------
# Alert operations
# ---------------------------------------------------------------------------

def has_alert(conn: sqlite3.Connection, token_address: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM alerts WHERE token_address=?", (token_address.lower(),)
    ).fetchone()
    return row is not None


def insert_alert(
    conn: sqlite3.Connection,
    token_address: str,
    score: float,
    reason: str,
    metrics: dict[str, Any],
) -> bool:
    """
    Insert an alert. Returns True if inserted, False if already existed
    (dedup guarantee: one alert per token across restarts).
    """
    now = _now()
    try:
        with _tx(conn):
            conn.execute(
                """
                INSERT INTO alerts (token_address, alerted_at, score, reason, metrics_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    token_address.lower(),
                    now,
                    score,
                    reason,
                    json.dumps(metrics),
                ),
            )
        return True
    except sqlite3.IntegrityError:
        logger.debug("Alert already exists for %s – skipping duplicate", token_address)
        return False


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
