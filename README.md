# Cazador de Gemas BSC

A real-time (polling) BSC PancakeSwap v2/v3 **gem hunter** pipeline.

Uses [DexScreener](https://dexscreener.com/) for market-data discovery and enrichment,
[GoPlus Security](https://gopluslabs.io/) + [Honeypot.is](https://honeypot.is/) for
security gating, SQLite for persistence, and Telegram for alert delivery.

> **This is an analysis-only tool. It never executes trades and never holds or handles private keys.**

---

## Architecture

```
DexScreener API (polling)
        |
        v
  ingestion.py   --  Discover BSC PancakeSwap v2/v3 pairs every ~15 s
                     (explicit dexId allowlist: pancakeswap, pancakeswap-v2,
                      pancakeswap-v3 and non-hyphenated variants)
        |
        v
  security.py    --  GoPlus + Honeypot.is (fail-closed gate)
        |
        +--[UNSAFE]--> database.py  --  Persist snapshot for later analysis
        |                               (no alert, no analysis for unsafe tokens)
        |
        | [SAFE]
        v
  database.py    --  Persist token + snapshot in SQLite
        |
        v
  analyzer.py    --  Heuristic quantitative scoring on first secure snapshot
        |  (signal)
        v
  notifier.py    --  Telegram Bot API alert (no-op when creds absent)
        |
        v
  database.py    --  Persist alert (de-duplicated across restarts)
```

### Module summary

| Module | Responsibility |
|---|---|
| `ingestion.py` | Poll DexScreener; filter PancakeSwap v2/v3 on BSC; extract liquidity, volume 5m, txns 5m, FDV, price |
| `security.py` | GoPlus + Honeypot.is checks; returns `(ok, score, raw_json)`; fail-closed on API errors |
| `database.py` | SQLite schema (tokens, snapshots, alerts); dedup alerts across restarts |
| `analyzer.py` | Heuristic scoring against configurable thresholds; no analysis before security gate |
| `notifier.py` | Telegram Bot notifications with retries and rate-limit handling |
| `main.py` | Orchestrator loop tying all modules together |

---

## Requirements

- Python 3.10+
- A Telegram bot token and chat ID (optional -- alerts are logged if not configured)

---

## Quick start

```bash
# 1. Clone and enter the directory
git clone https://github.com/mamutrading520-coder/cazador-de-gemas-BSC.git
cd cazador-de-gemas-BSC

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
cp .env.example .env
# Edit .env -- at minimum set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
# (leave them blank to run in log-only mode)

# 5. Run
python main.py
```

Press **Ctrl-C** to stop. The pipeline shuts down gracefully.

---

## Configuration

All settings are read from `.env` (or environment variables directly).
See `.env.example` for the full list with descriptions.

### Analyser thresholds

| Variable | Default | Description |
|---|---|---|
| `MIN_LIQ_USD` | `12000` | Minimum liquidity in USD |
| `MIN_VOL5_USD` | `25000` | Minimum 5-minute volume in USD |
| `MIN_BUY_RATIO` | `0.65` | Minimum buy/(buy+sell) transaction ratio |
| `MAX_FDV_TO_LIQ` | `250` | Maximum FDV-to-liquidity ratio |
| `MIN_SECURITY_SCORE` | `60` | Minimum combined security score (0-100) |

### Telegram

| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Target chat or channel ID |

If either variable is empty the notifier logs alerts to stdout instead of
sending them to Telegram, so the pipeline still runs fully.

### Poll interval

| Variable | Default | Description |
|---|---|
| `POLL_INTERVAL_SECONDS` | `15` | Seconds between DexScreener polls (10-20 recommended) |

---

## Database

SQLite database stored at `DB_PATH` (default `gems.db`).

### Schema

```sql
tokens      -- one row per unique base token
snapshots   -- market-data snapshot per token per poll cycle
alerts      -- de-duplicated signals (one alert per token, ever)
```

The schema is designed for straightforward migration to PostgreSQL: column types
and constraints are PostgreSQL-compatible; the only SQLite-specific syntax used
is `AUTOINCREMENT` (-> `SERIAL`/`BIGSERIAL` in Postgres) and `INTEGER PRIMARY KEY`
(-> `BIGINT PRIMARY KEY`).

---

## Security design

- **Fail-closed**: if GoPlus or Honeypot.is APIs return an error, time out, or
  return an empty response, the token is treated as **unsafe** and skipped.
- **No analysis before security**: price/volume analysis only runs on snapshots
  captured *after* the security check passes.
- **Unsafe token storage**: snapshots for tokens that fail the security gate are
  still persisted in SQLite (table `snapshots`, `security_ok=0`).  They are
  never analysed or alerted, but they are available for offline research and
  threshold calibration.
- **No auto-trading**: the system has no wallet integration; it only reads
  public market data and sends read-only alerts.

---

## License

MIT
