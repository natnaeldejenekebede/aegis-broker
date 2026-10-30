from __future__ import annotations

import sqlite3
from typing import Any

from app.config import BrokerConfig


class SQLPolicyError(Exception):
    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


def classify_and_execute_sql(
    config: BrokerConfig,
    sql: str,
    params: list[Any],
    sql_read_only: bool,
    execute_now: bool = True,
) -> tuple[bool, list[dict[str, Any]]]:
    """
    Starter implementation (VULNERABLE):
    Uses a naive substring check ('SELECT' in upper) without sqlite3.set_authorizer
    and falls back to executescript when multiple statements are present.
    """
    stripped = (sql or "").strip()
    if not stripped:
        raise SQLPolicyError(400, "SQL_POLICY_VIOLATION", "Empty SQL statement")

    upper = stripped.upper()
    # Naive check: assumes any query containing SELECT is a read query
    is_write = "SELECT" not in upper

    if sql_read_only and is_write:
        raise SQLPolicyError(
            403, "SQL_POLICY_VIOLATION", "Write query blocked in read-only mode"
        )

    if not execute_now:
        return is_write, []

    conn = sqlite3.connect(config.app_db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        if ";" in stripped.rstrip(";"):
            cur.executescript(stripped)
            rows = []
        else:
            cur.execute(stripped, params)
            rows = [dict(r) for r in cur.fetchall()]
        conn.commit()
        return is_write, rows
    except sqlite3.Error as exc:
        conn.rollback()
        raise SQLPolicyError(403, "SQL_POLICY_VIOLATION", str(exc)) from exc
    finally:
        conn.close()
