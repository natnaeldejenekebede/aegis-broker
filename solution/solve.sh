#!/bin/bash
set -euo pipefail

WORKSPACE_DIR="${AEGIS_WORKSPACE:-/workspace}"
APP_DIR="${WORKSPACE_DIR}/app"

cat <<'EOF' > "${APP_DIR}/canonicalize.py"
from __future__ import annotations

import os
import posixpath
import re
import stat
import unicodedata
from pathlib import Path, PurePosixPath

from app.config import BrokerConfig


class PathSecurityError(Exception):
    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


_PERCENT_ENC_RE = re.compile(r"%[0-9a-fA-F]{2}")


def normalize_pure_sandbox_path(config: BrokerConfig, raw_path: str) -> PurePosixPath:
    if not raw_path or not isinstance(raw_path, str):
        raise PathSecurityError(400, "INVALID_PATH_ENCODING", "Path must be a non-empty string")

    if "\x00" in raw_path or any(ord(ch) < 32 for ch in raw_path):
        raise PathSecurityError(400, "INVALID_PATH_ENCODING", "Path contains control characters or null byte")

    if _PERCENT_ENC_RE.search(raw_path):
        raise PathSecurityError(400, "INVALID_PATH_ENCODING", "Percent-encoded path segments are forbidden")

    nfc_path = unicodedata.normalize("NFC", raw_path)
    if not nfc_path.startswith("/"):
        raise PathSecurityError(400, "INVALID_PATH_ENCODING", "Path must be absolute")

    norm_str = posixpath.normpath(nfc_path)
    target_pure = PurePosixPath(norm_str)

    sandbox_pure = PurePosixPath(posixpath.normpath(str(config.sandbox_root)))
    if not target_pure.is_relative_to(sandbox_pure):
        raise PathSecurityError(403, "PATH_BOUNDARY_VIOLATION", "Target path escapes sandbox root")

    # Walk every component from sandbox_root down to target_pure and reject symlinks
    rel_parts = target_pure.relative_to(sandbox_pure).parts
    curr = Path(str(sandbox_pure))
    if os.path.lexists(curr):
        st0 = os.lstat(curr)
        if stat.S_ISLNK(st0.st_mode):
            raise PathSecurityError(403, "PATH_SYMLINK_FORBIDDEN", "Sandbox root is a symlink")

    for part in rel_parts:
        curr = curr / part
        if os.path.lexists(curr):
            st = os.lstat(curr)
            if stat.S_ISLNK(st.st_mode):
                raise PathSecurityError(
                    403, "PATH_SYMLINK_FORBIDDEN", f"Symlink component forbidden: {curr}"
                )

    return target_pure


def canonicalize_sandbox_path(
    config: BrokerConfig,
    raw_path: str,
    allowed_prefixes: list[str] | None = None,
) -> Path:
    target_pure = normalize_pure_sandbox_path(config, raw_path)

    if allowed_prefixes is not None:
        norm_prefixes = [normalize_pure_sandbox_path(config, p) for p in allowed_prefixes]
        if not any(target_pure.is_relative_to(pref) for pref in norm_prefixes):
            raise PathSecurityError(
                403, "PATH_BOUNDARY_VIOLATION", "Target path is outside allowed prefixes"
            )

    return Path(str(target_pure))
EOF

cat <<'EOF' > "${APP_DIR}/tokens.py"
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from pathlib import PurePosixPath
from typing import Any

from app.canonicalize import normalize_pure_sandbox_path
from app.config import BrokerConfig
from app.models import CapabilityToken, Caveat


class TokenPolicyError(Exception):
    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _compute_root_hmac(
    root_key_hex: str, hop_id: str, principal: str, issued_at: int, caveat: Caveat
) -> str:
    payload = {
        "caveat": caveat.to_dict(),
        "hop_id": hop_id,
        "issued_at": issued_at,
        "principal": principal,
    }
    return hmac.new(
        bytes.fromhex(root_key_hex),
        canonical_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()


def _compute_hop_hmac(prev_sig_hex: str, hop_id: str, caveat: Caveat) -> str:
    payload = {
        "caveat": caveat.to_dict(),
        "hop_id": hop_id,
    }
    return hmac.new(
        bytes.fromhex(prev_sig_hex),
        canonical_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()


def _validate_caveat_self(config: BrokerConfig, caveat: Caveat) -> list[PurePosixPath]:
    tools_set = set(caveat.allowed_tools)
    if not tools_set:
        raise TokenPolicyError(403, "PRIVILEGE_ESCALATION_ATTEMPT", "allowed_tools cannot be empty")

    needs_fs = bool(tools_set & {"fs.read", "fs.write"})
    norm_prefixes = [
        normalize_pure_sandbox_path(config, p) for p in caveat.allowed_path_prefixes
    ]
    if needs_fs and not norm_prefixes:
        raise TokenPolicyError(
            403,
            "PRIVILEGE_ESCALATION_ATTEMPT",
            "Filesystem tools require at least one allowed_path_prefix",
        )
    return norm_prefixes


def _validate_narrowing_step(
    config: BrokerConfig,
    parent_tools: set[str],
    parent_prefixes: list[PurePosixPath],
    parent_sql_ro: bool,
    parent_max_calls: int,
    parent_expires_at: int,
    child_caveat: Caveat,
) -> tuple[set[str], list[PurePosixPath], bool, int, int]:
    child_prefixes = _validate_caveat_self(config, child_caveat)
    child_tools = set(child_caveat.allowed_tools)

    # 1. Tools must be subset of parent tools
    if not child_tools.issubset(parent_tools):
        raise TokenPolicyError(
            403, "PRIVILEGE_ESCALATION_ATTEMPT", "Child caveat widens allowed_tools"
        )

    # 2. Path prefixes must be contained within parent prefixes
    for cp in child_prefixes:
        if not any(cp.is_relative_to(pp) for pp in parent_prefixes):
            raise TokenPolicyError(
                403, "PRIVILEGE_ESCALATION_ATTEMPT", f"Child prefix {cp} widens parent prefixes"
            )

    # 3. SQL read-only cannot be relaxed from True to False
    if parent_sql_ro and not child_caveat.sql_read_only:
        raise TokenPolicyError(
            403, "PRIVILEGE_ESCALATION_ATTEMPT", "Cannot relax sql_read_only from True to False"
        )

    # 4. Expiration cannot exceed parent
    if child_caveat.expires_at > parent_expires_at:
        raise TokenPolicyError(
            403, "PRIVILEGE_ESCALATION_ATTEMPT", "Child expires_at exceeds parent expires_at"
        )

    # 5. Max calls cannot exceed parent
    if child_caveat.max_calls > parent_max_calls:
        raise TokenPolicyError(
            403, "PRIVILEGE_ESCALATION_ATTEMPT", "Child max_calls exceeds parent max_calls"
        )

    eff_tools = parent_tools & child_tools
    eff_prefixes = child_prefixes
    eff_sql_ro = parent_sql_ro or child_caveat.sql_read_only
    eff_max_calls = min(parent_max_calls, child_caveat.max_calls)
    eff_expires_at = min(parent_expires_at, child_caveat.expires_at)
    return eff_tools, eff_prefixes, eff_sql_ro, eff_max_calls, eff_expires_at


def _verify_chain_and_compute_effective(
    config: BrokerConfig, token: CapabilityToken
) -> tuple[set[str], list[PurePosixPath], bool, int, int]:
    if (
        not token.lineage_ids
        or not token.caveats
        or len(token.lineage_ids) != len(token.caveats)
    ):
        raise TokenPolicyError(401, "INVALID_TOKEN_SIGNATURE", "Malformed token lineage or caveats")

    if len(set(token.lineage_ids)) != len(token.lineage_ids):
        raise TokenPolicyError(401, "INVALID_TOKEN_SIGNATURE", "Duplicate hop_id in lineage")

    try:
        sig = _compute_root_hmac(
            config.root_key_hex,
            token.lineage_ids[0],
            token.principal,
            token.issued_at,
            token.caveats[0],
        )
        for idx in range(1, len(token.caveats)):
            sig = _compute_hop_hmac(sig, token.lineage_ids[idx], token.caveats[idx])
    except Exception as exc:
        raise TokenPolicyError(401, "INVALID_TOKEN_SIGNATURE", "Invalid signature format") from exc

    if not hmac.compare_digest(sig, token.signature):
        raise TokenPolicyError(401, "INVALID_TOKEN_SIGNATURE", "Chained HMAC verification failed")

    # Check revocation of any hop in lineage
    conn = sqlite3.connect(config.broker_state_db_path)
    try:
        placeholders = ",".join("?" for _ in token.lineage_ids)
        row = conn.execute(
            f"SELECT hop_id FROM revoked_hops WHERE hop_id IN ({placeholders}) LIMIT 1",
            tuple(token.lineage_ids),
        ).fetchone()
        if row is not None:
            raise TokenPolicyError(
                401, "TOKEN_REVOKED", f"Token lineage hop {row[0]} has been revoked"
            )
    finally:
        conn.close()

    # Validate root caveat and every attenuation step monotonically
    c0 = token.caveats[0]
    eff_prefixes = _validate_caveat_self(config, c0)
    eff_tools = set(c0.allowed_tools)
    eff_sql_ro = c0.sql_read_only
    eff_max_calls = c0.max_calls
    eff_expires_at = c0.expires_at

    for idx in range(1, len(token.caveats)):
        eff_tools, eff_prefixes, eff_sql_ro, eff_max_calls, eff_expires_at = (
            _validate_narrowing_step(
                config,
                eff_tools,
                eff_prefixes,
                eff_sql_ro,
                eff_max_calls,
                eff_expires_at,
                token.caveats[idx],
            )
        )

    return eff_tools, eff_prefixes, eff_sql_ro, eff_max_calls, eff_expires_at


def mint_root_token(
    config: BrokerConfig,
    principal: str,
    caveat: Caveat,
    hop_id: str | None = None,
    issued_at: int | None = None,
) -> CapabilityToken:
    _validate_caveat_self(config, caveat)
    actual_hop_id = hop_id or f"hop_{uuid.uuid4().hex[:12]}"
    actual_issued_at = issued_at if issued_at is not None else int(time.time())
    sig0 = _compute_root_hmac(
        config.root_key_hex, actual_hop_id, principal, actual_issued_at, caveat
    )
    return CapabilityToken(
        lineage_ids=[actual_hop_id],
        principal=principal,
        issued_at=actual_issued_at,
        caveats=[caveat],
        signature=sig0,
    )


def attenuate_token(
    config: BrokerConfig,
    parent_token: CapabilityToken,
    caveat: Caveat,
    hop_id: str | None = None,
) -> CapabilityToken:
    eff_tools, eff_prefixes, eff_sql_ro, eff_max_calls, eff_expires_at = (
        _verify_chain_and_compute_effective(config, parent_token)
    )
    _validate_narrowing_step(
        config,
        eff_tools,
        eff_prefixes,
        eff_sql_ro,
        eff_max_calls,
        eff_expires_at,
        caveat,
    )

    actual_hop_id = hop_id or f"hop_{uuid.uuid4().hex[:12]}"
    if actual_hop_id in parent_token.lineage_ids:
        raise TokenPolicyError(400, "INVALID_TOKEN_SIGNATURE", "hop_id already in lineage")

    next_sig = _compute_hop_hmac(parent_token.signature, actual_hop_id, caveat)
    return CapabilityToken(
        lineage_ids=list(parent_token.lineage_ids) + [actual_hop_id],
        principal=parent_token.principal,
        issued_at=parent_token.issued_at,
        caveats=list(parent_token.caveats) + [caveat],
        signature=next_sig,
    )


def revoke_hop(config: BrokerConfig, hop_id: str) -> None:
    conn = sqlite3.connect(config.broker_state_db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO revoked_hops (hop_id, revoked_at) VALUES (?, ?)",
            (hop_id, int(time.time())),
        )
        conn.commit()
    finally:
        conn.close()


def verify_and_authorize_token(
    config: BrokerConfig,
    token: CapabilityToken,
    tool_name: str,
    canonical_target_path: str | None = None,
) -> Caveat:
    eff_tools, eff_prefixes, eff_sql_ro, eff_max_calls, eff_expires_at = (
        _verify_chain_and_compute_effective(config, token)
    )

    now = int(time.time())
    if now > eff_expires_at:
        raise TokenPolicyError(403, "CAPABILITY_VIOLATION", "Capability token has expired")

    if tool_name not in eff_tools:
        raise TokenPolicyError(
            403, "CAPABILITY_VIOLATION", f"Tool '{tool_name}' is not permitted by token chain"
        )

    if canonical_target_path is not None:
        target_pure = normalize_pure_sandbox_path(config, canonical_target_path)
        for hop_caveat in token.caveats:
            hop_prefixes = [
                normalize_pure_sandbox_path(config, p)
                for p in hop_caveat.allowed_path_prefixes
            ]
            if not any(target_pure.is_relative_to(hp) for hp in hop_prefixes):
                raise TokenPolicyError(
                    403,
                    "PATH_BOUNDARY_VIOLATION",
                    f"Target path '{target_pure}' is outside allowed prefixes",
                )

    # Check shared lineage quota across all hops in lineage_ids
    conn = sqlite3.connect(config.broker_state_db_path)
    try:
        for hop_id, hop_caveat in zip(token.lineage_ids, token.caveats):
            row = conn.execute(
                "SELECT calls_used FROM token_usage WHERE hop_id = ?", (hop_id,)
            ).fetchone()
            used = int(row[0]) if row is not None else 0
            if used >= hop_caveat.max_calls:
                raise TokenPolicyError(
                    403,
                    "TOKEN_QUOTA_EXCEEDED",
                    f"Quota exceeded at lineage hop '{hop_id}' ({used}/{hop_caveat.max_calls})",
                )
    finally:
        conn.close()

    return Caveat(
        allowed_tools=sorted(eff_tools),  # type: ignore[arg-type]
        allowed_path_prefixes=[str(p) for p in eff_prefixes],
        sql_read_only=eff_sql_ro,
        max_calls=eff_max_calls,
        expires_at=eff_expires_at,
    )


def record_token_usage(config: BrokerConfig, token: CapabilityToken) -> None:
    conn = sqlite3.connect(config.broker_state_db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        for hop_id in token.lineage_ids:
            conn.execute(
                """
                INSERT INTO token_usage (hop_id, calls_used)
                VALUES (?, 1)
                ON CONFLICT(hop_id) DO UPDATE SET calls_used = calls_used + 1
                """,
                (hop_id,),
            )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
EOF

cat <<'EOF' > "${APP_DIR}/sql_guard.py"
from __future__ import annotations

import re
import sqlite3
from typing import Any

from app.config import BrokerConfig


class SQLPolicyError(Exception):
    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


_UNCONDITIONALLY_DENIED_ACTIONS = {
    sqlite3.SQLITE_ATTACH,
    sqlite3.SQLITE_DETACH,
    sqlite3.SQLITE_PRAGMA,
    sqlite3.SQLITE_CREATE_INDEX,
    sqlite3.SQLITE_CREATE_TABLE,
    sqlite3.SQLITE_CREATE_TEMP_INDEX,
    sqlite3.SQLITE_CREATE_TEMP_TABLE,
    sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
    sqlite3.SQLITE_CREATE_TEMP_VIEW,
    sqlite3.SQLITE_CREATE_TRIGGER,
    sqlite3.SQLITE_CREATE_VIEW,
    sqlite3.SQLITE_ALTER_TABLE,
    sqlite3.SQLITE_DROP_INDEX,
    sqlite3.SQLITE_DROP_TABLE,
    sqlite3.SQLITE_DROP_TEMP_INDEX,
    sqlite3.SQLITE_DROP_TEMP_TABLE,
    sqlite3.SQLITE_DROP_TEMP_TRIGGER,
    sqlite3.SQLITE_DROP_TEMP_VIEW,
    sqlite3.SQLITE_DROP_TRIGGER,
    sqlite3.SQLITE_DROP_VIEW,
}

_WRITE_ACTIONS = {
    sqlite3.SQLITE_INSERT,
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_ANALYZE,
    sqlite3.SQLITE_REINDEX,
}

_USER_TX_RE = re.compile(
    r"^\s*(BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b", re.IGNORECASE
)


def _is_protected_table(table_name: str | None) -> bool:
    if not table_name:
        return False
    lower = table_name.lower()
    return lower == "system_secrets" or lower.startswith("sqlite_")


def classify_and_execute_sql(
    config: BrokerConfig,
    sql: str,
    params: list[Any],
    sql_read_only: bool,
    execute_now: bool = True,
) -> tuple[bool, list[dict[str, Any]]]:
    stripped = (sql or "").strip()
    if not stripped:
        raise SQLPolicyError(400, "SQL_POLICY_VIOLATION", "SQL query cannot be empty")

    if _USER_TX_RE.match(stripped):
        raise SQLPolicyError(
            403, "SQL_POLICY_VIOLATION", "User-controlled transaction statements are forbidden"
        )

    saw_write = False
    policy_denied_reason: list[str] = []

    def authorizer(
        action: int,
        arg1: str | None,
        arg2: str | None,
        dbname: str | None,
        source: str | None,
    ) -> int:
        nonlocal saw_write
        if action in _UNCONDITIONALLY_DENIED_ACTIONS:
            policy_denied_reason.append(f"Forbidden SQLite action code {action}")
            return sqlite3.SQLITE_DENY

        if action == sqlite3.SQLITE_READ:
            if _is_protected_table(arg1):
                policy_denied_reason.append(f"Access to protected table '{arg1}' is denied")
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        if action in _WRITE_ACTIONS:
            saw_write = True
            if _is_protected_table(arg1):
                policy_denied_reason.append(f"Write to protected table '{arg1}' is denied")
                return sqlite3.SQLITE_DENY
            if sql_read_only:
                policy_denied_reason.append("Write operation denied in sql_read_only mode")
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        if action in (
            sqlite3.SQLITE_SELECT,
            sqlite3.SQLITE_FUNCTION,
            sqlite3.SQLITE_TRANSACTION,
        ):
            return sqlite3.SQLITE_OK

        policy_denied_reason.append(f"Disallowed SQLite action {action}")
        return sqlite3.SQLITE_DENY

    conn = sqlite3.connect(config.app_db_path, isolation_level="DEFERRED")
    conn.row_factory = sqlite3.Row
    try:
        conn.set_authorizer(authorizer)
        cur = conn.cursor()
        if not execute_now:
            # Compile statement via EXPLAIN to trigger sqlite3 authorizer without mutating data
            cur.execute(f"EXPLAIN {stripped}", params)
            conn.rollback()
            return saw_write, []

        cur.execute(stripped, params)
        rows = [dict(r) for r in cur.fetchall()]
        if saw_write and not sql_read_only:
            conn.commit()
        else:
            conn.rollback()
        return saw_write, rows
    except (sqlite3.Error, sqlite3.Warning) as exc:
        conn.set_authorizer(None)
        conn.rollback()
        detail = policy_denied_reason[0] if policy_denied_reason else str(exc)
        raise SQLPolicyError(403, "SQL_POLICY_VIOLATION", detail) from exc
    finally:
        conn.set_authorizer(None)
        conn.close()
EOF

cat <<'EOF' > "${APP_DIR}/taint.py"
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import time
from typing import Any

from app.config import BrokerConfig
from app.models import HITLReceipt


class TaintPolicyError(Exception):
    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def compute_canonical_args_sha256(
    tool_name: str, canonical_args: dict[str, Any]
) -> str:
    canonical_bytes = json.dumps(
        canonical_args, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def create_hitl_receipt(
    session_id: str,
    tool_name: str,
    canonical_args: dict[str, Any],
    expires_at: int,
    nonce: str,
    hitl_key_hex: str,
) -> HITLReceipt:
    args_sha256 = compute_canonical_args_sha256(tool_name, canonical_args)
    signing_input = (
        f"v1|{session_id}|{tool_name}|{args_sha256}|{expires_at}|{nonce}"
    ).encode("utf-8")
    signature = hmac.new(
        bytes.fromhex(hitl_key_hex),
        signing_input,
        hashlib.sha256,
    ).hexdigest()
    return HITLReceipt(
        session_id=session_id,
        tool_name=tool_name,  # type: ignore[arg-type]
        canonical_args_sha256=args_sha256,
        expires_at=expires_at,
        nonce=nonce,
        signature=signature,
    )


def is_session_tainted(config: BrokerConfig, session_id: str) -> bool:
    conn = sqlite3.connect(config.broker_state_db_path)
    try:
        row = conn.execute(
            "SELECT tainted FROM session_taint WHERE session_id = ?", (session_id,)
        ).fetchone()
        return bool(row and int(row[0]) == 1)
    finally:
        conn.close()


def mark_session_tainted(
    config: BrokerConfig, session_id: str, source_info: str
) -> None:
    conn = sqlite3.connect(config.broker_state_db_path)
    try:
        conn.execute(
            """
            INSERT INTO session_taint (session_id, tainted, taint_source)
            VALUES (?, 1, ?)
            ON CONFLICT(session_id) DO UPDATE SET tainted = 1, taint_source = excluded.taint_source
            """,
            (session_id, source_info),
        )
        conn.commit()
    finally:
        conn.close()


def enforce_taint_and_hitl(
    config: BrokerConfig,
    session_id: str,
    tool_name: str,
    canonical_args: dict[str, Any],
    is_sensitive_sink: bool,
    hitl_receipt: HITLReceipt | None,
) -> None:
    if not is_sensitive_sink:
        return

    if not is_session_tainted(config, session_id):
        return

    if hitl_receipt is None:
        raise TaintPolicyError(
            403,
            "TAINT_VIOLATION",
            f"Session '{session_id}' is TAINTED; sensitive sink '{tool_name}' requires a valid HITLReceipt",
        )

    if not _NONCE_RE.match(hitl_receipt.nonce):
        raise TaintPolicyError(403, "INVALID_HITL_SIGNATURE", "Malformed HITL nonce")

    signing_input = (
        f"v1|{hitl_receipt.session_id}|{hitl_receipt.tool_name}|"
        f"{hitl_receipt.canonical_args_sha256}|{hitl_receipt.expires_at}|{hitl_receipt.nonce}"
    ).encode("utf-8")
    expected_sig = hmac.new(
        bytes.fromhex(config.hitl_key_hex),
        signing_input,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, hitl_receipt.signature):
        raise TaintPolicyError(
            403, "INVALID_HITL_SIGNATURE", "HITL receipt HMAC signature verification failed"
        )

    expected_args_sha256 = compute_canonical_args_sha256(tool_name, canonical_args)
    if (
        hitl_receipt.session_id != session_id
        or hitl_receipt.tool_name != tool_name
        or not hmac.compare_digest(hitl_receipt.canonical_args_sha256, expected_args_sha256)
    ):
        raise TaintPolicyError(
            403,
            "HITL_BINDING_MISMATCH",
            "HITL receipt is not bound to this session, tool, or canonical arguments",
        )

    now = int(time.time())
    if now > hitl_receipt.expires_at:
        raise TaintPolicyError(403, "HITL_RECEIPT_EXPIRED", "HITL receipt has expired")

    # Atomic single-use nonce consumption using BEGIN IMMEDIATE
    conn = sqlite3.connect(config.broker_state_db_path, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO consumed_hitl_nonces (nonce, session_id, consumed_at) VALUES (?, ?, ?)",
            (hitl_receipt.nonce, session_id, now),
        )
        conn.execute("COMMIT")
    except sqlite3.IntegrityError as exc:
        conn.execute("ROLLBACK")
        raise TaintPolicyError(
            403, "HITL_NONCE_REPLAYED", f"HITL nonce '{hitl_receipt.nonce}' was already consumed"
        ) from exc
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
EOF

cat <<'EOF' > "${APP_DIR}/tools.py"
from __future__ import annotations

import errno
import json
import os
import time
from pathlib import Path
from typing import Any

from app.canonicalize import PathSecurityError, normalize_pure_sandbox_path
from app.config import BrokerConfig


def execute_fs_read(config: BrokerConfig, target_path: Path) -> dict[str, Any]:
    normalize_pure_sandbox_path(config, str(target_path))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(target_path), flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EACCES, errno.EPERM):
            raise PathSecurityError(
                403, "PATH_SYMLINK_FORBIDDEN", f"Descriptor open rejected symlink: {target_path}"
            ) from exc
        raise

    with os.fdopen(fd, "r", encoding="utf-8") as fh:
        content = fh.read()
    return {"path": str(target_path), "content": content}


def execute_fs_write(
    config: BrokerConfig, target_path: Path, content: str
) -> dict[str, Any]:
    normalize_pure_sandbox_path(config, str(target_path))
    target_path.parent.mkdir(parents=True, exist_ok=True)
    # Re-verify parent components after mkdir
    normalize_pure_sandbox_path(config, str(target_path))

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(target_path), flags, 0o644)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PathSecurityError(
                403, "PATH_SYMLINK_FORBIDDEN", f"Refusing to write to symlink: {target_path}"
            ) from exc
        raise

    data_bytes = content.encode("utf-8")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data_bytes)
        fh.flush()
        os.fsync(fh.fileno())
    return {"path": str(target_path), "bytes_written": len(data_bytes)}


def execute_webhook_send(
    config: BrokerConfig, destination: str, payload: Any, session_id: str
) -> dict[str, Any]:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": int(time.time()),
        "session_id": session_id,
        "destination": destination,
        "payload": payload,
    }
    with open(config.webhook_sink_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return {"delivered": True, "destination": destination}
EOF

cat <<'EOF' > "${APP_DIR}/audit.py"
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from app.config import BrokerConfig
from app.models import AuditReceipt, AuditVerificationResult


class AuditSubsystemError(Exception):
    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _ratchet_key_hex(key_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()


def _atomic_write_text(target: Path, text: str) -> None:
    tmp_path = target.with_name(f".{target.name}.tmp")
    with open(tmp_path, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, target)


def _replay_wal_commit_if_present(config: BrokerConfig) -> None:
    # Clean any uncommitted temporary WAL staging file
    if config.audit_wal_tmp_path.exists():
        config.audit_wal_tmp_path.unlink(missing_ok=True)

    wal_path = config.audit_wal_commit_path
    if not wal_path.exists():
        return

    try:
        wal_data = json.loads(wal_path.read_text(encoding="utf-8"))
        wal_seq = int(wal_data["seq"])
        entry_line = str(wal_data["entry_line"]).strip()
        anchor_obj = dict(wal_data["anchor_obj"])
        next_ratchet_obj = dict(wal_data["next_ratchet_obj"])
        expected_sha = str(wal_data["wal_sha256"])
    except Exception as exc:
        raise AuditSubsystemError(
            503, "AUDIT_STATE_CORRUPTED", "Committed WAL journal is unreadable"
        ) from exc

    core = {
        "anchor_obj": anchor_obj,
        "entry_line": entry_line,
        "next_ratchet_obj": next_ratchet_obj,
        "seq": wal_seq,
    }
    computed_sha = hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(computed_sha, expected_sha):
        raise AuditSubsystemError(
            503, "AUDIT_STATE_CORRUPTED", "Committed WAL checksum mismatch"
        )

    # Inspect and repair audit.jsonl up to wal_seq
    valid_prefix_lines: list[str] = []
    if config.audit_ledger_path.exists():
        raw_bytes = config.audit_ledger_path.read_bytes()
        text = raw_bytes.decode("utf-8", errors="replace")
        for line in text.splitlines():
            s = line.strip()
            if not s:
                continue
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict) and "seq" in parsed and "entry_hmac" in parsed:
                    valid_prefix_lines.append(s)
                else:
                    break
            except Exception:
                # Truncate torn trailing line covered by committed WAL
                break

    if len(valid_prefix_lines) == wal_seq:
        valid_prefix_lines.append(entry_line)
    elif len(valid_prefix_lines) == wal_seq + 1:
        if valid_prefix_lines[-1] != entry_line:
            raise AuditSubsystemError(
                503, "AUDIT_STATE_CORRUPTED", "Ledger line conflicts with committed WAL"
            )
    else:
        raise AuditSubsystemError(
            503,
            "AUDIT_STATE_CORRUPTED",
            f"Ledger length {len(valid_prefix_lines)} cannot be recovered by WAL at seq={wal_seq}",
        )

    _atomic_write_text(
        config.audit_ledger_path, "\n".join(valid_prefix_lines) + "\n"
    )
    _atomic_write_text(
        config.audit_anchor_path, _canonical_json(anchor_obj) + "\n"
    )
    _atomic_write_text(
        config.ratchet_state_path, _canonical_json(next_ratchet_obj) + "\n"
    )
    wal_path.unlink(missing_ok=True)


def recover_or_fail_closed(config: BrokerConfig) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    _replay_wal_commit_if_present(config)

    if not config.ratchet_state_path.exists():
        raise AuditSubsystemError(
            503, "AUDIT_STATE_CORRUPTED", "Missing ratchet_state.json"
        )

    try:
        ratchet = json.loads(config.ratchet_state_path.read_text(encoding="utf-8"))
        next_seq = int(ratchet["next_seq"])
        signing_key_hex = str(ratchet["signing_key_hex"])
        anchor_key_hex = str(ratchet["anchor_key_hex"])
        if len(signing_key_hex) != 64 or len(anchor_key_hex) != 64 or next_seq < 0:
            raise ValueError("Invalid ratchet fields")
    except Exception as exc:
        raise AuditSubsystemError(
            503, "AUDIT_STATE_CORRUPTED", "Corrupted ratchet_state.json"
        ) from exc

    entries: list[dict[str, Any]] = []
    if config.audit_ledger_path.exists():
        raw_text = config.audit_ledger_path.read_text(encoding="utf-8")
        if raw_text and not raw_text.endswith("\n"):
            raise AuditSubsystemError(
                503, "AUDIT_STATE_CORRUPTED", "Torn line in audit.jsonl without WAL"
            )
        for idx, line in enumerate(raw_text.splitlines()):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception as exc:
                raise AuditSubsystemError(
                    503, "AUDIT_STATE_CORRUPTED", f"Invalid JSON in audit.jsonl at line {idx}"
                ) from exc
            if obj.get("seq") != idx:
                raise AuditSubsystemError(
                    503, "AUDIT_STATE_CORRUPTED", f"Sequence gap at line {idx}"
                )
            expected_prev = "GENESIS" if idx == 0 else entries[-1].get("entry_hmac")
            if obj.get("prev_entry_hmac") != expected_prev:
                raise AuditSubsystemError(
                    503, "AUDIT_STATE_CORRUPTED", f"Broken prev_entry_hmac chain at seq {idx}"
                )
            entries.append(obj)

    if len(entries) != next_seq:
        raise AuditSubsystemError(
            503,
            "AUDIT_STATE_CORRUPTED",
            f"Ledger entry count ({len(entries)}) does not match ratchet next_seq ({next_seq})",
        )

    if next_seq == 0:
        if config.audit_anchor_path.exists():
            raise AuditSubsystemError(
                503, "AUDIT_STATE_CORRUPTED", "Unexpected anchor file when next_seq is 0"
            )
    else:
        if not config.audit_anchor_path.exists():
            raise AuditSubsystemError(
                503, "AUDIT_STATE_CORRUPTED", "Missing audit_anchor.json for non-empty ledger"
            )
        try:
            anchor = json.loads(config.audit_anchor_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise AuditSubsystemError(
                503, "AUDIT_STATE_CORRUPTED", "Corrupted audit_anchor.json"
            ) from exc
        if (
            anchor.get("last_seq") != next_seq - 1
            or anchor.get("last_entry_hmac") != entries[-1].get("entry_hmac")
        ):
            raise AuditSubsystemError(
                503, "AUDIT_STATE_CORRUPTED", "Anchor checkpoint does not match ledger head"
            )


def append_audit_entry(
    config: BrokerConfig,
    session_id: str,
    token_hop_id: str,
    tool_name: str,
    canonical_args_sha256: str,
    taint_state: str,
    decision: str,
    reason_code: str,
) -> AuditReceipt:
    recover_or_fail_closed(config)

    ratchet = json.loads(config.ratchet_state_path.read_text(encoding="utf-8"))
    seq = int(ratchet["next_seq"])
    k_curr = str(ratchet["signing_key_hex"])
    a_curr = str(ratchet["anchor_key_hex"])

    prev_entry_hmac = "GENESIS"
    prev_rolling_hash = "GENESIS"
    if seq > 0:
        anchor_prev = json.loads(config.audit_anchor_path.read_text(encoding="utf-8"))
        prev_entry_hmac = str(anchor_prev["last_entry_hmac"])
        prev_rolling_hash = str(anchor_prev["rolling_hash"])

    entry_core = {
        "canonical_args_sha256": canonical_args_sha256,
        "decision": decision,
        "prev_entry_hmac": prev_entry_hmac,
        "reason_code": reason_code,
        "seq": seq,
        "session_id": session_id,
        "taint_state": taint_state,
        "timestamp": int(time.time()),
        "token_hop_id": token_hop_id,
        "tool_name": tool_name,
    }
    core_json = _canonical_json(entry_core)
    entry_hmac = hmac.new(
        bytes.fromhex(k_curr),
        f"{seq}|{prev_entry_hmac}|{core_json}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    full_entry = dict(entry_core)
    full_entry["entry_hmac"] = entry_hmac
    entry_line = _canonical_json(full_entry)

    rolling_hash = hashlib.sha256(
        f"{prev_rolling_hash}|{entry_hmac}".encode("utf-8")
    ).hexdigest()
    anchor_mac = hmac.new(
        bytes.fromhex(a_curr),
        f"{seq}|{entry_hmac}|{rolling_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    anchor_obj = {
        "anchor_mac": anchor_mac,
        "last_entry_hmac": entry_hmac,
        "last_seq": seq,
        "rolling_hash": rolling_hash,
    }

    next_ratchet_obj = {
        "anchor_key_hex": _ratchet_key_hex(a_curr),
        "next_seq": seq + 1,
        "signing_key_hex": _ratchet_key_hex(k_curr),
    }

    wal_core = {
        "anchor_obj": anchor_obj,
        "entry_line": entry_line,
        "next_ratchet_obj": next_ratchet_obj,
        "seq": seq,
    }
    wal_sha256 = hashlib.sha256(_canonical_json(wal_core).encode("utf-8")).hexdigest()
    wal_full = dict(wal_core)
    wal_full["wal_sha256"] = wal_sha256

    # Step 1: Write WAL to .tmp, fsync, and promote to .commit
    with open(config.audit_wal_tmp_path, "w", encoding="utf-8") as wfh:
        wfh.write(_canonical_json(wal_full) + "\n")
        wfh.flush()
        os.fsync(wfh.fileno())
    os.replace(config.audit_wal_tmp_path, config.audit_wal_commit_path)

    # Step 2: Append to audit.jsonl and fsync
    with open(config.audit_ledger_path, "a", encoding="utf-8") as lfh:
        lfh.write(entry_line + "\n")
        lfh.flush()
        os.fsync(lfh.fileno())

    # Step 3: Atomically update audit_anchor.json and ratchet_state.json
    _atomic_write_text(config.audit_anchor_path, _canonical_json(anchor_obj) + "\n")
    _atomic_write_text(config.ratchet_state_path, _canonical_json(next_ratchet_obj) + "\n")

    # Step 4: Remove WAL commit file
    config.audit_wal_commit_path.unlink(missing_ok=True)

    return AuditReceipt(seq=seq, entry_hmac=entry_hmac)


def verify_audit_ledger(
    ledger_path: Path,
    anchor_path: Path,
    ratchet_path: Path,
    trusted_genesis_audit_key_hex: str,
    trusted_genesis_anchor_key_hex: str,
    expected_min_seq: int | None = None,
) -> AuditVerificationResult:
    ledger_path = Path(ledger_path)
    anchor_path = Path(anchor_path)
    ratchet_path = Path(ratchet_path)

    lines: list[str] = []
    if ledger_path.exists():
        raw_text = ledger_path.read_text(encoding="utf-8")
        if raw_text and not raw_text.endswith("\n"):
            return AuditVerificationResult(
                valid=False,
                entries_checked=0,
                first_corrupted_seq=0,
                error_code="TORN_LEDGER_LINE",
            )
        lines = [ln for ln in raw_text.splitlines() if ln.strip()]

    k_curr = trusted_genesis_audit_key_hex
    a_curr = trusted_genesis_anchor_key_hex
    prev_entry_hmac = "GENESIS"
    rolling_hash = "GENESIS"
    last_anchor_mac = ""

    for idx, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except Exception:
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                first_corrupted_seq=idx,
                error_code="CORRUPTED_JSON",
            )

        if entry.get("seq") != idx:
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                first_corrupted_seq=idx,
                error_code="SEQUENCE_MISMATCH",
            )

        if entry.get("prev_entry_hmac") != prev_entry_hmac:
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                first_corrupted_seq=idx,
                error_code="PREV_HASH_MISMATCH",
            )

        recorded_hmac = str(entry.get("entry_hmac", ""))
        entry_core = {k: v for k, v in entry.items() if k != "entry_hmac"}
        core_json = _canonical_json(entry_core)
        expected_hmac = hmac.new(
            bytes.fromhex(k_curr),
            f"{idx}|{prev_entry_hmac}|{core_json}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_hmac, recorded_hmac):
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                first_corrupted_seq=idx,
                error_code="ENTRY_HMAC_MISMATCH",
            )

        rolling_hash = hashlib.sha256(
            f"{rolling_hash}|{recorded_hmac}".encode("utf-8")
        ).hexdigest()
        last_anchor_mac = hmac.new(
            bytes.fromhex(a_curr),
            f"{idx}|{recorded_hmac}|{rolling_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        prev_entry_hmac = recorded_hmac
        k_curr = _ratchet_key_hex(k_curr)
        a_curr = _ratchet_key_hex(a_curr)

    count = len(lines)

    # Check expected_min_seq if provided by external caller witness
    if expected_min_seq is not None and count <= expected_min_seq:
        return AuditVerificationResult(
            valid=False,
            entries_checked=count,
            first_corrupted_seq=count,
            error_code="TAIL_TRUNCATION_DETECTED",
        )

    # Check anchor checkpoint
    if count == 0:
        if anchor_path.exists():
            return AuditVerificationResult(
                valid=False,
                entries_checked=0,
                first_corrupted_seq=0,
                error_code="UNEXPECTED_ANCHOR",
            )
    else:
        if not anchor_path.exists():
            return AuditVerificationResult(
                valid=False,
                entries_checked=count,
                first_corrupted_seq=count - 1,
                error_code="MISSING_ANCHOR",
            )
        try:
            anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
        except Exception:
            return AuditVerificationResult(
                valid=False,
                entries_checked=count,
                first_corrupted_seq=count - 1,
                error_code="CORRUPTED_ANCHOR",
            )

        anchor_seq = int(anchor.get("last_seq", -1))
        if anchor_seq != count - 1:
            corrupted_seq = min(count, max(0, anchor_seq))
            return AuditVerificationResult(
                valid=False,
                entries_checked=count,
                first_corrupted_seq=corrupted_seq,
                error_code="TAIL_TRUNCATION_DETECTED",
            )

        if (
            anchor.get("last_entry_hmac") != prev_entry_hmac
            or anchor.get("rolling_hash") != rolling_hash
            or not hmac.compare_digest(str(anchor.get("anchor_mac", "")), last_anchor_mac)
        ):
            return AuditVerificationResult(
                valid=False,
                entries_checked=count,
                first_corrupted_seq=count - 1,
                error_code="ANCHOR_MAC_MISMATCH",
            )

    # Check ratchet state matches post-count ratcheted keys
    if not ratchet_path.exists():
        return AuditVerificationResult(
            valid=False,
            entries_checked=count,
            first_corrupted_seq=count,
            error_code="MISSING_RATCHET_STATE",
        )
    try:
        ratchet = json.loads(ratchet_path.read_text(encoding="utf-8"))
    except Exception:
        return AuditVerificationResult(
            valid=False,
            entries_checked=count,
            first_corrupted_seq=count,
            error_code="CORRUPTED_RATCHET_STATE",
        )

    if (
        ratchet.get("next_seq") != count
        or not hmac.compare_digest(str(ratchet.get("signing_key_hex", "")), k_curr)
        or not hmac.compare_digest(str(ratchet.get("anchor_key_hex", "")), a_curr)
    ):
        return AuditVerificationResult(
            valid=False,
            entries_checked=count,
            first_corrupted_seq=count,
            error_code="RATCHET_STATE_MISMATCH",
        )

    return AuditVerificationResult(
        valid=True,
        entries_checked=count,
        first_corrupted_seq=None,
        error_code=None,
    )
EOF

python3 "${WORKSPACE_ROOT:-${WORKSPACE_DIR}}/scripts/init_sandbox.py"
python3 "${WORKSPACE_ROOT:-${WORKSPACE_DIR}}/tests/test_smoke.py"
