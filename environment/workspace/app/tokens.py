from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from typing import Any

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


def mint_root_token(
    config: BrokerConfig,
    principal: str,
    caveat: Caveat,
    hop_id: str | None = None,
    issued_at: int | None = None,
) -> CapabilityToken:
    """Starter implementation: creates a root capability token."""
    actual_hop_id = hop_id or f"hop_{uuid.uuid4().hex[:12]}"
    actual_issued_at = issued_at if issued_at is not None else int(time.time())
    payload = {
        "hop_id": actual_hop_id,
        "principal": principal,
        "issued_at": actual_issued_at,
        "caveat": caveat.to_dict(),
    }
    sig0 = hmac.new(
        bytes.fromhex(config.root_key_hex),
        canonical_json_bytes(payload),
        hashlib.sha256,
    ).hexdigest()
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
    """
    Starter implementation (INCOMPLETE):
    Appends the child caveat and chains HMAC from parent_token.signature,
    but does NOT validate whether the child caveat widens parent permissions!
    """
    actual_hop_id = hop_id or f"hop_{uuid.uuid4().hex[:12]}"
    step_payload = {
        "hop_id": actual_hop_id,
        "caveat": caveat.to_dict(),
    }
    next_sig = hmac.new(
        bytes.fromhex(parent_token.signature),
        canonical_json_bytes(step_payload),
        hashlib.sha256,
    ).hexdigest()
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
    """
    Starter implementation (VULNERABLE):
    Only inspects the LAST caveat in the chain and does not verify the full
    chained HMAC from root_key_hex, does not check ancestor revocation, and
    only tracks usage on the leaf hop_id.
    """
    if not token.caveats or not token.lineage_ids:
        raise TokenPolicyError(401, "INVALID_TOKEN_SIGNATURE", "Empty token chain")

    leaf_caveat = token.caveats[-1]
    now = int(time.time())
    if now > leaf_caveat.expires_at:
        raise TokenPolicyError(403, "CAPABILITY_VIOLATION", "Token has expired")

    if tool_name not in leaf_caveat.allowed_tools:
        raise TokenPolicyError(
            403, "CAPABILITY_VIOLATION", f"Tool {tool_name} not permitted"
        )

    if canonical_target_path is not None:
        if not any(
            canonical_target_path.startswith(prefix)
            for prefix in leaf_caveat.allowed_path_prefixes
        ):
            raise TokenPolicyError(
                403, "PATH_BOUNDARY_VIOLATION", "Path not inside allowed prefixes"
            )

    return leaf_caveat


def record_token_usage(config: BrokerConfig, token: CapabilityToken) -> None:
    """Starter implementation: increments only the leaf hop_id without quota enforcement."""
    leaf_hop = token.lineage_ids[-1]
    conn = sqlite3.connect(config.broker_state_db_path)
    try:
        conn.execute(
            """
            INSERT INTO token_usage (hop_id, calls_used)
            VALUES (?, 1)
            ON CONFLICT(hop_id) DO UPDATE SET calls_used = calls_used + 1
            """,
            (leaf_hop,),
        )
        conn.commit()
    finally:
        conn.close()
