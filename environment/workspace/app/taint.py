from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from app.config import BrokerConfig
from app.models import HITLReceipt


class TaintPolicyError(Exception):
    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


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
    """Helper used by external human approval simulator / tests to sign a receipt."""
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
    """Starter stub: always returns False."""
    return False


def mark_session_tainted(
    config: BrokerConfig, session_id: str, source_info: str
) -> None:
    """Starter stub: no-op."""
    return None


def enforce_taint_and_hitl(
    config: BrokerConfig,
    session_id: str,
    tool_name: str,
    canonical_args: dict[str, Any],
    is_sensitive_sink: bool,
    hitl_receipt: HITLReceipt | None,
) -> None:
    """
    Starter implementation (VULNERABLE):
    Does not enforce taint restrictions or verify HITL receipts.
    """
    return None
