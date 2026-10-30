from __future__ import annotations

import hashlib
import json
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


def recover_or_fail_closed(config: BrokerConfig) -> None:
    """
    Starter implementation (INCOMPLETE):
    Does not replay audit_wal.commit or verify consistency between
    audit.jsonl, audit_anchor.json, and ratchet_state.json.
    """
    config.state_dir.mkdir(parents=True, exist_ok=True)


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
    """
    Starter implementation (VULNERABLE):
    Appends a plain SHA-256 hash without forward-ratcheting keys in
    ratchet_state.json or maintaining a WAL commit journal.
    """
    recover_or_fail_closed(config)
    ledger_path = config.audit_ledger_path
    existing_lines: list[str] = []
    if ledger_path.exists():
        existing_lines = [
            ln for ln in ledger_path.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
    seq = len(existing_lines)
    prev_hmac = "GENESIS"
    if existing_lines:
        last_obj = json.loads(existing_lines[-1])
        prev_hmac = last_obj.get("entry_hmac", "GENESIS")

    entry_core = {
        "seq": seq,
        "timestamp": int(time.time()),
        "session_id": session_id,
        "token_hop_id": token_hop_id,
        "tool_name": tool_name,
        "canonical_args_sha256": canonical_args_sha256,
        "taint_state": taint_state,
        "decision": decision,
        "reason_code": reason_code,
        "prev_entry_hmac": prev_hmac,
    }
    raw_core = json.dumps(entry_core, sort_keys=True, separators=(",", ":"))
    entry_hmac = hashlib.sha256(f"{seq}|{prev_hmac}|{raw_core}".encode("utf-8")).hexdigest()
    full_entry = dict(entry_core)
    full_entry["entry_hmac"] = entry_hmac

    with open(ledger_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(full_entry, sort_keys=True, separators=(",", ":")) + "\n")

    anchor_obj = {
        "last_seq": seq,
        "last_entry_hmac": entry_hmac,
        "rolling_hash": entry_hmac,
        "anchor_mac": entry_hmac,
    }
    config.audit_anchor_path.write_text(
        json.dumps(anchor_obj, sort_keys=True) + "\n", encoding="utf-8"
    )
    return AuditReceipt(seq=seq, entry_hmac=entry_hmac)


def verify_audit_ledger(
    ledger_path: Path,
    anchor_path: Path,
    ratchet_path: Path,
    trusted_genesis_audit_key_hex: str,
    trusted_genesis_anchor_key_hex: str,
    expected_min_seq: int | None = None,
) -> AuditVerificationResult:
    """
    Starter implementation (VULNERABLE):
    Only checks whether audit.jsonl is parseable JSON without verifying
    forward-ratcheted HMAC signatures, anchor MACs, or truncation.
    """
    if not Path(ledger_path).exists():
        return AuditVerificationResult(
            valid=True, entries_checked=0, first_corrupted_seq=None, error_code=None
        )
    lines = [
        ln for ln in Path(ledger_path).read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    for idx, line in enumerate(lines):
        try:
            json.loads(line)
        except Exception:
            return AuditVerificationResult(
                valid=False,
                entries_checked=idx,
                first_corrupted_seq=idx,
                error_code="CORRUPTED_ENTRY",
            )
    return AuditVerificationResult(
        valid=True,
        entries_checked=len(lines),
        first_corrupted_seq=None,
        error_code=None,
    )
