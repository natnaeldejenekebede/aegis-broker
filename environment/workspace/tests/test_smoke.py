from __future__ import annotations

import secrets
import sys
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from app.audit import verify_audit_ledger
from app.config import BrokerConfig
from app.main import create_app
from app.taint import create_hitl_receipt
from scripts.init_sandbox import initialize_environment


def _make_isolated_env(tmp_path: Path) -> tuple[BrokerConfig, TestClient]:
    cfg = BrokerConfig(
        sandbox_root=tmp_path / "sandbox",
        state_dir=tmp_path / "state",
        root_key_hex=secrets.token_hex(32),
        hitl_key_hex=secrets.token_hex(32),
        genesis_audit_key_hex=secrets.token_hex(32),
        genesis_anchor_key_hex=secrets.token_hex(32),
    )
    initialize_environment(cfg, clean=True)
    client = TestClient(create_app(cfg))
    return cfg, client


def test_smoke_health_and_mint(tmp_path: Path) -> None:
    cfg, client = _make_isolated_env(tmp_path)
    r_health = client.get("/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "ok"

    now = int(time.time())
    r_mint = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "orchestrator",
            "hop_id": "root_hop_1",
            "issued_at": now,
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 5,
                "expires_at": now + 3600,
            },
        },
    )
    assert r_mint.status_code == 200
    tok = r_mint.json()
    assert tok["lineage_ids"] == ["root_hop_1"]
    assert len(tok["signature"]) == 64


def test_smoke_attenuate_and_fs_read(tmp_path: Path) -> None:
    cfg, client = _make_isolated_env(tmp_path)
    now = int(time.time())
    root_tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "orchestrator",
            "caveat": {
                "allowed_tools": ["fs.read", "fs.write"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports")],
                "sql_read_only": True,
                "max_calls": 5,
                "expires_at": now + 3600,
            },
        },
    ).json()

    r_att = client.post(
        "/v1/tokens/attenuate",
        json={
            "parent_token": root_tok,
            "caveat": {
                "allowed_tools": ["fs.read"],
                "allowed_path_prefixes": [str(cfg.sandbox_root / "reports" / "2026")],
                "sql_read_only": True,
                "max_calls": 2,
                "expires_at": now + 1800,
            },
        },
    )
    assert r_att.status_code == 200
    child_tok = r_att.json()
    assert len(child_tok["lineage_ids"]) == 2

    target = str(cfg.sandbox_root / "reports" / "2026" / "q3" / "summary.txt")
    r_inv = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_smoke_1",
            "token": child_tok,
            "tool_name": "fs.read",
            "arguments": {"path": target},
        },
    )
    assert r_inv.status_code == 200
    body = r_inv.json()
    assert body["status"] == "ok"
    assert "nominal" in body["result"]["content"]
    assert body["audit_receipt"]["seq"] == 0


def test_smoke_db_query(tmp_path: Path) -> None:
    cfg, client = _make_isolated_env(tmp_path)
    now = int(time.time())
    tok = client.post(
        "/v1/tokens/mint",
        json={
            "principal": "db_reader",
            "caveat": {
                "allowed_tools": ["db.query"],
                "allowed_path_prefixes": [],
                "sql_read_only": True,
                "max_calls": 5,
                "expires_at": now + 3600,
            },
        },
    ).json()

    r_db = client.post(
        "/v1/tools/invoke",
        json={
            "session_id": "sess_smoke_db",
            "token": tok,
            "tool_name": "db.query",
            "arguments": {
                "sql": "SELECT id, title, status FROM tasks WHERE status = ?",
                "params": ["OPEN"],
            },
        },
    )
    assert r_db.status_code == 200
    rows = r_db.json()["result"]["rows"]
    assert len(rows) == 1
    assert rows[0]["title"] == "Audit firewall rules"


def test_smoke_hitl_receipt_helper(tmp_path: Path) -> None:
    cfg, _ = _make_isolated_env(tmp_path)
    now = int(time.time())
    target = str(cfg.sandbox_root / "reports" / "2026" / "out.txt")
    receipt = create_hitl_receipt(
        session_id="sess_1",
        tool_name="fs.write",
        canonical_args={"content": "hello", "path": target},
        expires_at=now + 300,
        nonce="nonce_1234567890abcd",
        hitl_key_hex=cfg.hitl_key_hex,
    )
    assert receipt.session_id == "sess_1"
    assert len(receipt.signature) == 64


def test_smoke_audit_verifier_callable(tmp_path: Path) -> None:
    cfg, client = _make_isolated_env(tmp_path)
    res = verify_audit_ledger(
        ledger_path=cfg.audit_ledger_path,
        anchor_path=cfg.audit_anchor_path,
        ratchet_path=cfg.ratchet_state_path,
        trusted_genesis_audit_key_hex=cfg.genesis_audit_key_hex,
        trusted_genesis_anchor_key_hex=cfg.genesis_anchor_key_hex,
    )
    assert res.valid is True


if __name__ == "__main__":
    funcs = [
        test_smoke_health_and_mint,
        test_smoke_attenuate_and_fs_read,
        test_smoke_db_query,
        test_smoke_hitl_receipt_helper,
        test_smoke_audit_verifier_callable,
    ]
    for fn in funcs:
        with tempfile.TemporaryDirectory() as td:
            fn(Path(td))
            print(f"PASS: {fn.__name__}")
    print(f"All {len(funcs)} public smoke tests passed.")
