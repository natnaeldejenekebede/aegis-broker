from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


# Disposable development fixture keys for local smoke testing only.
# Hidden verification tests always inject fresh random 32-byte keys per test.
DEFAULT_ROOT_KEY_HEX = (
    "7f4a8c1e9b2d3f6a0c5e8b1d4f7a2c9e6b3d0f1a4c7e9b2d5f8a1c4e7b0d3f6a"
)
DEFAULT_HITL_KEY_HEX = (
    "3c9e1a6b4d8f2c7e0a5b9d1f4c8e2a6b7d0f3c9e5a1b8d4f6c2e9a0b3d7f1c5e"
)
DEFAULT_GENESIS_AUDIT_KEY_HEX = (
    "9a2f5c8e1b4d7a0c3f6e9b2d5a8c1f4e7b0d3a6c9f2e5b8d1a4c7f0e3b6d9a2f"
)
DEFAULT_GENESIS_ANCHOR_KEY_HEX = (
    "1e6b9d4a7c2f5e8b0d3a6c9f1e4b7d2a5c8f0e3b6d9a1c4f7e2b5d8a0c3f6e9b"
)


@dataclass(frozen=True)
class BrokerConfig:
    sandbox_root: Path
    state_dir: Path
    root_key_hex: str = DEFAULT_ROOT_KEY_HEX
    hitl_key_hex: str = DEFAULT_HITL_KEY_HEX
    genesis_audit_key_hex: str = DEFAULT_GENESIS_AUDIT_KEY_HEX
    genesis_anchor_key_hex: str = DEFAULT_GENESIS_ANCHOR_KEY_HEX

    def __post_init__(self) -> None:
        object.__setattr__(self, "sandbox_root", Path(self.sandbox_root))
        object.__setattr__(self, "state_dir", Path(self.state_dir))

    @property
    def app_db_path(self) -> Path:
        return self.sandbox_root / "app.db"

    @property
    def broker_state_db_path(self) -> Path:
        return self.state_dir / "broker_state.db"

    @property
    def audit_ledger_path(self) -> Path:
        return self.state_dir / "audit.jsonl"

    @property
    def audit_anchor_path(self) -> Path:
        return self.state_dir / "audit_anchor.json"

    @property
    def ratchet_state_path(self) -> Path:
        return self.state_dir / "ratchet_state.json"

    @property
    def audit_wal_tmp_path(self) -> Path:
        return self.state_dir / "audit_wal.tmp"

    @property
    def audit_wal_commit_path(self) -> Path:
        return self.state_dir / "audit_wal.commit"

    @property
    def webhook_sink_path(self) -> Path:
        return self.state_dir / "webhook_events.jsonl"

    @classmethod
    def from_env(cls) -> "BrokerConfig":
        base_dir = Path(os.environ.get("AEGIS_WORKSPACE", "/workspace"))
        sandbox_root = Path(
            os.environ.get("AEGIS_SANDBOX_ROOT", str(base_dir / "sandbox"))
        )
        state_dir = Path(
            os.environ.get("AEGIS_STATE_DIR", str(base_dir / "state"))
        )
        return cls(
            sandbox_root=sandbox_root,
            state_dir=state_dir,
            root_key_hex=os.environ.get(
                "AEGIS_ROOT_KEY", DEFAULT_ROOT_KEY_HEX
            ),
            hitl_key_hex=os.environ.get(
                "AEGIS_HITL_KEY", DEFAULT_HITL_KEY_HEX
            ),
            genesis_audit_key_hex=os.environ.get(
                "AEGIS_GENESIS_AUDIT_KEY", DEFAULT_GENESIS_AUDIT_KEY_HEX
            ),
            genesis_anchor_key_hex=os.environ.get(
                "AEGIS_GENESIS_ANCHOR_KEY", DEFAULT_GENESIS_ANCHOR_KEY_HEX
            ),
        )
