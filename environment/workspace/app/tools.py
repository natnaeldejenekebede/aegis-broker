from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from app.config import BrokerConfig


def execute_fs_read(config: BrokerConfig, target_path: Path) -> dict[str, Any]:
    if not target_path.exists() or not target_path.is_file():
        raise FileNotFoundError(f"File not found: {target_path}")
    content = target_path.read_text(encoding="utf-8")
    return {"path": str(target_path), "content": content}


def execute_fs_write(
    config: BrokerConfig, target_path: Path, content: str
) -> dict[str, Any]:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(content, encoding="utf-8")
    return {"path": str(target_path), "bytes_written": len(content.encode("utf-8"))}


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
    return {"delivered": True, "destination": destination}
