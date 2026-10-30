from __future__ import annotations

from pathlib import Path

from app.config import BrokerConfig


class PathSecurityError(Exception):
    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message


def canonicalize_sandbox_path(
    config: BrokerConfig,
    raw_path: str,
    allowed_prefixes: list[str] | None = None,
) -> Path:
    """
    Starter implementation (VULNERABLE):
    Returns a Path object from the raw string without resolving '..' segments,
    percent encodings, null bytes, sibling prefix collisions, or symlinks
    before policy evaluation.
    """
    if not raw_path or not isinstance(raw_path, str):
        raise PathSecurityError(400, "INVALID_PATH_ENCODING", "Empty path")

    if allowed_prefixes:
        if not any(raw_path.startswith(p) for p in allowed_prefixes):
            raise PathSecurityError(
                403, "PATH_BOUNDARY_VIOLATION", "Path outside allowed prefix"
            )
    return Path(raw_path)
