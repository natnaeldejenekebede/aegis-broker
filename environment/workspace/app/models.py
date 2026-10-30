from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


AllowedToolName = Literal["fs.read", "fs.write", "db.query", "webhook.send"]


class BaseSchema(BaseModel):
    """Pydantic schema base supporting both Pydantic v2 and v1 environments."""

    def to_dict(self) -> dict[str, Any]:
        if hasattr(self, "model_dump"):
            return self.model_dump()
        return self.dict()


class Caveat(BaseSchema):
    allowed_tools: list[AllowedToolName] = Field(...)
    allowed_path_prefixes: list[str] = Field(default_factory=list)
    sql_read_only: bool = True
    max_calls: int = Field(..., ge=1)
    expires_at: int = Field(..., ge=1)


class CapabilityToken(BaseSchema):
    lineage_ids: list[str] = Field(...)
    principal: str = Field(..., min_length=1)
    issued_at: int = Field(..., ge=1)
    caveats: list[Caveat] = Field(...)
    signature: str = Field(..., min_length=1)


class MintTokenRequest(BaseSchema):
    principal: str = Field(..., min_length=1)
    hop_id: str | None = None
    issued_at: int | None = None
    caveat: Caveat


class AttenuateTokenRequest(BaseSchema):
    parent_token: CapabilityToken
    hop_id: str | None = None
    caveat: Caveat


class RevokeTokenRequest(BaseSchema):
    hop_id: str = Field(..., min_length=1)


class HITLReceipt(BaseSchema):
    session_id: str = Field(..., min_length=1)
    tool_name: AllowedToolName
    canonical_args_sha256: str = Field(..., min_length=64, max_length=64)
    expires_at: int = Field(..., ge=1)
    nonce: str = Field(..., min_length=16, max_length=64)
    signature: str = Field(..., min_length=64, max_length=64)


class ToolInvokeRequest(BaseSchema):
    session_id: str = Field(..., min_length=1)
    token: CapabilityToken
    tool_name: AllowedToolName
    arguments: dict[str, Any] = Field(default_factory=dict)
    hitl_receipt: HITLReceipt | None = None


class AuditReceipt(BaseSchema):
    seq: int
    entry_hmac: str


class ToolInvokeResponse(BaseSchema):
    status: Literal["ok", "error"]
    result: Any = None
    error_code: str | None = None
    message: str | None = None
    audit_receipt: AuditReceipt | None = None


class AuditVerificationResult(BaseSchema):
    valid: bool
    entries_checked: int
    first_corrupted_seq: int | None = None
    error_code: str | None = None
