from typing import Any, Optional
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.audit import (
    AuditSubsystemError,
    append_audit_entry,
    recover_or_fail_closed,
)
from app.canonicalize import PathSecurityError, canonicalize_sandbox_path
from app.config import BrokerConfig
from app.models import (
    AttenuateTokenRequest,
    MintTokenRequest,
    RevokeTokenRequest,
    ToolInvokeRequest,
    ToolInvokeResponse,
)
from app.sql_guard import SQLPolicyError, classify_and_execute_sql
from app.taint import (
    TaintPolicyError,
    compute_canonical_args_sha256,
    enforce_taint_and_hitl,
    is_session_tainted,
    mark_session_tainted,
)
from app.tokens import (
    TokenPolicyError,
    attenuate_token,
    mint_root_token,
    record_token_usage,
    revoke_hop,
    verify_and_authorize_token,
)
from app.tools import execute_fs_read, execute_fs_write, execute_webhook_send


def create_app(config: Optional[BrokerConfig] = None) -> FastAPI:
    cfg = config or BrokerConfig.from_env()
    app = FastAPI(title="Aegis Tool Broker", version="0.1.0")
    app.state.broker_config = cfg

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/tokens/mint")
    def api_mint_token(req: MintTokenRequest) -> Any:
        try:
            recover_or_fail_closed(cfg)
            token = mint_root_token(
                cfg,
                principal=req.principal,
                caveat=req.caveat,
                hop_id=req.hop_id,
                issued_at=req.issued_at,
            )
            return token.to_dict()
        except AuditSubsystemError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"status": "error", "error_code": exc.error_code, "message": exc.message},
            )
        except TokenPolicyError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"status": "error", "error_code": exc.error_code, "message": exc.message},
            )

    @app.post("/v1/tokens/attenuate")
    def api_attenuate_token(req: AttenuateTokenRequest) -> Any:
        try:
            recover_or_fail_closed(cfg)
            child = attenuate_token(
                cfg,
                parent_token=req.parent_token,
                caveat=req.caveat,
                hop_id=req.hop_id,
            )
            return child.to_dict()
        except AuditSubsystemError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"status": "error", "error_code": exc.error_code, "message": exc.message},
            )
        except (TokenPolicyError, PathSecurityError) as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"status": "error", "error_code": exc.error_code, "message": exc.message},
            )

    @app.post("/v1/tokens/revoke")
    def api_revoke_token(req: RevokeTokenRequest) -> Any:
        try:
            recover_or_fail_closed(cfg)
            revoke_hop(cfg, req.hop_id)
            return {"status": "ok", "revoked_hop_id": req.hop_id}
        except AuditSubsystemError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"status": "error", "error_code": exc.error_code, "message": exc.message},
            )

    @app.post("/v1/tools/invoke")
    def api_invoke_tool(req: ToolInvokeRequest) -> Any:
        try:
            recover_or_fail_closed(cfg)
        except AuditSubsystemError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "status": "error",
                    "result": None,
                    "error_code": exc.error_code,
                    "message": exc.message,
                    "audit_receipt": None,
                },
            )

        leaf_hop = req.token.lineage_ids[-1] if req.token.lineage_ids else "unknown"
        taint_label = "TAINTED" if is_session_tainted(cfg, req.session_id) else "CLEAN"
        canonical_args: dict[str, Any] = dict(req.arguments)
        args_hash = compute_canonical_args_sha256(req.tool_name, canonical_args)

        try:
            target_path = None
            if req.tool_name in ("fs.read", "fs.write"):
                raw_path = str(req.arguments.get("path", ""))
                target_path = canonicalize_sandbox_path(cfg, raw_path)
                if req.tool_name == "fs.read":
                    canonical_args = {"path": str(target_path)}
                else:
                    canonical_args = {
                        "content": str(req.arguments.get("content", "")),
                        "path": str(target_path),
                    }
            elif req.tool_name == "db.query":
                canonical_args = {
                    "params": list(req.arguments.get("params", [])),
                    "sql": str(req.arguments.get("sql", "")).strip(),
                }
            elif req.tool_name == "webhook.send":
                canonical_args = {
                    "destination": str(req.arguments.get("destination", "")).strip().lower(),
                    "payload": req.arguments.get("payload"),
                }

            args_hash = compute_canonical_args_sha256(req.tool_name, canonical_args)

            effective_caveat = verify_and_authorize_token(
                cfg,
                token=req.token,
                tool_name=req.tool_name,
                canonical_target_path=str(target_path) if target_path else None,
            )

            is_sink = req.tool_name in ("fs.write", "webhook.send")
            if req.tool_name == "db.query":
                is_write_sql, _ = classify_and_execute_sql(
                    cfg,
                    sql=canonical_args["sql"],
                    params=canonical_args["params"],
                    sql_read_only=effective_caveat.sql_read_only,
                    execute_now=False,
                )
                is_sink = is_write_sql

            enforce_taint_and_hitl(
                cfg,
                session_id=req.session_id,
                tool_name=req.tool_name,
                canonical_args=canonical_args,
                is_sensitive_sink=is_sink,
                hitl_receipt=req.hitl_receipt,
            )

            if req.tool_name == "fs.read":
                assert target_path is not None
                result = execute_fs_read(cfg, target_path)
                inbox_prefix = str(cfg.sandbox_root / "inbox")
                if str(target_path) == inbox_prefix or str(target_path).startswith(
                    inbox_prefix + "/"
                ):
                    mark_session_tainted(cfg, req.session_id, str(target_path))
                    taint_label = "TAINTED"
            elif req.tool_name == "fs.write":
                assert target_path is not None
                result = execute_fs_write(
                    cfg, target_path, canonical_args["content"]
                )
            elif req.tool_name == "db.query":
                _, rows = classify_and_execute_sql(
                    cfg,
                    sql=canonical_args["sql"],
                    params=canonical_args["params"],
                    sql_read_only=effective_caveat.sql_read_only,
                    execute_now=True,
                )
                result = {"rows": rows}
            elif req.tool_name == "webhook.send":
                result = execute_webhook_send(
                    cfg,
                    destination=canonical_args["destination"],
                    payload=canonical_args["payload"],
                    session_id=req.session_id,
                )
            else:
                raise TokenPolicyError(400, "CAPABILITY_VIOLATION", "Unknown tool")

            record_token_usage(cfg, req.token)
            receipt = append_audit_entry(
                cfg,
                session_id=req.session_id,
                token_hop_id=leaf_hop,
                tool_name=req.tool_name,
                canonical_args_sha256=args_hash,
                taint_state=taint_label,
                decision="ALLOW",
                reason_code="OK",
            )
            resp = ToolInvokeResponse(
                status="ok",
                result=result,
                error_code=None,
                message=None,
                audit_receipt=receipt,
            )
            return resp.to_dict()

        except (TokenPolicyError, PathSecurityError, SQLPolicyError, TaintPolicyError) as exc:
            receipt = append_audit_entry(
                cfg,
                session_id=req.session_id,
                token_hop_id=leaf_hop,
                tool_name=req.tool_name,
                canonical_args_sha256=args_hash,
                taint_state=taint_label,
                decision="DENY",
                reason_code=exc.error_code,
            )
            resp = ToolInvokeResponse(
                status="error",
                result=None,
                error_code=exc.error_code,
                message=exc.message,
                audit_receipt=receipt,
            )
            return JSONResponse(status_code=exc.status_code, content=resp.to_dict())
        except FileNotFoundError as exc:
            receipt = append_audit_entry(
                cfg,
                session_id=req.session_id,
                token_hop_id=leaf_hop,
                tool_name=req.tool_name,
                canonical_args_sha256=args_hash,
                taint_state=taint_label,
                decision="DENY",
                reason_code="FILE_NOT_FOUND",
            )
            resp = ToolInvokeResponse(
                status="error",
                result=None,
                error_code="FILE_NOT_FOUND",
                message=str(exc),
                audit_receipt=receipt,
            )
            return JSONResponse(status_code=404, content=resp.to_dict())

    return app


app = create_app()
