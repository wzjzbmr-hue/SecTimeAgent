#!/usr/bin/env python3
"""Strictly Isolated Human-Only Reference Guide Service & Store (Section 7).

Security & anti-leakage design:
  1. Stored in its own gitignored directory (eval/human-references/), NEVER mounted into Worker containers.
  2. Authenticated ONLY by a dedicated HUMAN_REF_TOKEN (strictly rejected if token == AGENT_TOKEN or missing).
  3. Worker credentials (AGENT_TOKEN, X-Project-Token) receive HTTP 403 Forbidden and are audit-logged.
  4. Never exposed via official challenge APIs (question_list/question_info/question_instance_info), MCP tools,
     /api/dashboard/snapshot, SSE streams, or generic logs.
  5. Records every read/write/rejection in an append-only audit log (audit.jsonl).
  6. Supports running either as a standalone human-only HTTP service (recommended) or mounted behind
     strictly token-isolated endpoints in the local cockpit.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

REQUIRED_SECTIONS = (
    "applicability",
    "goal_and_acceptance",
    "standard_stages",
    "alternative_routes",
    "time_and_resource_ref",
    "gap_analysis_hints",
    "verification",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class ReferenceVerification(BaseModel):
    verified: bool = False
    author: str = "未填写"
    reviewer: str = "未复核"
    version: str = "v0-draft"
    verified_at: str | None = None


class HumanReferenceDoc(BaseModel):
    challenge_id: str
    title: str = ""
    applicability: dict[str, Any] = Field(
        default_factory=lambda: {
            "prompt_version": "未标注",
            "attachment_sha256": "未标注",
            "env_version": "未标注",
            "allowed_scope": "仅限授权本地靶场范围",
        }
    )
    goal_and_acceptance: dict[str, Any] = Field(
        default_factory=lambda: {
            "expected_artifact": "未标注",
            "acceptance_rule": "未标注",
            "verification_method": "未标注",
        }
    )
    standard_stages: list[dict[str, Any]] = Field(default_factory=list)
    alternative_routes: list[dict[str, Any]] = Field(default_factory=list)
    time_and_resource_ref: dict[str, Any] = Field(
        default_factory=lambda: {
            "duration_range_sec": None,
            "measurement_conditions": "未测量（严禁凭空填写基准）",
            "source": "未标注",
        }
    )
    gap_analysis_hints: list[str] = Field(default_factory=list)
    verification: ReferenceVerification = Field(default_factory=ReferenceVerification)


class IsolatedHumanReferenceStore:
    """Server-side isolated reference guide store with strict token separation & audit log."""

    def __init__(
        self,
        root_dir: Path,
        human_token: str,
        *,
        forbidden_tokens: list[str] | None = None,
    ):
        self.root_dir = Path(root_dir).resolve()
        self.guides_dir = self.root_dir / "guides"
        self.audit_log = self.root_dir / "audit.jsonl"
        self.human_token = human_token.strip()
        self.forbidden_tokens = {t.strip() for t in (forbidden_tokens or []) if t and t.strip()}
        if not self.human_token:
            raise ValueError("human_token must not be empty")
        if self.human_token in self.forbidden_tokens:
            raise ValueError("SECURITY VIOLATION: human_token MUST NOT match AGENT_TOKEN or worker credentials")
        self._lock = threading.Lock()
        self.guides_dir.mkdir(parents=True, exist_ok=True)

    def _audit(
        self,
        *,
        action: str,
        operator: str,
        challenge_id: str | None,
        version: str | None,
        allowed: bool,
        reason: str = "",
    ) -> None:
        entry = {
            "ts": round(time.time(), 3),
            "at": _now_iso(),
            "action": action,
            "operator": operator or "unknown",
            "challenge_id": challenge_id,
            "version": version,
            "allowed": allowed,
            "reason": reason,
        }
        with self._lock:
            self.root_dir.mkdir(parents=True, exist_ok=True)
            with self.audit_log.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def verify_human_access(
        self,
        provided_token: str | None,
        *,
        operator: str | None,
        challenge_id: str | None = None,
        action: str = "read",
        authorization_header: str | None = None,
        project_token_header: str | None = None,
    ) -> str:
        """Strictly authenticate human operator; reject worker/agent tokens with 403."""
        op_name = (operator or "human-operator").strip() or "human-operator"

        # Explicitly reject if request carries a Worker project token or Agent bearer token
        if project_token_header:
            self._audit(
                action=action,
                operator=op_name,
                challenge_id=challenge_id,
                version=None,
                allowed=False,
                reason="rejected_worker_project_token",
            )
            raise HTTPException(403, "Worker credentials are forbidden from accessing human reference guides")

        if authorization_header and authorization_header.lower().startswith("bearer "):
            bearer = authorization_header[7:].strip()
            if bearer in self.forbidden_tokens:
                self._audit(
                    action=action,
                    operator=op_name,
                    challenge_id=challenge_id,
                    version=None,
                    allowed=False,
                    reason="rejected_agent_token",
                )
                raise HTTPException(403, "Agent/Worker token is strictly forbidden from accessing human reference guides")

        tok = (provided_token or "").strip()
        if not tok:
            self._audit(
                action=action,
                operator=op_name,
                challenge_id=challenge_id,
                version=None,
                allowed=False,
                reason="missing_human_token",
            )
            raise HTTPException(403, "Human reference token (X-Human-Ref-Token) is required")

        if tok in self.forbidden_tokens or not hmac.compare_digest(tok, self.human_token):
            self._audit(
                action=action,
                operator=op_name,
                challenge_id=challenge_id,
                version=None,
                allowed=False,
                reason="invalid_human_token",
            )
            raise HTTPException(403, "Invalid human reference token")

        return op_name

    def _safe_guide_path(self, challenge_id: str) -> Path:
        clean = "".join(ch for ch in challenge_id if ch.isalnum() or ch in ("-", "_"))
        if not clean or clean != challenge_id:
            raise HTTPException(400, "Invalid challenge_id format")
        path = (self.guides_dir / f"{clean}.json").resolve()
        if self.guides_dir not in path.parents:
            raise HTTPException(400, "Invalid challenge_id path")
        return path

    def get_guide(self, challenge_id: str, *, operator: str) -> dict[str, Any]:
        path = self._safe_guide_path(challenge_id)
        if not path.is_file():
            self._audit(
                action="read",
                operator=operator,
                challenge_id=challenge_id,
                version=None,
                allowed=True,
                reason="not_authored",
            )
            return {
                "exists": False,
                "challenge_id": challenge_id,
                "notice": "尚未由具备题面材料的人类评审编写或核验参考方法。系统不会捏造标准解法。",
                "template": HumanReferenceDoc(challenge_id=challenge_id).model_dump(),
            }
        data = json.loads(path.read_text(encoding="utf-8"))
        doc = HumanReferenceDoc(**data).model_dump()
        ver = doc["verification"]["version"]
        self._audit(action="read", operator=operator, challenge_id=challenge_id, version=ver, allowed=True)
        return {
            "exists": True,
            "challenge_id": challenge_id,
            "verified": bool(doc["verification"]["verified"]),
            "guide": doc,
        }

    def save_guide(self, doc: HumanReferenceDoc, *, operator: str) -> dict[str, Any]:
        path = self._safe_guide_path(doc.challenge_id)
        payload = doc.model_dump()
        with self._lock:
            self.guides_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        self._audit(
            action="write",
            operator=operator,
            challenge_id=doc.challenge_id,
            version=doc.verification.version,
            allowed=True,
        )
        return {"ok": True, "challenge_id": doc.challenge_id, "version": doc.verification.version}

    def list_audit_entries(self, limit: int = 50) -> list[dict[str, Any]]:
        if not self.audit_log.is_file():
            return []
        lines = self.audit_log.read_text(encoding="utf-8", errors="ignore").splitlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out


def mount_human_reference_routes(app: FastAPI, store: IsolatedHumanReferenceStore, prefix: str = "/api/human-reference") -> None:
    """Attach strictly isolated human-only endpoints to a FastAPI app."""

    @app.get(f"{prefix}/challenges/{{challenge_id}}")
    def get_human_reference(
        challenge_id: str,
        x_human_ref_token: str | None = Header(default=None, alias="X-Human-Ref-Token"),
        x_human_operator: str | None = Header(default=None, alias="X-Human-Operator"),
        authorization: str | None = Header(default=None, alias="Authorization"),
        x_project_token: str | None = Header(default=None, alias="X-Project-Token"),
    ):
        op = store.verify_human_access(
            x_human_ref_token,
            operator=x_human_operator,
            challenge_id=challenge_id,
            action="read",
            authorization_header=authorization,
            project_token_header=x_project_token,
        )
        return JSONResponse(store.get_guide(challenge_id, operator=op))

    @app.put(f"{prefix}/challenges/{{challenge_id}}")
    def put_human_reference(
        challenge_id: str,
        body: HumanReferenceDoc,
        x_human_ref_token: str | None = Header(default=None, alias="X-Human-Ref-Token"),
        x_human_operator: str | None = Header(default=None, alias="X-Human-Operator"),
        authorization: str | None = Header(default=None, alias="Authorization"),
        x_project_token: str | None = Header(default=None, alias="X-Project-Token"),
    ):
        op = store.verify_human_access(
            x_human_ref_token,
            operator=x_human_operator,
            challenge_id=challenge_id,
            action="write",
            authorization_header=authorization,
            project_token_header=x_project_token,
        )
        body.challenge_id = challenge_id
        return JSONResponse(store.save_guide(body, operator=op))

    @app.get(f"{prefix}/audit")
    def get_human_reference_audit(
        limit: int = 50,
        x_human_ref_token: str | None = Header(default=None, alias="X-Human-Ref-Token"),
        x_human_operator: str | None = Header(default=None, alias="X-Human-Operator"),
        authorization: str | None = Header(default=None, alias="Authorization"),
        x_project_token: str | None = Header(default=None, alias="X-Project-Token"),
    ):
        store.verify_human_access(
            x_human_ref_token,
            operator=x_human_operator,
            action="audit_read",
            authorization_header=authorization,
            project_token_header=x_project_token,
        )
        return JSONResponse({"ok": True, "entries": store.list_audit_entries(limit=limit)})


def create_standalone_app(store: IsolatedHumanReferenceStore) -> FastAPI:
    app = FastAPI(title="Isolated Human Reference Guide Service")
    mount_human_reference_routes(app, store)

    @app.get("/health")
    def health():
        return {"ok": True, "isolated": True}

    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="Standalone Isolated Human-Only Reference Guide Service")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18199)
    ap.add_argument("--dir", default="eval/human-references")
    ap.add_argument("--human-token", default=os.environ.get("HUMAN_REF_TOKEN", ""))
    ap.add_argument("--forbid-token", action="append", default=[])
    args = ap.parse_args()
    if not args.human_token:
        ap.error("--human-token or HUMAN_REF_TOKEN is required")
    forbid = list(args.forbid_token)
    for env_k in ("RACE_AGENT_TOKEN", "CAIRN_ADMIN_TOKEN"):
        if os.environ.get(env_k):
            forbid.append(os.environ[env_k])
    store = IsolatedHumanReferenceStore(Path(args.dir), args.human_token, forbidden_tokens=forbid)
    app = create_standalone_app(store)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
