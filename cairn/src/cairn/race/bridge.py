from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from cairn.race.client import OfficialRaceClient, RaceApiError, is_question_complete

LOG = logging.getLogger(__name__)


class BridgeSubmitRequest(BaseModel):
    flag: str


@dataclass
class ProjectBinding:
    project_id: str
    question_id: str
    token: str
    total_flag_num: int = 1
    current_user_solved: int = 0
    attempts: int = 0
    last_flag_at: float | None = None
    registered_at: float = field(default_factory=time.time)

    @property
    def question_complete(self) -> bool:
        return self.total_flag_num > 0 and self.current_user_solved >= self.total_flag_num


class RaceBridgeState:
    """Host-side submission bridge that keeps AGENT_TOKEN completely outside Worker containers."""

    def __init__(self, race_client: OfficialRaceClient):
        self.race_client = race_client
        self._lock = threading.Lock()
        self._by_token: dict[str, ProjectBinding] = {}
        self._by_project: dict[str, ProjectBinding] = {}

    def register_project(
        self,
        project_id: str,
        question_id: str,
        *,
        total_flag_num: int = 1,
        current_user_solved: int = 0,
        token: str | None = None,
    ) -> ProjectBinding:
        with self._lock:
            existing = self._by_project.get(project_id)
            if existing is not None:
                existing.total_flag_num = max(existing.total_flag_num, int(total_flag_num))
                existing.current_user_solved = max(existing.current_user_solved, int(current_user_solved))
                return existing
            tok = (token or secrets.token_urlsafe(24)).strip()
            pre = self._by_token.get(tok)
            if pre is not None:
                pre.project_id = project_id
                pre.total_flag_num = max(pre.total_flag_num, int(total_flag_num))
                pre.current_user_solved = max(pre.current_user_solved, int(current_user_solved))
                self._by_project[project_id] = pre
                return pre
            binding = ProjectBinding(
                project_id=project_id,
                question_id=str(question_id),
                token=tok,
                total_flag_num=max(1, int(total_flag_num)),
                current_user_solved=max(0, int(current_user_solved)),
            )
            self._by_token[tok] = binding
            self._by_project[project_id] = binding
            return binding

    def pre_register_token(
        self,
        question_id: str,
        *,
        total_flag_num: int = 1,
        current_user_solved: int = 0,
    ) -> ProjectBinding:
        """Mint and activate a project submit token BEFORE Cairn project creation to eliminate bootstrap race."""
        with self._lock:
            tok = secrets.token_urlsafe(24)
            binding = ProjectBinding(
                project_id=f"pending:{tok[:8]}",
                question_id=str(question_id),
                token=tok,
                total_flag_num=max(1, int(total_flag_num)),
                current_user_solved=max(0, int(current_user_solved)),
            )
            self._by_token[tok] = binding
            return binding

    def unregister_token(self, token: str) -> None:
        with self._lock:
            binding = self._by_token.pop(token, None)
            if binding is not None:
                self._by_project.pop(binding.project_id, None)

    def unregister_project(self, project_id: str) -> None:
        with self._lock:
            binding = self._by_project.pop(project_id, None)
            if binding is not None:
                self._by_token.pop(binding.token, None)

    def get_by_token(self, token: str | None) -> ProjectBinding | None:
        if not token:
            return None
        with self._lock:
            return self._by_token.get(token.strip())

    def get_by_project(self, project_id: str) -> ProjectBinding | None:
        with self._lock:
            return self._by_project.get(project_id)

    def submit_for_binding(self, binding: ProjectBinding, flag: str) -> dict[str, Any]:
        cleaned = flag.strip()
        if not cleaned:
            raise HTTPException(400, "flag must not be empty")
        try:
            submit_res = self.race_client.submit_flag(binding.question_id, cleaned)
        except RaceApiError as exc:
            LOG.warning(
                "bridge submit error project=%s question=%s code=%s message=%s",
                binding.project_id,
                binding.question_id,
                exc.code,
                exc.message,
            )
            return {
                "ok": False,
                "code": exc.code,
                "message": exc.message,
                "is_pass": False,
                "is_duplicate": False,
                "score": 0,
                "current_user_solved": binding.current_user_solved,
                "total_flag_num": binding.total_flag_num,
                "remaining_flags": max(0, binding.total_flag_num - binding.current_user_solved),
                "question_complete": binding.question_complete,
            }

        prev_solved = binding.current_user_solved
        # Authoritative multi-flag progress refresh from question_info (API_接入.md)
        if submit_res.get("is_pass") or submit_res.get("is_duplicate"):
            try:
                info = self.race_client.question_info(binding.question_id)
                total = int(info.get("total_flag_num") or binding.total_flag_num)
                solved = int(info.get("current_user_solved") or binding.current_user_solved)
                with self._lock:
                    binding.total_flag_num = total
                    binding.current_user_solved = solved
                    if solved > prev_solved:
                        binding.last_flag_at = time.time()
            except Exception as exc:
                LOG.warning("bridge progress refresh failed question=%s err=%s", binding.question_id, exc)
                if submit_res.get("is_pass") and not submit_res.get("is_duplicate"):
                    with self._lock:
                        binding.current_user_solved = min(binding.total_flag_num, binding.current_user_solved + 1)
                        binding.last_flag_at = time.time()

        with self._lock:
            binding.attempts += 1
            solved_now = binding.current_user_solved
            total_now = binding.total_flag_num
            complete_now = binding.question_complete

        LOG.info(
            "bridge submit project=%s question=%s pass=%s dup=%s progress=%s/%s complete=%s",
            binding.project_id,
            binding.question_id,
            submit_res.get("is_pass"),
            submit_res.get("is_duplicate"),
            solved_now,
            total_now,
            complete_now,
        )
        return {
            "ok": True,
            "code": submit_res.get("code", "AD-000000"),
            "is_pass": bool(submit_res.get("is_pass")),
            "is_duplicate": bool(submit_res.get("is_duplicate")),
            "score": submit_res.get("score", 0),
            "current_user_solved": solved_now,
            "total_flag_num": total_now,
            "remaining_flags": max(0, total_now - solved_now),
            "question_complete": complete_now,
        }

    def refresh_progress(self, binding: ProjectBinding) -> dict[str, Any]:
        info = self.race_client.question_info(binding.question_id)
        total = int(info.get("total_flag_num") or binding.total_flag_num)
        solved = int(info.get("current_user_solved") or 0)
        with self._lock:
            if solved > binding.current_user_solved:
                binding.last_flag_at = time.time()
            binding.total_flag_num = total
            binding.current_user_solved = solved
        return {
            "question_id": binding.question_id,
            "current_user_solved": solved,
            "total_flag_num": total,
            "remaining_flags": max(0, total - solved),
            "question_complete": is_question_complete(info),
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "ok": True,
                "active_bindings": [
                    {
                        "project_id": b.project_id,
                        "question_id": b.question_id,
                        "current_user_solved": b.current_user_solved,
                        "total_flag_num": b.total_flag_num,
                        "attempts": b.attempts,
                        "question_complete": b.question_complete,
                    }
                    for b in self._by_project.values()
                ],
            }


def create_bridge_app(state: RaceBridgeState) -> FastAPI:
    app = FastAPI(title="Cairn Race Submit Bridge")

    @app.get("/bridge/health")
    def health():
        return state.snapshot()

    @app.post("/bridge/submit")
    def submit(
        body: BridgeSubmitRequest,
        x_project_token: str | None = Header(default=None, alias="X-Project-Token"),
    ):
        binding = state.get_by_token(x_project_token)
        if binding is None:
            raise HTTPException(401, "invalid or expired project submit token")
        return state.submit_for_binding(binding, body.flag)

    @app.get("/bridge/progress")
    def progress(x_project_token: str | None = Header(default=None, alias="X-Project-Token")):
        binding = state.get_by_token(x_project_token)
        if binding is None:
            raise HTTPException(401, "invalid or expired project submit token")
        return state.refresh_progress(binding)

    return app
