#!/usr/bin/env python3
"""1:1 仿真官方 AI 赛平台（完全对齐 API_接入.md 全部 7 个接口与全部 AD-xxxxxx 错误码）。

支持仿真特性：
  - 所有业务错误一律返回 HTTP 200 + code != "AD-000000"
  - 全接口共享限流 3 次/秒（含 question_list），超限返 HTTP 200 + AD-002002
  - 分阶段放题（按题目配置 release_after_sec 动态解锁）
  - 场景并发上限（默认 2，可配置），超限返 AD-162006
  - 场景故障注入（fail_first_start=true -> 首次启动进入 scene_status=20，须 stop->3->start 恢复）
  - 一题多 Flag（交一个得一个，重复提交返 AD-160014 / is_duplicate=true）
  - 附件下载免认证 GET /attachments/<question_id>/<name>
  - 状态持久化到 JSON 文件（重启不丢分）
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

import uvicorn
import yaml
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel


class QuestionIdBody(BaseModel):
    question_id: str


class SubmitFlagBody(BaseModel):
    question_id: str
    flag: str


def _envelope(code: str = "AD-000000", message: str = "", detail: str = "", data: Any = None) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "detail": detail,
        "timestamp": round(time.time(), 6),
        "data": data,
    }


class MockRacePlatformState:
    def __init__(
        self,
        *,
        valid_token: str = "test-agent-token",
        max_scenes: int = 2,
        rate_limit_rps: int = 3,
        base_url: str = "http://127.0.0.1:18099",
        state_file: Path | None = None,
        attachments_root: Path | None = None,
    ):
        self.valid_token = valid_token
        self.max_scenes = max_scenes
        self.rate_limit_rps = rate_limit_rps
        self.base_url = base_url.rstrip("/")
        self.state_file = state_file
        self.attachments_root = attachments_root
        self.started_at = time.monotonic()
        self.lock = threading.Lock()
        self.questions: dict[str, dict[str, Any]] = {}
        self.solved_flags: dict[str, set[str]] = {}
        self.scene_status: dict[str, int] = {}
        self.scene_start_attempts: dict[str, int] = {}
        self.rate_windows: dict[str, deque[float]] = {}
        self.total_score: float = 0.0
        self.submissions: list[dict[str, Any]] = []

    def load_config(self, path: Path) -> None:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if "max_scenes" in raw:
            self.max_scenes = int(raw["max_scenes"])
        if "rate_limit_rps" in raw:
            self.rate_limit_rps = int(raw["rate_limit_rps"])
        for item in raw.get("questions") or []:
            qid = str(item["id"])
            flags = [str(f).strip() for f in (item.get("flags") or ([item["flag"]] if item.get("flag") else []))]
            q = {
                "id": qid,
                "name": str(item.get("name") or qid),
                "direction": str(item.get("direction") or "web"),
                "score": float(item.get("score") or 100),
                "difficulty": int(item.get("difficulty") or 1),
                "desc": str(item.get("desc") or ""),
                "flags": flags,
                "has_scene": bool(item.get("has_scene", True)),
                "scene_addresses": list(item.get("scene_addresses") or []),
                "attachments": list(item.get("attachments") or []),
                "release_after_sec": float(item.get("release_after_sec") or 0.0),
                "fail_first_start": bool(item.get("fail_first_start", False)),
                "all_user_solved": int(item.get("all_user_solved") or 0),
            }
            self.questions[qid] = q
            self.solved_flags.setdefault(qid, set())
            if q["has_scene"]:
                self.scene_status.setdefault(qid, 3)
        self._load_persisted()

    def _load_persisted(self) -> None:
        if not self.state_file or not self.state_file.is_file():
            return
        try:
            saved = json.loads(self.state_file.read_text(encoding="utf-8"))
            self.total_score = float(saved.get("total_score") or 0.0)
            for qid, flist in (saved.get("solved_flags") or {}).items():
                self.solved_flags[qid] = set(flist)
        except Exception:
            pass

    def persist(self) -> None:
        if not self.state_file:
            return
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "total_score": self.total_score,
            "solved_flags": {k: sorted(v) for k, v in self.solved_flags.items()},
            "submissions_count": len(self.submissions),
        }
        self.state_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def check_auth_and_rate(self, authorization: str | None) -> dict[str, Any] | None:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "Authorization header is required")
        token = authorization[7:].strip()
        if token != self.valid_token:
            return _envelope("AD-160019", "当前比赛中不存在该 token", "invalid token")
        now = time.monotonic()
        win = self.rate_windows.setdefault(token, deque())
        while win and now - win[0] >= 1.0:
            win.popleft()
        if len(win) >= self.rate_limit_rps:
            return _envelope("AD-002002", "提交过于频繁，请在 1 秒后重试", "提交过于频繁，请在 1 秒后重试")
        win.append(now)
        return None

    def is_visible(self, q: dict[str, Any]) -> bool:
        return (time.monotonic() - self.started_at) >= q["release_after_sec"]

    def _attachment_entries(self, q: dict[str, Any]) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for att in q["attachments"]:
            name = att["name"] if isinstance(att, dict) else str(att)
            url = att["url"] if isinstance(att, dict) and att.get("url") else f"{self.base_url}/attachments/{q['id']}/{name}"
            out.append({"name": name, "url": url})
        return out

    def running_scene_count(self) -> int:
        return sum(1 for st in self.scene_status.values() if st in (0, 1))


def create_mock_race_app(state: MockRacePlatformState) -> FastAPI:
    app = FastAPI(title="1:1 Mock Official AI-Race Platform")
    prefix = "/api/ct/agent/ai_race/race/checkpoints/robot"

    @app.get("/health")
    def health():
        with state.lock:
            return {
                "ok": True,
                "visible_questions": sum(1 for q in state.questions.values() if state.is_visible(q)),
                "total_questions": len(state.questions),
                "running_scenes": state.running_scene_count(),
                "total_score": state.total_score,
            }

    @app.get(f"{prefix}/question_list")
    def question_list(
        direction: str | None = Query(default=None),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            out = []
            for q in state.questions.values():
                if not state.is_visible(q):
                    continue
                if direction and q["direction"] != direction:
                    continue
                entry: dict[str, Any] = {
                    "id": q["id"],
                    "name": q["name"],
                    "direction": q["direction"],
                    "score": q["score"],
                    "all_user_solved": q["all_user_solved"],
                    "total_flag_num": len(q["flags"]),
                    "current_user_solved": len(state.solved_flags.get(q["id"], set())),
                    "attachment": state._attachment_entries(q),
                    "has_scene": q["has_scene"],
                }
                if q["has_scene"]:
                    st = state.scene_status.get(q["id"], 3)
                    entry["scene_status"] = st
                    if st == 1:
                        entry["scene_addresses"] = q["scene_addresses"]
                out.append(entry)
            return JSONResponse(_envelope(data={"total": len(out), "list": out}))

    @app.get(f"{prefix}/question_info")
    def question_info(
        question_id: str = Query(...),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            q = state.questions.get(question_id)
            if not q or not state.is_visible(q):
                return JSONResponse(_envelope("AD-160003", "参数校验错误", "题目不存在"))
            return JSONResponse(
                _envelope(
                    data={
                        "id": q["id"],
                        "name": q["name"],
                        "direction": q["direction"],
                        "score": q["score"],
                        "difficulty": q["difficulty"],
                        "all_user_solved": q["all_user_solved"],
                        "total_flag_num": len(q["flags"]),
                        "current_user_solved": len(state.solved_flags.get(q["id"], set())),
                        "desc": q["desc"],
                        "attachment": state._attachment_entries(q),
                    }
                )
            )

    @app.post(f"{prefix}/question_start")
    def question_start(
        body: QuestionIdBody,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            q = state.questions.get(body.question_id)
            if not q or not state.is_visible(q):
                return JSONResponse(_envelope("AD-160003", "参数校验错误", "题目不存在"))
            if not q["has_scene"]:
                return JSONResponse(_envelope("AD-161003", f"题目[{q['name']}]没有开启场景, 无法创建实例"))
            cur = state.scene_status.get(q["id"], 3)
            if cur in (0, 1):
                return JSONResponse(_envelope(data=True))
            if state.running_scene_count() >= state.max_scenes:
                return JSONResponse(
                    _envelope(
                        "AD-162006",
                        f"场景数量[{state.running_scene_count()}]达到上限, 请关闭其他场景后重试",
                    )
                )
            attempts = state.scene_start_attempts.get(q["id"], 0) + 1
            state.scene_start_attempts[q["id"]] = attempts
            if q["fail_first_start"] and attempts == 1:
                state.scene_status[q["id"]] = 20
            else:
                state.scene_status[q["id"]] = 1
            return JSONResponse(_envelope(data=True))

    @app.get(f"{prefix}/question_instance_info")
    def question_instance_info(
        question_id: str = Query(...),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            q = state.questions.get(question_id)
            if not q or not state.is_visible(q):
                return JSONResponse(_envelope("AD-160003", "参数校验错误", "题目不存在"))
            # Per API_接入.md: uses resource_id, omits has_scene & solved statistics
            data: dict[str, Any] = {
                "resource_id": q["id"],
                "name": q["name"],
                "direction": q["direction"],
                "score": q["score"],
                "attachment": state._attachment_entries(q),
            }
            if q["has_scene"]:
                st = state.scene_status.get(q["id"], 3)
                data["scene_status"] = st
                data["scene_addresses"] = q["scene_addresses"] if st == 1 else []
            return JSONResponse(_envelope(data=data))

    @app.post(f"{prefix}/question_stop")
    def question_stop(
        body: QuestionIdBody,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            # Per API_接入.md: does not reject non-existent or stopped challenges
            if body.question_id in state.scene_status:
                state.scene_status[body.question_id] = 3
            return JSONResponse(_envelope(data=True))

    @app.post(f"{prefix}/question/submit_flag")
    def submit_flag(
        body: SubmitFlagBody,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            q = state.questions.get(body.question_id)
            if not q or not state.is_visible(q):
                return JSONResponse(_envelope("AD-160003", "参数校验错误", "题目不存在"))
            flag = body.flag.strip()
            solved_set = state.solved_flags.setdefault(q["id"], set())
            if flag not in q["flags"]:
                state.submissions.append({"ts": time.time(), "qid": q["id"], "pass": False})
                return JSONResponse(_envelope(data={"is_pass": False, "score": 0, "is_duplicate": False}))
            if flag in solved_set:
                return JSONResponse(_envelope("AD-160014", "答案重复写入", "duplicate flag"))
            solved_set.add(flag)
            per_flag_score = round(q["score"] / max(1, len(q["flags"])), 2)
            state.total_score = round(state.total_score + per_flag_score, 2)
            state.submissions.append({"ts": time.time(), "qid": q["id"], "pass": True, "score": per_flag_score})
            state.persist()
            return JSONResponse(_envelope(data={"is_pass": True, "score": per_flag_score, "is_duplicate": False}))

    @app.get("/attachments/{question_id}/{filename}")
    def download_attachment(question_id: str, filename: str):
        # Per API_接入.md §7: no Authorization required
        with state.lock:
            q = state.questions.get(question_id)
            if not q or not state.is_visible(q):
                raise HTTPException(404, "question not found or hidden")
        if not state.attachments_root:
            raise HTTPException(404, "attachments root not configured")
        base = (state.attachments_root / question_id).resolve()
        target = (base / filename).resolve()
        if base not in target.parents or not target.is_file():
            raise HTTPException(404, "attachment not found")
        return FileResponse(target, filename=filename)

    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="1:1 Mock Official AI-Race Platform")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18099)
    ap.add_argument("--config", required=True, help="YAML file defining mock race questions")
    ap.add_argument("--token", default="test-agent-token")
    ap.add_argument("--max-scenes", type=int, default=2)
    ap.add_argument("--rate-limit", type=int, default=3)
    ap.add_argument("--state-file", default=None)
    ap.add_argument("--attachments-dir", default=None)
    args = ap.parse_args()

    state = MockRacePlatformState(
        valid_token=args.token,
        max_scenes=args.max_scenes,
        rate_limit_rps=args.rate_limit,
        base_url=f"http://{args.host}:{args.port}",
        state_file=Path(args.state_file) if args.state_file else None,
        attachments_root=Path(args.attachments_dir) if args.attachments_dir else None,
    )
    state.load_config(Path(args.config))
    app = create_mock_race_app(state)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
