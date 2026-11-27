from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import uvicorn

from cairn.dispatcher.protocol.client import CairnClient
from cairn.race.bridge import RaceBridgeState, create_bridge_app
from cairn.race.client import (
    ERR_SCENE_LIMIT,
    OfficialRaceClient,
    RaceApiError,
    is_question_complete,
)

LOG = logging.getLogger("cairn.race.orchestrator")


@dataclass
class OrchestratorConfig:
    race_base_url: str
    agent_token: str
    cairn_url: str = "http://127.0.0.1:8000"
    cairn_admin_token: str | None = None
    bridge_host: str = "127.0.0.1"
    bridge_port: int = 8098
    max_scenes: int = 2
    max_attachments: int = 2
    poll_interval_sec: float = 30.0
    tick_interval_sec: float = 3.0
    scene_wait_timeout_sec: float = 120.0
    scene_poll_interval_sec: float = 3.0
    base_budget_easy_sec: int = 480
    base_budget_medium_sec: int = 720
    base_budget_hard_sec: int = 1080
    extra_budget_per_flag_sec: int = 360
    stale_timeout_sec: int = 600
    max_reopens: int = 3
    disk_min_free_gb: float = 4.0
    attachments_dir: str = "/tmp/cairn-attachments"
    state_file: str = "runtime/race-orchestrator-state.json"
    start_at: str | None = None  # ISO-8601 e.g. 2026-12-02T08:30:00+08:00
    end_at: str | None = None    # ISO-8601 e.g. 2026-12-02T12:30:00+08:00


@dataclass
class TrackedQuestion:
    question_id: str
    name: str
    direction: str
    score: float
    difficulty: int  # 1=easy, 2=medium, 3=hard (0/unknown -> treated as 2)
    has_scene: bool
    total_flag_num: int
    current_user_solved: int
    all_user_solved: int = 0
    desc: str = ""
    attachments: list[dict[str, Any]] = field(default_factory=list)
    scene_addresses: list[dict[str, Any]] = field(default_factory=list)
    status: str = "pending"  # pending | running | solved | revisit | exhausted
    project_id: str | None = None
    started_at: float | None = None
    last_progress_at: float | None = None
    budget_sec: int = 720
    reopen_count: int = 0
    attempts_runs: int = 0

    def priority_key(self) -> tuple[int, int, float, int, str]:
        # Pure attachment challenges (has_scene=False -> 0) and difficulty=1 run first
        # to lock Top-50 / First-Blood bonuses before long hard scenes.
        diff_rank = self.difficulty if self.difficulty in (1, 2, 3) else 2
        return (1 if self.has_scene else 0, diff_rank, -float(self.score), int(self.all_user_solved), self.question_id)


def _format_addresses(addresses: list[dict[str, Any]]) -> str:
    if not addresses:
        return "(none)"
    parts: list[str] = []
    for addr in addresses:
        proto = str(addr.get("protocol") or "tcp").lower()
        ip = str(addr.get("access_ip") or "")
        port = addr.get("access_port")
        if proto in ("http", "https"):
            parts.append(f"{proto}://{ip}:{port}")
        else:
            parts.append(f"{proto}://{ip}:{port}")
    return ", ".join(parts)


class RaceOrchestrator:
    """Official AI-Race master controller:
    - Scheduled auto-start (08:30) and clean hard-stop (12:30)
    - Periodic phased challenge polling (question_list)
    - Dual-pool concurrency (2 scene slots + 2 attachment slots, adapting on AD-162006)
    - Difficulty/score/rank priority queue + late-game revisit queue
    - Authoritative multi-flag completion & automatic Cairn /reopen on premature complete
    - Zero-token-leak submission bridge
    """

    def __init__(
        self,
        config: OrchestratorConfig,
        *,
        race_client: OfficialRaceClient | None = None,
        cairn_client: CairnClient | None = None,
        bridge_state: RaceBridgeState | None = None,
    ):
        self.config = config
        self.race = race_client or OfficialRaceClient(config.race_base_url, config.agent_token)
        self.cairn = cairn_client or CairnClient(config.cairn_url, admin_token=config.cairn_admin_token)
        self.bridge = bridge_state or RaceBridgeState(self.race)
        self.questions: dict[str, TrackedQuestion] = {}
        self.effective_max_scenes = max(1, int(config.max_scenes))
        self._last_poll_at = 0.0
        self._last_disk_check_at = 0.0
        self._stop_event = threading.Event()
        self._bridge_server: uvicorn.Server | None = None
        self._bridge_thread: threading.Thread | None = None

    @property
    def bridge_url(self) -> str:
        return f"http://{self.config.bridge_host}:{self.config.bridge_port}"

    def start_embedded_bridge(self) -> None:
        if self._bridge_thread is not None and self._bridge_thread.is_alive():
            return
        app = create_bridge_app(self.bridge)
        uv_cfg = uvicorn.Config(
            app,
            host=self.config.bridge_host,
            port=self.config.bridge_port,
            log_level="warning",
        )
        self._bridge_server = uvicorn.Server(uv_cfg)
        self._bridge_thread = threading.Thread(target=self._bridge_server.run, daemon=True)
        self._bridge_thread.start()
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if getattr(self._bridge_server, "started", False):
                LOG.info("embedded race bridge listening on %s", self.bridge_url)
                return
            time.sleep(0.1)

    def stop_embedded_bridge(self) -> None:
        if self._bridge_server is not None:
            self._bridge_server.should_exit = True
        if self._bridge_thread is not None:
            self._bridge_thread.join(timeout=5.0)

    def _compute_budget(self, difficulty: int, total_flag_num: int) -> int:
        if difficulty == 1:
            base = self.config.base_budget_easy_sec
        elif difficulty == 3:
            base = self.config.base_budget_hard_sec
        else:
            base = self.config.base_budget_medium_sec
        extra = max(0, int(total_flag_num) - 1) * self.config.extra_budget_per_flag_sec
        return base + extra

    def poll_questions(self) -> int:
        """Fetch question_list and merge any newly phased-in challenges."""
        try:
            items = self.race.question_list()
        except RaceApiError as exc:
            LOG.warning("question_list failed code=%s message=%s", exc.code, exc.message)
            return 0
        added = 0
        for item in items:
            qid = str(item["id"])
            solved_now = int(item.get("current_user_solved") or 0)
            total_now = int(item.get("total_flag_num") or 1)
            complete_now = is_question_complete(item)

            existing = self.questions.get(qid)
            if existing is not None:
                if solved_now > existing.current_user_solved:
                    existing.current_user_solved = solved_now
                    existing.last_progress_at = time.monotonic()
                existing.total_flag_num = total_now
                existing.all_user_solved = int(item.get("all_user_solved") or existing.all_user_solved)
                if complete_now and existing.status != "solved":
                    self._finalize_solved(existing)
                continue

            # Fetch detailed metadata (desc, difficulty, attachments) once on discovery
            detail: dict[str, Any] = {}
            try:
                detail = self.race.question_info(qid)
            except RaceApiError as exc:
                LOG.warning("question_info failed on discovery qid=%s code=%s", qid, exc.code)

            difficulty = int(detail.get("difficulty") or item.get("difficulty") or 2)
            has_scene = bool(item.get("has_scene"))
            attachments = list(detail.get("attachment") or item.get("attachment") or [])
            desc = str(detail.get("desc") or "")
            q = TrackedQuestion(
                question_id=qid,
                name=str(item.get("name") or detail.get("name") or qid),
                direction=str(item.get("direction") or detail.get("direction") or "unknown"),
                score=float(item.get("score") or detail.get("score") or 0),
                difficulty=difficulty,
                has_scene=has_scene,
                total_flag_num=total_now,
                current_user_solved=solved_now,
                all_user_solved=int(item.get("all_user_solved") or 0),
                desc=desc,
                attachments=attachments,
                status="solved" if complete_now else "pending",
                budget_sec=self._compute_budget(difficulty, total_now),
            )
            self.questions[qid] = q
            added += 1
            LOG.info(
                "discovered challenge qid=%s name=%s dir=%s diff=%s score=%s flags=%s/%s has_scene=%s",
                q.question_id,
                q.name,
                q.direction,
                q.difficulty,
                q.score,
                q.current_user_solved,
                q.total_flag_num,
                q.has_scene,
            )
        self._save_state()
        return added

    def _active_counts(self) -> tuple[int, int]:
        scenes = sum(1 for q in self.questions.values() if q.status == "running" and q.has_scene)
        attachments = sum(1 for q in self.questions.values() if q.status == "running" and not q.has_scene)
        return scenes, attachments

    def _dispatch_pending(self) -> int:
        started = 0
        for pool_status in ("pending", "revisit"):
            candidates = [q for q in self.questions.values() if q.status == pool_status]
            candidates.sort(key=lambda q: q.priority_key())
            for q in candidates:
                active_scenes, active_att = self._active_counts()
                if q.has_scene:
                    if active_scenes >= self.effective_max_scenes:
                        continue
                else:
                    if active_att >= self.config.max_attachments:
                        continue
                if self._launch_question(q):
                    started += 1
        return started

    def _launch_question(self, q: TrackedQuestion) -> bool:
        addresses: list[dict[str, Any]] = []
        if q.has_scene:
            try:
                inst = self.race.ensure_scene_running(
                    q.question_id,
                    wait_timeout=self.config.scene_wait_timeout_sec,
                    poll_interval=self.config.scene_poll_interval_sec,
                )
                addresses = list(inst.get("scene_addresses") or [])
            except RaceApiError as exc:
                if exc.code == ERR_SCENE_LIMIT:
                    active_scenes, _ = self._active_counts()
                    self.effective_max_scenes = max(1, active_scenes)
                    LOG.warning(
                        "platform returned %s (scene cap reached); adapting effective_max_scenes=%s",
                        ERR_SCENE_LIMIT,
                        self.effective_max_scenes,
                    )
                    return False
                LOG.warning("failed to start scene qid=%s code=%s msg=%s", q.question_id, exc.code, exc.message)
                q.status = "revisit"
                return False
            q.scene_addresses = addresses

        local_attachments: list[str] = []
        if q.attachments:
            att_dir = Path(self.config.attachments_dir) / q.question_id
            for att in q.attachments:
                url = str(att.get("url") or "").strip()
                fname = str(att.get("name") or "attachment.bin").strip()
                if not url:
                    continue
                try:
                    saved = self.race.download_attachment(url, att_dir / fname)
                    local_attachments.append(f"{fname} (url={url}, local={saved})")
                except Exception as exc:
                    LOG.warning("attachment download failed qid=%s url=%s err=%s", q.question_id, url, exc)
                    local_attachments.append(f"{fname} (url={url})")

        # Pre-mint and activate ephemeral submit token BEFORE create_project so even an immediate
        # bootstrap worker sees CAIRN_BRIDGE_URL & CAIRN_PROJECT_TOKEN atomically (zero race).
        pre_binding = self.bridge.pre_register_token(
            q.question_id,
            total_flag_num=q.total_flag_num,
            current_user_solved=q.current_user_solved,
        )
        submit_instructions = (
            f"Submission Bridge: CAIRN_BRIDGE_URL={self.bridge_url} "
            f"CAIRN_PROJECT_TOKEN={pre_binding.token}\n"
            f"Run: CAIRN_BRIDGE_URL={self.bridge_url} CAIRN_PROJECT_TOKEN={pre_binding.token} submit-flag '<flag>'\n"
            f"Check progress: CAIRN_BRIDGE_URL={self.bridge_url} CAIRN_PROJECT_TOKEN={pre_binding.token} submit-flag --progress\n"
            "Do NOT attempt to call external APIs directly or stop the scene yourself; the orchestrator manages scenes."
        )
        target_text = _format_addresses(addresses) if q.has_scene else "Offline attachment challenge (no remote target)"
        origin = (
            f"Challenge ID: {q.question_id} | Name: {q.name} | Direction: {q.direction} | "
            f"Difficulty: {q.difficulty} | Score: {q.score}\n"
            f"Authorized Targets (ONLY scan these): {target_text}\n"
            f"Attachments: {'; '.join(local_attachments) if local_attachments else 'none'}\n"
            f"{submit_instructions}\n"
            f"Description:\n{q.desc}"
        )
        goal = (
            f"Find and submit ALL {q.total_flag_num} flag(s) for challenge {q.question_id} ({q.name}). "
            f"Current solved progress: {q.current_user_solved}/{q.total_flag_num}. "
            "Submit EACH flag immediately via `submit-flag <flag>` upon discovery. "
            "Do NOT output `complete` until `submit-flag` confirms `question_complete: true`."
        )
        resp = self.cairn.create_project(
            title=f"race-{q.question_id}-{q.name}",
            origin=origin,
            goal=goal,
            bootstrap_enabled=True,
        )
        if not resp.ok or not isinstance(resp.data, dict):
            LOG.warning("cairn create_project failed qid=%s status=%s", q.question_id, resp.status_code)
            self.bridge.unregister_token(pre_binding.token)
            if q.has_scene:
                self._safe_stop_scene(q.question_id)
            return False

        pid = resp.data["project"]["id"]
        self.bridge.register_project(
            pid,
            q.question_id,
            total_flag_num=q.total_flag_num,
            current_user_solved=q.current_user_solved,
            token=pre_binding.token,
        )
        self.cairn.add_hint(pid, submit_instructions, creator="race_orchestrator")

        now = time.monotonic()
        q.project_id = pid
        q.status = "running"
        q.started_at = now
        q.last_progress_at = now
        q.attempts_runs += 1
        LOG.info(
            "launched challenge qid=%s project=%s has_scene=%s flags=%s/%s budget=%ss",
            q.question_id,
            pid,
            q.has_scene,
            q.current_user_solved,
            q.total_flag_num,
            q.budget_sec,
        )
        self._save_state()
        return True

    def _monitor_running(self) -> None:
        now = time.monotonic()
        for q in list(self.questions.values()):
            if q.status != "running" or not q.project_id:
                continue

            pid = q.project_id
            binding = self.bridge.get_by_project(pid)
            if binding is not None:
                if binding.current_user_solved > q.current_user_solved:
                    q.current_user_solved = binding.current_user_solved
                    q.last_progress_at = now
                q.total_flag_num = binding.total_flag_num
                if binding.question_complete:
                    LOG.info("bridge confirmed ALL flags solved qid=%s project=%s (%s/%s)", q.question_id, pid, q.current_user_solved, q.total_flag_num)
                    self._finalize_solved(q)
                    continue

            try:
                detail = self.cairn.get_project(pid)
            except Exception as exc:
                LOG.warning("failed to inspect project=%s err=%s", pid, exc)
                continue

            pstatus = detail.project.status
            if pstatus == "completed":
                # Authoritative multi-flag completion gate!
                try:
                    info = self.race.question_info(q.question_id)
                    q.current_user_solved = int(info.get("current_user_solved") or q.current_user_solved)
                    q.total_flag_num = int(info.get("total_flag_num") or q.total_flag_num)
                    complete_auth = is_question_complete(info)
                except RaceApiError as exc:
                    LOG.warning("authoritative question_info failed qid=%s code=%s", q.question_id, exc.code)
                    complete_auth = q.total_flag_num > 0 and q.current_user_solved >= q.total_flag_num

                if complete_auth:
                    self._finalize_solved(q)
                    continue

                # Premature complete on multi-flag (or zero-flag) challenge -> auto /reopen!
                remaining = max(1, q.total_flag_num - q.current_user_solved)
                if q.reopen_count < self.config.max_reopens:
                    q.reopen_count += 1
                    feedback = (
                        f"[MULTI_FLAG_GATE] Project prematurely marked completed, but authoritative platform progress "
                        f"is {q.current_user_solved}/{q.total_flag_num} ({remaining} flag(s) still unsolved). "
                        "Do NOT stop or close existing footholds. Inspect existing facts/sessions and find the remaining flags."
                    )
                    reopen = self.cairn.reopen_project(pid, feedback, creator="race_orchestrator")
                    if reopen.ok:
                        LOG.warning(
                            "reopened premature completion qid=%s project=%s progress=%s/%s reopen=%s/%s",
                            q.question_id,
                            pid,
                            q.current_user_solved,
                            q.total_flag_num,
                            q.reopen_count,
                            self.config.max_reopens,
                        )
                        continue
                LOG.warning("max reopens reached qid=%s project=%s -> suspending to revisit", q.question_id, pid)
                self._suspend_question(q, reason="max_reopens_reached")
                continue

            if pstatus == "stopped":
                self._suspend_question(q, reason="project_stopped_externally")
                continue

            # Check total budget and stale-since-last-flag timeout
            elapsed_total = now - (q.started_at or now)
            elapsed_stale = now - (q.last_progress_at or q.started_at or now)
            if elapsed_total >= q.budget_sec:
                self._suspend_question(q, reason=f"budget_exceeded({int(elapsed_total)}s/{q.budget_sec}s)")
            elif elapsed_stale >= self.config.stale_timeout_sec:
                self._suspend_question(q, reason=f"stale_no_new_flag({int(elapsed_stale)}s)")

    def _finalize_solved(self, q: TrackedQuestion) -> None:
        if q.project_id:
            self.cairn.stop_project(q.project_id)
            self.bridge.unregister_project(q.project_id)
        if q.has_scene:
            self._safe_stop_scene(q.question_id)
        q.status = "solved"
        LOG.info(
            "SOLVED qid=%s name=%s flags=%s/%s score=%s",
            q.question_id,
            q.name,
            q.current_user_solved,
            q.total_flag_num,
            q.score,
        )
        self._save_state()

    def _suspend_question(self, q: TrackedQuestion, *, reason: str) -> None:
        LOG.warning(
            "suspending qid=%s project=%s reason=%s partial_progress=%s/%s",
            q.question_id,
            q.project_id,
            reason,
            q.current_user_solved,
            q.total_flag_num,
        )
        if q.project_id:
            self.cairn.stop_project(q.project_id)
            self.bridge.unregister_project(q.project_id)
        if q.has_scene:
            self._safe_stop_scene(q.question_id)
        q.project_id = None
        q.started_at = None
        q.last_progress_at = None
        q.status = "revisit" if q.attempts_runs < 2 else "exhausted"
        self._save_state()

    def _safe_stop_scene(self, question_id: str) -> None:
        try:
            self.race.question_stop(question_id)
        except RaceApiError as exc:
            LOG.warning("question_stop failed qid=%s code=%s", question_id, exc.code)

    def _check_disk_watermark(self) -> None:
        now = time.monotonic()
        if now - self._last_disk_check_at < 300.0:
            return
        self._last_disk_check_at = now
        try:
            usage = shutil.disk_usage("/")
            free_gb = usage.free / (1024 ** 3)
            if free_gb < self.config.disk_min_free_gb:
                LOG.warning("LOW DISK WARNING: %.2f GB free (threshold %.1f GB)", free_gb, self.config.disk_min_free_gb)
        except Exception:
            pass

    def _save_state(self) -> None:
        try:
            path = Path(self.config.state_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "updated_at": datetime.now().isoformat(),
                "effective_max_scenes": self.effective_max_scenes,
                "questions": {
                    qid: {
                        "name": q.name,
                        "direction": q.direction,
                        "difficulty": q.difficulty,
                        "score": q.score,
                        "has_scene": q.has_scene,
                        "status": q.status,
                        "project_id": q.project_id,
                        "current_user_solved": q.current_user_solved,
                        "total_flag_num": q.total_flag_num,
                        "reopen_count": q.reopen_count,
                        "attempts_runs": q.attempts_runs,
                    }
                    for qid, q in self.questions.items()
                },
            }
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:
            LOG.warning("failed to persist orchestrator state: %s", exc)

    def _wait_until_start(self) -> None:
        if not self.config.start_at:
            return
        target = datetime.fromisoformat(self.config.start_at)
        while not self._stop_event.is_set():
            now = datetime.now(target.tzinfo)
            remaining = (target - now).total_seconds()
            if remaining <= 0:
                LOG.info("scheduled start_at=%s reached; launching competition loop!", self.config.start_at)
                return
            LOG.info("waiting for scheduled start_at=%s (%.1fs remaining)", self.config.start_at, remaining)
            self._stop_event.wait(min(remaining, 15.0))

    def _past_end_time(self) -> bool:
        if not self.config.end_at:
            return False
        target = datetime.fromisoformat(self.config.end_at)
        return datetime.now(target.tzinfo) >= target

    def tick(self) -> None:
        now = time.monotonic()
        if now - self._last_poll_at >= self.config.poll_interval_sec or not self.questions:
            self.poll_questions()
            self._last_poll_at = now
        self._monitor_running()
        self._dispatch_pending()
        self._check_disk_watermark()

    def run(self, *, max_ticks: int | None = None, embed_bridge: bool = True) -> None:
        if embed_bridge:
            self.start_embedded_bridge()
        try:
            self._wait_until_start()
            ticks = 0
            while not self._stop_event.is_set():
                if self._past_end_time():
                    LOG.info("competition end_at=%s reached; stopping cleanly", self.config.end_at)
                    break
                try:
                    self.tick()
                except Exception:
                    LOG.exception("orchestrator tick failed; continuing after interval")
                ticks += 1
                if max_ticks is not None and ticks >= max_ticks:
                    break
                self._stop_event.wait(self.config.tick_interval_sec)
        finally:
            if embed_bridge:
                self.stop_embedded_bridge()

    def stop(self) -> None:
        self._stop_event.set()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(name)s %(message)s")
    ap = argparse.ArgumentParser(description="Official AI-Race Master Orchestrator")
    ap.add_argument("--race-base-url", default=os.environ.get("RACE_BASE_URL", ""), required=False)
    ap.add_argument("--agent-token", default=os.environ.get("RACE_AGENT_TOKEN", ""), required=False)
    ap.add_argument("--cairn-url", default=os.environ.get("CAIRN_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--cairn-admin-token", default=os.environ.get("CAIRN_ADMIN_TOKEN") or None)
    ap.add_argument("--bridge-host", default=os.environ.get("BRIDGE_HOST", "127.0.0.1"))
    ap.add_argument("--bridge-port", type=int, default=int(os.environ.get("BRIDGE_PORT", "8098")))
    ap.add_argument("--max-scenes", type=int, default=int(os.environ.get("MAX_SCENES", "2")))
    ap.add_argument("--max-attachments", type=int, default=int(os.environ.get("MAX_ATTACHMENTS", "2")))
    ap.add_argument("--poll-interval", type=float, default=float(os.environ.get("POLL_INTERVAL", "30")))
    ap.add_argument("--start-at", default=os.environ.get("RACE_START_AT") or None)
    ap.add_argument("--end-at", default=os.environ.get("RACE_END_AT") or None)
    ap.add_argument("--state-file", default="runtime/race-orchestrator-state.json")
    args = ap.parse_args()

    if not args.race_base_url or not args.agent_token:
        ap.error("--race-base-url (or RACE_BASE_URL) and --agent-token (or RACE_AGENT_TOKEN) are required")

    cfg = OrchestratorConfig(
        race_base_url=args.race_base_url,
        agent_token=args.agent_token,
        cairn_url=args.cairn_url,
        cairn_admin_token=args.cairn_admin_token,
        bridge_host=args.bridge_host,
        bridge_port=args.bridge_port,
        max_scenes=args.max_scenes,
        max_attachments=args.max_attachments,
        poll_interval_sec=args.poll_interval,
        start_at=args.start_at,
        end_at=args.end_at,
        state_file=args.state_file,
    )
    orch = RaceOrchestrator(cfg)
    orch.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
