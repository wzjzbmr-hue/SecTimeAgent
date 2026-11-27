from __future__ import annotations

import threading
import time
from concurrent.futures import Future
from pathlib import Path

from fastapi.testclient import TestClient

from cairn.dispatcher.config import ContainerConfig, validate_prompt_resources
from cairn.dispatcher.models import RunningTask
from cairn.dispatcher.output_parser import extract_json_object
from cairn.dispatcher.protocol.client import ApiResult
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.containers import ContainerManager
from cairn.dispatcher.runtime.process import ManagedProcess
from cairn.dispatcher.runtime.startup_healthcheck import StartupHealthcheckResult
from cairn.dispatcher.scheduler.loop import DispatcherLoop
from cairn.server import db
from cairn.server.app import app
from cairn.server.models import ProjectSummary

from conftest import make_config


def test_competition_prompt_group_is_valid() -> None:
    validate_prompt_resources("competition")


def test_output_parser_prefers_last_protocol_json_over_earlier_tool_echo() -> None:
    noisy_output = (
        'I submitted the flag and got tool output: {"ok": true, "is_pass": true, "score": 100}.\n'
        "Here is the final result:\n"
        '```json\n{"accepted": true, "data": {"fact": {"description": "solved 1/1"}, '
        '"complete": {"description": "all flags submitted"}}}\n```'
    )
    parsed = extract_json_object(noisy_output)
    assert parsed["accepted"] is True
    assert parsed["data"]["complete"]["description"] == "all flags submitted"


def test_output_parser_prefers_last_protocol_json_without_fences() -> None:
    raw = (
        'Tool returned {"status": 200, "body": "ok"} then '
        '{"accepted": true, "data": {"description": "found ssh key"}}'
    )
    parsed = extract_json_object(raw)
    assert parsed == {"accepted": True, "data": {"description": "found ssh key"}}


def test_managed_process_caps_stdout_tail_and_kills_process_group() -> None:
    commands_seen: list[list[str]] = []

    class FakeContainer:
        name = "cairn-dispatch-test"
        client = type("C", (), {"api": object()})()

        def exec_run(self, cmd, stdout=False, stderr=False):
            commands_seen.append(cmd)
            return type("R", (), {"exit_code": 0})()

    proc = ManagedProcess(FakeContainer(), ["sh"], {}, max_output_bytes=1024)
    chunks: list[str] = []
    cur_len, trunc = 0, False
    for i in range(40):
        piece = f"line-{i:03d}-" + ("x" * 50) + "\n"
        cur_len, trunc = proc._append_capped(chunks, piece, cur_len, trunc)
    joined = "".join(chunks)
    assert trunc is True
    assert len(joined) == 1024
    assert "line-039-" in joined

    proc._kill_pid(4321)
    assert commands_seen
    assert "pgid=" in " ".join(commands_seen[0])
    assert "kill -KILL -\"$pgid\"" in " ".join(commands_seen[0])


def test_container_manager_applies_resource_limits_init_and_archives_before_remove(tmp_path: Path) -> None:
    run_calls: list[dict] = []

    class FakeContainer:
        name = "cairn-dispatch-proj_009"
        image = type("Img", (), {"id": "sha256:deadbeef"})()
        removed = False

        def remove(self, force=True):
            self.removed = True

    class FakeContainersAPI:
        def run(self, image, cmd, **kwargs):
            run_calls.append({"image": image, "cmd": cmd, **kwargs})
            return FakeContainer()

    mgr = ContainerManager.__new__(ContainerManager)
    mgr._config = ContainerConfig(
        image="cairn-worker:test",
        network_mode="host",
        completed_action="remove",
        init=True,
        mem_limit="3g",
        cpu_limit=2.5,
        pids_limit=512,
        archive_dir=str(tmp_path / "archives"),
    )
    mgr._client = type("Client", (), {"containers": FakeContainersAPI()})()
    mgr._ensure_running_locks = {}
    mgr._ensure_running_locks_guard = threading.Lock()
    mgr.inspect_state = lambda _name: None

    name = mgr.ensure_running("proj_009")
    assert name == "cairn-dispatch-proj_009"
    assert run_calls[0]["init"] is True
    assert run_calls[0]["mem_limit"] == "3g"
    assert run_calls[0]["nano_cpus"] == 2_500_000_000
    assert run_calls[0]["pids_limit"] == 512

    fc = FakeContainer()
    states = iter(["running", None])
    mgr.inspect_state = lambda _name: next(states)
    mgr._require_container = lambda _name: fc
    assert mgr.cleanup_completed("proj_009")
    assert fc.removed is True
    archive_file = tmp_path / "archives" / "proj_009.json"
    assert archive_file.is_file()
    assert "sha256:deadbeef" in archive_file.read_text(encoding="utf-8")


def test_startup_healthcheck_blacklists_failed_workers(monkeypatch) -> None:
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.config = make_config()
    loop.worker_unhealthy_until = {}

    monkeypatch.setattr(
        "cairn.dispatcher.scheduler.loop.run_startup_healthchecks",
        lambda _cfg, show_commands=False: [
            StartupHealthcheckResult("glm53", True, 200, 120, "", "url1"),
            StartupHealthcheckResult("deepseek_reason", False, 402, 80, "Insufficient Balance", "url2"),
        ],
    )
    monkeypatch.setattr("cairn.dispatcher.scheduler.loop.time.time", lambda: 1000.0)

    loop._run_startup_healthchecks(show_commands=False)
    assert "glm53" not in loop.worker_unhealthy_until
    assert loop.worker_unhealthy_until["deepseek_reason"] == 1060.0


def test_intent_failure_circuit_breaker_and_project_budget() -> None:
    concluded: list[tuple[str, str, str]] = []
    stopped: list[str] = []

    class FakeClient:
        def heartbeat(self, pid, iid, worker):
            return ApiResult(200, {})

        def conclude(self, pid, iid, worker, desc):
            concluded.append((pid, iid, desc))
            return ApiResult(200, {})

        def stop_project(self, pid):
            stopped.append(pid)
            return ApiResult(200, {})

    loop = DispatcherLoop.__new__(DispatcherLoop)
    base_cfg = make_config()
    loop.config = base_cfg.model_copy(
        update={
            "runtime": base_cfg.runtime.model_copy(
                update={"max_intent_failures": 2, "failure_backoff_base": 5, "project_max_duration": 10}
            )
        }
    )
    loop.client = FakeClient()
    loop.intent_failure_counts = {}
    loop.intent_backoff_until = {}
    loop.project_started_at = {"proj_old": time.monotonic() - 20.0}
    cancel = TaskCancellation()
    loop.futures = {Future(): RunningTask("proj_old", "explore", "w1", cancel, intent_id="i001")}

    task = RunningTask("proj_1", "explore", "w1", TaskCancellation(), intent_id="i002")
    loop._record_intent_outcome(task, "failed")
    assert loop.intent_failure_counts[("proj_1", "i002")] == 1
    assert concluded == []

    loop._record_intent_outcome(task, "failed")
    assert len(concluded) == 1
    assert "[CIRCUIT_BREAKER]" in concluded[0][2]

    summary = ProjectSummary(
        id="proj_old",
        title="old",
        status="active",
        bootstrap_enabled=True,
        created_at="2026-01-01T00:00:00Z",
        fact_count=2,
        intent_count=1,
        working_intent_count=1,
        unclaimed_intent_count=0,
        hint_count=0,
    )
    loop._enforce_project_budgets([summary])
    assert cancel.reason == "project_budget_exceeded"
    assert stopped == ["proj_old"]


def test_server_admin_token_guard_and_concurrent_sqlite_writes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "concurrent.db")

    # 1. Verify optional admin token protection
    monkeypatch.setenv("CAIRN_ADMIN_TOKEN", "secret-admin-xyz")
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/projects").status_code == 401
        assert client.get("/projects", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/projects", headers={"Authorization": "Bearer secret-admin-xyz"}).status_code == 200

    # 2. Verify concurrent SQLite writes succeed cleanly without database-is-locked errors
    monkeypatch.delenv("CAIRN_ADMIN_TOKEN", raising=False)
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        try:
            with TestClient(app) as c:
                r = c.post(
                    "/projects",
                    json={"title": f"p-{idx}", "origin": "o", "goal": "g"},
                )
                assert r.status_code == 201, r.text
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
