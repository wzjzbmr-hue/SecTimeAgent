from __future__ import annotations

import importlib.util
import json
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any

import requests
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from cairn.dispatcher.protocol.client import CairnClient
from cairn.race.client import OfficialRaceClient, RaceApiError
from cairn.race.orchestrator import OrchestratorConfig, RaceOrchestrator
from cairn.server import db
from cairn.server.app import app as cairn_app

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_uvicorn(asgi_app: FastAPI, port: int) -> tuple[uvicorn.Server, threading.Thread]:
    cfg = uvicorn.Config(asgi_app, host="127.0.0.1", port=port, log_level="error")
    srv = uvicorn.Server(cfg)
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if getattr(srv, "started", False):
            return srv, th
        time.sleep(0.05)
    raise RuntimeError(f"uvicorn failed to start on port {port}")


def test_official_mock_platform_bridge_and_multiflag_orchestrator_end_to_end(tmp_path: Path, monkeypatch) -> None:
    mock_mod = _load_module("mock_race_platform", REPO_ROOT / "bench" / "mock_race_platform.py")

    # Prepare 1:1 mock official platform with:
    # - 1 easy attachment challenge (does NOT consume scene slot)
    # - 1 easy scene challenge with fail_first_start=True (scene_status=20 auto-recovery!)
    # - 1 medium 3-flag scene challenge (multi-flag + premature complete -> auto /reopen!)
    # - 1 phased challenge released after 0.6s (tests periodic question_list discovery!)
    att_dir = tmp_path / "attachments" / "q_att"
    att_dir.mkdir(parents=True)
    (att_dir / "sample.bin").write_bytes(b"CTF-ATTACHMENT-DATA")

    cfg_yaml = tmp_path / "race.yaml"
    cfg_yaml.write_text(
        """
max_scenes: 2
rate_limit_rps: 50
questions:
  - id: "q_att"
    name: "Offline Crypto"
    direction: "crypto"
    score: 100
    difficulty: 1
    has_scene: false
    desc: "Analyze sample.bin"
    attachments: ["sample.bin"]
    flags: ["flag{att_1}"]
  - id: "q_scene_recover"
    name: "Web Recovery"
    direction: "web"
    score: 150
    difficulty: 1
    has_scene: true
    fail_first_start: true
    scene_addresses:
      - access_ip: "127.0.0.1"
        access_port: 18081
        protocol: "http"
    flags: ["flag{web_recover}"]
  - id: "q_multiflag"
    name: "Intranet 3-Flag Chain"
    direction: "comprehensive"
    score: 300
    difficulty: 2
    has_scene: true
    scene_addresses:
      - access_ip: "127.0.0.1"
        access_port: 18082
        protocol: "http"
    flags: ["flag{chain_1}", "flag{chain_2}", "flag{chain_3}"]
  - id: "q_phase2"
    name: "Phase 2 ICS"
    direction: "ics"
    score: 200
    difficulty: 1
    has_scene: true
    release_after_sec: 0.6
    scene_addresses:
      - access_ip: "127.0.0.1"
        access_port: 18083
        protocol: "tcp"
    flags: ["flag{ics_phase2}"]
""",
        encoding="utf-8",
    )

    mock_port = _free_port()
    cairn_port = _free_port()
    bridge_port = _free_port()

    state_file = tmp_path / "platform-state.json"
    pstate = mock_mod.MockRacePlatformState(
        valid_token="real-secret-team-token",
        max_scenes=2,
        rate_limit_rps=50,
        base_url=f"http://127.0.0.1:{mock_port}",
        state_file=state_file,
        attachments_root=tmp_path / "attachments",
    )
    pstate.load_config(cfg_yaml)
    mock_srv, mock_th = _start_uvicorn(mock_mod.create_mock_race_app(pstate), mock_port)

    monkeypatch.setattr(db, "_db_path", None)
    monkeypatch.delenv("CAIRN_ADMIN_TOKEN", raising=False)
    db.configure(tmp_path / "cairn.db")
    cairn_srv, cairn_th = _start_uvicorn(cairn_app, cairn_port)

    orch: RaceOrchestrator | None = None
    try:
        race_client = OfficialRaceClient(f"http://127.0.0.1:{mock_port}", "real-secret-team-token", rate_per_sec=40.0)
        cairn_client = CairnClient(f"http://127.0.0.1:{cairn_port}")
        ocfg = OrchestratorConfig(
            race_base_url=f"http://127.0.0.1:{mock_port}",
            agent_token="real-secret-team-token",
            cairn_url=f"http://127.0.0.1:{cairn_port}",
            bridge_host="127.0.0.1",
            bridge_port=bridge_port,
            max_scenes=2,
            max_attachments=2,
            poll_interval_sec=0.2,
            scene_poll_interval_sec=0.05,
            attachments_dir=str(tmp_path / "dl"),
            state_file=str(tmp_path / "orch-state.json"),
        )
        orch = RaceOrchestrator(ocfg, race_client=race_client, cairn_client=cairn_client)
        orch.start_embedded_bridge()

        # Tick 1: discovers initial 3 visible challenges, launches 2 scenes + 1 attachment in parallel!
        # Also verifies q_scene_recover auto-recovers from scene_status=20 -> stop -> 3 -> start -> 1!
        orch.tick()
        assert set(orch.questions.keys()) == {"q_att", "q_scene_recover", "q_multiflag"}
        assert orch.questions["q_att"].status == "running"
        assert orch.questions["q_scene_recover"].status == "running"
        assert orch.questions["q_multiflag"].status == "running"
        assert pstate.running_scene_count() == 2
        assert (tmp_path / "dl" / "q_att" / "sample.bin").read_bytes() == b"CTF-ATTACHMENT-DATA"

        # Verify zero AGENT_TOKEN leak in Cairn project hints/origin!
        mf_pid = orch.questions["q_multiflag"].project_id
        assert mf_pid is not None
        mf_detail = cairn_client.get_project(mf_pid)
        full_text = json.dumps(mf_detail.model_dump(), ensure_ascii=False)
        assert "real-secret-team-token" not in full_text

        # Simulate Worker submitting flag 1/3 via zero-leak bridge
        binding = orch.bridge.get_by_project(mf_pid)
        assert binding is not None
        r_wrong = requests.post(
            f"http://127.0.0.1:{bridge_port}/bridge/submit",
            headers={"X-Project-Token": binding.token},
            json={"flag": "flag{wrong}"},
            timeout=5,
        ).json()
        assert r_wrong["ok"] is True and r_wrong["is_pass"] is False and r_wrong["question_complete"] is False

        r1 = requests.post(
            f"http://127.0.0.1:{bridge_port}/bridge/submit",
            headers={"X-Project-Token": binding.token},
            json={"flag": "flag{chain_1}"},
            timeout=5,
        ).json()
        assert r1["is_pass"] is True
        assert r1["current_user_solved"] == 1
        assert r1["total_flag_num"] == 3
        assert r1["remaining_flags"] == 2
        assert r1["question_complete"] is False

        # Duplicate submit of flag 1/3 handled gracefully (AD-160014 -> is_duplicate=True)
        r1_dup = requests.post(
            f"http://127.0.0.1:{bridge_port}/bridge/submit",
            headers={"X-Project-Token": binding.token},
            json={"flag": "flag{chain_1}"},
            timeout=5,
        ).json()
        assert r1_dup["is_duplicate"] is True
        assert r1_dup["current_user_solved"] == 1

        # Simulate premature completion by LLM after 1/3 flags -> Orchestrator MUST auto /reopen!
        cairn_client.complete(mf_pid, ["origin"], "thought 1 flag was enough", "worker")
        assert cairn_client.get_project(mf_pid).project.status == "completed"
        orch.tick()
        mf_after = cairn_client.get_project(mf_pid)
        assert mf_after.project.status == "active"
        assert orch.questions["q_multiflag"].reopen_count == 1
        assert any("[MULTI_FLAG_GATE]" in f.description for f in mf_after.facts)

        # Now submit remaining flags 2/3 and 3/3 -> Orchestrator marks solved & stops scene!
        r2 = requests.post(
            f"http://127.0.0.1:{bridge_port}/bridge/submit",
            headers={"X-Project-Token": binding.token},
            json={"flag": "flag{chain_2}"},
            timeout=5,
        ).json()
        assert r2["current_user_solved"] == 2 and r2["question_complete"] is False

        r3 = requests.post(
            f"http://127.0.0.1:{bridge_port}/bridge/submit",
            headers={"X-Project-Token": binding.token},
            json={"flag": "flag{chain_3}"},
            timeout=5,
        ).json()
        assert r3["current_user_solved"] == 3 and r3["question_complete"] is True

        # Wait past phased release (0.6s) and tick -> q_multiflag closes scene, q_phase2 discovered & launched!
        time.sleep(0.7)
        orch.tick()
        assert orch.questions["q_multiflag"].status == "solved"
        assert pstate.scene_status["q_multiflag"] == 3  # scene released!
        assert "q_phase2" in orch.questions
        assert orch.questions["q_phase2"].status == "running"
        assert pstate.total_score == 300.0
        assert state_file.is_file()
    finally:
        if orch is not None:
            orch.stop_embedded_bridge()
        mock_srv.should_exit = True
        cairn_srv.should_exit = True
        mock_th.join(timeout=5)
        cairn_th.join(timeout=5)


def test_token_proxy_key_injection_and_whitelist_failover(tmp_path: Path) -> None:
    proxy_mod = _load_module("token_proxy_mod", REPO_ROOT / "bench" / "token_proxy.py")
    proxy_mod.LOG = tmp_path / "tokens.jsonl"

    received_primary: list[dict[str, Any]] = []
    received_backup: list[dict[str, Any]] = []

    upstream_app = FastAPI()

    @upstream_app.post("/primary/v1/messages")
    async def primary_endpoint(req: Request):
        received_primary.append(
            {"auth": req.headers.get("authorization"), "x_api_key": req.headers.get("x-api-key"), "body": await req.json()}
        )
        return JSONResponse({"error": {"code": "1113", "message": "quota depleted"}}, status_code=429)

    @upstream_app.post("/backup/v1/messages")
    async def backup_endpoint(req: Request):
        body = await req.json()
        received_backup.append(
            {"auth": req.headers.get("authorization"), "x_api_key": req.headers.get("x-api-key"), "body": body}
        )
        return JSONResponse(
            {"id": "msg_1", "model": body.get("model"), "usage": {"input_tokens": 10, "output_tokens": 5}},
            status_code=200,
        )

    up_port = _free_port()
    srv, th = _start_uvicorn(upstream_app, up_port)
    try:
        proxy_mod.ROUTES.clear()
        proxy_mod.COOLDOWN_UNTIL.clear()
        proxy_mod.ROUTES["glm"] = proxy_mod.RouteTarget(
            name="glm",
            url=f"http://127.0.0.1:{up_port}/primary",
            api_key="REAL-GLM-SECRET-KEY",
            auth_header="both",
            fallbacks=["qwen"],
        )
        proxy_mod.ROUTES["qwen"] = proxy_mod.RouteTarget(
            name="qwen",
            url=f"http://127.0.0.1:{up_port}/backup",
            api_key="REAL-QWEN-SECRET-KEY",
            auth_header="bearer",
            model_override="qwen-coder-backup",
        )

        with TestClient(proxy_mod.app) as client:
            r = client.post(
                "/glm/v1/messages",
                headers={"Authorization": "Bearer worker-dummy-placeholder"},
                json={"model": "glm-5.3", "messages": [{"role": "user", "content": "hi"}]},
            )
            assert r.status_code == 200
            assert r.json()["model"] == "qwen-coder-backup"
            # Verify primary received REAL-GLM key (NOT dummy placeholder)
            assert received_primary[0]["x_api_key"] == "REAL-GLM-SECRET-KEY"
            assert "worker-dummy-placeholder" not in str(received_primary[0])
            # Verify backup received REAL-QWEN key & rewritten model
            assert received_backup[0]["auth"] == "Bearer REAL-QWEN-SECRET-KEY"
            assert received_backup[0]["body"]["model"] == "qwen-coder-backup"
            assert "worker-dummy-placeholder" not in str(received_backup[0])
    finally:
        srv.should_exit = True
        th.join(timeout=5)


def test_ics_client_modbus_frame_and_loopback_read() -> None:
    ics_mod = _load_module("ics_client_mod", REPO_ROOT / "worker" / "deployed-rootfs" / "opt" / "cairn-poc" / "ics_client.py")
    frame = ics_mod.build_mbap_read_frame(1, 1, 3, 0, 2)
    assert len(frame) == 12
    assert struct.unpack(">HHHBBHH", frame) == (1, 0, 6, 1, 3, 0, 2)

    # Tiny loopback Modbus TCP server returning holding registers [0x4142, 0x4344] ("ABCD")
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.bind(("127.0.0.1", 0))
    port = srv_sock.getsockname()[1]
    srv_sock.listen(1)

    def serve_one():
        conn, _ = srv_sock.accept()
        with conn:
            req = conn.recv(64)
            assert len(req) == 12
            payload = struct.pack(">BBHH", 3, 4, 0x4142, 0x4344)
            resp = struct.pack(">HHHB", 1, 0, 1 + len(payload), 1) + payload
            conn.sendall(resp)
        srv_sock.close()

    th = threading.Thread(target=serve_one, daemon=True)
    th.start()
    res = ics_mod.modbus_read("127.0.0.1", port, unit=1, fc=3, addr=0, count=2)
    th.join(timeout=5)
    assert res["ok"] is True
    assert res["registers"] == [0x4142, 0x4344]
    assert res["ascii"] == "ABCD"


def test_race_client_bounds_persistent_scene_status_20_recovery() -> None:
    class BrokenRaceClient(OfficialRaceClient):
        def __init__(self):
            super().__init__("http://127.0.0.1:1", "tok", rate_per_sec=100.0)
            self.starts = 0
            self.stops = 0
            self.state = 3

        def question_instance_info(self, question_id: str) -> dict[str, Any]:
            return {"resource_id": question_id, "scene_status": self.state, "scene_addresses": []}

        def question_start(self, question_id: str) -> bool:
            self.starts += 1
            self.state = 20
            return True

        def question_stop(self, question_id: str) -> bool:
            self.stops += 1
            self.state = 3
            return True

    client = BrokenRaceClient()
    try:
        client.ensure_scene_running("q_broken", wait_timeout=10.0, poll_interval=0.01)
        raise AssertionError("expected SCENE_RECOVERY_EXHAUSTED")
    except RaceApiError as exc:
        assert exc.code == "SCENE_RECOVERY_EXHAUSTED"
        assert client.stops == 2


def test_orchestrator_does_not_spam_poll_when_zero_questions_visible() -> None:
    calls = {"list": 0}

    class EmptyRace:
        def question_list(self):
            calls["list"] += 1
            return []

    class DummyCairn:
        pass

    cfg = OrchestratorConfig(
        race_base_url="http://127.0.0.1:1",
        agent_token="tok",
        poll_interval_sec=60.0,
    )
    orch = RaceOrchestrator(cfg, race_client=EmptyRace(), cairn_client=DummyCairn())
    orch.tick()
    orch.tick()
    orch.tick()
    assert calls["list"] == 1
