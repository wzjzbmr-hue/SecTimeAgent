from __future__ import annotations

import importlib.util
import json
import socket
import sys
import threading
import time
from pathlib import Path

import requests
import uvicorn

from cairn.race.client import StreamableMCPClient

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
        return int(s.getsockname()[1])


def test_mock_platform_v2_mcp_rank_scoring_dashboard_and_auditor(tmp_path: Path) -> None:
    mock_mod = _load_module("mock_race_platform_v2", REPO_ROOT / "bench" / "mock_race_platform.py")
    ana_mod = _load_module("eval_analyze_run", REPO_ROOT / "eval" / "analyze_run.py")

    cfg_yaml = tmp_path / "sim.yaml"
    cfg_yaml.write_text(
        """
max_scenes: 2
rate_limit_rps: 30
simulate_competitors: true
duration_sec: 3600
questions:
  - id: "q01"
    name: "App IDOR"
    category: "应用系统"
    direction: "web"
    score: 100
    difficulty: 1
    has_scene: true
    scene_addresses:
      - access_ip: "127.0.0.1"
        access_port: 19001
        protocol: "http"
    flags: ["flag{app_1}"]
  - id: "q02"
    name: "ICS PCAP"
    category: "协议安全"
    direction: "ics"
    score: 200
    difficulty: 3
    has_scene: false
    release_after_sec: 999
    flags: ["flag{ics_1}", "flag{ics_2}"]
""",
        encoding="utf-8",
    )

    state = mock_mod.MockRacePlatformState(
        valid_token="secret-team-token-9999",
        max_scenes=2,
        rate_limit_rps=30,
        base_url="http://127.0.0.1:18099",
        state_file=tmp_path / "state.json",
        simulate_competitors=True,
        secret_patterns=["SECRET-API-KEY-1234"],
    )
    state.load_config(cfg_yaml)
    app = mock_mod.create_mock_race_app(state)

    # 1. Start live server to verify StreamableMCPClient against /mcp!
    port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if getattr(srv, "started", False):
            break
        time.sleep(0.05)

    try:
        mcp = StreamableMCPClient(f"http://127.0.0.1:{port}/mcp", "secret-team-token-9999")
        init_res = mcp.initialize()
        assert init_res["result"]["protocolVersion"] == "2024-11-05"

        qlist = mcp.call_tool("question_list", {})
        assert qlist["total"] == 1
        assert qlist["list"][0]["id"] == "q01"

        # Submitting flag before starting scene MUST fail with AD-160003
        r_before = requests.post(
            f"http://127.0.0.1:{port}/api/ct/agent/ai_race/race/checkpoints/robot/question/submit_flag",
            headers={"Authorization": "Bearer secret-team-token-9999"},
            json={"question_id": "q01", "flag": "flag{app_1}"},
            timeout=5,
        ).json()
        assert r_before["code"] == "AD-160003"

        # Start scene via MCP and submit flag via MCP (gets Rank #1 +5% bonus!)
        assert mcp.call_tool("question_start", {"question_id": "q01"}) is True
        inst = mcp.call_tool("question_instance_info", {"question_id": "q01"})
        assert inst["resource_id"] == "q01" and inst["scene_status"] == 1

        sub = mcp.call_tool("question_submit_flag", {"question_id": "q01", "flag": "flag{app_1}"})
        assert sub["is_pass"] is True
        assert state.total_score == 100.0
        assert state.ranked_score == 105.0  # First blood +5%

        # Admin release next wave unlocks q02
        rel = requests.post(f"http://127.0.0.1:{port}/api/admin/release-next", timeout=5).json()
        assert rel["unlocked"] == ["q02"]

        # Compliance auditor detects leaked secret if submitted and deduplicates repeated leaks
        for _ in range(2):
            requests.post(
                f"http://127.0.0.1:{port}/api/ct/agent/ai_race/race/checkpoints/robot/question/submit_flag",
                headers={"Authorization": "Bearer secret-team-token-9999"},
                json={"question_id": "q02", "flag": "flag{SECRET-API-KEY-1234}"},
                timeout=5,
            )
        snap = requests.get(f"http://127.0.0.1:{port}/api/dashboard/snapshot", timeout=5).json()
        assert len(snap["audit"]["credential_leaks"]) == 1
        assert snap["summary"]["solved_flags"] == 1
        assert snap["summary"]["total_flags"] == 3

        # Dashboard HTML serves cleanly
        dash = requests.get(f"http://127.0.0.1:{port}/dashboard", timeout=5)
        assert dash.status_code == 200 and "SecTimeAgent" in dash.text

        # Analyzer produces report + shortcoming taxonomy for unsolved q02
        metrics, md = ana_mod.generate_report(snap, run_label="unit-smoke")
        assert metrics["shortcoming_counts"]["REASONING_CAPABILITY_GAP"] == 1
        assert "协议安全" in md and "应用系统" in md
    finally:
        srv.should_exit = True
        th.join(timeout=5)
