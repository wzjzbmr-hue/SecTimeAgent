from __future__ import annotations

import importlib.util
import json
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module(name: str, path: Path):
    if name in sys.modules:
        del sys.modules[name]
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


def test_cockpit_all_10_regressions_and_human_reference_isolation(tmp_path: Path) -> None:
    mock_mod = _load_module("mock_race_platform_reg", REPO_ROOT / "bench" / "mock_race_platform.py")
    href_mod = _load_module("human_reference_reg", REPO_ROOT / "eval" / "human_reference.py")
    cm = _load_module("cockpit_models_reg", REPO_ROOT / "bench" / "cockpit_models.py")

    # Prepare mixed dataset reproducing ALL review findings:
    # - 5 directions (web, system, ics, forensics, pwn) -> D06 taxonomy accuracy
    # - 1 Flag challenge with legacy incomplete persisted state -> D01 zero undefined / zero fake 00:00:00
    # - 1 Scene challenge bound to 0.0.0.0 -> D02 (stopped vs never_started), D03 (no running+queued), D05 (0.0.0.0 hygiene)
    # - 1 PoC challenge (flags: []) -> D04 no 0/0 (0%)
    # - 1 Attachment-only challenge (flags: [], has_scene: false) -> D04 attachment milestone
    # - 1 Unconfigured challenge (flags: [], no poc/attachment) -> D04 unconfigured
    att_dir = tmp_path / "attachments" / "MVP-S4-06"
    att_dir.mkdir(parents=True)
    (att_dir / "capture.pcap").write_bytes(b"PCAP-TEST-DATA")

    legacy_state = tmp_path / "legacy-state.json"
    legacy_state.write_text(
        json.dumps(
            {
                "total_score": 100.0,
                "solved_flags": {"MVP-S1-01": ["flag{legacy_1}"]},
                # Simulate legacy record missing flag_index / ranked_score / simulated_rank / elapsed_sec / ts!
                "solved_flag_details": {
                    "MVP-S1-01": [{"qid": "MVP-S1-01", "pass": True, "score": 100}]
                },
            }
        ),
        encoding="utf-8",
    )

    cfg_yaml = tmp_path / "cockpit_sim.yaml"
    cfg_yaml.write_text(
        """
max_scenes: 2
rate_limit_rps: 50
simulate_competitors: false
questions:
  - id: "MVP-S1-01"
    name: "Web Order Audit"
    direction: "web"
    score: 100
    difficulty: 1
    has_scene: true
    scene_addresses:
      - access_ip: "127.0.0.1"
        access_port: 19101
        protocol: "http"
    flags: ["flag{legacy_1}"]
  - id: "MVP-S3-01"
    name: "Modbus Telemetry"
    direction: "ics"
    score: 150
    difficulty: 2
    has_scene: true
    scene_addresses:
      - access_ip: "0.0.0.0"
        access_port: 32866
        protocol: "tcp"
    flags: ["flag{ics_ok}"]
  - id: "POC-001"
    name: "Kernel PoC Replay"
    direction: "pwn"
    grading_type: "poc"
    score: 200
    difficulty: 3
    has_scene: true
    scene_addresses:
      - access_ip: "0.0.0.0"
        access_port: 32867
        protocol: "tcp"
    flags: []
  - id: "MVP-S4-06"
    name: "Forensics Traffic"
    direction: "forensics"
    grading_type: "attachment"
    score: 120
    difficulty: 1
    has_scene: false
    attachments: ["capture.pcap"]
    flags: []
  - id: "SYS-UNCONF"
    name: "Unconfigured Host"
    direction: "system"
    score: 100
    difficulty: 2
    has_scene: true
    flags: []
""",
        encoding="utf-8",
    )

    # Strictly isolated Human Reference Store with distinct token
    agent_token = "agent-secret-token-1111"
    human_token = "human-only-ref-token-8888"
    href_store = href_mod.IsolatedHumanReferenceStore(
        tmp_path / "human-refs",
        human_token,
        forbidden_tokens=[agent_token],
    )
    canary = "CANARY-HUMAN-ONLY-REF-9911"
    href_store.save_guide(
        href_mod.HumanReferenceDoc(
            challenge_id="MVP-S3-01",
            title="Modbus Reference",
            standard_stages=[{"stage": 1, "note": canary}],
            verification=href_mod.ReferenceVerification(verified=True, author="alice", reviewer="bob", version="v1.0"),
        ),
        operator="alice",
    )

    state = mock_mod.MockRacePlatformState(
        valid_token=agent_token,
        max_scenes=2,
        rate_limit_rps=50,
        base_url="http://127.0.0.1:18099",
        state_file=legacy_state,
        attachments_root=tmp_path / "attachments",
        simulate_competitors=False,
        public_host=None,
        human_ref_store=href_store,
    )
    state.load_config(cfg_yaml)
    app = mock_mod.create_mock_race_app(state)

    with TestClient(app) as client:
        auth = {"Authorization": f"Bearer {agent_token}"}

        # 1. Regression D01: Legacy missing fields -> NO undefined/NaN, time_reported=False, rank_applicable=False
        snap0 = client.get("/api/dashboard/snapshot").json()
        q1 = next(q for q in snap0["questions"] if q["id"] == "MVP-S1-01")
        assert len(q1["solved_details"]) == 1
        sd = q1["solved_details"][0]
        assert sd["flag_index"] is None and sd["flag_label"] == "编号未上报"
        assert sd["elapsed_sec"] is None and sd["time_reported"] is False
        assert sd["ranked_score"] is None and sd["simulated_rank"] is None and sd["rank_applicable"] is False
        assert "undefined" not in json.dumps(snap0, ensure_ascii=False)
        # Solved legacy flag IS exposed in obtained_flags, while unsolved MVP-S3-01 flag is NEVER leaked!
        assert [f["flag"] for f in q1["obtained_flags"]] == ["flag{legacy_1}"]
        assert "flag{ics_ok}" not in json.dumps(snap0, ensure_ascii=False)

        # 2. Regression D02 & D03 & D05: start -> running (NOT queued!) -> stop -> stopped (NOT never_started!) -> restart (2 attempts!)
        q3_before = next(q for q in snap0["questions"] if q["id"] == "MVP-S3-01")
        assert q3_before["states"]["env"]["code"] == "never_started"

        r_start = client.post("/api/ct/agent/ai_race/race/checkpoints/robot/question_start", headers=auth, json={"question_id": "MVP-S3-01"})
        assert r_start.json()["code"] == "AD-000000"

        snap_run = client.get("/api/dashboard/snapshot").json()
        q3_run = next(q for q in snap_run["questions"] if q["id"] == "MVP-S3-01")
        assert q3_run["states"]["env"]["code"] == "running"
        assert q3_run["states"]["schedule"]["code"] == "external_active"
        assert q3_run["states"]["schedule"]["label"] != "待调度"
        # D05: 0.0.0.0 bind address MUST NOT produce a clickable operator_url
        assert len(q3_run["addresses"]) == 1
        assert q3_run["addresses"][0]["operator_url"] is None
        assert q3_run["addresses"][0]["clickable"] is False
        assert "0.0.0.0" in q3_run["addresses"][0]["reachability_note"]
        # D07: Pinned Current Focus has MVP-S3-01
        assert any(f["challenge_id"] == "MVP-S3-01" for f in snap_run["current_focus"])
        # D08/D12: Compound system diagnosis explicitly explains running scene + Cairn/Proxy unconfigured
        diag_titles = [d["title"] for d in snap_run["system_diagnosis"]]
        assert any("Cairn" in t for t in diag_titles)
        assert any("代理" in t for t in diag_titles)

        # Stop scene -> MUST become env.code == "stopped" (NOT never_started!), preserve Attempt #1
        client.post("/api/ct/agent/ai_race/race/checkpoints/robot/question_stop", headers=auth, json={"question_id": "MVP-S3-01"})
        snap_stop = client.get("/api/dashboard/snapshot").json()
        q3_stop = next(q for q in snap_stop["questions"] if q["id"] == "MVP-S3-01")
        assert q3_stop["states"]["env"]["code"] == "stopped"
        assert q3_stop["states"]["env"]["ever_started"] is True
        assert q3_stop["states"]["env"]["last_stop_reason"] is not None
        assert len(q3_stop["attempts"]) == 1 and q3_stop["attempts"][0]["status"] == "stopped"

        # Restart scene -> Attempt #2 opened while Attempt #1 preserved!
        client.post("/api/ct/agent/ai_race/race/checkpoints/robot/question_start", headers=auth, json={"question_id": "MVP-S3-01"})
        snap_re = client.get("/api/dashboard/snapshot").json()
        q3_re = next(q for q in snap_re["questions"] if q["id"] == "MVP-S3-01")
        assert len(q3_re["attempts"]) == 2
        assert q3_re["attempts"][0]["attempt_id"] != q3_re["attempts"][1]["attempt_id"]

        # 3. Regression D04: PoC, Attachment, and Unconfigured grading (NO 0/0 percentage!)
        qpoc = next(q for q in snap_re["questions"] if q["id"] == "POC-001")
        assert qpoc["states"]["verdict"]["type"] == "poc"
        assert len(qpoc["states"]["verdict"]["milestones"]) == 3
        client.post("/api/admin/milestone/POC-001", json={"key": "artifact", "status": "done", "detail": "poc.py ready"})
        client.post("/api/admin/milestone/POC-001", json={"key": "replay", "status": "done", "detail": "verified"})
        client.post("/api/admin/milestone/POC-001", json={"key": "verdict", "status": "done", "detail": "accepted", "score": 200})

        # Download attachment -> automatically advances attachment 'fetched' milestone!
        att_resp = client.get("/attachments/MVP-S4-06/capture.pcap")
        assert att_resp.status_code == 200

        snap_ms = client.get("/api/dashboard/snapshot").json()
        qpoc2 = next(q for q in snap_ms["questions"] if q["id"] == "POC-001")
        assert qpoc2["states"]["verdict"]["complete"] is True
        qatt = next(q for q in snap_ms["questions"] if q["id"] == "MVP-S4-06")
        assert qatt["states"]["verdict"]["type"] == "attachment"
        assert any(m["key"] == "fetched" and m["status"] == "done" for m in qatt["states"]["verdict"]["milestones"])
        qunc = next(q for q in snap_ms["questions"] if q["id"] == "SYS-UNCONF")
        assert qunc["states"]["verdict"]["type"] == "unconfigured" and qunc["states"]["verdict"]["pct"] is None

        # 4. Regression D06: Taxonomy accuracy (3 of canonical 8 included + 2 extra: forensics, pwn)
        tax = snap_ms["taxonomy"]
        assert tax["canonical_total"] == 8
        assert tax["canonical_included"] == 3
        assert tax["extra_count"] == 2
        assert "3/8" in tax["headline"] and "2 个扩展类" in tax["headline"]

        # 5. Regression D09: Release-next when all released returns explicit message & dashboard disables button
        assert snap_ms["summary"]["unreleased_questions"] == 0
        rel_res = client.post("/api/admin/release-next").json()
        assert rel_res["unlocked"] == [] and "全部题目均已放出" in rel_res["message"]

        # 6. Regression Section 6.1: Monotonic seq, event_id dedup, per-challenge/attempt backfill API
        ev_all = client.get("/api/dashboard/events?since_seq=0").json()
        seqs = [e["seq"] for e in ev_all["events"]]
        assert seqs == sorted(seqs) and len(seqs) == len(set(seqs))
        mid_seq = seqs[len(seqs) // 2]
        ev_backfill = client.get(f"/api/dashboard/events?since_seq={mid_seq}&challenge_id=MVP-S3-01").json()
        assert all(e["seq"] > mid_seq and e["challenge_id"] == "MVP-S3-01" for e in ev_backfill["events"])

        # 7. Regression D10 & HTML checks: Semantic <button class="qcard">, focus-visible, zero clickable div cards
        html = client.get("/dashboard").text
        assert '<button type="button" class="qcard' in html
        assert ':focus-visible' in html
        assert '全部题目已放出' in html

        # 8. Regression Section 7: STRICT Human Reference Isolation (ZERO leakage to Worker/Agent/Public APIs!)
        # Reject missing token
        assert client.get("/api/human-reference/challenges/MVP-S3-01").status_code == 403
        # Reject AGENT_TOKEN passed as Bearer or X-Human-Ref-Token
        assert client.get("/api/human-reference/challenges/MVP-S3-01", headers={"Authorization": f"Bearer {agent_token}"}).status_code == 403
        assert client.get("/api/human-reference/challenges/MVP-S3-01", headers={"X-Human-Ref-Token": agent_token}).status_code == 403
        # Reject Worker X-Project-Token even if human token were somehow present
        assert client.get(
            "/api/human-reference/challenges/MVP-S3-01",
            headers={"X-Human-Ref-Token": human_token, "X-Project-Token": "worker-proj-tok"},
        ).status_code == 403
        # Human operator with dedicated HUMAN_REF_TOKEN succeeds & writes audit log!
        ok_ref = client.get(
            "/api/human-reference/challenges/MVP-S3-01",
            headers={"X-Human-Ref-Token": human_token, "X-Human-Operator": "reviewer-1"},
        )
        assert ok_ref.status_code == 200
        assert ok_ref.json()["verified"] is True
        assert canary in json.dumps(ok_ref.json(), ensure_ascii=False)
        audit_entries = href_store.list_audit_entries()
        assert any(e["allowed"] is False and e["reason"] == "rejected_agent_token" for e in audit_entries)
        assert any(e["allowed"] is True and e["operator"] == "reviewer-1" for e in audit_entries)

        # Public APIs, dashboard snapshot, and event streams MUST NEVER contain the canary string!
        pub_qlist = client.get("/api/ct/agent/ai_race/race/checkpoints/robot/question_list", headers=auth).text
        pub_qinfo = client.get("/api/ct/agent/ai_race/race/checkpoints/robot/question_info?question_id=MVP-S3-01", headers=auth).text
        pub_inst = client.get("/api/ct/agent/ai_race/race/checkpoints/robot/question_instance_info?question_id=MVP-S3-01", headers=auth).text
        pub_snap = client.get("/api/dashboard/snapshot").text
        pub_evs = client.get("/api/dashboard/events").text
        for blob in (pub_qlist, pub_qinfo, pub_inst, pub_snap, pub_evs):
            assert canary not in blob

        # 9. Regression D12: Stale worker heartbeat detection (>90s)
        old_hb = (datetime.now(timezone.utc) - timedelta(seconds=180)).isoformat()
        four = cm.compute_four_states(
            q={"has_scene": True, "wave": 1},
            visible=True,
            raw_scene_status=1,
            ever_started=True,
            last_stop_reason=None,
            last_stopped_at=None,
            orch_q={"status": "running"},
            cairn_q={"status": "active", "reason": {"worker": "w1", "last_heartbeat_at": old_hb}, "active_intents": []},
            verdict={"complete": False, "type": "flag", "status": "unscored"},
            active_attempt=None,
        )
        assert four["worker"]["code"] == "offline" and four["worker"]["heartbeat_stale"] is True

        # 10. Regression D05 explicit public_host produces clickable operator_url
        pub_addrs = cm.format_scene_addresses(
            [{"access_ip": "0.0.0.0", "access_port": 32866, "protocol": "http"}],
            public_host="192.168.198.130",
        )
        assert pub_addrs[0]["operator_url"] == "http://192.168.198.130:32866"
        assert pub_addrs[0]["clickable"] is True


def test_token_proxy_model_version_and_thinking_telemetry(tmp_path: Path) -> None:
    proxy_mod = _load_module("token_proxy_telemetry_test", REPO_ROOT / "bench" / "token_proxy.py")
    proxy_mod.LOG = tmp_path / "tokens.jsonl"
    proxy_mod.STATS.clear()
    proxy_mod.ROUTES.clear()
    proxy_mod.COOLDOWN_UNTIL.clear()

    upstream_app = FastAPI()

    @upstream_app.post("/v1/messages")
    async def messages(req: Request):
        body = await req.json()
        return JSONResponse(
            {"id": "m1", "model": body.get("model"), "usage": {"input_tokens": 42, "output_tokens": 18}},
            status_code=200,
        )

    up_port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(upstream_app, host="127.0.0.1", port=up_port, log_level="error"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if getattr(srv, "started", False):
            break
        time.sleep(0.05)

    try:
        proxy_mod.ROUTES["kimi"] = proxy_mod.RouteTarget(
            name="kimi",
            url=f"http://127.0.0.1:{up_port}",
            api_key="SECRET-UPSTREAM-KEY",
            auth_header="bearer",
        )
        with TestClient(proxy_mod.app) as client:
            r = client.post(
                "/kimi/v1/messages",
                json={
                    "model": "kimi-k3.1-pro-highspeed",
                    "thinking": {"type": "enabled", "budget_tokens": 4096},
                    "messages": [{"role": "user", "content": "hi"}],
                },
            )
            assert r.status_code == 200
            st = client.get("/stats").json()
            assert st["by_route"]["kimi"]["requested_model"] == "kimi-k3.1-pro-highspeed"
            assert st["by_route"]["kimi"]["response_model"] == "kimi-k3.1-pro-highspeed"
            assert st["by_route"]["kimi"]["thinking_effort"] == "enabled(budget=4096)"
            assert st["route_configs"]["kimi"]["endpoint_redacted"] == f"http://127.0.0.1:{up_port}"
            assert "SECRET-UPSTREAM-KEY" not in json.dumps(st)
    finally:
        srv.should_exit = True
        th.join(timeout=5)


def test_on_demand_dag_endpoint_and_zero_agent_overhead(tmp_path: Path) -> None:
    """Verify lazy on-demand Fact-Intent DAG endpoint preserves topology and adds zero Agent rate overhead."""
    mod = _load_module("mock_race_platform_dag_test", REPO_ROOT / "bench" / "mock_race_platform.py")

    # Spin up a tiny mock Cairn server exposing /projects and /projects/{pid}
    cairn_app = FastAPI()

    @cairn_app.get("/projects")
    def list_projects():
        return JSONResponse(
            [
                {
                    "id": "proj_dag_1",
                    "title": "race-WEB-01-SQLi",
                    "status": "active",
                    "created_at": "2026-11-28T10:00:00Z",
                    "fact_count": 2,
                    "intent_count": 3,
                    "working_intent_count": 1,
                    "unclaimed_intent_count": 1,
                    "hint_count": 0,
                    "reason": None,
                }
            ]
        )

    @cairn_app.get("/projects/proj_dag_1")
    def get_project():
        return JSONResponse(
            {
                "project": {"id": "proj_dag_1", "title": "race-WEB-01-SQLi", "status": "active", "reason": None},
                "facts": [
                    {"id": "origin", "description": "Target http://127.0.0.1:8000"},
                    {"id": "goal", "description": "Find and submit flag"},
                    {"id": "f_01", "description": "GET /login exposes SQLi in username param"},
                    {"id": "f_02", "description": "Extracted flag{dag_verified_ok} from admins table"},
                ],
                "intents": [
                    {
                        "id": "i_01",
                        "from": ["origin"],
                        "to": "f_01",
                        "description": "Probe HTTP endpoints and auth inputs",
                        "creator": "reason-1",
                        "worker": "kimi_w1",
                        "created_at": "2026-11-28T10:00:05Z",
                        "last_heartbeat_at": "2026-11-28T10:00:20Z",
                        "concluded_at": "2026-11-28T10:00:22Z",
                    },
                    {
                        "id": "i_02",
                        "from": ["f_01"],
                        "to": "f_02",
                        "description": "Dump admins table via UNION SELECT",
                        "creator": "reason-1",
                        "worker": "kimi_w2",
                        "created_at": "2026-11-28T10:00:25Z",
                        "last_heartbeat_at": "2026-11-28T10:00:40Z",
                        "concluded_at": None,
                    },
                    {
                        "id": "i_03",
                        "from": ["f_01"],
                        "to": None,
                        "description": "Check backup /admin.bak endpoint",
                        "creator": "reason-1",
                        "worker": None,
                        "created_at": "2026-11-28T10:00:26Z",
                        "last_heartbeat_at": None,
                        "concluded_at": None,
                    },
                ],
                "hints": [],
            }
        )

    cairn_port = _free_port()
    srv = uvicorn.Server(uvicorn.Config(cairn_app, host="127.0.0.1", port=cairn_port, log_level="error"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if getattr(srv, "started", False):
            break
        time.sleep(0.05)

    try:
        cfg_path = tmp_path / "race.yaml"
        cfg_path.write_text(
            """
max_scenes: 2
rate_limit_rps: 2
questions:
  - id: "WEB-01"
    name: "SQLi"
    category: "应用系统"
    direction: "web"
    score: 100
    difficulty: 1
    wave: 1
    has_scene: true
    flags: ["flag{dag_verified_ok}"]
  - id: "WEB-02"
    name: "Queued Challenge"
    category: "应用系统"
    direction: "web"
    score: 100
    difficulty: 1
    wave: 1
    has_scene: true
    flags: ["flag{q2}"]
""",
            encoding="utf-8",
        )
        state = mod.MockRacePlatformState(
            valid_token="AGENT-TOK",
            max_scenes=2,
            rate_limit_rps=2,
            base_url="http://127.0.0.1:18099",
            state_file=tmp_path / "state.json",
            cairn_url=f"http://127.0.0.1:{cairn_port}",
        )
        state.load_config(cfg_path)
        app = mod.create_mock_race_app(state)

        with TestClient(app) as client:
            for _ in range(5):
                r = client.get("/api/dashboard/dag/WEB-01")
                assert r.status_code == 200
            dag = r.json()
            assert dag["available"] is True
            assert dag["project_id"] == "proj_dag_1"
            assert dag["stats"]["facts"] == 2
            assert dag["stats"]["intents"] == 3
            assert dag["stats"]["working"] == 1
            assert dag["stats"]["unclaimed"] == 1
            assert dag["stats"]["concluded"] == 1
            node_map = {n["id"]: n for n in dag["nodes"]}
            assert {"origin", "goal", "f_01", "f_02", "i_01", "i_02", "i_03"} <= set(node_map)
            assert node_map["f_02"]["has_flag_hint"] is True
            edge_pairs = {(e["from"], e["to"], e["kind"]) for e in dag["edges"]}
            assert ("origin", "i_01", "depends") in edge_pairs
            assert ("i_01", "f_01", "produces") in edge_pairs
            assert ("f_01", "i_02", "depends") in edge_pairs
            assert ("i_02", "f_02", "produces") in edge_pairs
            assert ("f_01", "i_03", "depends") in edge_pairs

            # Unlinked challenge returns honest no_project state
            r2 = client.get("/api/dashboard/dag/WEB-02")
            assert r2.status_code == 200
            assert r2.json()["available"] is False
            assert r2.json()["status"] == "no_project"

            # Zero impact on Agent rate-limit / API call counters
            snap = client.get("/api/dashboard/snapshot").json()
            assert snap["audit"]["total_api_calls"] == 0
            assert snap["audit"]["rate_limit_hits"] == 0

            # Dashboard HTML includes the DAG tab, tool log tab, budget progress strip, and selected-Q Flag KPI
            html = client.get("/dashboard").text
            assert 'id="tab-dag"' in html
            assert "解题过程 DAG" in html
            assert "/api/dashboard/dag/" in html
            assert 'id="tab-tools"' in html
            assert "工具调用日志" in html
            assert "展开日志" in html
            assert 'id="detailBudgetStrip"' in html
            assert "单题预算分配进度表" in html
            assert "Flag 进度" in html
    finally:
        srv.should_exit = True
        th.join(timeout=5)


def test_proxy_tool_summary_stall_radar_single_q_controls_and_export(tmp_path: Path) -> None:
    """Verify P0-P2: proxy bypass tool summaries, per-Q tokens, P50/P95 latency, stall radar, skip/reset-Q, report export."""
    proxy_mod = _load_module("token_proxy_tools_test", REPO_ROOT / "bench" / "token_proxy.py")
    mock_mod = _load_module("mock_race_platform_p2_test", REPO_ROOT / "bench" / "mock_race_platform.py")

    proxy_mod.LOG = tmp_path / "tokens.jsonl"
    proxy_mod.STATS.clear()
    proxy_mod.QID_STATS.clear()
    proxy_mod.ROUTE_LATENCIES.clear()
    proxy_mod.TOOL_RING_ALL.clear()
    proxy_mod.TOOL_RING_BY_QID.clear()
    proxy_mod.TOOL_INDEX_BY_ID.clear()
    proxy_mod.LLM_TURNS_ALL.clear()
    proxy_mod.LLM_TURNS_BY_QID.clear()
    proxy_mod.ROUTES.clear()
    proxy_mod.COOLDOWN_UNTIL.clear()

    # Mock upstream LLM emitting thinking + answer text + repeated tool_use calls
    up_app = FastAPI()
    turn_counter = {"n": 0}

    @up_app.post("/v1/messages")
    async def messages(req: Request):
        turn_counter["n"] += 1
        n = turn_counter["n"]
        return JSONResponse(
            {
                "id": f"msg_{n}",
                "model": "kimi-k3.1-pro-highspeed",
                "content": [
                    {"type": "thinking", "thinking": f"Step {n}: inspect /admin auth boundary without leaking sk-testsecret999999"},
                    {"type": "text", "text": f"Turn {n} answer: probing /admin endpoint for privilege check."},
                    {
                        "type": "tool_use",
                        "id": f"toolu_{n}",
                        "name": "Bash",
                        "input": {"command": "curl -s http://127.0.0.1:9001/admin -H 'Authorization: Bearer SUPERSECRET123456'"},
                    },
                ],
                "usage": {"input_tokens": 120, "output_tokens": 45, "cache_read_input_tokens": 800},
            },
            status_code=200,
        )

    up_port = _free_port()
    up_srv = uvicorn.Server(uvicorn.Config(up_app, host="127.0.0.1", port=up_port, log_level="error"))
    up_th = threading.Thread(target=up_srv.run, daemon=True)
    up_th.start()

    proxy_port = _free_port()
    proxy_mod.ROUTES["kimi"] = proxy_mod.RouteTarget(
        name="kimi",
        url=f"http://127.0.0.1:{up_port}",
        api_key="SECRET-PROXY-KEY",
        auth_header="bearer",
    )
    px_srv = uvicorn.Server(uvicorn.Config(proxy_mod.app, host="127.0.0.1", port=proxy_port, log_level="error"))
    px_th = threading.Thread(target=px_srv.run, daemon=True)
    px_th.start()

    for _ in range(100):
        if getattr(up_srv, "started", False) and getattr(px_srv, "started", False):
            break
        time.sleep(0.05)

    try:
        # Drive 3 turns with identical command + error tool_result to trigger repeat + error streak stall radar!
        import requests as _req

        origin_msg = {"role": "user", "content": "Challenge ID: WEB-01 | Name: Admin Check\nFind flag."}
        for i in range(1, 4):
            msgs = [origin_msg]
            if i > 1:
                msgs.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": f"toolu_{i - 1}",
                                "is_error": True,
                                "content": "HTTP 403 Forbidden (CAIRN_PROJECT_TOKEN=secret_tok_999)",
                            }
                        ],
                    }
                )
            r = _req.post(
                f"http://127.0.0.1:{proxy_port}/kimi/v1/messages",
                json={"model": "kimi-k3.1-pro-highspeed", "messages": msgs},
                timeout=5,
            )
            assert r.status_code == 200

        # Send final turn with tool_result for toolu_3 so error_streak reaches 3
        _req.post(
            f"http://127.0.0.1:{proxy_port}/kimi/v1/messages",
            json={
                "model": "kimi-k3.1-pro-highspeed",
                "messages": [
                    origin_msg,
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_result", "tool_use_id": "toolu_3", "is_error": True, "content": "exit 1"}
                        ],
                    },
                ],
            },
            timeout=5,
        )

        # Verify proxy /stats has P50/P95 + per-Q stats, and /tools redacts secrets
        pstats = _req.get(f"http://127.0.0.1:{proxy_port}/stats", timeout=5).json()
        assert pstats["by_route"]["kimi"]["p50_sec"] is not None
        assert pstats["by_qid"]["WEB-01"]["calls"] == 4
        assert pstats["by_qid"]["WEB-01"]["tool_errors"] == 3
        assert pstats["by_qid"]["WEB-01"]["repeat_streak"] >= 3

        ptools = _req.get(f"http://127.0.0.1:{proxy_port}/tools", params={"qid": "WEB-01"}, timeout=5).json()
        assert ptools["count"] == 4
        assert ptools["tools"][0]["input_detail"].startswith("curl -s http://127.0.0.1:9001/admin")
        assert "HTTP 403 Forbidden" in ptools["tools"][0]["output_detail"]
        raw_tools_dump = json.dumps(ptools)
        assert "SUPERSECRET123456" not in raw_tools_dump
        assert "secret_tok_999" not in raw_tools_dump
        assert "[REDACTED]" in raw_tools_dump

        # Mount MockRacePlatform connected to this proxy
        cfg_path = tmp_path / "race.yaml"
        cfg_path.write_text(
            """
max_scenes: 2
rate_limit_rps: 20
default_time_budget_sec: 600
default_token_budget: 20000
default_max_llm_calls: 20
stale_timeout_sec: 300
questions:
  - id: "WEB-01"
    name: "Admin Check"
    category: "应用系统"
    direction: "web"
    score: 100
    difficulty: 1
    wave: 1
    has_scene: true
    scene_addresses:
      - access_ip: "127.0.0.1"
        access_port: 9001
        protocol: "http"
    flags: ["flag{ok_1}", "flag{ok_1b}"]
  - id: "WEB-02"
    name: "Keep Score"
    category: "应用系统"
    direction: "web"
    score: 200
    difficulty: 1
    wave: 1
    has_scene: false
    flags: ["flag{ok_2}"]
""",
            encoding="utf-8",
        )
        state = mock_mod.MockRacePlatformState(
            valid_token="AGENT-TOK",
            max_scenes=2,
            rate_limit_rps=20,
            base_url="http://127.0.0.1:18099",
            state_file=tmp_path / "state.json",
            proxy_url=f"http://127.0.0.1:{proxy_port}",
        )
        state.load_config(cfg_path)
        app = mock_mod.create_mock_race_app(state)
        auth = {"Authorization": "Bearer AGENT-TOK"}

        with TestClient(app) as client:
            # Start WEB-01 and solve WEB-02
            client.post("/api/ct/agent/ai_race/race/checkpoints/robot/question_start", headers=auth, json={"question_id": "WEB-01"})
            client.post(
                "/api/ct/agent/ai_race/race/checkpoints/robot/question/submit_flag",
                headers=auth,
                json={"question_id": "WEB-02", "flag": "flag{ok_2}"},
            )

            # Snapshot must flag WEB-01 on stall radar AND expose accurate per-question budget progress!
            snap = client.get("/api/dashboard/snapshot").json()
            q1 = next(q for q in snap["questions"] if q["id"] == "WEB-01")
            assert q1["stall"]["level"] in ("warn", "critical")
            assert any("报错" in r or "重复" in r for r in q1["stall"]["reasons"])
            assert q1["llm_usage"]["calls"] == 4
            bmap = {b["key"]: b for b in q1["budgets"]}
            assert bmap["time"]["limit"] == 600.0 and bmap["time"]["configured"] is True
            assert bmap["stale"]["limit"] == 300.0 and bmap["stale"]["configured"] is True
            assert bmap["tokens"]["limit"] == 20000 and bmap["tokens"]["used"] == (120 + 45) * 4
            assert bmap["tokens"]["pct"] == round(((120 + 45) * 4 / 20000) * 100.0, 1)
            assert bmap["llm_calls"]["used"] == 4 and bmap["llm_calls"]["limit"] == 20 and bmap["llm_calls"]["pct"] == 20.0
            assert bmap["attempts"]["used"] == 1 and bmap["attempts"]["limit"] == 2 and bmap["attempts"]["pct"] == 50.0
            assert bmap["reopens"]["limit"] == 3

            # On-demand tools & LLM Q&A timeline endpoints work with zero impact on agent API calls
            before_api = snap["audit"]["total_api_calls"]
            rt = client.get("/api/dashboard/tools/WEB-01")
            assert rt.status_code == 200
            assert rt.json()["available"] is True
            assert rt.json()["count"] == 4
            rl = client.get("/api/dashboard/llm-logs/WEB-01")
            assert rl.status_code == 200
            llm_data = rl.json()
            assert llm_data["available"] is True
            assert llm_data["count"] == 4
            t0 = llm_data["turns"][0]
            assert "Challenge ID: WEB-01" in t0["question_detail"]
            assert "Turn 1 answer" in t0["answer_detail"]
            assert "Step 1:" in t0["thinking_detail"]
            assert "sk-testsecret999999" not in json.dumps(llm_data)
            assert "SUPERSECRET123456" not in json.dumps(llm_data)
            assert "secret_tok_999" not in json.dumps(llm_data)
            assert t0["ttft_sec"] is not None and t0["dur_sec"] is not None
            assert client.get("/api/dashboard/snapshot").json()["audit"]["total_api_calls"] == before_api

            # Dashboard HTML includes LLM Q&A timeline tab
            html = client.get("/dashboard").text
            assert 'id="tab-llm"' in html
            assert "模型对话时间线" in html
            assert "/api/dashboard/llm-logs/" in html

            # One-click Markdown export report works & exposes ONLY obtained flags (never unsolved truth!)
            snap_flags = client.get("/api/dashboard/snapshot").json()
            q2_f = next(q for q in snap_flags["questions"] if q["id"] == "WEB-02")
            q1_f = next(q for q in snap_flags["questions"] if q["id"] == "WEB-01")
            assert [f["flag"] for f in q2_f["obtained_flags"]] == ["flag{ok_2}"]
            assert q1_f["obtained_flags"] == []
            snap_dump = json.dumps(snap_flags, ensure_ascii=False)
            assert "flag{ok_1}" not in snap_dump and "flag{ok_1b}" not in snap_dump
            assert any(s.get("flag") == "flag{ok_2}" for s in snap_flags["submissions"])

            rep = client.get("/api/dashboard/export-report?format=md")
            assert rep.status_code == 200
            assert "WEB-01" in rep.text and "P50 / P95" in rep.text
            assert "flag{ok_2}" in rep.text
            assert "flag{ok_1}" not in rep.text and "flag{ok_1b}" not in rep.text

            # Single-question skip stops WEB-01 scene and leaves WEB-02 untouched
            sk = client.post("/api/admin/skip-question/WEB-01")
            assert sk.status_code == 200 and sk.json()["stopped_scene"] is True
            snap2 = client.get("/api/dashboard/snapshot").json()
            q1_after = next(q for q in snap2["questions"] if q["id"] == "WEB-01")
            assert q1_after["skipped"] is True
            assert q1_after["states"]["env"]["code"] == "stopped"
            assert snap2["summary"]["total_score"] == 200.0

            # Single-question reset clears ONLY WEB-02 score without touching WEB-01 skip history
            rq = client.post("/api/admin/reset-question/WEB-02")
            assert rq.status_code == 200
            snap3 = client.get("/api/dashboard/snapshot").json()
            assert snap3["summary"]["total_score"] == 0.0
            assert next(q for q in snap3["questions"] if q["id"] == "WEB-01")["skipped"] is True
    finally:
        px_srv.should_exit = True
        up_srv.should_exit = True
        px_th.join(timeout=5)
        up_th.join(timeout=5)
