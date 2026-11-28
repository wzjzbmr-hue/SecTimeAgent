#!/usr/bin/env python3
"""1:1 仿真官方 AI 赛平台 + 人类决策驾驶舱后端（完全对齐 API_接入.md + MCP_接入.md）。

核心能力：
  1. HTTP API 全部 7 个接口与全部 AD-xxxxxx 错误码（业务错误统一 HTTP 200）
  2. Streamable HTTP MCP 端点（POST /mcp，协议 2024-11-05，6 个 question_* 工具，共享状态与限流）
  3. 真实 Docker 动态靶机生命周期管理（单容器与多容器隔离内网，真实 3->0->1->2->3 与 20 故障注入）
  4. 严格四维状态分离（调度 / 环境 / Worker / 验收判定）、Attempt 历史保留、地址可达性规范与 8 大类基线矩阵
  5. 统一结构化事件契约（seq 缺口检测、event_id 去重、按题与 attempt 过滤、重连补拉）与多源连接健康诊断
  6. 可选服务端隔离人类参考对照接口（独立 HUMAN_REF_TOKEN 鉴权、拒绝 Worker/Agent 凭据、完整审计日志）
"""

from __future__ import annotations

import argparse
import asyncio
import atexit
import importlib.util
import json
import math
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

import requests
import uvicorn
import yaml
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

ROOT_DIR = Path(__file__).resolve().parent
REPO_ROOT = ROOT_DIR.parent
DASHBOARD_HTML_PATH = ROOT_DIR / "dashboard.html"


def _import_sibling(module_name: str, file_path: Path):
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    if not spec or not spec.loader:
        raise ImportError(f"Cannot load {module_name} from {file_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


cockpit_models = _import_sibling("cockpit_models", ROOT_DIR / "cockpit_models.py")
human_ref_mod = _import_sibling("human_reference", REPO_ROOT / "eval" / "human_reference.py")


class QuestionIdBody(BaseModel):
    question_id: str


class SubmitFlagBody(BaseModel):
    question_id: str
    flag: str


class MilestoneUpdateBody(BaseModel):
    key: str
    status: str  # pending | running | done | failed
    detail: str = ""
    score: float | None = None


class OperatorActionBody(BaseModel):
    action: str  # note | pause | resume | priority | budget | hint
    operator: str = "human-operator"
    summary: str = ""
    affects_autonomy: bool = False


def _envelope(code: str = "AD-000000", message: str = "", detail: str = "", data: Any = None) -> dict[str, Any]:
    return {
        "code": code,
        "message": message,
        "detail": detail,
        "timestamp": round(time.time(), 6),
        "data": data,
    }


def _rank_multiplier(rank: int) -> float:
    """Official 152-team rank bonus/decay multiplier."""
    if rank <= 1:
        return 1.05
    if rank == 2:
        return 1.03
    if rank == 3:
        return 1.01
    if rank <= 50:
        return 1.00
    if rank <= 100:
        return 0.90
    if rank <= 130:
        return 0.80
    return 0.60


def _pick_free_port(bind_host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((bind_host, 0))
        return int(s.getsockname()[1])


def _probe_tcp(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_http(host: str, port: int, path: str = "/", timeout: float = 2.0) -> bool:
    url = f"http://{host}:{port}/{path.lstrip('/')}"
    try:
        r = requests.get(url, timeout=timeout)
        return r.status_code < 500
    except requests.RequestException:
        return False


class DockerSceneManager:
    """Manages real Docker target containers (single-container or multi-container intranet)."""

    def __init__(self, *, target_host: str = "127.0.0.1", label_prefix: str = "eval-mock-scene"):
        self.target_host = target_host
        self.label_prefix = label_prefix
        self._lock = threading.Lock()
        self._active: dict[str, dict[str, Any]] = {}

    def _run_docker(self, args: list[str], *, check: bool = True, timeout: float = 60.0) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )

    def active_containers_for(self, qid: str) -> list[str]:
        with self._lock:
            entry = self._active.get(qid)
            return list(entry.get("containers") or []) if entry else []

    def start_scene(
        self,
        qid: str,
        q: dict[str, Any],
        flags: list[str],
    ) -> list[dict[str, Any]]:
        self.stop_scene(qid)
        flag_env = {f"FLAG_{i + 1}": f for i, f in enumerate(flags)}
        if flags:
            flag_env["FLAG"] = flags[0]

        if q.get("multi_docker"):
            return self._start_multi_container(qid, q["multi_docker"], flag_env)
        if q.get("docker"):
            return self._start_single_container(qid, q["docker"], flag_env)
        return list(q.get("scene_addresses") or [])

    def _start_single_container(
        self,
        qid: str,
        spec: dict[str, Any],
        flag_env: dict[str, str],
    ) -> list[dict[str, Any]]:
        image = str(spec["image"])
        container_port = int(spec.get("container_port") or 8000)
        protocol = str(spec.get("protocol") or "http")
        host_port = int(spec["host_port"]) if spec.get("host_port") else _pick_free_port(self.target_host)
        cname = f"{self.label_prefix}-{qid}-{secrets.token_hex(3)}"

        cmd = [
            "run", "-d", "--rm",
            "--name", cname,
            "--label", f"{self.label_prefix}=1",
            "--label", f"{self.label_prefix}.qid={qid}",
            "--init",
            "--memory", str(spec.get("mem_limit") or "256m"),
            "--pids-limit", str(spec.get("pids_limit") or 128),
            "-p", f"{self.target_host}:{host_port}:{container_port}",
        ]
        merged_env = {**(spec.get("env") or {}), **flag_env}
        for k, v in merged_env.items():
            cmd.extend(["-e", f"{k}={v}"])
        extra_ports = spec.get("extra_ports") or []
        addresses = [{"access_ip": self.target_host, "access_port": host_port, "protocol": protocol}]
        for ep in extra_ports:
            ecp = int(ep["container_port"])
            ehp = int(ep["host_port"]) if ep.get("host_port") else _pick_free_port(self.target_host)
            cmd.extend(["-p", f"{self.target_host}:{ehp}:{ecp}"])
            addresses.append(
                {"access_ip": self.target_host, "access_port": ehp, "protocol": str(ep.get("protocol") or "tcp")}
            )
        cmd.append(image)
        if spec.get("command"):
            if isinstance(spec["command"], list):
                cmd.extend([str(x) for x in spec["command"]])
            else:
                cmd.append(str(spec["command"]))

        self._run_docker(cmd, check=True)
        with self._lock:
            self._active[qid] = {"containers": [cname], "network": None}

        hc_type = str(spec.get("healthcheck_type") or ("http" if protocol in ("http", "https") else "tcp"))
        hc_path = str(spec.get("healthcheck_path") or "/")
        timeout = float(spec.get("startup_timeout_sec") or 30.0)
        probe_host = "127.0.0.1" if cockpit_models.is_wildcard_ip(self.target_host) else self.target_host
        self._wait_ready(probe_host, host_port, hc_type, hc_path, timeout, cname)
        return addresses

    def _start_multi_container(
        self,
        qid: str,
        spec: dict[str, Any],
        flag_env: dict[str, str],
    ) -> list[dict[str, Any]]:
        suffix = secrets.token_hex(3)
        net_name = f"{self.label_prefix}-net-{qid}-{suffix}"
        self._run_docker(["network", "create", "--driver", "bridge", net_name], check=True)

        created_containers: list[str] = []
        addresses: list[dict[str, Any]] = []
        primary_probe: tuple[str, int, str, str, str] | None = None
        probe_host = "127.0.0.1" if cockpit_models.is_wildcard_ip(self.target_host) else self.target_host

        try:
            for svc in spec.get("services") or []:
                alias = str(svc["name"])
                cname = f"{self.label_prefix}-{qid}-{alias}-{suffix}"
                cmd = [
                    "run", "-d", "--rm",
                    "--name", cname,
                    "--network", net_name,
                    "--network-alias", alias,
                    "--label", f"{self.label_prefix}=1",
                    "--label", f"{self.label_prefix}.qid={qid}",
                    "--init",
                    "--memory", str(svc.get("mem_limit") or "256m"),
                    "--pids-limit", str(svc.get("pids_limit") or 128),
                ]
                if svc.get("expose_port"):
                    cport = int(svc["expose_port"])
                    exposed_host_port = int(svc["host_port"]) if svc.get("host_port") else _pick_free_port(self.target_host)
                    proto = str(svc.get("protocol") or "http")
                    cmd.extend(["-p", f"{self.target_host}:{exposed_host_port}:{cport}"])
                    addresses.append({"access_ip": self.target_host, "access_port": exposed_host_port, "protocol": proto})
                    if primary_probe is None:
                        hc_type = str(svc.get("healthcheck_type") or ("http" if proto in ("http", "https") else "tcp"))
                        hc_path = str(svc.get("healthcheck_path") or "/")
                        primary_probe = (probe_host, exposed_host_port, hc_type, hc_path, cname)

                merged_env = {**(svc.get("env") or {}), **flag_env}
                for k, v in merged_env.items():
                    cmd.extend(["-e", f"{k}={v}"])
                cmd.append(str(svc["image"]))
                if svc.get("command"):
                    cmd.extend([str(x) for x in svc["command"]] if isinstance(svc["command"], list) else [str(svc["command"])])

                self._run_docker(cmd, check=True)
                created_containers.append(cname)
        except Exception:
            for cn in created_containers:
                self._run_docker(["rm", "-f", cn], check=False)
            self._run_docker(["network", "rm", net_name], check=False)
            raise

        with self._lock:
            self._active[qid] = {"containers": created_containers, "network": net_name}

        if primary_probe is not None:
            host, port, hc_type, hc_path, cname = primary_probe
            self._wait_ready(host, port, hc_type, hc_path, float(spec.get("startup_timeout_sec") or 40.0), cname)
        else:
            time.sleep(1.0)
        return addresses

    def _wait_ready(
        self,
        host: str,
        port: int,
        hc_type: str,
        hc_path: str,
        timeout: float,
        cname: str,
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            chk = self._run_docker(["inspect", "-f", "{{.State.Running}}", cname], check=False)
            if chk.returncode != 0 or chk.stdout.strip() != "true":
                logs = self._run_docker(["logs", "--tail", "20", cname], check=False)
                raise RuntimeError(f"scene container {cname} exited early: {logs.stdout} {logs.stderr}")
            ok = _probe_http(host, port, hc_path) if hc_type == "http" else _probe_tcp(host, port)
            if ok:
                return
            time.sleep(0.4)
        raise RuntimeError(f"scene container {cname} healthcheck timed out on {host}:{port}")

    def stop_scene(self, qid: str) -> None:
        with self._lock:
            entry = self._active.pop(qid, None)
        if not entry:
            return
        for cname in entry.get("containers") or []:
            self._run_docker(["rm", "-f", cname], check=False, timeout=30.0)
        net = entry.get("network")
        if net:
            self._run_docker(["network", "rm", net], check=False, timeout=20.0)

    def stop_all(self) -> None:
        with self._lock:
            qids = list(self._active.keys())
        for qid in qids:
            self.stop_scene(qid)


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
        docker_enabled: bool = False,
        target_host: str = "127.0.0.1",
        public_host: str | None = None,
        dynamic_flags: bool = False,
        enforce_scene_running_on_submit: bool = True,
        simulate_competitors: bool = False,
        time_scale: float = 1.0,
        duration_sec: float = 14400.0,
        cairn_url: str | None = None,
        cairn_admin_token: str | None = None,
        proxy_url: str | None = None,
        orch_state_file: Path | None = None,
        secret_patterns: list[str] | None = None,
        human_ref_store: Any | None = None,
    ):
        self.run_id = f"run_{secrets.token_hex(4)}"
        self.valid_token = valid_token
        self.max_scenes = max_scenes
        self.rate_limit_rps = rate_limit_rps
        self.base_url = base_url.rstrip("/")
        self.state_file = state_file
        self.attachments_root = attachments_root
        self.docker_enabled = docker_enabled
        self.target_host = target_host
        self.public_host = (public_host or "").strip() or None
        self.dynamic_flags = dynamic_flags
        self.enforce_scene_running_on_submit = enforce_scene_running_on_submit
        self.simulate_competitors = simulate_competitors
        self.time_scale = max(0.01, float(time_scale))
        self.duration_sec = float(duration_sec)
        self.cairn_url = cairn_url.rstrip("/") if cairn_url else None
        self.cairn_admin_token = cairn_admin_token
        self.proxy_url = proxy_url.rstrip("/") if proxy_url else None
        self.orch_state_file = orch_state_file
        self.secret_patterns = [s for s in (secret_patterns or []) if s]
        self.human_ref_store = human_ref_store

        self.started_at = time.monotonic()
        self.started_wall = time.time()
        self.lock = threading.RLock()
        self.questions: dict[str, dict[str, Any]] = {}
        self.active_flags: dict[str, list[str]] = {}
        self.solved_flags: dict[str, set[str]] = {}
        self.solved_flag_details: dict[str, list[dict[str, Any]]] = {}
        self.milestones: dict[str, list[dict[str, Any]]] = {}
        self.scene_status: dict[str, int] = {}
        self.ever_started: dict[str, bool] = {}
        self.last_stop_reason: dict[str, str | None] = {}
        self.last_stopped_at: dict[str, float | None] = {}
        self.live_addresses: dict[str, list[dict[str, Any]]] = {}
        self.scene_start_attempts: dict[str, int] = {}
        self.scene_started_at: dict[str, float] = {}
        self.question_solved_at: dict[str, float] = {}
        self.attempts_history: dict[str, list[dict[str, Any]]] = {}
        self.platform_decisions: list[dict[str, Any]] = []
        self._decision_seq = 0
        self.rate_windows: dict[str, deque[float]] = {}
        self.total_score: float = 0.0
        self.ranked_score: float = 0.0
        self.submissions: list[dict[str, Any]] = []
        self.event_store = cockpit_models.EventStore(self.run_id, maxlen=800)
        self.mcp_sessions: dict[str, float] = {}

        # Compliance telemetry (explicitly excludes dashboard polling!)
        self.audit: dict[str, Any] = {
            "rate_limit_hits": 0,
            "scene_limit_hits": 0,
            "credential_leaks": [],
            "scene_faults_injected": 0,
            "scene_faults_recovered": 0,
            "total_api_calls": 0,
            "total_mcp_calls": 0,
            "dashboard_polls": 0,
            "human_interventions": [],
        }
        self.scene_mgr = DockerSceneManager(target_host=target_host) if docker_enabled else None

        # Per-connection health tracking (D08, D12)
        self._last_ok: dict[str, float | None] = {
            "platform": time.time(),
            "docker": None,
            "cairn": None,
            "proxy": None,
            "orchestrator": None,
        }
        self._obs_cache_ts = 0.0
        self._obs_cache: dict[str, Any] = {}
        self._docker_stats_ts = 0.0
        self._docker_stats_cache: dict[str, Any] = {
            "available": False,
            "observed_at": None,
            "reason": "尚未采样",
            "containers": {},
        }
        # On-demand per-challenge DAG, tool-summary & LLM Q&A caches (2s TTL) + lock-free observer hardening
        self._obs_lock = threading.Lock()
        self._cairn_proj_detail_cache: dict[str, tuple[tuple[Any, ...], list[dict[str, Any]], list[dict[str, Any]]]] = {}
        self._snap_cache: tuple[float, int, dict[str, Any]] | None = None
        self._state_version = 0
        self._dag_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._tools_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._llm_logs_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self.skipped_questions: dict[str, dict[str, Any]] = {}
        self.budget_defaults: dict[str, Any] = {}

    @property
    def events(self) -> list[dict[str, Any]]:
        """Backward-compatible property exposing recent events."""
        return self.event_store.recent(300)

    def _emit_event(
        self,
        kind: str,
        message: str,
        *,
        qid: str | None = None,
        source: str = "platform",
        severity: str | None = None,
        attempt_id: str | None = None,
        worker_id: str | None = None,
        decision_id: str | None = None,
        tool_call_id: str | None = None,
        submission_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if severity is None:
            if kind in ("flag_pass", "milestone_done", "scene_running"):
                severity = "ok"
            elif any(tok in kind for tok in ("fault", "err", "leak", "wrong", "fail")):
                severity = "error"
            elif any(tok in kind for tok in ("limit", "warn", "reopen")):
                severity = "warn"
            else:
                severity = "info"
        if attempt_id is None and qid:
            cur = self._current_attempt(qid)
            if cur:
                attempt_id = cur["attempt_id"]
        self._state_version += 1
        return self.event_store.emit(
            event_type=kind,
            message=message,
            source=source,
            severity=severity,
            elapsed_sec=self.elapsed_sec(),
            challenge_id=qid,
            attempt_id=attempt_id,
            worker_id=worker_id,
            decision_id=decision_id,
            tool_call_id=tool_call_id,
            submission_id=submission_id,
            details=extra or {},
        )

    def _record_platform_decision(
        self,
        *,
        trigger: str,
        to_qid: str | None,
        reason: str,
        outcome: str,
        from_qid: str | None = None,
        budget_sec: int | None = None,
        worker_id: str | None = None,
    ) -> str:
        self._decision_seq += 1
        did = f"pdec_{self._decision_seq:04d}"
        now = time.time()
        self.platform_decisions.append(
            {
                "decision_id": did,
                "ts": round(now, 3),
                "at": cockpit_models.iso_utc(now),
                "elapsed_sec": round(self.elapsed_sec(), 1),
                "source": "platform",
                "trigger": trigger,
                "from_qid": from_qid,
                "to_qid": to_qid,
                "reason": reason,
                "budget_sec": budget_sec,
                "worker_id": worker_id,
                "outcome": outcome,
            }
        )
        if len(self.platform_decisions) > 150:
            self.platform_decisions = self.platform_decisions[-150:]
        return did

    def _open_attempt(self, qid: str, *, trigger: str = "question_start") -> dict[str, Any]:
        hist = self.attempts_history.setdefault(qid, [])
        # Close any unclosed prior attempt gracefully
        for prev in hist:
            if prev.get("ended_at") is None:
                prev["ended_at"] = round(time.time(), 3)
                prev["ended_at_iso"] = cockpit_models.iso_utc(prev["ended_at"])
                prev["duration_sec"] = round(max(0.0, prev["ended_at"] - prev["started_at"]), 1)
                if prev["status"] in ("starting", "running"):
                    prev["status"] = "stopped"
                    prev["stop_reason"] = prev.get("stop_reason") or "superseded_by_restart"
        num = len(hist) + 1
        now = time.time()
        att = {
            "attempt_id": f"att_{qid}_{num:02d}",
            "attempt_number": num,
            "challenge_id": qid,
            "trigger": trigger,
            "started_at": round(now, 3),
            "started_at_iso": cockpit_models.iso_utc(now),
            "started_elapsed_sec": round(self.elapsed_sec(), 1),
            "ended_at": None,
            "ended_at_iso": None,
            "duration_sec": None,
            "status": "starting",
            "stop_reason": None,
            "scene_faults": 0,
            "submissions": [],
        }
        hist.append(att)
        return att

    def _current_attempt(self, qid: str) -> dict[str, Any] | None:
        hist = self.attempts_history.get(qid) or []
        return hist[-1] if hist else None

    def _close_current_attempt(self, qid: str, *, status: str, reason: str) -> dict[str, Any] | None:
        cur = self._current_attempt(qid)
        if not cur or cur.get("ended_at") is not None:
            return cur
        now = time.time()
        cur["ended_at"] = round(now, 3)
        cur["ended_at_iso"] = cockpit_models.iso_utc(now)
        cur["duration_sec"] = round(max(0.0, now - float(cur["started_at"])), 1)
        cur["status"] = status
        cur["stop_reason"] = reason
        return cur

    def _cumulative_attempt_sec(self, qid: str) -> float:
        now = time.time()
        total = 0.0
        for att in self.attempts_history.get(qid) or []:
            if att.get("duration_sec") is not None:
                total += float(att["duration_sec"])
            elif att.get("started_at") is not None and att.get("status") in ("starting", "running"):
                total += max(0.0, now - float(att["started_at"]))
        return round(total, 1)

    def elapsed_sec(self) -> float:
        return (time.monotonic() - self.started_at) * self.time_scale

    def load_config(self, path: Path) -> None:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if "max_scenes" in raw:
            self.max_scenes = int(raw["max_scenes"])
        if "rate_limit_rps" in raw:
            self.rate_limit_rps = int(raw["rate_limit_rps"])
        if "simulate_competitors" in raw:
            self.simulate_competitors = bool(raw["simulate_competitors"])
        if "dynamic_flags" in raw:
            self.dynamic_flags = bool(raw["dynamic_flags"])
        if "duration_sec" in raw:
            self.duration_sec = float(raw["duration_sec"])
        if "public_host" in raw and not self.public_host:
            self.public_host = str(raw["public_host"]).strip() or None
        self.budget_defaults = {
            "time_budget_sec": raw.get("default_time_budget_sec") or raw.get("time_budget_sec"),
            "stale_timeout_sec": raw.get("stale_timeout_sec"),
            "token_budget": raw.get("default_token_budget") or raw.get("token_budget"),
            "max_llm_calls": raw.get("default_max_llm_calls") or raw.get("max_llm_calls"),
            "max_attempts": raw.get("max_attempts"),
            "max_reopens": raw.get("max_reopens"),
        }

        for item in raw.get("questions") or []:
            qid = str(item["id"])
            raw_flags = [str(f).strip() for f in (item.get("flags") or ([item["flag"]] if item.get("flag") else []))]
            has_docker = bool(item.get("docker") or item.get("multi_docker"))
            if self.dynamic_flags and has_docker and raw_flags:
                eff_flags = [f"flag{{{qid}_f{i+1}_{secrets.token_hex(6)}}}" for i in range(len(raw_flags))]
            else:
                eff_flags = list(raw_flags)
            canon_cat, is_canon = cockpit_models.normalize_category(item.get("category"), item.get("direction"))
            q = {
                "id": qid,
                "name": str(item.get("name") or qid),
                "direction": str(item.get("direction") or "web"),
                "category": str(item.get("category") or item.get("direction") or "web"),
                "canonical_category": canon_cat,
                "is_canonical_category": is_canon,
                "score": float(item.get("score") or 100),
                "difficulty": int(item.get("difficulty") or 1),
                "desc": str(item.get("desc") or ""),
                "flags": eff_flags,
                "static_flags": raw_flags,
                "grading_type": item.get("grading_type"),
                "poc_spec": item.get("poc_spec"),
                "has_scene": bool(item.get("has_scene", True)),
                "scene_addresses": list(item.get("scene_addresses") or []),
                "docker": item.get("docker"),
                "multi_docker": item.get("multi_docker"),
                "startup_delay_sec": float(item.get("startup_delay_sec") or 0.0),
                "attachments": list(item.get("attachments") or []),
                "release_after_sec": float(item.get("release_after_sec") or 0.0),
                "initial_release_after_sec": float(item.get("release_after_sec") or 0.0),
                "fail_first_start": bool(item.get("fail_first_start", False)),
                "force_next_fault": False,
                "all_user_solved": int(item.get("all_user_solved") or 0),
                "wave": int(item.get("wave") or (1 if float(item.get("release_after_sec") or 0.0) <= 0 else 2)),
                "time_budget_sec": item.get("time_budget_sec"),
                "stale_timeout_sec": item.get("stale_timeout_sec"),
                "token_budget": item.get("token_budget"),
                "max_llm_calls": item.get("max_llm_calls"),
                "max_attempts": item.get("max_attempts"),
                "max_reopens": item.get("max_reopens"),
            }
            self.questions[qid] = q
            self.active_flags[qid] = eff_flags
            self.solved_flags.setdefault(qid, set())
            self.solved_flag_details.setdefault(qid, [])
            gtype = cockpit_models.infer_grading_type(q, eff_flags)
            self.milestones[qid] = cockpit_models.default_milestones(gtype)
            self.attempts_history.setdefault(qid, [])
            self.ever_started.setdefault(qid, False)
            self.last_stop_reason.setdefault(qid, None)
            self.last_stopped_at.setdefault(qid, None)
            if q["has_scene"]:
                self.scene_status.setdefault(qid, 3)
                self.live_addresses.setdefault(qid, list(q["scene_addresses"]))
        self._load_persisted()
        self._emit_event("platform_init", f"Loaded {len(self.questions)} challenges (docker={self.docker_enabled})")

    def _load_persisted(self) -> None:
        if not self.state_file or not self.state_file.is_file():
            return
        try:
            saved = json.loads(self.state_file.read_text(encoding="utf-8"))
            self.total_score = float(saved.get("total_score") or 0.0)
            self.ranked_score = float(saved.get("ranked_score") or self.total_score)
            for qid, flist in (saved.get("solved_flags") or {}).items():
                self.solved_flags[qid] = set(flist)
            # Strictly normalize persisted solved_flag_details so legacy records never render undefined (D01)
            raw_details = saved.get("solved_flag_details") or {}
            for qid, recs in raw_details.items():
                self.solved_flag_details[qid] = [
                    cockpit_models.normalize_submission_record(r, simulate_competitors=self.simulate_competitors)
                    for r in (recs or [])
                    if isinstance(r, dict)
                ]
            for qid, flist in self.solved_flags.items():
                if flist and not self.solved_flag_details.get(qid):
                    # Backfill clean structured records with explicit unreported time/rank (never fake 0 or undefined!)
                    q = self.questions.get(qid)
                    per_score = round((q["score"] / max(1, len(self.active_flags.get(qid) or [1]))), 2) if q else None
                    self.solved_flag_details[qid] = [
                        cockpit_models.normalize_submission_record(
                            {
                                "qid": qid,
                                "name": q["name"] if q else qid,
                                "flag_index": (self.active_flags[qid].index(f) + 1)
                                if (qid in self.active_flags and f in self.active_flags[qid])
                                else None,
                                "pass": True,
                                "duplicate": False,
                                "score": per_score,
                                "elapsed_sec": None,
                                "ts": None,
                            },
                            simulate_competitors=self.simulate_competitors,
                        )
                        for f in sorted(flist)
                    ]
            for r in (saved.get("submissions") or []):
                if isinstance(r, dict):
                    self.submissions.append(
                        cockpit_models.normalize_submission_record(r, simulate_competitors=self.simulate_competitors)
                    )
            for qid, ms in (saved.get("milestones") or {}).items():
                if isinstance(ms, list):
                    self.milestones[qid] = ms
        except Exception:
            pass

    def persist(self) -> None:
        if not self.state_file:
            return
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": self.run_id,
            "updated_at": time.time(),
            "elapsed_sec": round(self.elapsed_sec(), 1),
            "total_score": self.total_score,
            "ranked_score": self.ranked_score,
            "solved_flags": {k: sorted(v) for k, v in self.solved_flags.items()},
            "solved_flag_details": self.solved_flag_details,
            "milestones": self.milestones,
            "attempts_history": self.attempts_history,
            "submissions": self.submissions[-200:],
            "submissions_count": len(self.submissions),
            "audit": self.audit,
        }
        self.state_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def simulated_all_user_solved(self, q: dict[str, Any]) -> int:
        base = int(q["all_user_solved"])
        if not self.simulate_competitors or not self.is_visible(q):
            return base
        since_release = max(0.0, self.elapsed_sec() - float(q["release_after_sec"]))
        diff = int(q["difficulty"])
        half_sec = 720.0 if diff == 1 else (2100.0 if diff == 2 else 5400.0)
        cap = 142 if diff == 1 else (95 if diff == 2 else 42)
        ratio = 1.0 - math.exp(-since_release / half_sec)
        npc = int(round(cap * ratio))
        my_solved = 1 if self.solved_flags.get(q["id"]) else 0
        return max(base, npc + my_solved)

    def check_auth_and_rate(self, authorization: str | None, *, is_mcp: bool = False) -> dict[str, Any] | None:
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
            self.audit["rate_limit_hits"] += 1
            self._emit_event("rate_limit", "Hit 3 req/s rate limit (AD-002002)", source="auditor", severity="warn")
            return _envelope("AD-002002", "提交过于频繁，请在 1 秒后重试", "提交过于频繁，请在 1 秒后重试")
        win.append(now)
        if is_mcp:
            self.audit["total_mcp_calls"] += 1
        else:
            self.audit["total_api_calls"] += 1
        return None

    def _audit_text_for_leaks(self, text: str, source: str) -> None:
        needles = [self.valid_token, *self.secret_patterns]
        with self.lock:
            seen = {(e["source"], e["secret_hint"]) for e in self.audit["credential_leaks"]}
            for secret in needles:
                if secret and len(secret) >= 8 and secret in text:
                    hint = secret[:4] + "***"
                    if (source, hint) not in seen:
                        seen.add((source, hint))
                        self.audit["credential_leaks"].append({"ts": time.time(), "source": source, "secret_hint": hint})
                        self._emit_event(
                            "compliance_leak",
                            f"Secret leak detected in {source}",
                            source="auditor",
                            severity="error",
                        )

    def is_visible(self, q: dict[str, Any]) -> bool:
        return self.elapsed_sec() >= float(q["release_after_sec"])

    def _attachment_entries(self, q: dict[str, Any]) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for att in q["attachments"]:
            name = att["name"] if isinstance(att, dict) else str(att)
            url = att["url"] if isinstance(att, dict) and att.get("url") else f"{self.base_url}/attachments/{q['id']}/{name}"
            out.append({"name": name, "url": url})
        return out

    def running_scene_count(self) -> int:
        return sum(1 for st in self.scene_status.values() if st in (0, 1))

    # --- Core Business Operations (shared by HTTP API & MCP endpoint) ---

    def op_question_list(self, direction: str | None = None) -> dict[str, Any]:
        out = []
        for q in self.questions.values():
            if not self.is_visible(q):
                continue
            if direction and q["direction"] != direction:
                continue
            entry: dict[str, Any] = {
                "id": q["id"],
                "name": q["name"],
                "direction": q["direction"],
                "score": q["score"],
                "all_user_solved": self.simulated_all_user_solved(q),
                "total_flag_num": len(self.active_flags[q["id"]]),
                "current_user_solved": len(self.solved_flags.get(q["id"], set())),
                "attachment": self._attachment_entries(q),
                "has_scene": q["has_scene"],
            }
            if q["has_scene"]:
                st = self.scene_status.get(q["id"], 3)
                entry["scene_status"] = st
                if st == 1:
                    entry["scene_addresses"] = list(self.live_addresses.get(q["id"]) or q["scene_addresses"])
            out.append(entry)
        return _envelope(data={"total": len(out), "list": out})

    def op_question_info(self, question_id: str) -> dict[str, Any]:
        q = self.questions.get(question_id)
        if not q or not self.is_visible(q):
            return _envelope("AD-160003", "参数校验错误", "题目不存在")
        return _envelope(
            data={
                "id": q["id"],
                "name": q["name"],
                "direction": q["direction"],
                "score": q["score"],
                "difficulty": q["difficulty"],
                "all_user_solved": self.simulated_all_user_solved(q),
                "total_flag_num": len(self.active_flags[q["id"]]),
                "current_user_solved": len(self.solved_flags.get(q["id"], set())),
                "desc": q["desc"],
                "attachment": self._attachment_entries(q),
            }
        )

    def op_question_start(self, question_id: str) -> dict[str, Any]:
        q = self.questions.get(question_id)
        if not q or not self.is_visible(q):
            return _envelope("AD-160003", "参数校验错误", "题目不存在")
        if not q["has_scene"]:
            return _envelope("AD-161003", f"题目[{q['name']}]没有开启场景, 无法创建实例")
        cur = self.scene_status.get(q["id"], 3)
        if cur in (0, 1):
            return _envelope(data=True)
        if self.running_scene_count() >= self.max_scenes:
            self.audit["scene_limit_hits"] += 1
            self._emit_event(
                "scene_limit",
                f"Scene cap ({self.max_scenes}) rejected start for {q['id']}",
                qid=q["id"],
                source="auditor",
                severity="warn",
            )
            return _envelope(
                "AD-162006",
                f"场景数量[{self.running_scene_count()}]达到上限, 请关闭其他场景后重试",
            )

        self.ever_started[q["id"]] = True
        self.last_stop_reason[q["id"]] = None
        attempts = self.scene_start_attempts.get(q["id"], 0) + 1
        self.scene_start_attempts[q["id"]] = attempts
        att_rec = self._open_attempt(q["id"], trigger="question_start")
        did = self._record_platform_decision(
            trigger="question_start",
            to_qid=q["id"],
            reason=f"启动靶机环境（第 {attempts} 次尝试）",
            outcome="starting",
        )

        should_fault = (q["fail_first_start"] and attempts == 1) or bool(q.get("force_next_fault"))
        q["force_next_fault"] = False

        if should_fault:
            self.scene_status[q["id"]] = 20
            att_rec["status"] = "failed"
            att_rec["scene_faults"] += 1
            att_rec["stop_reason"] = "simulated_start_failure(status=20)"
            self._close_current_attempt(q["id"], status="failed", reason="simulated_start_failure(status=20)")
            self.audit["scene_faults_injected"] += 1
            self._emit_event(
                "scene_fault",
                f"Injected scene start failure (status=20) on {q['id']} (attempt #{attempts})",
                qid=q["id"],
                attempt_id=att_rec["attempt_id"],
                decision_id=did,
                severity="error",
            )
            return _envelope(data=True)

        use_docker = bool(self.docker_enabled and self.scene_mgr and (q.get("docker") or q.get("multi_docker")))
        delay = float(q.get("startup_delay_sec") or 0.0)

        if use_docker or delay > 0.0:
            self.scene_status[q["id"]] = 0
            self.live_addresses[q["id"]] = []
            self._emit_event(
                "scene_creating",
                f"Starting scene {q['id']} (docker={use_docker})",
                qid=q["id"],
                attempt_id=att_rec["attempt_id"],
                decision_id=did,
                source="docker" if use_docker else "platform",
            )
            flags_copy = list(self.active_flags[q["id"]])
            q_copy = dict(q)
            att_id = att_rec["attempt_id"]

            def _bg_start() -> None:
                try:
                    if delay > 0.0:
                        time.sleep(delay)
                    addrs = (
                        self.scene_mgr.start_scene(q["id"], q_copy, flags_copy)
                        if use_docker and self.scene_mgr
                        else list(q_copy["scene_addresses"])
                    )
                    need_stop = False
                    with self.lock:
                        if self.scene_status.get(q["id"]) == 0:
                            self.live_addresses[q["id"]] = addrs
                            self.scene_status[q["id"]] = 1
                            self.scene_started_at[q["id"]] = time.time()
                            att_rec["status"] = "running"
                            if attempts > 1 and q["fail_first_start"]:
                                self.audit["scene_faults_recovered"] += 1
                            self._emit_event(
                                "scene_running",
                                f"Scene {q['id']} RUNNING ({len(addrs)} endpoint(s))",
                                qid=q["id"],
                                attempt_id=att_id,
                                source="docker" if use_docker else "platform",
                                severity="ok",
                            )
                        elif use_docker and self.scene_mgr:
                            need_stop = True
                    if need_stop and self.scene_mgr:
                        self.scene_mgr.stop_scene(q["id"])
                except Exception as exc:
                    with self.lock:
                        self.scene_status[q["id"]] = 20
                        att_rec["scene_faults"] += 1
                        self._close_current_attempt(q["id"], status="failed", reason=f"start_error: {exc}")
                        self._emit_event(
                            "scene_error",
                            f"Scene {q['id']} start failed: {exc}",
                            qid=q["id"],
                            attempt_id=att_id,
                            source="docker" if use_docker else "platform",
                            severity="error",
                        )

            threading.Thread(target=_bg_start, daemon=True).start()
            return _envelope(data=True)

        self.scene_status[q["id"]] = 1
        self.live_addresses[q["id"]] = list(q["scene_addresses"])
        self.scene_started_at[q["id"]] = time.time()
        att_rec["status"] = "running"
        if attempts > 1 and q["fail_first_start"]:
            self.audit["scene_faults_recovered"] += 1
        self._emit_event(
            "scene_running",
            f"Scene {q['id']} RUNNING",
            qid=q["id"],
            attempt_id=att_rec["attempt_id"],
            decision_id=did,
            severity="ok",
        )
        return _envelope(data=True)

    def op_question_instance_info(self, question_id: str) -> dict[str, Any]:
        q = self.questions.get(question_id)
        if not q or not self.is_visible(q):
            return _envelope("AD-160003", "参数校验错误", "题目不存在")
        data: dict[str, Any] = {
            "resource_id": q["id"],
            "name": q["name"],
            "direction": q["direction"],
            "score": q["score"],
            "attachment": self._attachment_entries(q),
        }
        if q["has_scene"]:
            st = self.scene_status.get(q["id"], 3)
            data["scene_status"] = st
            data["scene_addresses"] = list(self.live_addresses.get(q["id"]) or q["scene_addresses"]) if st == 1 else []
        return _envelope(data=data)

    def op_question_stop(self, question_id: str, *, reason: str | None = None) -> dict[str, Any]:
        # Per API_接入.md §5: never rejects non-existent or stopped questions
        if question_id in self.scene_status:
            prev = self.scene_status[question_id]
            q = self.questions[question_id]
            f_total = len(self.active_flags.get(question_id) or [])
            f_solved = len(self.solved_flags.get(question_id, set()))
            inferred_reason = reason or (
                "已全解释放" if (f_total > 0 and f_solved >= f_total)
                else ("故障恢复停机" if prev == 20 else "调用 question_stop 停止")
            )
            use_docker = bool(self.docker_enabled and self.scene_mgr and (q.get("docker") or q.get("multi_docker")))
            cur_att = self._current_attempt(question_id)
            att_id = cur_att["attempt_id"] if cur_att else None
            did = self._record_platform_decision(
                trigger="question_stop",
                from_qid=question_id,
                to_qid=None,
                reason=inferred_reason,
                outcome="stopped",
            )
            if use_docker and prev in (0, 1, 20):
                self.scene_status[question_id] = 2
                self.live_addresses[question_id] = []
                self._emit_event(
                    "scene_stopping",
                    f"Stopping Docker scene {question_id} ({inferred_reason})",
                    qid=question_id,
                    attempt_id=att_id,
                    decision_id=did,
                    source="docker",
                )

                def _bg_stop() -> None:
                    try:
                        if self.scene_mgr:
                            self.scene_mgr.stop_scene(question_id)
                    finally:
                        with self.lock:
                            self.scene_status[question_id] = 3
                            self.live_addresses[question_id] = []
                            self.last_stop_reason[question_id] = inferred_reason
                            self.last_stopped_at[question_id] = time.time()
                            final_st = "completed" if (f_total > 0 and f_solved >= f_total) else "stopped"
                            self._close_current_attempt(question_id, status=final_st, reason=inferred_reason)
                            self._emit_event(
                                "scene_stopped",
                                f"Scene {question_id} stopped ({inferred_reason})",
                                qid=question_id,
                                attempt_id=att_id,
                                decision_id=did,
                                source="docker",
                            )

                threading.Thread(target=_bg_stop, daemon=True).start()
            else:
                self.scene_status[question_id] = 3
                self.live_addresses[question_id] = []
                if prev != 3:
                    self.last_stop_reason[question_id] = inferred_reason
                    self.last_stopped_at[question_id] = time.time()
                    final_st = "completed" if (f_total > 0 and f_solved >= f_total) else "stopped"
                    self._close_current_attempt(question_id, status=final_st, reason=inferred_reason)
                    self._emit_event(
                        "scene_stopped",
                        f"Scene {question_id} stopped ({inferred_reason})",
                        qid=question_id,
                        attempt_id=att_id,
                        decision_id=did,
                    )
        return _envelope(data=True)

    def op_submit_flag(self, question_id: str, flag: str) -> dict[str, Any]:
        self._audit_text_for_leaks(flag, f"submit_flag:{question_id}")
        q = self.questions.get(question_id)
        if not q or not self.is_visible(q):
            return _envelope("AD-160003", "参数校验错误", "题目不存在")
        if self.enforce_scene_running_on_submit and q["has_scene"] and self.scene_status.get(q["id"], 3) != 1:
            return _envelope("AD-160003", "场景未运行，请先启动场景后再提交 Flag", "scene not running")
        cleaned = flag.strip()
        valid_flags = self.active_flags[q["id"]]
        solved_set = self.solved_flags.setdefault(q["id"], set())
        cur_att = self._current_attempt(q["id"])
        att_id = cur_att["attempt_id"] if cur_att else None
        sub_id = f"sub_{secrets.token_hex(4)}"

        if cleaned not in valid_flags:
            ev = self._emit_event(
                "flag_wrong",
                f"Wrong flag on {q['id']} ({q['name']})",
                qid=q["id"],
                attempt_id=att_id,
                submission_id=sub_id,
                severity="error",
            )
            rec = cockpit_models.normalize_submission_record(
                {
                    "submission_id": sub_id,
                    "attempt_id": att_id,
                    "event_id": ev["event_id"],
                    "ts": round(time.time(), 3),
                    "elapsed_sec": round(self.elapsed_sec(), 1),
                    "qid": q["id"],
                    "name": q["name"],
                    "pass": False,
                    "duplicate": False,
                    "score": 0.0,
                },
                simulate_competitors=self.simulate_competitors,
            )
            self.submissions.append(rec)
            if cur_att:
                cur_att["submissions"].append(sub_id)
            return _envelope(data={"is_pass": False, "score": 0, "is_duplicate": False})

        if cleaned in solved_set:
            flag_idx = valid_flags.index(cleaned) + 1
            ev = self._emit_event(
                "flag_duplicate",
                f"Duplicate flag #{flag_idx} on {q['id']} ({q['name']})",
                qid=q["id"],
                attempt_id=att_id,
                submission_id=sub_id,
                severity="warn",
            )
            rec = cockpit_models.normalize_submission_record(
                {
                    "submission_id": sub_id,
                    "attempt_id": att_id,
                    "event_id": ev["event_id"],
                    "ts": round(time.time(), 3),
                    "elapsed_sec": round(self.elapsed_sec(), 1),
                    "qid": q["id"],
                    "name": q["name"],
                    "flag_index": flag_idx,
                    "flag": cleaned,
                    "pass": True,
                    "duplicate": True,
                    "score": 0.0,
                },
                simulate_competitors=self.simulate_competitors,
            )
            self.submissions.append(rec)
            return _envelope("AD-160014", "答案重复写入", "duplicate flag")

        solved_set.add(cleaned)
        rank = max(1, self.simulated_all_user_solved(q)) if self.simulate_competitors else None
        mult = _rank_multiplier(rank) if (self.simulate_competitors and rank is not None) else None
        per_flag_base = round(q["score"] / max(1, len(valid_flags)), 2)
        per_flag_ranked = round(per_flag_base * mult, 2) if mult is not None else per_flag_base
        self.total_score = round(self.total_score + per_flag_base, 2)
        self.ranked_score = round(self.ranked_score + per_flag_ranked, 2)
        flag_idx = valid_flags.index(cleaned) + 1
        rank_msg = f" / 排名分 +{per_flag_ranked} (#{rank})" if rank is not None else ""
        ev = self._emit_event(
            "flag_pass",
            f"SOLVED Flag #{flag_idx} ({len(solved_set)}/{len(valid_flags)}) on {q['id']} (+{per_flag_base}{rank_msg})",
            qid=q["id"],
            attempt_id=att_id,
            submission_id=sub_id,
            severity="ok",
        )
        rec = cockpit_models.normalize_submission_record(
            {
                "submission_id": sub_id,
                "attempt_id": att_id,
                "event_id": ev["event_id"],
                "ts": round(time.time(), 3),
                "elapsed_sec": round(self.elapsed_sec(), 1),
                "qid": q["id"],
                "name": q["name"],
                "flag_index": flag_idx,
                "flag": cleaned,
                "pass": True,
                "duplicate": False,
                "score": per_flag_base,
                "ranked_score": per_flag_ranked if rank is not None else None,
                "simulated_rank": rank,
                "multiplier": mult,
            },
            simulate_competitors=self.simulate_competitors,
        )
        self.submissions.append(rec)
        self.solved_flag_details.setdefault(q["id"], []).append(rec)
        if cur_att:
            cur_att["submissions"].append(sub_id)
        if len(solved_set) >= len(valid_flags):
            self.question_solved_at[q["id"]] = time.time()
        self.persist()
        return _envelope(data={"is_pass": True, "score": per_flag_base, "is_duplicate": False})

    def update_milestone(self, question_id: str, *, key: str, status: str, detail: str = "", score: float | None = None) -> dict[str, Any]:
        """Update PoC / Attachment verification milestone (D04)."""
        with self.lock:
            q = self.questions.get(question_id)
            if not q:
                raise HTTPException(404, "question not found")
            ms_list = self.milestones.setdefault(question_id, [])
            now_iso = cockpit_models.iso_utc(time.time())
            matched = None
            for m in ms_list:
                if m["key"] == key:
                    m["status"] = status
                    m["updated_at"] = now_iso
                    m["detail"] = detail
                    matched = m
                    break
            if matched is None:
                matched = {"key": key, "label": key, "status": status, "updated_at": now_iso, "detail": detail}
                ms_list.append(matched)
            if score is not None and score > 0 and status == "done":
                self.total_score = round(self.total_score + float(score), 2)
                self.ranked_score = round(self.ranked_score + float(score), 2)
            self._emit_event(
                "milestone_done" if status == "done" else "milestone_update",
                f"[{question_id}] 验收里程碑 {matched['label']} -> {status}" + (f" ({detail})" if detail else ""),
                qid=question_id,
                severity="ok" if status == "done" else ("error" if status == "failed" else "info"),
            )
            self.persist()
            return {"ok": True, "question_id": question_id, "milestones": ms_list}

    # --- Observer Aggregation (Read-only, Local Cockpit Only) ---

    def _fetch_observer_sources(self) -> dict[str, Any]:
        now_mono = time.monotonic()
        if self._obs_cache and (now_mono - self._obs_cache_ts < 1.8):
            return self._obs_cache
        with self._obs_lock:
            now_mono = time.monotonic()
            if self._obs_cache and (now_mono - self._obs_cache_ts < 1.8):
                return self._obs_cache
            return self._fetch_observer_sources_unlocked(now_mono)

    def _fetch_observer_sources_unlocked(self, now_mono: float) -> dict[str, Any]:
        now_ts = time.time()
        self._last_ok["platform"] = now_ts

        # 1. Cairn Server link
        cairn_data: dict[str, Any] = {"available": False, "projects": {}, "by_qid": {}}
        if not self.cairn_url:
            cairn_conn = {
                "status": "unconfigured",
                "observed_at": cockpit_models.iso_utc(now_ts),
                "last_ok_at": cockpit_models.iso_utc(self._last_ok["cairn"]),
                "age_sec": None,
                "error_reason": "启动参数未配置 --cairn-url",
                "recovery_hint": "启动 Mock 平台时附加 --cairn-url http://127.0.0.1:8000",
            }
        else:
            headers = {"Authorization": f"Bearer {self.cairn_admin_token}"} if self.cairn_admin_token else {}
            try:
                r = requests.get(f"{self.cairn_url}/projects", headers=headers, timeout=2.0)
                if r.status_code == 200:
                    self._last_ok["cairn"] = now_ts
                    plist = r.json()
                    cairn_data["available"] = True
                    for p in plist:
                        pid = p["id"]
                        title = str(p.get("title") or "")
                        matched_qid = None
                        for cand_qid in sorted(self.questions, key=len, reverse=True):
                            if (
                                title.startswith(f"race-{cand_qid}-")
                                or title == f"race-{cand_qid}"
                                or cand_qid in title
                            ):
                                matched_qid = cand_qid
                                break
                        if matched_qid is None and title.startswith("race-"):
                            parts = title.split("-", 2)
                            if len(parts) >= 2:
                                matched_qid = parts[1]
                        entry = {
                            "id": pid,
                            "title": title,
                            "status": p.get("status"),
                            "created_at": p.get("created_at"),
                            "fact_count": p.get("fact_count", 0),
                            "intent_count": p.get("intent_count", 0),
                            "working_intent_count": p.get("working_intent_count", 0),
                            "unclaimed_intent_count": p.get("unclaimed_intent_count", 0),
                            "reason": p.get("reason"),
                            "recent_facts": [],
                            "active_intents": [],
                            "hints_count": p.get("hint_count", 0),
                        }
                        if p.get("status") == "active" or matched_qid:
                            proj_sig = (
                                p.get("status"),
                                int(p.get("fact_count") or 0),
                                int(p.get("intent_count") or 0),
                                int(p.get("working_intent_count") or 0),
                            )
                            cached_detail = self._cairn_proj_detail_cache.get(pid)
                            if cached_detail and cached_detail[0] == proj_sig:
                                entry["recent_facts"] = cached_detail[1]
                                entry["active_intents"] = cached_detail[2]
                            else:
                                try:
                                    dr = requests.get(f"{self.cairn_url}/projects/{pid}", headers=headers, timeout=1.5)
                                    if dr.status_code == 200:
                                        detail = dr.json()
                                        facts = [f for f in detail.get("facts") or [] if f.get("id") not in ("origin", "goal")]
                                        rf = [
                                            {"id": f.get("id"), "description": str(f.get("description") or "")[:600]}
                                            for f in facts[-8:]
                                        ]
                                        intents = detail.get("intents") or []
                                        ai = [
                                            {
                                                "id": i.get("id"),
                                                "worker": i.get("worker"),
                                                "description": str(i.get("description") or "")[:320],
                                                "created_at": i.get("created_at"),
                                                "last_heartbeat_at": i.get("last_heartbeat_at"),
                                                "concluded_at": i.get("concluded_at"),
                                            }
                                            for i in intents[-8:]
                                        ]
                                        entry["recent_facts"] = rf
                                        entry["active_intents"] = ai
                                        self._cairn_proj_detail_cache[pid] = (proj_sig, rf, ai)
                                        for f in facts[-4:]:
                                            self._audit_text_for_leaks(str(f.get("description") or ""), f"cairn_fact:{pid}:{f.get('id')}")
                                except Exception:
                                    pass
                        cairn_data["projects"][pid] = entry
                        if matched_qid:
                            cairn_data["by_qid"][matched_qid] = entry
                    cairn_conn = {
                        "status": "connected",
                        "observed_at": cockpit_models.iso_utc(now_ts),
                        "last_ok_at": cockpit_models.iso_utc(now_ts),
                        "age_sec": 0.0,
                        "error_reason": None,
                        "recovery_hint": None,
                    }
                else:
                    age = round(now_ts - self._last_ok["cairn"], 1) if self._last_ok["cairn"] else None
                    cairn_conn = {
                        "status": "disconnected",
                        "observed_at": cockpit_models.iso_utc(now_ts),
                        "last_ok_at": cockpit_models.iso_utc(self._last_ok["cairn"]),
                        "age_sec": age,
                        "error_reason": f"HTTP {r.status_code}" + ("（请检查 CAIRN_ADMIN_TOKEN）" if r.status_code == 401 else ""),
                        "recovery_hint": "检查 cairn-server 服务状态及 --cairn-admin-token 是否匹配",
                    }
            except Exception as exc:
                age = round(now_ts - self._last_ok["cairn"], 1) if self._last_ok["cairn"] else None
                cairn_conn = {
                    "status": "disconnected",
                    "observed_at": cockpit_models.iso_utc(now_ts),
                    "last_ok_at": cockpit_models.iso_utc(self._last_ok["cairn"]),
                    "age_sec": age,
                    "error_reason": f"无法连接 {self.cairn_url}: {type(exc).__name__}",
                    "recovery_hint": "确认 cairn-ubuntu-server 容器已启动且监听正确端口",
                }

        # 2. Token Proxy link
        proxy_data: dict[str, Any] = {"available": False}
        if not self.proxy_url:
            proxy_conn = {
                "status": "unconfigured",
                "observed_at": cockpit_models.iso_utc(now_ts),
                "last_ok_at": cockpit_models.iso_utc(self._last_ok["proxy"]),
                "age_sec": None,
                "error_reason": "启动参数未配置 --proxy-url",
                "recovery_hint": "启动 Mock 平台时附加 --proxy-url http://127.0.0.1:8100 以采集真实模型版本与 Token",
            }
        else:
            try:
                sr = requests.get(f"{self.proxy_url}/stats", timeout=1.5)
                hr = requests.get(f"{self.proxy_url}/health", timeout=1.5)
                if sr.status_code == 200:
                    self._last_ok["proxy"] = now_ts
                    proxy_data = {"available": True, **sr.json()}
                    if hr.status_code == 200:
                        proxy_data["health"] = hr.json()
                    proxy_conn = {
                        "status": "connected",
                        "observed_at": cockpit_models.iso_utc(now_ts),
                        "last_ok_at": cockpit_models.iso_utc(now_ts),
                        "age_sec": 0.0,
                        "error_reason": None,
                        "recovery_hint": None,
                    }
                else:
                    age = round(now_ts - self._last_ok["proxy"], 1) if self._last_ok["proxy"] else None
                    proxy_conn = {
                        "status": "disconnected",
                        "observed_at": cockpit_models.iso_utc(now_ts),
                        "last_ok_at": cockpit_models.iso_utc(self._last_ok["proxy"]),
                        "age_sec": age,
                        "error_reason": f"Token Proxy 返回 HTTP {sr.status_code}",
                        "recovery_hint": "检查 cairn-ubuntu-proxy 容器日志",
                    }
            except Exception as exc:
                age = round(now_ts - self._last_ok["proxy"], 1) if self._last_ok["proxy"] else None
                proxy_conn = {
                    "status": "disconnected",
                    "observed_at": cockpit_models.iso_utc(now_ts),
                    "last_ok_at": cockpit_models.iso_utc(self._last_ok["proxy"]),
                    "age_sec": age,
                    "error_reason": f"无法连接 {self.proxy_url}: {type(exc).__name__}",
                    "recovery_hint": "确认 token_proxy 已运行并开放 --proxy-url",
                }

        # 3. Orchestrator state file link
        orch_data: dict[str, Any] = {"available": False}
        if not self.orch_state_file:
            orch_conn = {
                "status": "unconfigured",
                "observed_at": cockpit_models.iso_utc(now_ts),
                "last_ok_at": cockpit_models.iso_utc(self._last_ok["orchestrator"]),
                "age_sec": None,
                "error_reason": "未配置 --orch-state 状态文件路径",
                "recovery_hint": "启动时传入 --orch-state runtime/race-orchestrator-state.json",
            }
        elif not self.orch_state_file.is_file():
            orch_conn = {
                "status": "disconnected",
                "observed_at": cockpit_models.iso_utc(now_ts),
                "last_ok_at": cockpit_models.iso_utc(self._last_ok["orchestrator"]),
                "age_sec": None,
                "error_reason": f"状态文件尚未生成 ({self.orch_state_file.name})",
                "recovery_hint": "确认 cairn race 总控进程已启动并完成首次轮询",
            }
        else:
            try:
                raw_o = json.loads(self.orch_state_file.read_text(encoding="utf-8"))
                orch_data = {"available": True, **raw_o}
                mtime = self.orch_state_file.stat().st_mtime
                hb_ts = cockpit_models.safe_float(raw_o.get("heartbeat_ts")) or mtime
                age = round(max(0.0, now_ts - hb_ts), 1)
                self._last_ok["orchestrator"] = hb_ts
                is_stale = age > 90.0
                orch_conn = {
                    "status": "degraded" if is_stale else "connected",
                    "observed_at": cockpit_models.iso_utc(now_ts),
                    "last_ok_at": cockpit_models.iso_utc(hb_ts),
                    "age_sec": age,
                    "error_reason": f"总控状态文件已 {age}s 未更新（可能已暂停或退出）" if is_stale else None,
                    "recovery_hint": "检查 cairn race 总控日志确认心跳" if is_stale else None,
                }
            except Exception as exc:
                orch_conn = {
                    "status": "disconnected",
                    "observed_at": cockpit_models.iso_utc(now_ts),
                    "last_ok_at": cockpit_models.iso_utc(self._last_ok["orchestrator"]),
                    "age_sec": None,
                    "error_reason": f"读取总控状态失败: {exc}",
                    "recovery_hint": "检查状态文件权限与 JSON 完整性",
                }

        # 4. Docker container resource telemetry (skip subprocess when 0 scenes running; 10s interval when active)
        has_running_scene = any(st in (0, 1) for st in self.scene_status.values())
        if self.docker_enabled:
            if has_running_scene and (now_mono - self._docker_stats_ts >= 10.0 or not self._docker_stats_cache.get("available")):
                self._docker_stats_cache = cockpit_models.sample_docker_container_stats()
                self._docker_stats_ts = now_mono
                if self._docker_stats_cache.get("available"):
                    self._last_ok["docker"] = now_ts
            elif not has_running_scene and self._docker_stats_ts == 0.0:
                # One lightweight probe on startup; avoid spawning docker CLI every 5s when idle
                self._docker_stats_cache = cockpit_models.sample_docker_container_stats()
                self._docker_stats_ts = now_mono
                if self._docker_stats_cache.get("available"):
                    self._last_ok["docker"] = now_ts
            elif not has_running_scene and self._docker_stats_cache.get("available"):
                self._docker_stats_cache = {
                    "available": True,
                    "observed_at": cockpit_models.iso_utc(now_ts),
                    "reason": None,
                    "containers": {},
                }
                self._last_ok["docker"] = now_ts

        if not self.docker_enabled:
            docker_conn = {
                "status": "unconfigured",
                "observed_at": cockpit_models.iso_utc(now_ts),
                "last_ok_at": None,
                "age_sec": None,
                "error_reason": "当前为非 Docker 仿真模式（未传 --docker-scenes）",
                "recovery_hint": "附加 --docker-scenes 以启用真实容器启停与资源采样",
            }
        elif self._docker_stats_cache.get("available"):
            docker_conn = {
                "status": "connected",
                "observed_at": self._docker_stats_cache.get("observed_at"),
                "last_ok_at": cockpit_models.iso_utc(self._last_ok["docker"]),
                "age_sec": round(max(0.0, now_ts - (self._last_ok["docker"] or now_ts)), 1),
                "error_reason": None,
                "recovery_hint": None,
            }
        else:
            docker_conn = {
                "status": "degraded",
                "observed_at": self._docker_stats_cache.get("observed_at") or cockpit_models.iso_utc(now_ts),
                "last_ok_at": cockpit_models.iso_utc(self._last_ok["docker"]),
                "age_sec": None,
                "error_reason": self._docker_stats_cache.get("reason"),
                "recovery_hint": "确认容器内挂载了 /var/run/docker.sock 与 docker CLI",
            }

        connections = {
            "platform": {
                "status": "connected",
                "observed_at": cockpit_models.iso_utc(now_ts),
                "last_ok_at": cockpit_models.iso_utc(now_ts),
                "age_sec": 0.0,
                "error_reason": None,
                "recovery_hint": None,
            },
            "docker": docker_conn,
            "orchestrator": orch_conn,
            "cairn": cairn_conn,
            "proxy": proxy_conn,
        }

        self._obs_cache = {
            "cairn": cairn_data,
            "proxy": proxy_data,
            "orchestrator": orch_data,
            "docker_stats": self._docker_stats_cache,
            "connections": connections,
        }
        self._obs_cache_ts = now_mono
        return self._obs_cache

    def _extract_model_summary(self, proxy_data: dict[str, Any]) -> dict[str, Any]:
        if not proxy_data or not proxy_data.get("available"):
            return {
                "available": False,
                "provider_endpoint": None,
                "requested_model": None,
                "response_model": None,
                "version_disclosed": False,
                "thinking_effort": None,
                "routes": [],
            }
        by_route = proxy_data.get("by_route") or {}
        route_cfgs = proxy_data.get("route_configs") or {}
        routes_out = []
        latest_route = None
        latest_ts = -1.0
        for rname, cfg in route_cfgs.items():
            st = by_route.get(rname) or {}
            req_m = st.get("requested_model") or cfg.get("model_override")
            resp_m = st.get("response_model")
            disclosed = bool(resp_m and resp_m != req_m)
            entry = {
                "route": rname,
                "endpoint_redacted": cfg.get("endpoint_redacted"),
                "requested_model": req_m,
                "response_model": resp_m,
                "version_label": resp_m if disclosed else (f"{resp_m}（可变别名/精确版本未披露）" if resp_m else "版本未披露"),
                "thinking_effort": st.get("thinking_effort") or "未上报/不支持",
                "calls": int(st.get("calls") or 0),
                "failovers": int(st.get("failovers") or 0),
                "input": int(st.get("input") or 0),
                "output": int(st.get("output") or 0),
                "cache_read": int(st.get("cache_read") or 0),
                "p50_sec": st.get("p50_sec"),
                "p95_sec": st.get("p95_sec"),
                "last_dur_sec": st.get("last_dur_sec"),
                "last_call_at": cockpit_models.iso_utc(st.get("last_call_at")),
                "fallbacks": cfg.get("fallbacks") or [],
            }
            routes_out.append(entry)
            lca = cockpit_models.safe_float(st.get("last_call_at")) or 0.0
            if entry["calls"] > 0 and lca >= latest_ts:
                latest_ts = lca
                latest_route = entry
        if latest_route is None and routes_out:
            latest_route = routes_out[0]
        return {
            "available": True,
            "active": latest_route,
            "routes": routes_out,
            "by_qid": proxy_data.get("by_qid") or {},
            "total": proxy_data.get("total") or {},
            "cooling_down": proxy_data.get("cooling_down") or {},
            "last_failover": proxy_data.get("last_failover"),
            "observed_at": cockpit_models.iso_utc(proxy_data.get("observed_at")),
        }

    def dashboard_snapshot(self, *, use_cache: bool = False) -> dict[str, Any]:
        now_mono = time.monotonic()
        if use_cache and self._snap_cache is not None:
            ts_c, ver_c, snap_c = self._snap_cache
            if ver_c == self._state_version and (now_mono - ts_c < 1.5):
                return snap_c
        obs = self._fetch_observer_sources()
        with self.lock:
            now_ts = time.time()
            self.audit["dashboard_polls"] = int(self.audit.get("dashboard_polls") or 0) + 1
            elapsed = self.elapsed_sec()
            remaining = max(0.0, self.duration_sec - elapsed)
            orch_raw = obs.get("orchestrator") or {}
            orch_qs = orch_raw.get("questions") or {}
            cairn_by_qid = (obs.get("cairn") or {}).get("by_qid") or {}
            docker_containers = (obs.get("docker_stats") or {}).get("containers") or {}
            model_summary = self._extract_model_summary(obs.get("proxy") or {})

            questions_view: list[dict[str, Any]] = []
            total_flags = 0
            solved_flags_total = 0
            flag_questions_count = 0
            non_flag_questions_count = 0
            fully_solved_questions = 0
            visible_questions = 0
            unstopped_solved: list[str] = []

            for qid, q in self.questions.items():
                vis = self.is_visible(q)
                if vis:
                    visible_questions += 1

                active_f = self.active_flags[qid]
                solved_f = self.solved_flags.get(qid, set())
                verdict = cockpit_models.build_verdict_summary(
                    q,
                    active_flags=active_f,
                    solved_flags=solved_f,
                    milestones=self.milestones.get(qid),
                )
                is_complete = bool(verdict["complete"])
                if verdict["type"] == "flag" and (verdict.get("total") or 0) > 0:
                    flag_questions_count += 1
                    total_flags += int(verdict["total"])
                    solved_flags_total += int(verdict["solved"])
                else:
                    non_flag_questions_count += 1
                if is_complete:
                    fully_solved_questions += 1

                raw_st = self.scene_status.get(qid, 3) if q["has_scene"] else None
                if is_complete and q["has_scene"] and raw_st in (0, 1):
                    solved_ts = self.question_solved_at.get(qid, now_ts)
                    if now_ts - solved_ts > 30.0:
                        unstopped_solved.append(qid)

                oq = orch_qs.get(qid) or {}
                cq = cairn_by_qid.get(qid)
                cur_att = self._current_attempt(qid)
                four = cockpit_models.compute_four_states(
                    q=q,
                    visible=vis,
                    raw_scene_status=raw_st,
                    ever_started=bool(self.ever_started.get(qid, False)),
                    last_stop_reason=self.last_stop_reason.get(qid) or oq.get("last_stop_reason"),
                    last_stopped_at=self.last_stopped_at.get(qid),
                    orch_q=oq,
                    cairn_q=cq,
                    verdict=verdict,
                    active_attempt=cur_att,
                )

                raw_addrs = list(self.live_addresses.get(qid) or []) if raw_st == 1 else []
                hygienic_addrs = cockpit_models.format_scene_addresses(raw_addrs, public_host=self.public_host)

                # Per-challenge timers (never confuse global race clock with per-challenge timer!)
                cur_attempt_sec = None
                if cur_att and cur_att.get("started_at") is not None and cur_att.get("ended_at") is None:
                    cur_attempt_sec = round(max(0.0, now_ts - float(cur_att["started_at"])), 1)
                elif oq.get("started_wall_at") and oq.get("status") == "running":
                    cur_attempt_sec = round(max(0.0, now_ts - float(oq["started_wall_at"])), 1)
                cumulative_sec = max(
                    self._cumulative_attempt_sec(qid),
                    cockpit_models.safe_float(oq.get("cumulative_active_sec")) or 0.0,
                )
                budget_sec = cockpit_models.safe_int(oq.get("budget_sec"))
                budget_rem = (
                    round(max(0.0, budget_sec - cur_attempt_sec), 1)
                    if (budget_sec is not None and cur_attempt_sec is not None)
                    else None
                )
                last_prog_ts = cockpit_models.safe_float(oq.get("last_progress_wall_at"))
                if self.solved_flag_details.get(qid):
                    last_sub_ts = cockpit_models.safe_float(self.solved_flag_details[qid][-1].get("ts"))
                    if last_sub_ts and (last_prog_ts is None or last_sub_ts > last_prog_ts):
                        last_prog_ts = last_sub_ts
                no_progress_sec = (
                    round(max(0.0, now_ts - last_prog_ts), 1)
                    if (last_prog_ts is not None and four["schedule"]["code"] in ("running", "external_active"))
                    else None
                )

                # Attach live Docker container stats for this scene if available
                scene_cnames = self.scene_mgr.active_containers_for(qid) if self.scene_mgr else []
                res_containers = [docker_containers[cn] for cn in scene_cnames if cn in docker_containers]

                # Per-challenge LLM telemetry (attributed by proxy) & stall/spin-loop radar
                q_llm_raw = (model_summary.get("by_qid") or {}).get(qid)
                q_llm = dict(q_llm_raw) if isinstance(q_llm_raw, dict) else None
                is_skipped = qid in self.skipped_questions
                stall_sig = cockpit_models.compute_stall_signal(
                    states=four,
                    no_progress_sec=no_progress_sec,
                    llm_usage=q_llm,
                    cairn_q=cq,
                    skipped=is_skipped,
                )

                # Normalize solved_details strictly (D01)
                norm_solved = [
                    cockpit_models.normalize_submission_record(r, simulate_competitors=self.simulate_competitors)
                    for r in (self.solved_flag_details.get(qid) or [])
                ]
                # Expose ONLY already-obtained (solved) flags to the local human cockpit — NEVER unsolved truth!
                obtained_flags: list[dict[str, Any]] = []
                seen_flag_vals: set[str] = set()
                for sd in norm_solved:
                    fv = sd.get("flag")
                    if fv and fv not in seen_flag_vals:
                        seen_flag_vals.add(fv)
                        obtained_flags.append(
                            {
                                "flag_index": sd.get("flag_index"),
                                "flag_label": sd.get("flag_label"),
                                "flag": fv,
                                "obtained_at_iso": sd.get("submitted_at_iso"),
                                "elapsed_sec": sd.get("elapsed_sec"),
                                "score": sd.get("score"),
                                "ranked_score": sd.get("ranked_score"),
                                "simulated_rank": sd.get("simulated_rank"),
                            }
                        )
                for idx_f, af in enumerate(active_f, start=1):
                    if af in solved_f and af not in seen_flag_vals:
                        seen_flag_vals.add(af)
                        obtained_flags.append(
                            {
                                "flag_index": idx_f,
                                "flag_label": f"Flag #{idx_f}",
                                "flag": af,
                                "obtained_at_iso": None,
                                "elapsed_sec": None,
                                "score": None,
                                "ranked_score": None,
                                "simulated_rank": None,
                            }
                        )
                timers_obj = {
                    "current_attempt_sec": cur_attempt_sec,
                    "cumulative_active_sec": round(cumulative_sec, 1),
                    "budget_sec": budget_sec,
                    "budget_remaining_sec": budget_rem,
                    "no_progress_sec": no_progress_sec,
                    "pause_excluded": True,
                }
                q_budgets = cockpit_models.build_question_budgets(
                    q=q,
                    timers=timers_obj,
                    states=four,
                    llm_usage=q_llm,
                    orch_raw=orch_raw,
                    orch_q=oq,
                    attempts_count=len(self.attempts_history.get(qid) or []),
                    defaults=self.budget_defaults,
                )

                questions_view.append(
                    {
                        "id": qid,
                        "name": q["name"],
                        "category": q["category"],
                        "canonical_category": q["canonical_category"],
                        "is_canonical_category": q["is_canonical_category"],
                        "direction": q["direction"],
                        "difficulty": q["difficulty"],
                        "score": q["score"],
                        "wave": q["wave"],
                        "visible": vis,
                        "release_after_sec": q["release_after_sec"],
                        "has_scene": q["has_scene"],
                        "scene_status": raw_st,
                        "scene_addresses": raw_addrs,
                        "addresses": hygienic_addrs,
                        "current_user_solved": len(solved_f),
                        "total_flag_num": len(active_f),
                        "complete": is_complete,
                        "skipped": is_skipped,
                        "skip_info": self.skipped_questions.get(qid),
                        "all_user_solved": self.simulated_all_user_solved(q),
                        # Backward-compat fields + new 4-dimension states
                        "orch_status": four["schedule"]["code"],
                        "states": four,
                        "stall": stall_sig,
                        "llm_usage": q_llm,
                        "budgets": q_budgets,
                        "timers": timers_obj,
                        "attempts": list(self.attempts_history.get(qid) or []),
                        "active_attempt_id": cur_att["attempt_id"] if cur_att else None,
                        "reopen_count": four["schedule"]["reopen_count"],
                        "attempts_runs": four["schedule"]["attempts_runs"],
                        "project_id": oq.get("project_id") or (cq["id"] if cq else None),
                        "cairn": cq,
                        "resources": {
                            "available": bool(res_containers),
                            "containers": res_containers,
                            "note": None if res_containers else (obs.get("docker_stats") or {}).get("reason") or "未采集/无运行容器",
                        },
                        "solved_details": norm_solved,
                        "obtained_flags": obtained_flags,
                    }
                )

            taxonomy = cockpit_models.build_taxonomy_summary(questions_view)

            # Build Current Execution Focus & Idle Diagnosis (D07)
            active_focus = [
                {
                    "challenge_id": q["id"],
                    "name": q["name"],
                    "category": q["canonical_category"],
                    "attempt_id": q["active_attempt_id"],
                    "states": q["states"],
                    "stall": q["stall"],
                    "llm_usage": q["llm_usage"],
                    "timers": q["timers"],
                    "addresses": q["addresses"],
                    "project_id": q["project_id"],
                    "last_fact": (q["cairn"]["recent_facts"][-1] if (q["cairn"] and q["cairn"].get("recent_facts")) else None),
                    "active_intent": (
                        next((i for i in reversed(q["cairn"].get("active_intents") or []) if not i.get("concluded_at")), None)
                        if q["cairn"]
                        else None
                    ),
                    "resources": q["resources"],
                }
                for q in questions_view
                if q["states"]["schedule"]["code"] in ("running", "external_active")
                or q["states"]["env"]["code"] in ("starting", "running")
            ]

            hidden_qs = [q for q in self.questions.values() if not self.is_visible(q)]
            next_release_in = (
                round(max(0.0, min(float(q["release_after_sec"]) for q in hidden_qs) - elapsed), 1)
                if hidden_qs
                else None
            )
            last_ev = self.event_store.recent(1)[0] if self.event_store.recent(1) else None
            if active_focus:
                idle_diag = None
            elif fully_solved_questions == len(questions_view) and len(questions_view) > 0:
                idle_diag = {
                    "reason": "全部题目已完成验收",
                    "next_condition": "本场无待处理题目（可导出报告或重置新一轮仿真）",
                    "last_activity": last_ev,
                }
            elif hidden_qs and all(q["complete"] for q in questions_view if q["visible"]):
                idle_diag = {
                    "reason": f"当前已放出题目均已处理，等待下一波放题（约 {next_release_in}s 后）",
                    "next_condition": "等待定时放题，或手动点击「提前释放下一波题目」",
                    "last_activity": last_ev,
                }
            elif obs["connections"]["orchestrator"]["status"] != "connected":
                idle_diag = {
                    "reason": "当前无运行中场景，且总控（cairn race）未连接或未写入状态",
                    "next_condition": "启动 cairn race 总控与 cairn-dispatcher，或通过 API/MCP 手动拉起场景",
                    "last_activity": last_ev,
                }
            else:
                idle_diag = {
                    "reason": "当前所有槽位空闲，等待下一轮调度周期",
                    "next_condition": "调度器将在下一个 tick 按优先级拉起队列首位题目",
                    "last_activity": last_ev,
                }

            # Merge orchestrator + platform schedule decisions chronologically
            merged_decisions = list(self.platform_decisions[-60:])
            for od in (orch_raw.get("decisions") or [])[-60:]:
                merged_decisions.append(
                    {
                        "decision_id": od.get("decision_id"),
                        "ts": od.get("ts"),
                        "at": cockpit_models.iso_utc(cockpit_models.safe_float(od.get("ts"))),
                        "elapsed_sec": None,
                        "source": "orchestrator",
                        "trigger": od.get("trigger"),
                        "from_qid": od.get("from_qid"),
                        "to_qid": od.get("to_qid"),
                        "reason": od.get("reason"),
                        "budget_sec": od.get("budget_sec"),
                        "worker_id": od.get("worker_id"),
                        "outcome": od.get("outcome"),
                    }
                )
            merged_decisions.sort(key=lambda d: float(d.get("ts") or 0.0), reverse=True)

            summary = {
                "total_questions": len(self.questions),
                "visible_questions": visible_questions,
                "unreleased_questions": len(hidden_qs),
                "next_release_in_sec": next_release_in,
                "solved_questions": fully_solved_questions,
                "flag_questions": flag_questions_count,
                "non_flag_questions": non_flag_questions_count,
                "total_flags": total_flags,
                "solved_flags": solved_flags_total,
                "total_score": self.total_score,
                "ranked_score": self.ranked_score if self.simulate_competitors else None,
                "simulate_competitors": self.simulate_competitors,
                "running_scenes": self.running_scene_count(),
                "max_scenes": self.max_scenes,
            }

            sys_diag = cockpit_models.build_system_diagnosis(
                summary=summary,
                connections=obs["connections"],
                questions_view=questions_view,
            )

            audit_copy = dict(self.audit)
            audit_copy["unstopped_solved_scenes"] = unstopped_solved

            result = {
                "run_id": self.run_id,
                "ts": now_ts,
                "observed_at": cockpit_models.iso_utc(now_ts),
                "last_seq": self.event_store.last_seq,
                "clock": {
                    "elapsed_sec": round(elapsed, 1),
                    "remaining_sec": round(remaining, 1),
                    "duration_sec": self.duration_sec,
                    "time_scale": self.time_scale,
                },
                "summary": summary,
                "current_focus": active_focus,
                "idle_diagnosis": idle_diag,
                "system_diagnosis": sys_diag,
                "connections": obs["connections"],
                "taxonomy": taxonomy,
                "categories": taxonomy["active_categories"],  # backward compat with eval/analyze_run.py
                "questions": questions_view,
                "schedule_decisions": merged_decisions[:80],
                "submissions": list(self.submissions[-80:]),
                "events": self.event_store.recent(120),
                "audit": audit_copy,
                "proxy": obs.get("proxy"),
                "model_telemetry": model_summary,
                "orchestrator": {
                    "available": bool(orch_raw.get("available")),
                    "updated_at": orch_raw.get("updated_at"),
                    "effective_max_scenes": orch_raw.get("effective_max_scenes"),
                    "active_scenes": orch_raw.get("active_scenes"),
                    "active_attachments": orch_raw.get("active_attachments"),
                    "max_attachments": orch_raw.get("max_attachments"),
                },
                "cairn_available": bool((obs.get("cairn") or {}).get("available")),
                "human_reference_enabled": self.human_ref_store is not None,
            }
            self._snap_cache = (time.monotonic(), self._state_version, result)
            return result

    def get_challenge_dag(self, qid: str, *, force: bool = False) -> dict[str, Any]:
        """On-demand read-only Fact-Intent DAG fetcher (2s TTL cache, zero impact on Worker/Agent)."""
        now_mono = time.monotonic()
        now_ts = time.time()
        if qid not in self.questions:
            return {
                "available": False,
                "status": "not_found",
                "challenge_id": qid,
                "reason": f"未找到题目 {qid}",
                "nodes": [],
                "edges": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }

        if not force and qid in self._dag_cache:
            cached_ts, cached_payload = self._dag_cache[qid]
            if now_mono - cached_ts < 2.0:
                return cached_payload

        if not self.cairn_url:
            return {
                "available": False,
                "status": "unconfigured",
                "challenge_id": qid,
                "reason": "启动参数未配置 --cairn-url，无法采集解题过程 DAG",
                "recovery_hint": "启动平台时附加 --cairn-url http://127.0.0.1:8000",
                "nodes": [],
                "edges": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }

        # Resolve project_id from existing observability cache (no extra /projects fanout)
        obs = self._fetch_observer_sources()
        orch_q = ((obs.get("orchestrator") or {}).get("questions") or {}).get(qid) or {}
        cairn_q = ((obs.get("cairn") or {}).get("by_qid") or {}).get(qid) or {}
        pid = orch_q.get("project_id") or cairn_q.get("id")

        if not pid:
            cairn_status = ((obs.get("connections") or {}).get("cairn") or {}).get("status")
            if cairn_status == "disconnected":
                err_reason = ((obs.get("connections") or {}).get("cairn") or {}).get("error_reason") or "Cairn 服务不可达"
                return {
                    "available": False,
                    "status": "disconnected",
                    "challenge_id": qid,
                    "reason": f"Cairn 连接已断开：{err_reason}",
                    "recovery_hint": "检查 cairn-server 服务状态及 --cairn-admin-token 配置",
                    "nodes": [],
                    "edges": [],
                    "observed_at": cockpit_models.iso_utc(now_ts),
                }
            return {
                "available": False,
                "status": "no_project",
                "challenge_id": qid,
                "reason": "本题尚未关联 Cairn 探索项目（排队中、纯外部执行或尚未启动探索）",
                "nodes": [],
                "edges": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }

        headers = {"Authorization": f"Bearer {self.cairn_admin_token}"} if self.cairn_admin_token else {}
        try:
            dr = requests.get(f"{self.cairn_url}/projects/{pid}", headers=headers, timeout=1.5)
            if dr.status_code != 200:
                return {
                    "available": False,
                    "status": "error",
                    "challenge_id": qid,
                    "project_id": pid,
                    "reason": f"Cairn 返回 HTTP {dr.status_code}" + ("（请检查 CAIRN_ADMIN_TOKEN）" if dr.status_code == 401 else ""),
                    "nodes": [],
                    "edges": [],
                    "observed_at": cockpit_models.iso_utc(now_ts),
                }
            detail = dr.json()
        except Exception as exc:
            return {
                "available": False,
                "status": "disconnected",
                "challenge_id": qid,
                "project_id": pid,
                "reason": f"拉取 Cairn 图谱失败：{type(exc).__name__}",
                "nodes": [],
                "edges": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }

        proj = detail.get("project") or {}
        raw_facts = list(detail.get("facts") or [])
        raw_intents = list(detail.get("intents") or [])

        # Cap huge graphs cleanly so browser layout remains < 5ms
        max_items = 160
        truncated = (len(raw_facts) + len(raw_intents)) > max_items
        if truncated:
            # Always keep origin/goal + most recent facts & intents
            pinned_f = [f for f in raw_facts if f.get("id") in ("origin", "goal")]
            other_f = [f for f in raw_facts if f.get("id") not in ("origin", "goal")]
            half = max(20, (max_items - len(pinned_f)) // 2)
            raw_facts = pinned_f + other_f[-half:]
            raw_intents = raw_intents[-half:]

        nodes: list[dict[str, Any]] = []
        node_ids: set[str] = set()
        for f in raw_facts:
            fid = str(f.get("id") or "")
            if not fid or fid in node_ids:
                continue
            desc = str(f.get("description") or "")
            if fid not in ("origin", "goal"):
                self._audit_text_for_leaks(desc, f"cairn_dag_fact:{pid}:{fid}")
            kind = fid if fid in ("origin", "goal") else "fact"
            first_line = next((ln.strip() for ln in desc.splitlines() if ln.strip()), "")
            short = (first_line[:68] + "…") if len(first_line) > 68 else (first_line or fid)
            nodes.append(
                {
                    "id": fid,
                    "kind": kind,
                    "status": "root" if kind in ("origin", "goal") else "verified",
                    "label": short,
                    "description": desc[:2400],
                    "is_hypothesis": "[HYPOTHESIS]" in desc,
                    "has_flag_hint": "flag{" in desc.lower(),
                }
            )
            node_ids.add(fid)

        edges: list[dict[str, Any]] = []
        working_cnt = 0
        unclaimed_cnt = 0
        concluded_cnt = 0
        for it in raw_intents:
            iid = str(it.get("id") or "")
            if not iid or iid in node_ids:
                continue
            desc = str(it.get("description") or "")
            first_line = next((ln.strip() for ln in desc.splitlines() if ln.strip()), "")
            short = (first_line[:68] + "…") if len(first_line) > 68 else (first_line or iid)
            if it.get("concluded_at"):
                ist = "concluded"
                concluded_cnt += 1
            elif it.get("worker"):
                ist = "working"
                working_cnt += 1
            else:
                ist = "unclaimed"
                unclaimed_cnt += 1
            src_list = [str(x) for x in (it.get("from") or []) if x]
            to_fid = str(it.get("to") or "") or None
            nodes.append(
                {
                    "id": iid,
                    "kind": "intent",
                    "status": ist,
                    "label": short,
                    "description": desc[:2400],
                    "worker": it.get("worker"),
                    "creator": it.get("creator"),
                    "from": src_list,
                    "to": to_fid,
                    "created_at": it.get("created_at"),
                    "last_heartbeat_at": it.get("last_heartbeat_at"),
                    "concluded_at": it.get("concluded_at"),
                }
            )
            node_ids.add(iid)
            for src in src_list:
                if src in node_ids:
                    edges.append({"from": src, "to": iid, "kind": "depends"})
            if to_fid and to_fid in node_ids:
                edges.append({"from": iid, "to": to_fid, "kind": "produces"})

        # Build operator-clickable native Cairn UI URL if possible
        cairn_ui_url = None
        if self.cairn_url:
            cairn_ui_url = f"{self.cairn_url.rstrip('/')}/?project={pid}"
            if self.public_host and ("127.0.0.1" in cairn_ui_url or "localhost" in cairn_ui_url):
                cairn_ui_url = cairn_ui_url.replace("127.0.0.1", self.public_host).replace("localhost", self.public_host)

        non_root_facts = sum(1 for n in nodes if n["kind"] == "fact")
        payload = {
            "available": True,
            "status": "ok",
            "challenge_id": qid,
            "project_id": pid,
            "project_status": proj.get("status"),
            "project_title": proj.get("title"),
            "reason": proj.get("reason"),
            "cairn_ui_url": cairn_ui_url,
            "truncated": truncated,
            "stats": {
                "facts": non_root_facts,
                "intents": len(raw_intents),
                "working": working_cnt,
                "unclaimed": unclaimed_cnt,
                "concluded": concluded_cnt,
                "edges": len(edges),
            },
            "nodes": nodes,
            "edges": edges,
            "observed_at": cockpit_models.iso_utc(now_ts),
        }
        self._dag_cache[qid] = (now_mono, payload)
        return payload

    def get_challenge_tools(self, qid: str, *, force: bool = False, limit: int = 50) -> dict[str, Any]:
        """On-demand read-only tool-call summary proxy fetcher (2s TTL cache, zero Worker overhead)."""
        now_mono = time.monotonic()
        now_ts = time.time()
        if qid not in self.questions:
            return {
                "available": False,
                "status": "not_found",
                "challenge_id": qid,
                "reason": f"未找到题目 {qid}",
                "tools": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }
        if not force and qid in self._tools_cache:
            cached_ts, cached_payload = self._tools_cache[qid]
            if now_mono - cached_ts < 2.0:
                return cached_payload
        if not self.proxy_url:
            return {
                "available": False,
                "status": "unconfigured",
                "challenge_id": qid,
                "reason": "未配置 --proxy-url，无法旁路采集工具调用摘要",
                "recovery_hint": "启动平台时附加 --proxy-url http://127.0.0.1:8100",
                "tools": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }
        try:
            r = requests.get(f"{self.proxy_url}/tools", params={"qid": qid, "limit": limit}, timeout=1.5)
            if r.status_code != 200:
                return {
                    "available": False,
                    "status": "error",
                    "challenge_id": qid,
                    "reason": f"Token Proxy /tools 返回 HTTP {r.status_code}（请确认已重启最新 token_proxy.py）",
                    "tools": [],
                    "observed_at": cockpit_models.iso_utc(now_ts),
                }
            data = r.json()
            items = list(data.get("tools") or [])
            # Fallback to global recent tools only as an explicit note if qid wasn't tagged yet
            fallback_used = False
            if not items:
                rg = requests.get(f"{self.proxy_url}/tools", params={"limit": min(limit, 30)}, timeout=1.5)
                if rg.status_code == 200:
                    g_items = [t for t in (rg.json().get("tools") or []) if not t.get("qid")]
                    if g_items:
                        items = g_items
                        fallback_used = True
            payload = {
                "available": True,
                "status": "ok",
                "challenge_id": qid,
                "count": len(items),
                "fallback_untagged": fallback_used,
                "tools": items,
                "observed_at": cockpit_models.iso_utc(now_ts),
            }
            self._tools_cache[qid] = (now_mono, payload)
            return payload
        except Exception as exc:
            return {
                "available": False,
                "status": "disconnected",
                "challenge_id": qid,
                "reason": f"无法连接 Token Proxy：{type(exc).__name__}",
                "tools": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }

    def get_challenge_llm_logs(self, qid: str, *, force: bool = False, limit: int = 40) -> dict[str, Any]:
        """On-demand read-only per-question LLM prompt/thinking/answer timeline (2s TTL, zero Worker impact)."""
        now_mono = time.monotonic()
        now_ts = time.time()
        if qid not in self.questions:
            return {
                "available": False,
                "status": "not_found",
                "challenge_id": qid,
                "reason": f"未找到题目 {qid}",
                "turns": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }
        if not force and qid in self._llm_logs_cache:
            cached_ts, cached_payload = self._llm_logs_cache[qid]
            if now_mono - cached_ts < 2.0:
                return cached_payload
        if not self.proxy_url:
            return {
                "available": False,
                "status": "unconfigured",
                "challenge_id": qid,
                "reason": "未配置 --proxy-url，无法旁路采集模型问答时间线",
                "recovery_hint": "启动平台时附加 --proxy-url http://127.0.0.1:8100",
                "turns": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }
        try:
            r = requests.get(f"{self.proxy_url}/llm-logs", params={"qid": qid, "limit": limit}, timeout=1.5)
            if r.status_code != 200:
                return {
                    "available": False,
                    "status": "error",
                    "challenge_id": qid,
                    "reason": f"Token Proxy /llm-logs 返回 HTTP {r.status_code}（请确认已重启最新 token_proxy.py）",
                    "turns": [],
                    "observed_at": cockpit_models.iso_utc(now_ts),
                }
            data = r.json()
            turns = list(data.get("turns") or [])
            fallback_used = False
            if not turns:
                rg = requests.get(f"{self.proxy_url}/llm-logs", params={"limit": min(limit, 25)}, timeout=1.5)
                if rg.status_code == 200:
                    g_turns = [t for t in (rg.json().get("turns") or []) if not t.get("qid")]
                    if g_turns:
                        turns = g_turns
                        fallback_used = True
            durs = [float(t["dur_sec"]) for t in turns if cockpit_models.safe_float(t.get("dur_sec")) is not None]
            ttfts = [float(t["ttft_sec"]) for t in turns if cockpit_models.safe_float(t.get("ttft_sec")) is not None]
            payload = {
                "available": True,
                "status": "ok",
                "challenge_id": qid,
                "count": len(turns),
                "fallback_untagged": fallback_used,
                "summary": {
                    "turns": len(turns),
                    "avg_dur_sec": round(sum(durs) / len(durs), 2) if durs else None,
                    "avg_ttft_sec": round(sum(ttfts) / len(ttfts), 2) if ttfts else None,
                    "total_input": sum(int(t.get("input") or 0) for t in turns),
                    "total_output": sum(int(t.get("output") or 0) for t in turns),
                    "total_cache_read": sum(int(t.get("cache_read") or 0) for t in turns),
                },
                "turns": turns,
                "observed_at": cockpit_models.iso_utc(now_ts),
            }
            self._llm_logs_cache[qid] = (now_mono, payload)
            return payload
        except Exception as exc:
            return {
                "available": False,
                "status": "disconnected",
                "challenge_id": qid,
                "reason": f"无法连接 Token Proxy：{type(exc).__name__}",
                "turns": [],
                "observed_at": cockpit_models.iso_utc(now_ts),
            }

    def skip_question(self, qid: str, *, reason: str = "人工跳过/止损", operator: str = "human") -> dict[str, Any]:
        """Local-eval operator stop-loss: stop running scene & mark challenge skipped."""
        with self.lock:
            q = self.questions.get(qid)
            if not q:
                raise HTTPException(404, f"question not found: {qid}")
            stopped_scene = False
            if q["has_scene"] and self.scene_status.get(qid, 3) in (0, 1):
                if self.scene_mgr:
                    try:
                        self.scene_mgr.stop(qid)
                    except Exception:
                        pass
                self.scene_status[qid] = 3
                self.last_stop_reason[qid] = reason
                self.last_stopped_at[qid] = time.time()
                self._close_current_attempt(qid, status="stopped", reason=reason)
                stopped_scene = True
            now_iso = cockpit_models.iso_utc(time.time())
            self.skipped_questions[qid] = {"at": now_iso, "reason": reason, "operator": operator}
            self.audit.setdefault("human_interventions", []).append(
                {
                    "ts": round(time.time(), 3),
                    "at": now_iso,
                    "question_id": qid,
                    "operator": operator,
                    "action": "skip",
                    "summary": reason,
                    "affects_autonomy": True,
                }
            )
            did = self._record_platform_decision(
                trigger="human_skip",
                from_qid=qid,
                to_qid=None,
                reason=reason,
                outcome="skipped",
            )
            self._emit_event(
                "human_skip",
                f"[{operator}] 人工跳过/止损 {qid}：{reason}" + ("（已停机释放槽位）" if stopped_scene else ""),
                qid=qid,
                decision_id=did,
                source="human",
                severity="warn",
            )
            self.persist()
            return {"ok": True, "question_id": qid, "stopped_scene": stopped_scene, "message": f"已跳过 {qid}" + ("并释放靶机槽位" if stopped_scene else "")}

    def reset_single_question(self, qid: str, *, operator: str = "human") -> dict[str, Any]:
        """Local-eval single-challenge reset: stop scene and clear ONLY this challenge's progress."""
        with self.lock:
            q = self.questions.get(qid)
            if not q:
                raise HTTPException(404, f"question not found: {qid}")
            if q["has_scene"] and self.scene_mgr:
                try:
                    self.scene_mgr.stop(qid)
                except Exception:
                    pass
            # Subtract previous score contribution from this question
            prev_details = list(self.solved_flag_details.get(qid) or [])
            for item in prev_details:
                self.total_score = round(max(0.0, self.total_score - float(item.get("score") or 0.0)), 2)
                self.ranked_score = round(max(0.0, self.ranked_score - float(item.get("ranked_score") or 0.0)), 2)
            self.solved_flags[qid] = set()
            self.solved_flag_details[qid] = []
            self.submissions = [s for s in self.submissions if s.get("qid") != qid]
            self.attempts_history[qid] = []
            self.scene_start_attempts.pop(qid, None)
            self.scene_started_at.pop(qid, None)
            self.question_solved_at.pop(qid, None)
            self.ever_started[qid] = False
            self.last_stop_reason[qid] = None
            self.last_stopped_at[qid] = None
            self.skipped_questions.pop(qid, None)
            q["force_next_fault"] = False
            gtype = cockpit_models.infer_grading_type(q, self.active_flags[qid])
            self.milestones[qid] = cockpit_models.default_milestones(gtype)
            if q["has_scene"]:
                self.scene_status[qid] = 3
                self.live_addresses[qid] = list(q["scene_addresses"])
            self._dag_cache.pop(qid, None)
            self._tools_cache.pop(qid, None)
            self._llm_logs_cache.pop(qid, None)
            self._snap_cache = None
            did = self._record_platform_decision(
                trigger="human_reset_question",
                to_qid=qid,
                reason="人工重置单题状态准备重跑",
                outcome="reset",
            )
            self._emit_event(
                "human_reset_question",
                f"[{operator}] 已重置单题 {qid} 状态与得分记录，可重新拉起验证",
                qid=qid,
                decision_id=did,
                source="human",
                severity="warn",
            )
            self.persist()
            return {"ok": True, "question_id": qid, "message": f"已重置单题 {qid} 状态与尝试记录。"}

    def build_export_markdown(self) -> str:
        snap = self.dashboard_snapshot()
        s = snap["summary"]
        a = snap["audit"]
        mt = snap["model_telemetry"]
        lines = [
            f"# SecTimeAgent 本地仿真评估快照报告 — `{snap['run_id']}`",
            "",
            f"- **导出时间**：{snap['observed_at']}",
            f"- **比赛已用时**：{snap['clock']['elapsed_sec']}s / {snap['clock']['duration_sec']}s",
            f"- **原始得分 / 排名分**：**{s['total_score']}** / **{s['ranked_score'] if s['ranked_score'] is not None else '未启用'}**",
            f"- **整题验收 / Flag 进度**：**{s['solved_questions']}/{s['total_questions']}** 题 · **{s['solved_flags']}/{s['total_flags']}** Flag",
            f"- **合规审计**：API/MCP `{a['total_api_calls']}/{a['total_mcp_calls']}`（看板轮询 `{a['dashboard_polls']}` 不计入）· 泄密 `{len(a['credential_leaks'])}` · 限流 `{a['rate_limit_hits']}` · 超槽 `{a['scene_limit_hits']}` · 故障自愈 `{a['scene_faults_recovered']}/{a['scene_faults_injected']}`",
            "",
            "## 一、逐题表现、单题消耗与停滞诊断",
            "",
            "| 题号 | 类别 | 状态 | 验收进度 | 已获得 Flag | 累计耗时 | LLM 轮次 / 工具 / Token(In+Out) | 停滞雷达 |",
            "| --- | --- | --- | :---: | --- | :---: | :---: | --- |",
        ]
        for q in snap["questions"]:
            u = q.get("llm_usage") or {}
            tok_txt = f"{u.get('calls', 0)}轮 / {u.get('tool_calls', 0)}工具 / {u.get('input', 0)+u.get('output', 0)}" if u else "未归因"
            st_txt = q["states"]["schedule"]["label"] + (" (已跳过)" if q.get("skipped") else "")
            stall = q.get("stall") or {}
            stall_txt = stall.get("label", "—") + (f": {'; '.join(stall.get('reasons') or [])}" if stall.get("reasons") else "")
            obs_flags = [f"`{f['flag']}`" for f in (q.get("obtained_flags") or []) if f.get("flag")]
            flags_txt = "<br>".join(obs_flags) if obs_flags else "—"
            lines.append(
                f"| `{q['id']}` {q['name']} | {q['canonical_category']} | {st_txt} | {q['states']['verdict']['short_label']} | {flags_txt} | {q['timers']['cumulative_active_sec']}s | {tok_txt} | {stall_txt} |"
            )
        lines.extend(["", "## 二、模型路由、延迟与 Failover 统计", ""])
        if mt.get("available"):
            lines.append("| 路由 | 请求模型 | 返回版本 | 调用/切换 | P50 / P95 延迟 | In / Out / Cache Read |")
            lines.append("| --- | --- | --- | :---: | :---: | :---: |")
            for r in mt.get("routes") or []:
                lat = f"{r.get('p50_sec') or '—'}s / {r.get('p95_sec') or '—'}s"
                lines.append(
                    f"| `{r['route']}` | {r.get('requested_model') or '—'} | {r.get('version_label')} | {r['calls']}/{r['failovers']} | {lat} | {r['input']}/{r['output']}/{r['cache_read']} |"
                )
            if mt.get("last_failover"):
                fo = mt["last_failover"]
                lines.append(f"\n- **最近 Failover**：`{fo.get('from_route')}` → `{fo.get('to_route')}`（原因：`{fo.get('reason')}`）")
        else:
            lines.append("- 模型代理未连接，无路由与 Token 数据。")
        return "\n".join(lines) + "\n"

    def release_next_wave(self) -> dict[str, Any]:
        """Admin helper: immediately unlock the next unreleased wave with explicit feedback (D09)."""
        with self.lock:
            hidden = [q for q in self.questions.values() if not self.is_visible(q)]
            if not hidden:
                return {"ok": True, "unlocked": [], "remaining_hidden": 0, "message": "全部题目均已放出，无新增波次"}
            min_rel = min(float(q["release_after_sec"]) for q in hidden)
            unlocked = []
            for q in hidden:
                if float(q["release_after_sec"]) <= min_rel + 1e-6:
                    q["release_after_sec"] = 0.0
                    unlocked.append(q["id"])
            rem = sum(1 for q in self.questions.values() if not self.is_visible(q))
            did = self._record_platform_decision(
                trigger="human_release_wave",
                to_qid=",".join(unlocked),
                reason=f"操作者手动提前释放下一波题目（共 {len(unlocked)} 题）",
                outcome="released",
            )
            self._emit_event(
                "admin_release",
                f"Manually released wave: {', '.join(unlocked)}",
                source="human",
                decision_id=did,
                severity="info",
            )
            return {
                "ok": True,
                "unlocked": unlocked,
                "remaining_hidden": rem,
                "message": f"已提前释放 {len(unlocked)} 道题目：{', '.join(unlocked)}",
            }

    def reset_all(self) -> None:
        if self.scene_mgr:
            self.scene_mgr.stop_all()
        with self.lock:
            self.run_id = f"run_{secrets.token_hex(4)}"
            self.started_at = time.monotonic()
            self.started_wall = time.time()
            self.total_score = 0.0
            self.ranked_score = 0.0
            self.submissions.clear()
            self.event_store.clear(self.run_id)
            self.scene_start_attempts.clear()
            self.scene_started_at.clear()
            self.question_solved_at.clear()
            self.platform_decisions.clear()
            self._decision_seq = 0
            self._dag_cache.clear()
            self._tools_cache.clear()
            self._llm_logs_cache.clear()
            self._cairn_proj_detail_cache.clear()
            self._snap_cache = None
            self.skipped_questions.clear()
            self.audit = {
                "rate_limit_hits": 0,
                "scene_limit_hits": 0,
                "credential_leaks": [],
                "scene_faults_injected": 0,
                "scene_faults_recovered": 0,
                "total_api_calls": 0,
                "total_mcp_calls": 0,
                "dashboard_polls": 0,
                "human_interventions": [],
            }
            for qid, q in self.questions.items():
                q["release_after_sec"] = q.get("initial_release_after_sec", q["release_after_sec"])
                q["force_next_fault"] = False
                self.solved_flags[qid] = set()
                self.solved_flag_details[qid] = []
                self.attempts_history[qid] = []
                self.ever_started[qid] = False
                self.last_stop_reason[qid] = None
                self.last_stopped_at[qid] = None
                gtype = cockpit_models.infer_grading_type(q, self.active_flags[qid])
                self.milestones[qid] = cockpit_models.default_milestones(gtype)
                if q["has_scene"]:
                    self.scene_status[qid] = 3
                    self.live_addresses[qid] = list(q["scene_addresses"])
            self._emit_event("admin_reset", "Simulation state reset by operator", source="human")
            self.persist()


MCP_TOOL_DEFS = [
    {
        "name": "question_list",
        "description": "获取当前可见题目列表",
        "inputSchema": {
            "type": "object",
            "properties": {"direction": {"type": "string"}},
        },
    },
    {
        "name": "question_info",
        "description": "获取指定题目详情",
        "inputSchema": {
            "type": "object",
            "properties": {"question_id": {"type": "string"}},
            "required": ["question_id"],
        },
    },
    {
        "name": "question_instance_info",
        "description": "获取场景状态和访问信息",
        "inputSchema": {
            "type": "object",
            "properties": {"question_id": {"type": "string"}},
            "required": ["question_id"],
        },
    },
    {
        "name": "question_start",
        "description": "启动指定题目的场景",
        "inputSchema": {
            "type": "object",
            "properties": {"question_id": {"type": "string"}},
            "required": ["question_id"],
        },
    },
    {
        "name": "question_stop",
        "description": "关闭指定题目的场景",
        "inputSchema": {
            "type": "object",
            "properties": {"question_id": {"type": "string"}},
            "required": ["question_id"],
        },
    },
    {
        "name": "question_submit_flag",
        "description": "提交题目答案",
        "inputSchema": {
            "type": "object",
            "properties": {
                "question_id": {"type": "string"},
                "flag": {"type": "string"},
            },
            "required": ["question_id", "flag"],
        },
    },
]


def create_mock_race_app(state: MockRacePlatformState) -> FastAPI:
    app = FastAPI(title="1:1 Mock Official AI-Race Platform + Human Decision Cockpit")
    prefix = "/api/ct/agent/ai_race/race/checkpoints/robot"

    @app.get("/health")
    def health():
        with state.lock:
            return {
                "ok": True,
                "run_id": state.run_id,
                "visible_questions": sum(1 for q in state.questions.values() if state.is_visible(q)),
                "total_questions": len(state.questions),
                "running_scenes": state.running_scene_count(),
                "total_score": state.total_score,
                "ranked_score": state.ranked_score,
                "docker_enabled": state.docker_enabled,
            }

    # --- Official HTTP API (7 endpoints — strictly zero reference-guide leakage) ---

    @app.get(f"{prefix}/question_list")
    def question_list(
        direction: str | None = Query(default=None),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            return JSONResponse(state.op_question_list(direction))

    @app.get(f"{prefix}/question_info")
    def question_info(
        question_id: str = Query(...),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            return JSONResponse(state.op_question_info(question_id))

    @app.post(f"{prefix}/question_start")
    def question_start(
        body: QuestionIdBody,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            return JSONResponse(state.op_question_start(body.question_id))

    @app.get(f"{prefix}/question_instance_info")
    def question_instance_info(
        question_id: str = Query(...),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            return JSONResponse(state.op_question_instance_info(question_id))

    @app.post(f"{prefix}/question_stop")
    def question_stop(
        body: QuestionIdBody,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            return JSONResponse(state.op_question_stop(body.question_id))

    @app.post(f"{prefix}/question/submit_flag")
    def submit_flag(
        body: SubmitFlagBody,
        authorization: str | None = Header(default=None, alias="Authorization"),
    ):
        with state.lock:
            err = state.check_auth_and_rate(authorization)
            if err:
                return JSONResponse(err)
            return JSONResponse(state.op_submit_flag(body.question_id, body.flag))

    @app.get("/attachments/{question_id}/{filename}")
    def download_attachment(question_id: str, filename: str):
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
        # Auto-advance attachment 'fetched' milestone (D04)
        with state.lock:
            for m in state.milestones.get(question_id) or []:
                if m["key"] == "fetched" and m["status"] == "pending":
                    m["status"] = "done"
                    m["updated_at"] = cockpit_models.iso_utc(time.time())
                    m["detail"] = f"已下载 {filename}"
                    state._emit_event("attachment_fetched", f"Attachment downloaded: {question_id}/{filename}", qid=question_id, severity="ok")
                    break
        return FileResponse(target, filename=filename)

    # --- Official Streamable HTTP MCP Endpoint (MCP_接入.md, protocol 2024-11-05) ---

    @app.post("/mcp")
    async def mcp_endpoint(
        request: Request,
        authorization: str | None = Header(default=None, alias="Authorization"),
        mcp_session_id: str | None = Header(default=None, alias="Mcp-Session-Id"),
        accept: str | None = Header(default=None, alias="Accept"),
    ):
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "Authorization header is required")
        try:
            rpc = await request.json()
        except Exception:
            raise HTTPException(400, "Invalid JSON-RPC payload")

        req_id = rpc.get("id")
        method = str(rpc.get("method") or "")
        params = rpc.get("params") or {}
        want_sse = "text/event-stream" in (accept or "")

        def _reply(payload: dict[str, Any], sid: str | None = None):
            headers = {"Mcp-Session-Id": sid} if sid else {}
            if want_sse:
                body = f"event: message\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
                return StreamingResponse(iter([body]), media_type="text/event-stream", headers=headers)
            return JSONResponse(payload, headers=headers)

        if method == "initialize":
            with state.lock:
                tok = authorization[7:].strip()
                if tok != state.valid_token:
                    raise HTTPException(401, "Invalid Agent Token")
                sid = secrets.token_hex(16)
                state.mcp_sessions[sid] = time.time()
            return _reply(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "ad-ai-race-agent", "version": "1.0.0"},
                    },
                },
                sid=sid,
            )

        if method == "notifications/initialized":
            return JSONResponse({"ok": True}, status_code=202)

        if not mcp_session_id or mcp_session_id not in state.mcp_sessions:
            raise HTTPException(400, "No valid session ID provided")

        if method == "tools/list":
            return _reply({"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOL_DEFS}}, sid=mcp_session_id)

        if method == "tools/call":
            tname = str(params.get("name") or "")
            targs = params.get("arguments") or {}
            with state.lock:
                err = state.check_auth_and_rate(authorization, is_mcp=True)
                if err is not None:
                    res_env = err
                elif tname == "question_list":
                    res_env = state.op_question_list(targs.get("direction"))
                elif tname == "question_info":
                    qid = str(targs.get("question_id") or "")
                    res_env = state.op_question_info(qid) if qid else _envelope("AD-160003", "Invalid request parameters")
                elif tname == "question_instance_info":
                    qid = str(targs.get("question_id") or "")
                    res_env = state.op_question_instance_info(qid) if qid else _envelope("AD-160003", "Invalid request parameters")
                elif tname == "question_start":
                    qid = str(targs.get("question_id") or "")
                    res_env = state.op_question_start(qid) if qid else _envelope("AD-160003", "Invalid request parameters")
                elif tname == "question_stop":
                    qid = str(targs.get("question_id") or "")
                    res_env = state.op_question_stop(qid) if qid else _envelope("AD-160003", "Invalid request parameters")
                elif tname == "question_submit_flag":
                    qid = str(targs.get("question_id") or "")
                    flag = str(targs.get("flag") or "")
                    res_env = (
                        state.op_submit_flag(qid, flag)
                        if (qid and flag)
                        else _envelope("AD-160003", "Invalid request parameters")
                    )
                else:
                    return _reply(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": f"unknown tool: {tname}"}],
                                "isError": True,
                            },
                        },
                        sid=mcp_session_id,
                    )

            return _reply(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(res_env, ensure_ascii=False)}],
                        "structuredContent": res_env,
                        "isError": False,
                    },
                },
                sid=mcp_session_id,
            )

        return _reply(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}},
            sid=mcp_session_id,
        )

    # --- Local Human Decision Cockpit & Admin Endpoints (Local Eval Only) ---

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page():
        if DASHBOARD_HTML_PATH.is_file():
            return HTMLResponse(DASHBOARD_HTML_PATH.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>Dashboard HTML missing</h1>", status_code=404)

    @app.get("/api/dashboard/snapshot")
    def dashboard_snapshot():
        return JSONResponse(state.dashboard_snapshot())

    @app.get("/api/dashboard/dag/{question_id}")
    def dashboard_challenge_dag(
        question_id: str,
        force: int = Query(default=0, ge=0, le=1),
    ):
        return JSONResponse(state.get_challenge_dag(question_id, force=bool(force)))

    @app.get("/api/dashboard/tools/{question_id}")
    def dashboard_challenge_tools(
        question_id: str,
        force: int = Query(default=0, ge=0, le=1),
        limit: int = Query(default=50, ge=1, le=120),
    ):
        return JSONResponse(state.get_challenge_tools(question_id, force=bool(force), limit=limit))

    @app.get("/api/dashboard/llm-logs/{question_id}")
    def dashboard_challenge_llm_logs(
        question_id: str,
        force: int = Query(default=0, ge=0, le=1),
        limit: int = Query(default=40, ge=1, le=100),
    ):
        return JSONResponse(state.get_challenge_llm_logs(question_id, force=bool(force), limit=limit))

    @app.get("/api/dashboard/export-report")
    def dashboard_export_report(format: str = Query(default="md")):
        from fastapi.responses import Response

        if format.lower() == "json":
            snap = state.dashboard_snapshot()
            return Response(
                content=json.dumps(snap, ensure_ascii=False, indent=2),
                media_type="application/json; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="cockpit-snapshot-{state.run_id}.json"'},
            )
        md = state.build_export_markdown()
        return Response(
            content=md,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="cockpit-report-{state.run_id}.md"'},
        )

    @app.get("/api/dashboard/events")
    def dashboard_events(
        since_seq: int = Query(default=0, ge=0),
        challenge_id: str | None = Query(default=None),
        attempt_id: str | None = Query(default=None),
        limit: int = Query(default=200, ge=1, le=500),
    ):
        with state.lock:
            return JSONResponse(
                {
                    "run_id": state.run_id,
                    "last_seq": state.event_store.last_seq,
                    "events": state.event_store.query(
                        since_seq=since_seq,
                        challenge_id=challenge_id,
                        attempt_id=attempt_id,
                        limit=limit,
                    ),
                }
            )

    @app.get("/api/dashboard/stream")
    async def dashboard_stream(request: Request):
        async def event_gen():
            while True:
                if await request.is_disconnected():
                    break
                snap = await asyncio.to_thread(state.dashboard_snapshot, use_cache=True)
                yield f"id: {snap['last_seq']}\ndata: {json.dumps(snap, ensure_ascii=False)}\n\n"
                await asyncio.sleep(2.0)

        return StreamingResponse(
            event_gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/api/admin/release-next")
    def admin_release_next():
        return JSONResponse(state.release_next_wave())

    @app.post("/api/admin/inject-fault/{question_id}")
    def admin_inject_fault(question_id: str):
        with state.lock:
            q = state.questions.get(question_id)
            if not q or not q["has_scene"]:
                raise HTTPException(404, "scene question not found")
            q["force_next_fault"] = True
            state._emit_event(
                "admin_fault",
                f"已为 {question_id} 预设下一次启动故障（status=20），用于验证自动停机重建恢复",
                qid=question_id,
                source="human",
                severity="warn",
            )
        return JSONResponse(
            {
                "ok": True,
                "question_id": question_id,
                "message": f"已生效：{question_id} 下一次启动将模拟启动失败（status=20），不会中断当前运行中实例。",
            }
        )

    @app.post("/api/admin/milestone/{question_id}")
    def admin_update_milestone(question_id: str, body: MilestoneUpdateBody):
        return JSONResponse(
            state.update_milestone(
                question_id,
                key=body.key,
                status=body.status,
                detail=body.detail,
                score=body.score,
            )
        )

    @app.post("/api/admin/operator-action/{question_id}")
    def admin_operator_action(question_id: str, body: OperatorActionBody):
        with state.lock:
            if question_id not in state.questions:
                raise HTTPException(404, "question not found")
            entry = {
                "ts": round(time.time(), 3),
                "at": cockpit_models.iso_utc(time.time()),
                "question_id": question_id,
                "operator": body.operator,
                "action": body.action,
                "summary": body.summary,
                "affects_autonomy": bool(body.affects_autonomy),
            }
            state.audit.setdefault("human_interventions", []).append(entry)
            did = state._record_platform_decision(
                trigger=f"human_{body.action}",
                to_qid=question_id,
                reason=body.summary or f"人工操作: {body.action}",
                outcome="recorded" + (" (影响自主评测)" if body.affects_autonomy else " (纯审计记录)"),
            )
            state._emit_event(
                "human_intervention",
                f"[{body.operator}] {body.action} on {question_id}: {body.summary}",
                qid=question_id,
                decision_id=did,
                source="human",
                severity="warn" if body.affects_autonomy else "info",
            )
            state.persist()
            return JSONResponse({"ok": True, "entry": entry})

    @app.post("/api/admin/skip-question/{question_id}")
    def admin_skip_question(question_id: str):
        return JSONResponse(state.skip_question(question_id))

    @app.post("/api/admin/reset-question/{question_id}")
    def admin_reset_question(question_id: str):
        return JSONResponse(state.reset_single_question(question_id))

    @app.post("/api/admin/reset")
    def admin_reset():
        state.reset_all()
        return JSONResponse({"ok": True, "message": "已重置仿真赛全部得分、场景状态、Attempt 历史与事件流。"})

    # --- Strictly Isolated Human-Only Reference Guide Routes (Section 7) ---
    if state.human_ref_store is not None:
        human_ref_mod.mount_human_reference_routes(app, state.human_ref_store)

    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="1:1 Mock Official AI-Race Platform + Human Decision Cockpit")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18099)
    ap.add_argument("--config", required=True, help="YAML file defining mock race questions")
    ap.add_argument("--token", default="test-agent-token")
    ap.add_argument("--max-scenes", type=int, default=2)
    ap.add_argument("--rate-limit", type=int, default=3)
    ap.add_argument("--state-file", default=None)
    ap.add_argument("--attachments-dir", default=None)
    ap.add_argument("--docker-scenes", action="store_true", help="Enable real Docker target lifecycle management")
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--public-host", default=os.environ.get("PUBLIC_TARGET_HOST") or None, help="Explicit reachable host for operator links (never guesses from 0.0.0.0)")
    ap.add_argument("--dynamic-flags", action="store_true", help="Inject fresh random flags into Docker targets")
    ap.add_argument("--simulate-competitors", action="store_true", help="Enable 152-team rank scoring simulation")
    ap.add_argument("--time-scale", type=float, default=1.0)
    ap.add_argument("--duration-sec", type=float, default=14400.0)
    ap.add_argument("--cairn-url", default=os.environ.get("CAIRN_URL") or None)
    ap.add_argument("--cairn-admin-token", default=os.environ.get("CAIRN_ADMIN_TOKEN") or None)
    ap.add_argument("--proxy-url", default=os.environ.get("PROXY_URL") or None)
    ap.add_argument("--orch-state", default=None, help="Path to race-orchestrator-state.json for cockpit")
    ap.add_argument("--human-ref-dir", default=os.environ.get("HUMAN_REF_DIR") or None, help="Isolated directory for human-only reference guides")
    ap.add_argument("--human-ref-token", default=os.environ.get("HUMAN_REF_TOKEN") or None, help="Dedicated human-only token (MUST NOT equal AGENT_TOKEN)")
    args = ap.parse_args()

    secret_patterns = [
        v for k, v in os.environ.items()
        if any(tag in k.upper() for tag in ("API_KEY", "AGENT_TOKEN", "ADMIN_TOKEN", "HUMAN_REF_TOKEN"))
        and len(v.strip()) >= 8
    ]

    href_store = None
    if args.human_ref_token:
        forbid = [args.token]
        if args.cairn_admin_token:
            forbid.append(args.cairn_admin_token)
        href_dir = Path(args.human_ref_dir) if args.human_ref_dir else (REPO_ROOT / "eval" / "human-references")
        href_store = human_ref_mod.IsolatedHumanReferenceStore(
            href_dir,
            args.human_ref_token,
            forbidden_tokens=forbid,
        )

    state = MockRacePlatformState(
        valid_token=args.token,
        max_scenes=args.max_scenes,
        rate_limit_rps=args.rate_limit,
        base_url=f"http://{args.public_host or ('127.0.0.1' if cockpit_models.is_wildcard_ip(args.target_host) else args.target_host)}:{args.port}",
        state_file=Path(args.state_file) if args.state_file else None,
        attachments_root=Path(args.attachments_dir) if args.attachments_dir else None,
        docker_enabled=args.docker_scenes,
        target_host=args.target_host,
        public_host=args.public_host,
        dynamic_flags=args.dynamic_flags,
        simulate_competitors=args.simulate_competitors,
        time_scale=args.time_scale,
        duration_sec=args.duration_sec,
        cairn_url=args.cairn_url,
        cairn_admin_token=args.cairn_admin_token,
        proxy_url=args.proxy_url,
        orch_state_file=Path(args.orch_state) if args.orch_state else None,
        secret_patterns=secret_patterns,
        human_ref_store=href_store,
    )
    state.load_config(Path(args.config))

    def _cleanup(*_args):
        if state.scene_mgr:
            state.scene_mgr.stop_all()

    atexit.register(_cleanup)
    signal.signal(signal.SIGTERM, lambda *_: (_cleanup(), os._exit(0)))

    app = create_mock_race_app(state)
    print(f"[mock-platform] API: http://{args.host}:{args.port}/api/ct/agent/ai_race/race/checkpoints/robot/question_list", flush=True)
    print(f"[mock-platform] MCP: http://{args.host}:{args.port}/mcp", flush=True)
    print(f"[mock-platform] Human Decision Cockpit: http://{args.host}:{args.port}/dashboard", flush=True)
    if href_store:
        print(f"[mock-platform] Isolated Human Reference Gate: ENABLED (dir={href_store.root_dir})", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
