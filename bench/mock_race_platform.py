#!/usr/bin/env python3
"""1:1 仿真官方 AI 赛平台（完全对齐 API_接入.md + MCP_接入.md + 动态 Docker 靶机 + 本地观测看板）。

核心仿真能力：
  1. HTTP API 全部 7 个接口与全部 AD-xxxxxx 错误码（业务错误统一 HTTP 200）
  2. Streamable HTTP MCP 端点（POST /mcp，协议 2024-11-05，6 个 question_* 工具，共享状态与限流）
  3. 真实 Docker 动态靶机生命周期管理（支持单容器与多容器隔离内网，真实 3->0->1->2->3 与 20 故障注入）
  4. 可选动态 Flag 注入、分阶段放题（release_after_sec）、并发场景上限（AD-162006）与共享 3 req/s 限流（AD-002002）
  5. 152 队竞争名次计分仿真（+5%/+3%/+1% 与 -10%/-20%/-40%）与赛场红线合规审计
  6. 零侵入本地实时观测看板（GET /dashboard + SSE /api/dashboard/stream，仅本地评估用）
"""

from __future__ import annotations

import argparse
import asyncio
import atexit
import json
import math
import os
import secrets
import signal
import socket
import subprocess
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
DASHBOARD_HTML_PATH = ROOT_DIR / "dashboard.html"


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

    def start_scene(
        self,
        qid: str,
        q: dict[str, Any],
        flags: list[str],
    ) -> list[dict[str, Any]]:
        """Start single or multi-container Docker scene; wait for healthcheck; return scene_addresses."""
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
        self._wait_ready(self.target_host, host_port, hc_type, hc_path, timeout, cname)
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
                exposed_host_port: int | None = None
                if svc.get("expose_port"):
                    cport = int(svc["expose_port"])
                    exposed_host_port = int(svc["host_port"]) if svc.get("host_port") else _pick_free_port(self.target_host)
                    proto = str(svc.get("protocol") or "http")
                    cmd.extend(["-p", f"{self.target_host}:{exposed_host_port}:{cport}"])
                    addresses.append({"access_ip": self.target_host, "access_port": exposed_host_port, "protocol": proto})
                    if primary_probe is None:
                        hc_type = str(svc.get("healthcheck_type") or ("http" if proto in ("http", "https") else "tcp"))
                        hc_path = str(svc.get("healthcheck_path") or "/")
                        primary_probe = (self.target_host, exposed_host_port, hc_type, hc_path, cname)

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
            # Confirm container didn't crash immediately
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
    ):
        self.valid_token = valid_token
        self.max_scenes = max_scenes
        self.rate_limit_rps = rate_limit_rps
        self.base_url = base_url.rstrip("/")
        self.state_file = state_file
        self.attachments_root = attachments_root
        self.docker_enabled = docker_enabled
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

        self.started_at = time.monotonic()
        self.started_wall = time.time()
        self.lock = threading.RLock()
        self.questions: dict[str, dict[str, Any]] = {}
        self.active_flags: dict[str, list[str]] = {}
        self.solved_flags: dict[str, set[str]] = {}
        self.solved_flag_details: dict[str, list[dict[str, Any]]] = {}
        self.scene_status: dict[str, int] = {}
        self.live_addresses: dict[str, list[dict[str, Any]]] = {}
        self.scene_start_attempts: dict[str, int] = {}
        self.scene_started_at: dict[str, float] = {}
        self.question_solved_at: dict[str, float] = {}
        self.rate_windows: dict[str, deque[float]] = {}
        self.total_score: float = 0.0
        self.ranked_score: float = 0.0
        self.submissions: list[dict[str, Any]] = []
        self.events: deque[dict[str, Any]] = deque(maxlen=300)
        self.mcp_sessions: dict[str, float] = {}

        # Compliance telemetry
        self.audit: dict[str, Any] = {
            "rate_limit_hits": 0,
            "scene_limit_hits": 0,
            "credential_leaks": [],
            "scene_faults_injected": 0,
            "scene_faults_recovered": 0,
            "total_api_calls": 0,
            "total_mcp_calls": 0,
        }
        self.scene_mgr = DockerSceneManager(target_host=target_host) if docker_enabled else None

        # Cached observer snapshots from Cairn & Token Proxy
        self._obs_cache_ts = 0.0
        self._obs_cache: dict[str, Any] = {"cairn": None, "proxy": None, "orchestrator": None}

    def _emit_event(self, kind: str, message: str, *, qid: str | None = None, extra: dict[str, Any] | None = None) -> None:
        self.events.append(
            {
                "ts": round(time.time(), 3),
                "elapsed_sec": round(self.elapsed_sec(), 1),
                "kind": kind,
                "qid": qid,
                "message": message,
                "extra": extra or {},
            }
        )

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

        for item in raw.get("questions") or []:
            qid = str(item["id"])
            raw_flags = [str(f).strip() for f in (item.get("flags") or ([item["flag"]] if item.get("flag") else []))]
            has_docker = bool(item.get("docker") or item.get("multi_docker"))
            if self.dynamic_flags and has_docker and raw_flags:
                eff_flags = [f"flag{{{qid}_f{i+1}_{secrets.token_hex(6)}}}" for i in range(len(raw_flags))]
            else:
                eff_flags = list(raw_flags)
            q = {
                "id": qid,
                "name": str(item.get("name") or qid),
                "direction": str(item.get("direction") or "web"),
                "category": str(item.get("category") or item.get("direction") or "web"),
                "score": float(item.get("score") or 100),
                "difficulty": int(item.get("difficulty") or 1),
                "desc": str(item.get("desc") or ""),
                "flags": eff_flags,
                "static_flags": raw_flags,
                "has_scene": bool(item.get("has_scene", True)),
                "scene_addresses": list(item.get("scene_addresses") or []),
                "docker": item.get("docker"),
                "multi_docker": item.get("multi_docker"),
                "startup_delay_sec": float(item.get("startup_delay_sec") or 0.0),
                "attachments": list(item.get("attachments") or []),
                "release_after_sec": float(item.get("release_after_sec") or 0.0),
                "fail_first_start": bool(item.get("fail_first_start", False)),
                "force_next_fault": False,
                "all_user_solved": int(item.get("all_user_solved") or 0),
                "wave": int(item.get("wave") or (1 if float(item.get("release_after_sec") or 0.0) <= 0 else 2)),
            }
            self.questions[qid] = q
            self.active_flags[qid] = eff_flags
            self.solved_flags.setdefault(qid, set())
            self.solved_flag_details.setdefault(qid, [])
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
        except Exception:
            pass

    def persist(self) -> None:
        if not self.state_file:
            return
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "updated_at": time.time(),
            "elapsed_sec": round(self.elapsed_sec(), 1),
            "total_score": self.total_score,
            "ranked_score": self.ranked_score,
            "solved_flags": {k: sorted(v) for k, v in self.solved_flags.items()},
            "solved_flag_details": self.solved_flag_details,
            "submissions": self.submissions[-200:],
            "submissions_count": len(self.submissions),
            "audit": self.audit,
        }
        self.state_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def simulated_all_user_solved(self, q: dict[str, Any]) -> int:
        """Compute deterministic 152-team competitor solve count when simulate_competitors=True."""
        base = int(q["all_user_solved"])
        if not self.simulate_competitors or not self.is_visible(q):
            return base
        since_release = max(0.0, self.elapsed_sec() - float(q["release_after_sec"]))
        # Half-saturation times (seconds) by difficulty: Easy ~12m, Medium ~35m, Hard ~90m
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
            self._emit_event("rate_limit", "Hit 3 req/s rate limit (AD-002002)")
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
                        self._emit_event("compliance_leak", f"Secret leak detected in {source}")

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
            self._emit_event("scene_limit", f"Scene cap ({self.max_scenes}) rejected start for {q['id']}", qid=q["id"])
            return _envelope(
                "AD-162006",
                f"场景数量[{self.running_scene_count()}]达到上限, 请关闭其他场景后重试",
            )

        attempts = self.scene_start_attempts.get(q["id"], 0) + 1
        self.scene_start_attempts[q["id"]] = attempts
        should_fault = (q["fail_first_start"] and attempts == 1) or bool(q.get("force_next_fault"))
        q["force_next_fault"] = False

        if should_fault:
            self.scene_status[q["id"]] = 20
            self.audit["scene_faults_injected"] += 1
            self._emit_event("scene_fault", f"Injected scene_status=20 on {q['id']} (attempt {attempts})", qid=q["id"])
            return _envelope(data=True)

        use_docker = bool(self.docker_enabled and self.scene_mgr and (q.get("docker") or q.get("multi_docker")))
        delay = float(q.get("startup_delay_sec") or 0.0)

        if use_docker or delay > 0.0:
            self.scene_status[q["id"]] = 0
            self.live_addresses[q["id"]] = []
            self._emit_event("scene_creating", f"Starting scene {q['id']} (docker={use_docker})", qid=q["id"])
            flags_copy = list(self.active_flags[q["id"]])
            q_copy = dict(q)

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
                            if attempts > 1 and q["fail_first_start"]:
                                self.audit["scene_faults_recovered"] += 1
                            self._emit_event("scene_running", f"Scene {q['id']} RUNNING at {addrs}", qid=q["id"])
                        elif use_docker and self.scene_mgr:
                            need_stop = True
                    if need_stop and self.scene_mgr:
                        self.scene_mgr.stop_scene(q["id"])
                except Exception as exc:
                    with self.lock:
                        self.scene_status[q["id"]] = 20
                        self._emit_event("scene_error", f"Scene {q['id']} start failed: {exc}", qid=q["id"])

            threading.Thread(target=_bg_start, daemon=True).start()
            return _envelope(data=True)

        self.scene_status[q["id"]] = 1
        self.live_addresses[q["id"]] = list(q["scene_addresses"])
        self.scene_started_at[q["id"]] = time.time()
        if attempts > 1 and q["fail_first_start"]:
            self.audit["scene_faults_recovered"] += 1
        self._emit_event("scene_running", f"Scene {q['id']} RUNNING", qid=q["id"])
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

    def op_question_stop(self, question_id: str) -> dict[str, Any]:
        # Per API_接入.md §5: never rejects non-existent or stopped questions
        if question_id in self.scene_status:
            prev = self.scene_status[question_id]
            use_docker = bool(self.docker_enabled and self.scene_mgr and (self.questions[question_id].get("docker") or self.questions[question_id].get("multi_docker")))
            if use_docker and prev in (0, 1, 20):
                self.scene_status[question_id] = 2
                self.live_addresses[question_id] = []
                self._emit_event("scene_stopping", f"Stopping Docker scene {question_id}", qid=question_id)

                def _bg_stop() -> None:
                    try:
                        if self.scene_mgr:
                            self.scene_mgr.stop_scene(question_id)
                    finally:
                        with self.lock:
                            self.scene_status[question_id] = 3
                            self.live_addresses[question_id] = []
                            self._emit_event("scene_stopped", f"Scene {question_id} stopped (status=3)", qid=question_id)

                threading.Thread(target=_bg_stop, daemon=True).start()
            else:
                self.scene_status[question_id] = 3
                self.live_addresses[question_id] = []
                if prev != 3:
                    self._emit_event("scene_stopped", f"Scene {question_id} stopped (status=3)", qid=question_id)
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
        if cleaned not in valid_flags:
            self.submissions.append(
                {
                    "ts": round(time.time(), 3),
                    "elapsed_sec": round(self.elapsed_sec(), 1),
                    "qid": q["id"],
                    "name": q["name"],
                    "pass": False,
                    "duplicate": False,
                    "score": 0,
                }
            )
            self._emit_event("flag_wrong", f"Wrong flag on {q['id']} ({q['name']})", qid=q["id"])
            return _envelope(data={"is_pass": False, "score": 0, "is_duplicate": False})
        if cleaned in solved_set:
            self.submissions.append(
                {
                    "ts": round(time.time(), 3),
                    "elapsed_sec": round(self.elapsed_sec(), 1),
                    "qid": q["id"],
                    "name": q["name"],
                    "pass": True,
                    "duplicate": True,
                    "score": 0,
                }
            )
            return _envelope("AD-160014", "答案重复写入", "duplicate flag")

        solved_set.add(cleaned)
        rank = max(1, self.simulated_all_user_solved(q))
        mult = _rank_multiplier(rank) if self.simulate_competitors else 1.0
        per_flag_base = round(q["score"] / max(1, len(valid_flags)), 2)
        per_flag_ranked = round(per_flag_base * mult, 2)
        self.total_score = round(self.total_score + per_flag_base, 2)
        self.ranked_score = round(self.ranked_score + per_flag_ranked, 2)
        flag_idx = valid_flags.index(cleaned) + 1
        rec = {
            "ts": round(time.time(), 3),
            "elapsed_sec": round(self.elapsed_sec(), 1),
            "qid": q["id"],
            "name": q["name"],
            "flag_index": flag_idx,
            "pass": True,
            "duplicate": False,
            "score": per_flag_base,
            "ranked_score": per_flag_ranked,
            "simulated_rank": rank,
            "multiplier": mult,
        }
        self.submissions.append(rec)
        self.solved_flag_details.setdefault(q["id"], []).append(rec)
        if len(solved_set) >= len(valid_flags):
            self.question_solved_at[q["id"]] = time.time()
        self._emit_event(
            "flag_pass",
            f"SOLVED flag {len(solved_set)}/{len(valid_flags)} on {q['id']} (+{per_flag_base} / ranked +{per_flag_ranked}, rank #{rank})",
            qid=q["id"],
        )
        self.persist()
        return _envelope(data={"is_pass": True, "score": per_flag_base, "is_duplicate": False})

    # --- Observer Aggregation (Read-only, Local Dashboard Only) ---

    def _fetch_observer_sources(self) -> dict[str, Any]:
        now = time.monotonic()
        if now - self._obs_cache_ts < 1.5:
            return self._obs_cache

        cairn_data: dict[str, Any] = {"available": False, "projects": {}, "by_qid": {}}
        if self.cairn_url:
            headers = {"Authorization": f"Bearer {self.cairn_admin_token}"} if self.cairn_admin_token else {}
            try:
                r = requests.get(f"{self.cairn_url}/projects", headers=headers, timeout=2.0)
                if r.status_code == 200:
                    plist = r.json()
                    cairn_data["available"] = True
                    for p in plist:
                        pid = p["id"]
                        title = str(p.get("title") or "")
                        # Match race-<qid>-<name>
                        matched_qid = None
                        if title.startswith("race-"):
                            parts = title.split("-", 2)
                            if len(parts) >= 2:
                                matched_qid = parts[1]
                        entry = {
                            "id": pid,
                            "title": title,
                            "status": p.get("status"),
                            "fact_count": p.get("fact_count", 0),
                            "intent_count": p.get("intent_count", 0),
                            "working_intent_count": p.get("working_intent_count", 0),
                            "reason": p.get("reason"),
                            "recent_facts": [],
                            "active_intents": [],
                        }
                        # Pull full detail for active or recently updated projects
                        if p.get("status") == "active" or matched_qid:
                            try:
                                dr = requests.get(f"{self.cairn_url}/projects/{pid}", headers=headers, timeout=2.0)
                                if dr.status_code == 200:
                                    detail = dr.json()
                                    facts = [f for f in detail.get("facts") or [] if f.get("id") not in ("origin", "goal")]
                                    entry["recent_facts"] = [
                                        {"id": f.get("id"), "description": str(f.get("description") or "")[:400]}
                                        for f in facts[-6:]
                                    ]
                                    intents = detail.get("intents") or []
                                    entry["active_intents"] = [
                                        {
                                            "id": i.get("id"),
                                            "worker": i.get("worker"),
                                            "description": str(i.get("description") or "")[:240],
                                            "concluded_at": i.get("concluded_at"),
                                        }
                                        for i in intents[-5:]
                                    ]
                                    # Passive leak audit on facts
                                    for f in facts[-4:]:
                                        self._audit_text_for_leaks(str(f.get("description") or ""), f"cairn_fact:{pid}:{f.get('id')}")
                            except Exception:
                                pass
                        cairn_data["projects"][pid] = entry
                        if matched_qid:
                            cairn_data["by_qid"][matched_qid] = entry
            except Exception:
                pass

        proxy_data: dict[str, Any] = {"available": False}
        if self.proxy_url:
            try:
                sr = requests.get(f"{self.proxy_url}/stats", timeout=1.5)
                hr = requests.get(f"{self.proxy_url}/health", timeout=1.5)
                if sr.status_code == 200:
                    proxy_data = {"available": True, **sr.json()}
                    if hr.status_code == 200:
                        proxy_data["health"] = hr.json()
            except Exception:
                pass

        orch_data: dict[str, Any] = {"available": False}
        if self.orch_state_file and self.orch_state_file.is_file():
            try:
                orch_data = {"available": True, **json.loads(self.orch_state_file.read_text(encoding="utf-8"))}
            except Exception:
                pass

        self._obs_cache = {"cairn": cairn_data, "proxy": proxy_data, "orchestrator": orch_data}
        self._obs_cache_ts = now
        return self._obs_cache

    def dashboard_snapshot(self) -> dict[str, Any]:
        obs = self._fetch_observer_sources()
        with self.lock:
            elapsed = self.elapsed_sec()
            remaining = max(0.0, self.duration_sec - elapsed)
            orch_qs = (obs.get("orchestrator") or {}).get("questions") or {}
            cairn_by_qid = (obs.get("cairn") or {}).get("by_qid") or {}

            questions_view = []
            total_flags = 0
            solved_flags_total = 0
            fully_solved_questions = 0
            visible_questions = 0
            categories_summary: dict[str, dict[str, Any]] = {}
            unstopped_solved = []

            for qid, q in self.questions.items():
                vis = self.is_visible(q)
                if vis:
                    visible_questions += 1
                f_total = len(self.active_flags[qid])
                f_solved = len(self.solved_flags.get(qid, set()))
                total_flags += f_total
                solved_flags_total += f_solved
                is_complete = f_total > 0 and f_solved >= f_total
                if is_complete:
                    fully_solved_questions += 1
                st = self.scene_status.get(qid, 3) if q["has_scene"] else None
                if is_complete and q["has_scene"] and st in (0, 1):
                    solved_ts = self.question_solved_at.get(qid, time.time())
                    if time.time() - solved_ts > 30.0:
                        unstopped_solved.append(qid)

                oq = orch_qs.get(qid) or {}
                cq = cairn_by_qid.get(qid)
                cat = q["category"]
                cs = categories_summary.setdefault(
                    cat, {"category": cat, "total_q": 0, "solved_q": 0, "total_flags": 0, "solved_flags": 0}
                )
                cs["total_q"] += 1
                cs["solved_q"] += 1 if is_complete else 0
                cs["total_flags"] += f_total
                cs["solved_flags"] += f_solved

                questions_view.append(
                    {
                        "id": qid,
                        "name": q["name"],
                        "category": cat,
                        "direction": q["direction"],
                        "difficulty": q["difficulty"],
                        "score": q["score"],
                        "wave": q["wave"],
                        "visible": vis,
                        "release_after_sec": q["release_after_sec"],
                        "has_scene": q["has_scene"],
                        "scene_status": st,
                        "scene_addresses": list(self.live_addresses.get(qid) or []) if st == 1 else [],
                        "current_user_solved": f_solved,
                        "total_flag_num": f_total,
                        "complete": is_complete,
                        "all_user_solved": self.simulated_all_user_solved(q),
                        "orch_status": oq.get("status") or ("solved" if is_complete else ("pending" if vis else "locked")),
                        "reopen_count": oq.get("reopen_count", 0),
                        "attempts_runs": oq.get("attempts_runs", 0),
                        "project_id": oq.get("project_id") or (cq["id"] if cq else None),
                        "cairn": cq,
                        "solved_details": list(self.solved_flag_details.get(qid) or []),
                    }
                )

            audit_copy = dict(self.audit)
            audit_copy["unstopped_solved_scenes"] = unstopped_solved

            return {
                "ts": time.time(),
                "clock": {
                    "elapsed_sec": round(elapsed, 1),
                    "remaining_sec": round(remaining, 1),
                    "duration_sec": self.duration_sec,
                    "time_scale": self.time_scale,
                },
                "summary": {
                    "total_questions": len(self.questions),
                    "visible_questions": visible_questions,
                    "solved_questions": fully_solved_questions,
                    "total_flags": total_flags,
                    "solved_flags": solved_flags_total,
                    "total_score": self.total_score,
                    "ranked_score": self.ranked_score,
                    "running_scenes": self.running_scene_count(),
                    "max_scenes": self.max_scenes,
                },
                "categories": list(categories_summary.values()),
                "questions": questions_view,
                "submissions": list(self.submissions[-60:]),
                "events": list(self.events)[-80:],
                "audit": audit_copy,
                "proxy": obs.get("proxy"),
                "orchestrator": {
                    "available": bool((obs.get("orchestrator") or {}).get("available")),
                    "updated_at": (obs.get("orchestrator") or {}).get("updated_at"),
                    "effective_max_scenes": (obs.get("orchestrator") or {}).get("effective_max_scenes"),
                },
                "cairn_available": bool((obs.get("cairn") or {}).get("available")),
            }

    def release_next_wave(self) -> list[str]:
        """Admin helper: immediately unlock the next unreleased wave."""
        with self.lock:
            hidden = [q for q in self.questions.values() if not self.is_visible(q)]
            if not hidden:
                return []
            min_rel = min(float(q["release_after_sec"]) for q in hidden)
            unlocked = []
            for q in hidden:
                if float(q["release_after_sec"]) <= min_rel + 1e-6:
                    q["release_after_sec"] = 0.0
                    unlocked.append(q["id"])
            self._emit_event("admin_release", f"Manually released wave: {unlocked}")
            return unlocked

    def reset_all(self) -> None:
        if self.scene_mgr:
            self.scene_mgr.stop_all()
        with self.lock:
            self.started_at = time.monotonic()
            self.started_wall = time.time()
            self.total_score = 0.0
            self.ranked_score = 0.0
            self.submissions.clear()
            self.events.clear()
            self.scene_start_attempts.clear()
            self.scene_started_at.clear()
            self.question_solved_at.clear()
            self.audit = {
                "rate_limit_hits": 0,
                "scene_limit_hits": 0,
                "credential_leaks": [],
                "scene_faults_injected": 0,
                "scene_faults_recovered": 0,
                "total_api_calls": 0,
                "total_mcp_calls": 0,
            }
            for qid, q in self.questions.items():
                self.solved_flags[qid] = set()
                self.solved_flag_details[qid] = []
                if q["has_scene"]:
                    self.scene_status[qid] = 3
                    self.live_addresses[qid] = list(q["scene_addresses"])
            self._emit_event("admin_reset", "Simulation state reset")
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
    app = FastAPI(title="1:1 Mock Official AI-Race Platform + Local Observer")
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
                "ranked_score": state.ranked_score,
                "docker_enabled": state.docker_enabled,
            }

    # --- Official HTTP API (7 endpoints) ---

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
                # Verify token without burning rate limit on handshake
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

    # --- Local Observer Dashboard & Admin Controls (Local Eval Only) ---

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page():
        if DASHBOARD_HTML_PATH.is_file():
            return HTMLResponse(DASHBOARD_HTML_PATH.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>Dashboard HTML missing</h1>", status_code=404)

    @app.get("/api/dashboard/snapshot")
    def dashboard_snapshot():
        return JSONResponse(state.dashboard_snapshot())

    @app.get("/api/dashboard/stream")
    async def dashboard_stream(request: Request):
        async def event_gen():
            while True:
                if await request.is_disconnected():
                    break
                snap = await asyncio.to_thread(state.dashboard_snapshot)
                yield f"data: {json.dumps(snap, ensure_ascii=False)}\n\n"
                await asyncio.sleep(2.0)

        return StreamingResponse(
            event_gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/api/admin/release-next")
    def admin_release_next():
        unlocked = state.release_next_wave()
        return JSONResponse({"ok": True, "unlocked": unlocked})

    @app.post("/api/admin/inject-fault/{question_id}")
    def admin_inject_fault(question_id: str):
        with state.lock:
            q = state.questions.get(question_id)
            if not q or not q["has_scene"]:
                raise HTTPException(404, "scene question not found")
            q["force_next_fault"] = True
            state._emit_event("admin_fault", f"Armed scene_status=20 fault on next start for {question_id}", qid=question_id)
        return JSONResponse({"ok": True, "question_id": question_id})

    @app.post("/api/admin/reset")
    def admin_reset():
        state.reset_all()
        return JSONResponse({"ok": True})

    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="1:1 Mock Official AI-Race Platform + Local Observer")
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
    ap.add_argument("--dynamic-flags", action="store_true", help="Inject fresh random flags into Docker targets")
    ap.add_argument("--simulate-competitors", action="store_true", help="Enable 152-team rank scoring simulation")
    ap.add_argument("--time-scale", type=float, default=1.0)
    ap.add_argument("--duration-sec", type=float, default=14400.0)
    ap.add_argument("--cairn-url", default=os.environ.get("CAIRN_URL") or None)
    ap.add_argument("--cairn-admin-token", default=os.environ.get("CAIRN_ADMIN_TOKEN") or None)
    ap.add_argument("--proxy-url", default=os.environ.get("PROXY_URL") or None)
    ap.add_argument("--orch-state", default=None, help="Path to race-orchestrator-state.json for dashboard")
    args = ap.parse_args()

    secret_patterns = [
        v for k, v in os.environ.items()
        if any(tag in k.upper() for tag in ("API_KEY", "AGENT_TOKEN", "ADMIN_TOKEN")) and len(v.strip()) >= 8
    ]

    state = MockRacePlatformState(
        valid_token=args.token,
        max_scenes=args.max_scenes,
        rate_limit_rps=args.rate_limit,
        base_url=f"http://{args.target_host}:{args.port}",
        state_file=Path(args.state_file) if args.state_file else None,
        attachments_root=Path(args.attachments_dir) if args.attachments_dir else None,
        docker_enabled=args.docker_scenes,
        target_host=args.target_host,
        dynamic_flags=args.dynamic_flags,
        simulate_competitors=args.simulate_competitors,
        time_scale=args.time_scale,
        duration_sec=args.duration_sec,
        cairn_url=args.cairn_url,
        cairn_admin_token=args.cairn_admin_token,
        proxy_url=args.proxy_url,
        orch_state_file=Path(args.orch_state) if args.orch_state else None,
        secret_patterns=secret_patterns,
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
    print(f"[mock-platform] Live Dashboard: http://{args.host}:{args.port}/dashboard", flush=True)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
