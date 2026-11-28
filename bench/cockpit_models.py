"""Cockpit state models, strict event contract, 4-dimension status separation,
address hygiene, typed verdict grading, and connection health diagnostics.

This module powers the local Human Decision Cockpit (/dashboard) without
modifying any official competition API/MCP semantics.
"""

from __future__ import annotations

import ipaddress
import json
import math
import secrets
import subprocess
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

# Canonical 8 categories (with direction/tag normalization aliases)
CANONICAL_8_CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("应用系统", ("应用系统", "应用", "web", "app", "application")),
    ("移动安全", ("移动安全", "移动", "mobile", "android", "ios", "apk", "miniapp")),
    ("操作系统", ("操作系统", "系统", "system", "os", "linux", "windows", "host")),
    ("协议安全", ("协议安全", "协议", "ics", "protocol", "modbus", "s7", "iec104", "network")),
    ("数据库", ("数据库", "db", "database", "sql", "redis", "mysql", "postgres")),
    ("基础平台", ("基础平台", "基础", "infra", "platform", "middleware", "container", "docker", "k8s")),
    ("研发平台", ("研发平台", "研发", "dev", "devops", "git", "cicd", "pipeline")),
    ("综合渗透", ("综合渗透", "综合", "comprehensive", "chain", "intranet", "pentest")),
]

_ALIAS_TO_CANONICAL: dict[str, str] = {}
for _canon, _aliases in CANONICAL_8_CATEGORIES:
    for _a in _aliases:
        _ALIAS_TO_CANONICAL[_a.lower()] = _canon


def normalize_category(raw_category: str | None, raw_direction: str | None = None) -> tuple[str, bool]:
    """Map raw category/direction to canonical 8-category name when matched.

    Returns (display_name, is_canonical_8).
    """
    for candidate in (raw_category, raw_direction):
        if not candidate:
            continue
        key = str(candidate).strip().lower()
        if key in _ALIAS_TO_CANONICAL:
            return _ALIAS_TO_CANONICAL[key], True
    fallback = str(raw_category or raw_direction or "未分类").strip()
    return fallback, False


def iso_utc(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        if math.isnan(ts) or math.isinf(ts):
            return None
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).astimezone().isoformat(timespec="seconds")
    except Exception:
        return None


def safe_float(val: Any) -> float | None:
    if val is None or isinstance(val, bool):
        return None
    try:
        f = float(val)
        return None if (math.isnan(f) or math.isinf(f)) else f
    except (TypeError, ValueError):
        return None


def safe_int(val: Any) -> int | None:
    if val is None or isinstance(val, bool):
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def is_wildcard_ip(host: str | None) -> bool:
    if not host:
        return True
    h = host.strip().lower()
    if h in ("0.0.0.0", "::", "[::]", "*", ""):
        return True
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
        return ip.is_unspecified
    except ValueError:
        return False


def format_scene_addresses(
    raw_addresses: list[dict[str, Any]] | None,
    *,
    public_host: str | None = None,
) -> list[dict[str, Any]]:
    """Address hygiene (D05): separate internal bind target, mapped port, and configured reachable URL.

    Never turns 0.0.0.0 / :: into a clickable operator link and never guesses the dashboard host.
    """
    out: list[dict[str, Any]] = []
    explicit_pub = (public_host or "").strip()
    if explicit_pub and is_wildcard_ip(explicit_pub):
        explicit_pub = ""

    for addr in raw_addresses or []:
        proto = str(addr.get("protocol") or "tcp").strip().lower()
        bind_ip = str(addr.get("access_ip") or "").strip()
        port = safe_int(addr.get("access_port"))
        internal_target = f"{proto}://{bind_ip}:{port}" if (bind_ip and port is not None) else (bind_ip or "未上报")

        # Operator URL is ONLY created from an explicitly configured non-wildcard host or concrete IP
        operator_host = ""
        if explicit_pub:
            operator_host = explicit_pub
        elif bind_ip and not is_wildcard_ip(bind_ip):
            operator_host = bind_ip

        if operator_host and port is not None:
            operator_url = f"{proto}://{operator_host}:{port}"
            clickable = proto in ("http", "https")
            note = "已配置操作者可达入口" if explicit_pub else "容器直接绑定可达地址"
        else:
            operator_url = None
            clickable = False
            if is_wildcard_ip(bind_ip):
                note = f"目标仅上报通配绑定地址 ({bind_ip or '0.0.0.0'}:{port or '?'})，未配置 --public-host，无法假定看板主机即目标主机"
            else:
                note = "入口端口或主机未完整上报"

        out.append(
            {
                "protocol": proto,
                "bind_ip": bind_ip or None,
                "mapped_port": port,
                "internal_target": internal_target,
                "operator_url": operator_url,
                "clickable": clickable,
                "reachable_configured": operator_url is not None,
                "reachability_note": note,
            }
        )
    return out


def infer_grading_type(q: dict[str, Any], active_flags: list[str]) -> str:
    """Determine challenge verdict type: flag | poc | attachment | unconfigured (D04)."""
    explicit = str(q.get("grading_type") or "").strip().lower()
    if explicit in ("flag", "poc", "attachment", "unconfigured"):
        return explicit
    if len(active_flags) > 0:
        return "flag"
    qid_l = str(q.get("id") or "").lower()
    name_l = str(q.get("name") or "").lower()
    dir_l = str(q.get("direction") or "").lower()
    if q.get("poc_spec") or "poc" in qid_l or "poc" in name_l or dir_l == "poc":
        return "poc"
    if (not q.get("has_scene", True)) and bool(q.get("attachments")):
        return "attachment"
    return "unconfigured"


def default_milestones(grading_type: str) -> list[dict[str, Any]]:
    if grading_type == "poc":
        return [
            {"key": "artifact", "label": "PoC 产物生成", "status": "pending", "updated_at": None, "detail": ""},
            {"key": "replay", "label": "裁判环境重放", "status": "pending", "updated_at": None, "detail": ""},
            {"key": "verdict", "label": "验收判定", "status": "pending", "updated_at": None, "detail": ""},
        ]
    if grading_type == "attachment":
        return [
            {"key": "fetched", "label": "附件获取", "status": "pending", "updated_at": None, "detail": ""},
            {"key": "analyzed", "label": "离线分析", "status": "pending", "updated_at": None, "detail": ""},
            {"key": "reported", "label": "结论/报告产出", "status": "pending", "updated_at": None, "detail": ""},
            {"key": "verified", "label": "裁判验收", "status": "pending", "updated_at": None, "detail": ""},
        ]
    return []


def build_verdict_summary(
    q: dict[str, Any],
    *,
    active_flags: list[str],
    solved_flags: set[str],
    milestones: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build typed verdict progress — never produces misleading 0/0 (0%) (D04)."""
    gtype = infer_grading_type(q, active_flags)
    if gtype == "flag":
        total = len(active_flags)
        solved = len(solved_flags)
        if total <= 0:
            return {
                "type": "unconfigured",
                "status": "unconfigured",
                "complete": False,
                "solved": 0,
                "total": None,
                "pct": None,
                "label": "判定规则未配置",
                "short_label": "未配置",
                "milestones": [],
            }
        pct = round(100.0 * solved / total, 1)
        complete = solved >= total
        status = "passed" if complete else ("partial" if solved > 0 else "unscored")
        label = f"已全解 {solved}/{total} Flag" if complete else (f"部分得分 {solved}/{total} Flag" if solved > 0 else f"尚未得分 0/{total} Flag")
        return {
            "type": "flag",
            "status": status,
            "complete": complete,
            "solved": solved,
            "total": total,
            "pct": pct,
            "label": label,
            "short_label": f"Flag {solved}/{total}",
            "milestones": [],
        }

    if gtype in ("poc", "attachment"):
        ms = list(milestones or default_milestones(gtype))
        done = sum(1 for m in ms if m.get("status") == "done")
        failed = any(m.get("status") == "failed" for m in ms)
        total_ms = len(ms)
        final_key = "verdict" if gtype == "poc" else "verified"
        complete = any(m.get("key") == final_key and m.get("status") == "done" for m in ms)
        if complete:
            status = "passed"
            label = "PoC 验收通过" if gtype == "poc" else "附件分析验收通过"
        elif failed:
            status = "failed"
            label = "PoC 重放/验收未通过" if gtype == "poc" else "附件验收未通过"
        elif done > 0:
            status = "in_progress"
            label = f"{'PoC' if gtype == 'poc' else '附件'} 里程碑 {done}/{total_ms}"
        else:
            status = "unscored"
            label = "PoC 待生成产物" if gtype == "poc" else "附件待获取与分析"
        return {
            "type": gtype,
            "status": status,
            "complete": complete,
            "solved": done,
            "total": total_ms,
            "pct": round(100.0 * done / total_ms, 1) if total_ms > 0 else None,
            "label": label,
            "short_label": f"{'PoC' if gtype == 'poc' else '附件'} {done}/{total_ms}",
            "milestones": ms,
        }

    return {
        "type": "unconfigured",
        "status": "unconfigured",
        "complete": False,
        "solved": None,
        "total": None,
        "pct": None,
        "label": "判定规则未配置（不适用 Flag 计数）",
        "short_label": "未配置",
        "milestones": [],
    }


def normalize_submission_record(raw: dict[str, Any], *, simulate_competitors: bool = False) -> dict[str, Any]:
    """Strictly normalize submission / score records to eliminate undefined / NaN / fake 00:00:00 (D01)."""
    sub_id = str(raw.get("submission_id") or f"sub_{secrets.token_hex(4)}")
    ts = safe_float(raw.get("ts"))
    elapsed = safe_float(raw.get("elapsed_sec"))
    score = safe_float(raw.get("score"))
    ranked_score = safe_float(raw.get("ranked_score"))
    sim_rank = safe_int(raw.get("simulated_rank"))
    flag_index = safe_int(raw.get("flag_index"))
    mult = safe_float(raw.get("multiplier"))

    rank_applicable = bool(simulate_competitors and sim_rank is not None and ranked_score is not None)
    flag_val = str(raw["flag"]).strip() if raw.get("flag") else None
    return {
        "submission_id": sub_id,
        "attempt_id": raw.get("attempt_id"),
        "qid": str(raw.get("qid") or ""),
        "name": str(raw.get("name") or raw.get("qid") or ""),
        "ts": ts,
        "submitted_at_iso": iso_utc(ts),
        "elapsed_sec": elapsed,
        "time_reported": (elapsed is not None) or (ts is not None),
        "flag_index": flag_index,
        "flag_label": f"Flag #{flag_index}" if flag_index is not None else "编号未上报",
        "flag": flag_val,
        "pass": bool(raw.get("pass")),
        "duplicate": bool(raw.get("duplicate")),
        "score": score,
        "ranked_score": ranked_score if rank_applicable else None,
        "simulated_rank": sim_rank if rank_applicable else None,
        "multiplier": mult if rank_applicable else None,
        "rank_applicable": rank_applicable,
        "rank_note": None if rank_applicable else ("排名仿真未启用（不适用）" if not simulate_competitors else "排名字段未上报"),
        "event_id": raw.get("event_id"),
    }


def compute_four_states(
    *,
    q: dict[str, Any],
    visible: bool,
    raw_scene_status: int | None,
    ever_started: bool,
    last_stop_reason: str | None,
    last_stopped_at: float | None,
    orch_q: dict[str, Any] | None,
    cairn_q: dict[str, Any] | None,
    verdict: dict[str, Any],
    active_attempt: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compute the 4 strictly orthogonal state dimensions (D02, D03, D12):
      1. env_state      (not_applicable | never_started | starting | running | stopping | stopped | failed)
      2. schedule_state (locked | queued | running | external_active | revisit | exhausted | completed)
      3. worker_state   (running | waiting_tool | waiting_llm | idle | offline | unassigned | unknown)
      4. verdict_state  (from typed verdict summary)
    """
    # 1. Environment state (fixes D02: stopped != never_started)
    if not q.get("has_scene", True):
        env_code = "not_applicable"
        env_label = "纯附件（无在线场景）"
    elif raw_scene_status == 0:
        env_code = "starting"
        env_label = "启动中"
    elif raw_scene_status == 1:
        env_code = "running"
        env_label = "环境运行中"
    elif raw_scene_status == 2:
        env_code = "stopping"
        env_label = "停止中"
    elif raw_scene_status == 20:
        env_code = "failed"
        env_label = "启动失败"
    elif raw_scene_status == 3:
        if ever_started:
            env_code = "stopped"
            env_label = "已停止"
        else:
            env_code = "never_started"
            env_label = "未启动"
    else:
        env_code = "never_started" if not ever_started else "stopped"
        env_label = "未启动" if not ever_started else "已停止"

    # 2. Schedule state (fixes D03: running scene NEVER labelled '待调度')
    oq_status = str((orch_q or {}).get("status") or "").lower()
    if not visible:
        sched_code = "locked"
        sched_label = f"波次 {q.get('wave', '?')} 未放出"
    elif verdict.get("complete") or oq_status == "solved":
        sched_code = "completed"
        sched_label = "已完成"
    elif oq_status == "running":
        sched_code = "running"
        sched_label = "调度执行中"
    elif env_code in ("starting", "running"):
        # Hard invariant (D03): active environment without orchestrator record is external_active, NOT queued!
        sched_code = "external_active"
        sched_label = "外部运行中"
    elif oq_status == "revisit":
        sched_code = "revisit"
        sched_label = "待回杀"
    elif oq_status == "exhausted":
        sched_code = "exhausted"
        sched_label = "预算耗尽"
    elif cairn_q and cairn_q.get("status") == "active":
        sched_code = "running"
        sched_label = "Cairn 执行中"
    else:
        sched_code = "queued"
        sched_label = "待调度"

    # 3. Worker state (fixes D08/D12: explicitly distinguishes offline/unassigned/heartbeat stale)
    worker_id = None
    active_phase = None
    current_tool = None
    last_hb = None
    hb_age = None
    hb_stale = False
    waiting_reason = None

    if cairn_q:
        reason_info = cairn_q.get("reason")
        intents = cairn_q.get("active_intents") or []
        open_working = [i for i in intents if not i.get("concluded_at") and i.get("worker")]
        open_unclaimed = [i for i in intents if not i.get("concluded_at") and not i.get("worker")]

        if reason_info and reason_info.get("worker"):
            worker_id = reason_info.get("worker")
            active_phase = "reason"
            last_hb = reason_info.get("last_heartbeat_at")
            waiting_reason = "正在进行图推理与下一步规划"
        elif open_working:
            w = open_working[-1]
            worker_id = w.get("worker")
            active_phase = "explore"
            current_tool = w.get("description")
            last_hb = w.get("last_heartbeat_at")
        elif cairn_q.get("status") == "active" and cairn_q.get("fact_count", 0) <= 2 and not intents:
            active_phase = "bootstrap"
            waiting_reason = "等待 Bootstrap Worker 认领或首轮初始化"
        elif open_unclaimed:
            active_phase = "queued_intent"
            waiting_reason = f"有 {len(open_unclaimed)} 条 Intent 等待空闲 Worker 认领"

    if last_hb:
        try:
            dt = datetime.fromisoformat(str(last_hb).replace("Z", "+00:00"))
            hb_age = round(max(0.0, time.time() - dt.timestamp()), 1)
            hb_stale = hb_age > 90.0
        except Exception:
            hb_age = None

    if worker_id:
        if hb_stale:
            w_code = "offline"
            w_label = "Worker 心跳过期"
            waiting_reason = f"最近心跳距今 {hb_age}s（>90s），可能已断连或卡死"
        elif active_phase == "reason":
            w_code = "waiting_llm"
            w_label = "模型推理中"
        else:
            w_code = "running"
            w_label = "Worker 执行中"
    elif sched_code in ("running", "external_active") or env_code == "running":
        if cairn_q is None:
            w_code = "offline"
            w_label = "无活跃 Worker（未接入 Cairn）"
            waiting_reason = "环境存活但未关联到 Cairn 活跃 Worker，可能由外部脚本或手动启动"
        else:
            w_code = "unassigned"
            w_label = "等待 Worker 分配"
            waiting_reason = waiting_reason or "项目已创建，等待调度器分配 Worker 槽位"
    elif sched_code == "completed":
        w_code = "idle"
        w_label = "已结束"
    else:
        w_code = "idle"
        w_label = "未分配"

    return {
        "env": {
            "code": env_code,
            "label": env_label,
            "raw_scene_status": raw_scene_status,
            "ever_started": ever_started,
            "last_stop_reason": last_stop_reason,
            "last_stopped_at": last_stopped_at,
            "last_stopped_at_iso": iso_utc(last_stopped_at),
        },
        "schedule": {
            "code": sched_code,
            "label": sched_label,
            "reopen_count": int((orch_q or {}).get("reopen_count") or 0),
            "attempts_runs": int((orch_q or {}).get("attempts_runs") or (active_attempt.get("attempt_number") if active_attempt else 0)),
        },
        "worker": {
            "code": w_code,
            "label": w_label,
            "worker_id": worker_id,
            "phase": active_phase,
            "current_tool": current_tool,
            "last_heartbeat_at": last_hb,
            "heartbeat_age_sec": hb_age,
            "heartbeat_stale": hb_stale,
            "waiting_reason": waiting_reason,
        },
        "verdict": verdict,
    }


class EventStore:
    """Ordered, deduplicatable structured event ring buffer with monotonic seq (Section 6.1)."""

    def __init__(self, run_id: str, maxlen: int = 800):
        self.run_id = run_id
        self._seq = 0
        self._events: deque[dict[str, Any]] = deque(maxlen=maxlen)

    @property
    def last_seq(self) -> int:
        return self._seq

    def emit(
        self,
        *,
        event_type: str,
        message: str,
        source: str = "platform",
        severity: str = "info",
        elapsed_sec: float | None = None,
        challenge_id: str | None = None,
        attempt_id: str | None = None,
        worker_id: str | None = None,
        decision_id: str | None = None,
        tool_call_id: str | None = None,
        submission_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._seq += 1
        now = time.time()
        ev = {
            "event_id": f"evt_{self.run_id[:6]}_{self._seq:06d}",
            "seq": self._seq,
            "run_id": self.run_id,
            "ts": round(now, 3),
            "observed_at": iso_utc(now),
            "elapsed_sec": round(elapsed_sec, 1) if elapsed_sec is not None else None,
            "event_type": event_type,
            "kind": event_type,  # backward compat
            "source": source,
            "severity": severity,
            "challenge_id": challenge_id,
            "qid": challenge_id,  # backward compat
            "attempt_id": attempt_id,
            "worker_id": worker_id,
            "decision_id": decision_id,
            "tool_call_id": tool_call_id,
            "submission_id": submission_id,
            "message": message,
            "details": details or {},
        }
        self._events.append(ev)
        return ev

    def query(
        self,
        *,
        since_seq: int = 0,
        challenge_id: str | None = None,
        attempt_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        out = []
        for ev in self._events:
            if ev["seq"] <= since_seq:
                continue
            if challenge_id and ev.get("challenge_id") != challenge_id:
                continue
            if attempt_id and ev.get("attempt_id") != attempt_id:
                continue
            out.append(ev)
        if limit > 0 and len(out) > limit:
            return out[-limit:]
        return out

    def recent(self, limit: int = 120) -> list[dict[str, Any]]:
        items = list(self._events)
        return items[-limit:] if limit > 0 else items

    def clear(self, new_run_id: str | None = None) -> None:
        if new_run_id:
            self.run_id = new_run_id
        self._seq = 0
        self._events.clear()


def sample_docker_container_stats(label_prefix: str = "eval-mock-scene") -> dict[str, Any]:
    """Best-effort, non-blocking sample of running container CPU/Mem for cockpit resource view.

    Returns explicit status='unavailable' rather than fabricating 0% / 0 MB.
    """
    now = time.time()
    try:
        proc = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}"],
            capture_output=True,
            text=True,
            timeout=4.0,
            check=False,
        )
        if proc.returncode != 0:
            return {
                "available": False,
                "observed_at": iso_utc(now),
                "reason": (proc.stderr or "docker stats 返回非零状态").strip()[:200],
                "containers": {},
            }
        by_name: dict[str, dict[str, Any]] = {}
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            name = str(obj.get("Name") or "")
            if not name:
                continue
            if label_prefix in name or "cairn-" in name:
                by_name[name] = {
                    "name": name,
                    "cpu_perc": obj.get("CPUPerc"),
                    "mem_usage": obj.get("MemUsage"),
                    "mem_perc": obj.get("MemPerc"),
                    "pids": obj.get("PIDs"),
                    "net_io": obj.get("NetIO"),
                }
        return {
            "available": True,
            "observed_at": iso_utc(now),
            "reason": None,
            "containers": by_name,
        }
    except FileNotFoundError:
        return {
            "available": False,
            "observed_at": iso_utc(now),
            "reason": "当前主机未安装 docker CLI，无法采集容器 CPU/内存指标",
            "containers": {},
        }
    except Exception as exc:
        return {
            "available": False,
            "observed_at": iso_utc(now),
            "reason": f"容器资源采集失败: {exc}",
            "containers": {},
        }


def build_taxonomy_summary(questions_view: list[dict[str, Any]]) -> dict[str, Any]:
    """Build canonical 8-category matrix + any extra non-standard categories (fixes D06)."""
    canon_map: dict[str, dict[str, Any]] = {}
    for cname, _ in CANONICAL_8_CATEGORIES:
        canon_map[cname] = {
            "category": cname,
            "is_canonical": True,
            "included": False,
            "total_q": 0,
            "solved_q": 0,
            "flag_q": 0,
            "total_flags": 0,
            "solved_flags": 0,
            "non_flag_q": 0,
            "non_flag_solved": 0,
        }

    extra_map: dict[str, dict[str, Any]] = {}
    for q in questions_view:
        cname = q["canonical_category"]
        is_canon = bool(q["is_canonical_category"])
        target = canon_map[cname] if is_canon and cname in canon_map else extra_map.setdefault(
            cname,
            {
                "category": cname,
                "is_canonical": False,
                "included": True,
                "total_q": 0,
                "solved_q": 0,
                "flag_q": 0,
                "total_flags": 0,
                "solved_flags": 0,
                "non_flag_q": 0,
                "non_flag_solved": 0,
            },
        )
        target["included"] = True
        target["total_q"] += 1
        if q["complete"]:
            target["solved_q"] += 1
        v = q["states"]["verdict"]
        if v["type"] == "flag" and (v.get("total") or 0) > 0:
            target["flag_q"] += 1
            target["total_flags"] += int(v["total"])
            target["solved_flags"] += int(v["solved"])
        else:
            target["non_flag_q"] += 1
            if q["complete"]:
                target["non_flag_solved"] += 1

    canon_list = list(canon_map.values())
    extra_list = list(extra_map.values())
    included_canon = sum(1 for c in canon_list if c["included"])
    total_active_cats = included_canon + len(extra_list)

    if included_canon == 8 and not extra_list:
        headline = "八大类场景覆盖进度（8/8 类全部纳入）"
    elif extra_list:
        headline = f"本场共 {total_active_cats} 类场景（对照八大类基线：已纳入 {included_canon}/8 类，未纳入 {8 - included_canon} 类，另含 {len(extra_list)} 个扩展类）"
    else:
        headline = f"本场共 {included_canon} 类场景（对照八大类基线：已纳入 {included_canon}/8 类，其余 {8 - included_canon} 类本场未纳入）"

    return {
        "headline": headline,
        "canonical_total": 8,
        "canonical_included": included_canon,
        "extra_count": len(extra_list),
        "canonical_categories": canon_list,
        "extra_categories": extra_list,
        "active_categories": [c for c in canon_list if c["included"]] + extra_list,
    }


def build_system_diagnosis(
    *,
    summary: dict[str, Any],
    connections: dict[str, dict[str, Any]],
    questions_view: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Explicitly explain compound system states so humans never confuse container liveness with Agent reasoning (D08, D12)."""
    notes: list[dict[str, str]] = []
    running_scenes = int(summary.get("running_scenes") or 0)
    cairn_st = connections["cairn"]["status"]
    orch_st = connections["orchestrator"]["status"]
    proxy_st = connections["proxy"]["status"]

    if running_scenes > 0 and cairn_st != "connected":
        notes.append(
            {
                "level": "warn",
                "title": "环境运行中，但 Cairn 服务端未连接",
                "detail": (
                    f"当前有 {running_scenes} 个在线靶机场景正在运行，但 Cairn 观测连接状态为「{cairn_st}」"
                    f"（原因：{connections['cairn'].get('error_reason') or '未配置'}）。"
                    "这说明场景由外部测试脚本或独立进程启动，看板目前只能看到裁判侧状态，无法观测 Worker 推理轨迹与心跳。"
                ),
            }
        )
    if running_scenes > 0 and orch_st != "connected":
        notes.append(
            {
                "level": "info",
                "title": "总控状态文件未接管当前运行场景",
                "detail": (
                    "场景正在运行，但未读取到最新 race-orchestrator-state.json（总控处于等待/未配置状态）。"
                    "相关题目已标记为「外部运行中」而非「待调度」，避免状态冲突。"
                ),
            }
        )
    if proxy_st != "connected":
        notes.append(
            {
                "level": "warn",
                "title": "模型代理未连接：Token 与模型版本为未知（非零消耗）",
                "detail": (
                    f"Token Proxy 状态为「{proxy_st}」（{connections['proxy'].get('error_reason') or '未配置'}）。"
                    "当前无法采集模型请求次数、Token 用量与思考强度配置；面板中显示为「未知/未连接」，切勿理解为 0 消耗。"
                ),
            }
        )
    if any(q["states"]["env"]["code"] == "failed" for q in questions_view):
        failed_ids = [q["id"] for q in questions_view if q["states"]["env"]["code"] == "failed"]
        notes.append(
            {
                "level": "error",
                "title": f"存在启动失败的场景：{', '.join(failed_ids)}",
                "detail": "场景返回启动失败状态（status=20），需先执行停止确认回到已停止（3）后再重新启动。",
            }
        )
    stalled = [q for q in questions_view if (q.get("stall") or {}).get("level") in ("warn", "critical")]
    if stalled:
        crit = any(q["stall"]["level"] == "critical" for q in stalled)
        desc = "；".join(
            f"{q['id']}（{' / '.join(q['stall']['reasons'][:2])}）" for q in stalled[:3]
        )
        notes.append(
            {
                "level": "error" if crit else "warn",
                "title": f"停滞/空转雷达告警：{len(stalled)} 道题疑似卡死或高耗无进展",
                "detail": f"{desc}。建议切入「工具调用摘要」或「解题过程 DAG」核查，必要时执行单题跳过或重跑。",
            }
        )
    return notes


def compute_stall_signal(
    *,
    states: dict[str, Any],
    no_progress_sec: float | None,
    llm_usage: dict[str, Any] | None,
    cairn_q: dict[str, Any] | None,
    skipped: bool = False,
) -> dict[str, Any]:
    """Compute per-challenge stall / spin-loop decision signal (ok | warn | critical)."""
    if skipped:
        return {"level": "ok", "label": "已人工跳过", "reasons": []}
    sched_code = (states.get("schedule") or {}).get("code")
    env_code = (states.get("env") or {}).get("code")
    if sched_code == "completed":
        return {"level": "ok", "label": "已完成", "reasons": []}
    is_active = sched_code in ("running", "external_active") or env_code in ("starting", "running")
    if not is_active:
        return {"level": "ok", "label": "未运行", "reasons": []}

    reasons: list[str] = []
    level = "ok"

    def _bump(lv: str, msg: str) -> None:
        nonlocal level
        reasons.append(msg)
        if lv == "critical":
            level = "critical"
        elif lv == "warn" and level == "ok":
            level = "warn"

    w = states.get("worker") or {}
    if w.get("heartbeat_stale"):
        _bump("critical", f"Worker 心跳过期 ({w.get('heartbeat_age_sec')}s)")

    u = llm_usage or {}
    err_streak = int(u.get("error_streak") or 0)
    rep_streak = int(u.get("repeat_streak") or 0)
    calls = int(u.get("calls") or 0)
    solved = int((states.get("verdict") or {}).get("solved") or 0)
    fact_cnt = int((cairn_q or {}).get("fact_count") or 0)

    if err_streak >= 5:
        _bump("critical", f"工具连续报错 {err_streak} 次")
    elif err_streak >= 3:
        _bump("warn", f"工具连续报错 {err_streak} 次")

    if rep_streak >= 5:
        _bump("critical", f"疑似重复命令空转 {rep_streak} 次")
    elif rep_streak >= 3:
        _bump("warn", f"疑似重复命令空转 {rep_streak} 次")

    if calls >= 25 and solved == 0 and fact_cnt <= 3:
        _bump("critical", f"已调用 LLM {calls} 轮仍无突破")
    elif calls >= 15 and solved == 0 and fact_cnt <= 2:
        _bump("warn", f"已调用 LLM {calls} 轮无进展")

    if no_progress_sec is not None:
        if no_progress_sec >= 360:
            _bump("critical", f"已 {int(no_progress_sec)}s 无新进展")
        elif no_progress_sec >= 180:
            _bump("warn", f"已 {int(no_progress_sec)}s 无新进展")

    label = "推进正常" if level == "ok" else ("严重停滞/疑似卡死" if level == "critical" else "疑似停滞/空转")
    return {"level": level, "label": label, "reasons": reasons}


def _fmt_sec_hms(sec: float | None) -> str:
    if sec is None or sec < 0:
        return "00:00:00"
    s = int(sec)
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def _budget_level(pct: float | None, configured: bool) -> str:
    if not configured or pct is None:
        return "na"
    if pct >= 90.0:
        return "critical"
    if pct >= 70.0:
        return "warn"
    return "ok"


def build_question_budgets(
    *,
    q: dict[str, Any],
    timers: dict[str, Any],
    states: dict[str, Any],
    llm_usage: dict[str, Any] | None,
    orch_raw: dict[str, Any] | None,
    orch_q: dict[str, Any] | None,
    attempts_count: int,
    defaults: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build per-challenge budget allocation & consumption rows (honest: never fabricates unconfigured caps)."""
    defs = defaults or {}
    oq = orch_q or {}
    oraw = orch_raw or {}
    u = llm_usage or {}

    items: list[dict[str, Any]] = []

    # 1. Time Budget (Orchestrator budget_sec or race.yaml time_budget_sec)
    time_limit = safe_float(oq.get("budget_sec")) or safe_float(q.get("time_budget_sec")) or safe_float(defs.get("time_budget_sec"))
    cur_sec = safe_float(timers.get("current_attempt_sec"))
    cum_sec = safe_float(timers.get("cumulative_active_sec")) or 0.0
    time_used = round(cur_sec if (cur_sec is not None and cur_sec > 0) else cum_sec, 1)
    if time_limit and time_limit > 0:
        pct = round(min(100.0, (time_used / time_limit) * 100.0), 1)
        items.append(
            {
                "key": "time",
                "label": "时间预算",
                "used": time_used,
                "limit": time_limit,
                "used_text": _fmt_sec_hms(time_used),
                "limit_text": _fmt_sec_hms(time_limit),
                "pct": pct,
                "configured": True,
                "level": _budget_level(pct, True),
                "note": f"累计投入 {_fmt_sec_hms(cum_sec)} · 剩余 {_fmt_sec_hms(max(0.0, time_limit - time_used))}",
            }
        )
    else:
        items.append(
            {
                "key": "time",
                "label": "时间预算",
                "used": time_used,
                "limit": None,
                "used_text": _fmt_sec_hms(time_used),
                "limit_text": "未设上限",
                "pct": None,
                "configured": False,
                "level": "na",
                "note": "未从总控或配置读取到单题时间预算",
            }
        )

    # 2. Stale / No-Progress Timeout Budget
    stale_limit = safe_float(q.get("stale_timeout_sec")) or safe_float(oraw.get("stale_timeout_sec")) or safe_float(defs.get("stale_timeout_sec"))
    stale_used = safe_float(timers.get("no_progress_sec")) or 0.0
    if stale_limit and stale_limit > 0:
        pct = round(min(100.0, (stale_used / stale_limit) * 100.0), 1)
        items.append(
            {
                "key": "stale",
                "label": "无进展超时预算",
                "used": stale_used,
                "limit": stale_limit,
                "used_text": _fmt_sec_hms(stale_used),
                "limit_text": _fmt_sec_hms(stale_limit),
                "pct": pct,
                "configured": True,
                "level": _budget_level(pct, True),
                "note": "距上次新得分/进展耗时，触顶后总控将自动挂起切题",
            }
        )

    # 3. Token Budget (optional cap from race.yaml; shows honest used tokens + cache read even when uncapped)
    tok_in = int(u.get("input") or 0)
    tok_out = int(u.get("output") or 0)
    tok_cache = int(u.get("cache_read") or 0)
    tok_used = tok_in + tok_out
    tok_limit = safe_int(q.get("token_budget")) or safe_int(defs.get("token_budget"))
    if tok_limit and tok_limit > 0:
        pct = round(min(100.0, (tok_used / tok_limit) * 100.0), 1)
        items.append(
            {
                "key": "tokens",
                "label": "Token 预算 (In+Out)",
                "used": tok_used,
                "limit": tok_limit,
                "used_text": f"{tok_used:,}",
                "limit_text": f"{tok_limit:,}",
                "pct": pct,
                "configured": True,
                "level": _budget_level(pct, True),
                "note": f"In {tok_in:,} / Out {tok_out:,} / Cache Read {tok_cache:,}",
            }
        )
    else:
        items.append(
            {
                "key": "tokens",
                "label": "Token 消耗 (In+Out)",
                "used": tok_used,
                "limit": None,
                "used_text": f"{tok_used:,}" if u else "尚无归因",
                "limit_text": "未设上限",
                "pct": None,
                "configured": False,
                "level": "na",
                "note": (f"In {tok_in:,} / Out {tok_out:,} / Cache Read {tok_cache:,}" if u else "可在 race.yaml 配 token_budget 开启占比预警"),
            }
        )

    # 4. LLM Call Turn Budget (optional max_llm_calls)
    calls_used = int(u.get("calls") or 0)
    calls_limit = safe_int(q.get("max_llm_calls")) or safe_int(defs.get("max_llm_calls"))
    if calls_limit and calls_limit > 0:
        pct = round(min(100.0, (calls_used / calls_limit) * 100.0), 1)
        items.append(
            {
                "key": "llm_calls",
                "label": "LLM 轮次预算",
                "used": calls_used,
                "limit": calls_limit,
                "used_text": f"{calls_used} 轮",
                "limit_text": f"{calls_limit} 轮",
                "pct": pct,
                "configured": True,
                "level": _budget_level(pct, True),
                "note": f"工具调用 {int(u.get('tool_calls') or 0)} 次（报错 {int(u.get('tool_errors') or 0)}）",
            }
        )
    elif calls_used > 0:
        items.append(
            {
                "key": "llm_calls",
                "label": "LLM 轮次消耗",
                "used": calls_used,
                "limit": None,
                "used_text": f"{calls_used} 轮",
                "limit_text": "未设上限",
                "pct": None,
                "configured": False,
                "level": "na",
                "note": f"工具调用 {int(u.get('tool_calls') or 0)} 次（报错 {int(u.get('tool_errors') or 0)}）",
            }
        )

    # 5. Attempt / Rotation Budget (Orchestrator default max_attempts = 2)
    att_used = max(int(attempts_count), int((states.get("schedule") or {}).get("attempts_runs") or 0))
    att_limit = safe_int(q.get("max_attempts")) or safe_int(oraw.get("max_attempts")) or safe_int(defs.get("max_attempts")) or 2
    att_pct = round(min(100.0, (att_used / att_limit) * 100.0), 1) if att_limit > 0 else None
    items.append(
        {
            "key": "attempts",
            "label": "尝试轮换预算",
            "used": att_used,
            "limit": att_limit,
            "used_text": f"{att_used} 次",
            "limit_text": f"{att_limit} 次",
            "pct": att_pct,
            "configured": True,
            "level": _budget_level(att_pct, True),
            "note": "超预算后从回杀队列转为预算耗尽 (exhausted)",
        }
    )

    # 6. Multi-Flag Reopen Budget (Orchestrator default max_reopens = 3)
    reopen_used = int((states.get("schedule") or {}).get("reopen_count") or 0)
    reopen_limit = safe_int(q.get("max_reopens")) or safe_int(oraw.get("max_reopens")) or safe_int(defs.get("max_reopens")) or 3
    reopen_pct = round(min(100.0, (reopen_used / reopen_limit) * 100.0), 1) if reopen_limit > 0 else None
    items.append(
        {
            "key": "reopens",
            "label": "Reopen 复开预算",
            "used": reopen_used,
            "limit": reopen_limit,
            "used_text": f"{reopen_used} 次",
            "limit_text": f"{reopen_limit} 次",
            "pct": reopen_pct,
            "configured": True,
            "level": _budget_level(reopen_pct, True),
            "note": "多 Flag 提前结束时自动 /reopen 唤醒上限",
        }
    )

    return items
