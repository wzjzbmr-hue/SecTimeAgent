#!/usr/bin/env python3
"""LLM 记账、密钥托管与白名单主备切换代理。

作用：
  1. 宿主机托管真实上游 API Key（Worker 容器只放占位符，杜绝公开审计日志泄密）
  2. 支持配置赛场平台分配的白名单专属网关 URL（保留 Anthropic /v1 路径）
  3. 支持主备白名单路由自动故障转移（402 / 429(code=1113) / 401 / 连续 5xx 自动切备）
  4. 支持流式（SSE，兼容 data: 有无空格）与非流式 token 记账，带 90s 流式读超时保护

用法：
  # 兼容旧命令行：
  python bench/token_proxy.py --port 8100 \
      --route glm=https://open.bigmodel.cn/api/anthropic \
      --route ds=https://api.deepseek.com/anthropic

  # 比赛推荐（YAML 配置文件，宿主机注入真实 Key + 主备切换）：
  python bench/token_proxy.py --port 8100 --config config/proxy.yaml
"""

from __future__ import annotations

import argparse
from collections import deque
import json
import os
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
import uvicorn
import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

ROOT = Path(__file__).resolve().parent
LOG = ROOT / "results" / "tokens.jsonl"
LOG.parent.mkdir(exist_ok=True)


@dataclass
class RouteTarget:
    name: str
    url: str
    api_key: str = ""
    auth_header: str = "x-api-key"  # "x-api-key" | "bearer" | "both"
    model_override: str | None = None
    fallbacks: list[str] = field(default_factory=list)


ROUTES: dict[str, RouteTarget] = {}
COOLDOWN_UNTIL: dict[str, float] = {}
FAILOVER_COOLDOWN_SECONDS = 120.0
CONNECT_TIMEOUT_SECONDS = 15.0
READ_TIMEOUT_SECONDS = 90.0

LOCK = threading.Lock()
STATS: dict[str, dict[str, Any]] = {}
QID_STATS: dict[str, dict[str, Any]] = {}
ROUTE_LATENCIES: dict[str, deque[float]] = {}
LAST_FAILOVER: dict[str, Any] | None = None
TOOL_RING_ALL: deque[dict[str, Any]] = deque(maxlen=160)
TOOL_RING_BY_QID: dict[str, deque[dict[str, Any]]] = {}
TOOL_INDEX_BY_ID: dict[str, dict[str, Any]] = {}
_TOOL_SEQ = 0
LLM_TURNS_ALL: deque[dict[str, Any]] = deque(maxlen=100)
LLM_TURNS_BY_QID: dict[str, deque[dict[str, Any]]] = {}
_LLM_TURN_SEQ = 0
_TELEMETRY_Q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=256)
_TELEMETRY_DROPPED = 0
_THREAD_LOCAL = threading.local()

_QID_PAT = re.compile(r"(?:Challenge\s+ID|question_id)\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9_-]{1,31})", re.I)
_SECRET_PAT = re.compile(
    r"(Authorization:\s*(?:Bearer\s+)?[A-Za-z0-9._-]{4,}|x-api-key:\s*[A-Za-z0-9._-]{4,}|Bearer\s+[A-Za-z0-9._-]{6,}|CAIRN_PROJECT_TOKEN=\S+|sk-[A-Za-z0-9_-]{12,})",
    re.I,
)


def _redact_preview(text: str, limit: int = 180) -> str:
    clean = " ".join(str(text or "").split())
    clean = _SECRET_PAT.sub("[REDACTED]", clean)
    return (clean[:limit] + "…") if len(clean) > limit else clean


def _redact_detail(text: str, limit: int = 8192) -> str:
    """Keep multi-line formatting while redacting secrets and preserving head+tail on large logs."""
    clean = _SECRET_PAT.sub("[REDACTED]", str(text or "")).strip()
    if len(clean) <= limit:
        return clean
    head_len = int(limit * 0.6)
    tail_len = max(256, limit - head_len)
    omitted = len(clean) - head_len - tail_len
    return f"{clean[:head_len]}\n... [已截断 {omitted} 字符，保留头尾日志] ...\n{clean[-tail_len:]}"


def _percentile(vals: list[float], p: float) -> float | None:
    if not vals:
        return None
    ordered = sorted(vals)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * p))))
    return round(ordered[idx], 2)


def _summarize_tool_input(tool_name: str, inp: Any) -> str:
    if isinstance(inp, str):
        return _redact_preview(inp, 180)
    if not isinstance(inp, dict):
        return _redact_preview(str(inp), 180)
    for key in ("command", "cmd", "file_path", "path", "pattern", "query", "url", "description"):
        if inp.get(key):
            return _redact_preview(str(inp[key]), 180)
    return _redact_preview(json.dumps(inp, ensure_ascii=False), 180)


def _format_tool_input_detail(inp: Any) -> str:
    if isinstance(inp, str):
        return _redact_detail(inp, 4096)
    if isinstance(inp, dict):
        if len(inp) == 1 and isinstance(inp.get("command"), str):
            return _redact_detail(inp["command"], 4096)
        if isinstance(inp.get("command"), str):
            meta = {k: v for k, v in inp.items() if k != "command"}
            head = f"$ {inp['command']}"
            if meta:
                head += f"\n# params: {json.dumps(meta, ensure_ascii=False)}"
            return _redact_detail(head, 4096)
        return _redact_detail(json.dumps(inp, ensure_ascii=False, indent=2), 4096)
    return _redact_detail(str(inp), 4096)


def _infer_qid_from_payload(payload: dict[str, Any]) -> str | None:
    # Fast scan of system + first 2 messages (where Cairn Origin places "Challenge ID: <qid>")
    sys_field = payload.get("system")
    if isinstance(sys_field, str):
        m = _QID_PAT.search(sys_field[:1200])
        if m:
            return m.group(1)
    elif isinstance(sys_field, list):
        for blk in sys_field[:3]:
            if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                m = _QID_PAT.search(blk["text"][:1200])
                if m:
                    return m.group(1)
    msgs = payload.get("messages")
    if isinstance(msgs, list):
        for msg in msgs[:2]:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                m = _QID_PAT.search(content[:1600])
                if m:
                    return m.group(1)
            elif isinstance(content, list):
                for blk in content[:4]:
                    if isinstance(blk, dict) and isinstance(blk.get("text"), str):
                        m = _QID_PAT.search(blk["text"][:1600])
                        if m:
                            return m.group(1)
    return None


def _record_tool_results_from_request(payload: dict[str, Any], qid: str | None) -> None:
    """Attach tool_result status & latency back onto prior tool_use ring entries (zero extra I/O)."""
    msgs = payload.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return
    last_msg = msgs[-1]
    if not isinstance(last_msg, dict) or last_msg.get("role") != "user":
        return
    content = last_msg.get("content")
    if not isinstance(content, list):
        return
    now_ts = time.time()
    with LOCK:
        for blk in content:
            if not isinstance(blk, dict) or blk.get("type") != "tool_result":
                continue
            tuid = str(blk.get("tool_use_id") or "")
            if not tuid or tuid not in TOOL_INDEX_BY_ID:
                continue
            entry = TOOL_INDEX_BY_ID[tuid]
            if entry.get("result_recorded"):
                continue
            is_err = bool(blk.get("is_error"))
            raw_c = blk.get("content")
            if isinstance(raw_c, list):
                text_parts = [str(x.get("text") or "") for x in raw_c if isinstance(x, dict)]
                raw_text = "\n".join(text_parts)
            else:
                raw_text = str(raw_c or "")
            preview = _redact_preview(raw_text, 160)
            detail_out = _redact_detail(raw_text, 8192)
            entry["is_error"] = is_err
            entry["status"] = "error" if is_err else "ok"
            entry["result_preview"] = preview
            entry["output_detail"] = detail_out
            entry["duration_sec"] = round(max(0.0, now_ts - float(entry["ts"])), 2)
            entry["result_recorded"] = True
            eqid = entry.get("qid") or qid
            if eqid and eqid in QID_STATS:
                if is_err:
                    QID_STATS[eqid]["tool_errors"] += 1
                    QID_STATS[eqid]["error_streak"] += 1
                else:
                    QID_STATS[eqid]["error_streak"] = 0


def _record_tool_uses(
    tool_uses: list[dict[str, Any]],
    *,
    route: str,
    qid: str | None,
) -> None:
    global _TOOL_SEQ
    if not tool_uses:
        return
    now_ts = time.time()
    with LOCK:
        for tu in tool_uses:
            tuid = str(tu.get("id") or f"tu_{_TOOL_SEQ + 1}")
            tname = str(tu.get("name") or "tool")
            summary = _summarize_tool_input(tname, tu.get("input"))
            input_detail = _format_tool_input_detail(tu.get("input"))
            sig_key = f"{tname}:{summary[:40].lower()}"
            prev = TOOL_RING_BY_QID.get(qid)[-1] if (qid and TOOL_RING_BY_QID.get(qid)) else (TOOL_RING_ALL[-1] if TOOL_RING_ALL else None)
            repeat_streak = (int(prev.get("repeat_streak") or 1) + 1) if (prev and prev.get("_sig") == sig_key) else 1
            _TOOL_SEQ += 1
            entry = {
                "seq": _TOOL_SEQ,
                "tool_use_id": tuid,
                "ts": round(now_ts, 3),
                "route": route,
                "qid": qid,
                "tool_name": tname,
                "summary": summary,
                "input_detail": input_detail,
                "status": "running",
                "is_error": False,
                "result_preview": "",
                "output_detail": "",
                "duration_sec": None,
                "repeat_streak": repeat_streak,
                "result_recorded": False,
                "_sig": sig_key,
            }
            TOOL_RING_ALL.append(entry)
            if qid:
                ring = TOOL_RING_BY_QID.setdefault(qid, deque(maxlen=60))
                ring.append(entry)
                qs = QID_STATS.setdefault(
                    qid,
                    {
                        "calls": 0,
                        "failovers": 0,
                        "input": 0,
                        "output": 0,
                        "cache_read": 0,
                        "cache_write": 0,
                        "tool_calls": 0,
                        "tool_errors": 0,
                        "error_streak": 0,
                        "repeat_streak": 0,
                        "last_call_at": None,
                        "last_tool": None,
                    },
                )
                qs["tool_calls"] += 1
                qs["repeat_streak"] = max(qs["repeat_streak"], repeat_streak) if repeat_streak >= 2 else 0
                qs["last_tool"] = f"{tname}: {summary[:60]}"
            TOOL_INDEX_BY_ID[tuid] = entry
            if len(TOOL_INDEX_BY_ID) > 320:
                oldest = next(iter(TOOL_INDEX_BY_ID))
                TOOL_INDEX_BY_ID.pop(oldest, None)


def _http_session() -> requests.Session:
    sess = getattr(_THREAD_LOCAL, "session", None)
    if sess is None:
        sess = requests.Session()
        adapter = HTTPAdapter(pool_connections=32, pool_maxsize=32)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        _THREAD_LOCAL.session = sess
    return sess

app = FastAPI(title="Token Meter & Failover Proxy")

HOP_BY_HOP = {
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "transfer-encoding",
    "keep-alive",
}


def _resolve_secret(raw: str | None, env_name: str | None = None, file_path: str | None = None) -> str:
    if env_name:
        val = os.environ.get(env_name, "").strip()
        if val:
            return val
    if file_path:
        p = Path(file_path)
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    return (raw or "").strip()


def load_routes_from_config(config_path: Path) -> dict[str, RouteTarget]:
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    loaded: dict[str, RouteTarget] = {}
    for name, item in (data.get("routes") or {}).items():
        if isinstance(item, str):
            loaded[name] = RouteTarget(name=name, url=item.strip())
            continue
        url = str(item["url"]).strip()
        api_key = _resolve_secret(
            item.get("api_key"),
            item.get("api_key_env"),
            item.get("api_key_file"),
        )
        loaded[name] = RouteTarget(
            name=name,
            url=url,
            api_key=api_key,
            auth_header=str(item.get("auth_header") or "both").lower(),
            model_override=item.get("model_override"),
            fallbacks=list(item.get("fallbacks") or []),
        )
    return loaded


def _inject_auth_headers(headers: dict[str, str], target: RouteTarget) -> dict[str, str]:
    out = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
    if not target.api_key:
        return out
    # Remove any placeholder auth headers coming from Worker container
    for key in list(out):
        if key.lower() in ("authorization", "x-api-key"):
            out.pop(key, None)
    if target.auth_header == "x-api-key":
        out["x-api-key"] = target.api_key
    elif target.auth_header == "bearer":
        out["Authorization"] = f"Bearer {target.api_key}"
    else:
        out["x-api-key"] = target.api_key
        out["Authorization"] = f"Bearer {target.api_key}"
    return out


def _maybe_rewrite_model(body: bytes, target: RouteTarget) -> bytes:
    if not target.model_override or not body:
        return body
    try:
        payload = json.loads(body)
    except Exception:
        return body
    if isinstance(payload, dict) and "model" in payload:
        payload["model"] = target.model_override
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return body


def _is_fatal_quota_or_auth_error(resp: requests.Response) -> bool:
    if resp.status_code in (401, 402, 403):
        return True
    if resp.status_code == 429:
        try:
            err = resp.json().get("error") or {}
            code = str(err.get("code", "")) if isinstance(err, dict) else ""
        except Exception:
            code = ""
        if code in ("1113", "1310", "insufficient_quota", "quota_exceeded"):
            return True
    return False


def _candidate_chain(primary: str) -> list[RouteTarget]:
    if primary not in ROUTES:
        return []
    visited: list[str] = []
    queue = [primary]
    while queue:
        name = queue.pop(0)
        if name in visited or name not in ROUTES:
            continue
        visited.append(name)
        for fb in ROUTES[name].fallbacks:
            if fb not in visited and fb in ROUTES:
                queue.append(fb)
    now = time.monotonic()
    healthy = [ROUTES[n] for n in visited if COOLDOWN_UNTIL.get(n, 0.0) <= now]
    cooling = [ROUTES[n] for n in visited if COOLDOWN_UNTIL.get(n, 0.0) > now]
    return healthy + cooling


def _extract_prompt_summary_and_detail(payload: dict[str, Any] | None) -> tuple[str, str, str, int]:
    """Extract the incremental prompt/question sent on this LLM turn (without duplicating full history)."""
    if not isinstance(payload, dict):
        return ("prompt", "", "", 0)
    msgs = payload.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return ("prompt", "", "", 0)
    msg_count = len(msgs)
    last_msg = msgs[-1] if isinstance(msgs[-1], dict) else {}
    content = last_msg.get("content")
    text_parts: list[str] = []
    tool_res_parts: list[str] = []

    if isinstance(content, str):
        if content.strip():
            text_parts.append(content.strip())
    elif isinstance(content, list):
        for blk in content:
            if not isinstance(blk, dict):
                continue
            btype = blk.get("type")
            if btype == "text" and isinstance(blk.get("text"), str) and blk["text"].strip():
                text_parts.append(blk["text"].strip())
            elif btype == "tool_result":
                tuid = str(blk.get("tool_use_id") or "")
                is_err = bool(blk.get("is_error"))
                raw_c = blk.get("content")
                if isinstance(raw_c, list):
                    rc = "\n".join(str(x.get("text") or "") for x in raw_c if isinstance(x, dict))
                else:
                    rc = str(raw_c or "")
                prefix = f"[tool_result {tuid}{' ERROR' if is_err else ' OK'}]"
                tool_res_parts.append(f"{prefix}\n{rc[:1500]}")

    if text_parts and tool_res_parts:
        q_kind = "mixed"
    elif tool_res_parts and not text_parts:
        q_kind = "tool_feedback"
    else:
        q_kind = "prompt"

    combined = "\n\n".join(text_parts + tool_res_parts).strip()
    preview_src = text_parts[0] if text_parts else (tool_res_parts[0] if tool_res_parts else "")
    return (
        q_kind,
        _redact_preview(preview_src, 180),
        _redact_detail(combined, 4096),
        msg_count,
    )


def _record_llm_turn(
    *,
    route: str,
    actual_route: str,
    qid: str | None,
    requested_model: str | None,
    response_model: str | None,
    thinking_effort: str | None,
    started_wall: float,
    finished_wall: float,
    ttft_sec: float | None,
    dur_sec: float,
    status: int,
    failover: bool,
    usage: dict[str, Any],
    req_payload: dict[str, Any] | None,
    answer_text: str,
    thinking_text: str,
    tool_uses: list[dict[str, Any]],
) -> None:
    global _LLM_TURN_SEQ
    q_kind, q_preview, q_detail, msg_count = _extract_prompt_summary_and_detail(req_payload)
    ans_preview = _redact_preview(answer_text, 180) if answer_text else ""
    ans_detail = _redact_detail(answer_text, 6144) if answer_text else ""
    think_preview = _redact_preview(thinking_text, 160) if thinking_text else ""
    think_detail = _redact_detail(thinking_text, 4096) if thinking_text else ""
    tools_brief = [
        {
            "tool_use_id": str(tu.get("id") or ""),
            "name": str(tu.get("name") or "tool"),
            "summary": _summarize_tool_input(str(tu.get("name") or "tool"), tu.get("input")),
        }
        for tu in (tool_uses or [])
    ]
    with LOCK:
        _LLM_TURN_SEQ += 1
        entry = {
            "turn_seq": _LLM_TURN_SEQ,
            "qid": qid,
            "route": route,
            "actual_route": actual_route,
            "failover": failover,
            "requested_model": requested_model,
            "response_model": response_model or None,
            "thinking_effort": thinking_effort,
            "started_at": round(started_wall, 3),
            "finished_at": round(finished_wall, 3),
            "ttft_sec": round(ttft_sec, 2) if ttft_sec is not None else None,
            "dur_sec": round(dur_sec, 2),
            "status": status,
            "msg_count": msg_count,
            "input": int(usage.get("input_tokens") or 0),
            "output": int(usage.get("output_tokens") or 0),
            "cache_read": int(usage.get("cache_read_input_tokens") or 0),
            "cache_write": int(usage.get("cache_creation_input_tokens") or 0),
            "question_kind": q_kind,
            "question_preview": q_preview,
            "question_detail": q_detail,
            "thinking_preview": think_preview,
            "thinking_detail": think_detail,
            "answer_preview": ans_preview,
            "answer_detail": ans_detail,
            "tools_called": tools_brief,
        }
        LLM_TURNS_ALL.append(entry)
        if qid:
            ring = LLM_TURNS_BY_QID.setdefault(qid, deque(maxlen=40))
            ring.append(entry)


def _process_telemetry_job(job: dict[str, Any]) -> None:
    """Runs exclusively on the background daemon thread (zero latency added to Worker LLM calls)."""
    try:
        req_payload = job.get("req_payload")
        qid = job.get("qid")
        if isinstance(req_payload, dict):
            _record_tool_results_from_request(req_payload, qid)
        tool_uses = job.get("tool_uses") or []
        if tool_uses:
            _record_tool_uses(tool_uses, route=job["actual_route"], qid=qid)
        record(
            job["route"],
            job["actual_route"],
            job["path"],
            job["model"],
            job["usage"],
            job["status"],
            job["dur"],
            failover=job["failover"],
            requested_model=job.get("requested_model"),
            thinking_effort=job.get("thinking_effort"),
            qid=qid,
        )
        _record_llm_turn(
            route=job["route"],
            actual_route=job["actual_route"],
            qid=qid,
            requested_model=job.get("requested_model"),
            response_model=job.get("model"),
            thinking_effort=job.get("thinking_effort"),
            started_wall=job["started_wall"],
            finished_wall=job["finished_wall"],
            ttft_sec=job.get("ttft_sec"),
            dur_sec=job["dur"],
            status=job["status"],
            failover=job["failover"],
            usage=job["usage"],
            req_payload=req_payload,
            answer_text=job.get("answer_text") or "",
            thinking_text=job.get("thinking_text") or "",
            tool_uses=tool_uses,
        )
    except Exception as exc:
        print(f"[warn] async telemetry worker error: {exc}", flush=True)


def _telemetry_loop() -> None:
    while True:
        job = _TELEMETRY_Q.get()
        try:
            _process_telemetry_job(job)
        finally:
            _TELEMETRY_Q.task_done()


_TELEMETRY_THREAD = threading.Thread(target=_telemetry_loop, name="proxy-telemetry", daemon=True)
_TELEMETRY_THREAD.start()


def _enqueue_telemetry(job: dict[str, Any]) -> None:
    """Non-blocking telemetry handoff; drops telemetry instead of ever slowing down the LLM worker."""
    global _TELEMETRY_DROPPED
    try:
        _TELEMETRY_Q.put_nowait(job)
    except queue.Full:
        _TELEMETRY_DROPPED += 1


def _drain_telemetry_brief(timeout_sec: float = 0.08) -> None:
    """Wait briefly ONLY on cockpit read endpoints so /stats, /tools, /llm-logs see fresh data."""
    deadline = time.monotonic() + max(0.0, timeout_sec)
    while _TELEMETRY_Q.unfinished_tasks > 0 and time.monotonic() < deadline:
        time.sleep(0.005)


def _extract_request_meta(body: bytes, explicit_qid: str | None = None) -> dict[str, Any]:
    """Fast metadata extraction on request path (zero redaction, zero lock, zero disk I/O)."""
    if not body:
        return {"requested_model": None, "thinking_effort": None, "qid": explicit_qid, "payload": None}
    try:
        payload = json.loads(body)
    except Exception:
        return {"requested_model": None, "thinking_effort": None, "qid": explicit_qid, "payload": None}
    if not isinstance(payload, dict):
        return {"requested_model": None, "thinking_effort": None, "qid": explicit_qid, "payload": None}
    req_model = payload.get("model")
    thinking_effort: str | None = None
    if isinstance(payload.get("thinking"), dict):
        t = payload["thinking"]
        t_type = str(t.get("type") or "")
        budget = t.get("budget_tokens")
        if t_type:
            thinking_effort = f"{t_type}(budget={budget})" if budget is not None else t_type
    elif payload.get("reasoning_effort"):
        thinking_effort = str(payload.get("reasoning_effort"))
    elif isinstance(payload.get("reasoning"), dict) and payload["reasoning"].get("effort"):
        thinking_effort = str(payload["reasoning"]["effort"])
    qid = explicit_qid or _infer_qid_from_payload(payload)
    return {
        "requested_model": str(req_model) if req_model else None,
        "thinking_effort": thinking_effort,
        "qid": qid,
        "payload": payload,
    }


def _redact_endpoint(url: str) -> str:
    """Keep only scheme://host for cockpit display (zero query params or tokens)."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return "(unconfigured)"


def record(
    route: str,
    actual_route: str,
    path: str,
    model: str,
    usage: dict,
    status: int,
    dur: float,
    failover: bool = False,
    requested_model: str | None = None,
    thinking_effort: str | None = None,
    qid: str | None = None,
) -> None:
    now_ts = time.time()
    ent = {
        "ts": now_ts,
        "route": route,
        "actual_route": actual_route,
        "qid": qid,
        "failover": failover,
        "path": path,
        "requested_model": requested_model,
        "model": model,
        "thinking_effort": thinking_effort,
        "input": int(usage.get("input_tokens") or 0),
        "output": int(usage.get("output_tokens") or 0),
        "cache_read": int(usage.get("cache_read_input_tokens") or 0),
        "cache_write": int(usage.get("cache_creation_input_tokens") or 0),
        "status": status,
        "dur": round(dur, 2),
    }
    with LOCK:
        try:
            LOG.parent.mkdir(parents=True, exist_ok=True)
            with LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(ent, ensure_ascii=False) + "\n")
        except OSError as exc:
            print(f"[warn] failed to write token log {LOG}: {exc}", flush=True)
        s = STATS.setdefault(
            actual_route,
            {
                "calls": 0,
                "failovers": 0,
                "input": 0,
                "output": 0,
                "cache_read": 0,
                "cache_write": 0,
                "requested_model": None,
                "response_model": None,
                "thinking_effort": None,
                "last_call_at": None,
                "last_status": None,
                "last_dur_sec": None,
            },
        )
        s["calls"] += 1
        if failover:
            s["failovers"] += 1
        for k in ("input", "output", "cache_read", "cache_write"):
            s[k] += ent[k]
        if requested_model:
            s["requested_model"] = requested_model
        if model:
            s["response_model"] = model
        if thinking_effort is not None:
            s["thinking_effort"] = thinking_effort
        s["last_call_at"] = round(now_ts, 3)
        s["last_status"] = status
        s["last_dur_sec"] = round(dur, 2)
        lat_q = ROUTE_LATENCIES.setdefault(actual_route, deque(maxlen=30))
        lat_q.append(round(dur, 2))

        if qid:
            qs = QID_STATS.setdefault(
                qid,
                {
                    "calls": 0,
                    "failovers": 0,
                    "input": 0,
                    "output": 0,
                    "cache_read": 0,
                    "cache_write": 0,
                    "tool_calls": 0,
                    "tool_errors": 0,
                    "error_streak": 0,
                    "repeat_streak": 0,
                    "last_call_at": None,
                    "last_tool": None,
                },
            )
            qs["calls"] += 1
            if failover:
                qs["failovers"] += 1
            for k in ("input", "output", "cache_read", "cache_write"):
                qs[k] += ent[k]
            qs["last_call_at"] = round(now_ts, 3)


def parse_sse_event(
    chunk: bytes,
    acc: dict,
    sse_tools: dict[int, dict[str, Any]],
    sse_text: dict[str, list[str]] | None = None,
) -> bool:
    """Parse SSE usage, tool blocks, and bounded text/thinking deltas. Returns True if first content token seen."""
    saw_content = False
    for line in chunk.split(b"\n"):
        line = line.strip()
        if not line.startswith(b"data:"):
            continue
        payload = line[5:].strip()
        if payload in (b"[DONE]", b""):
            continue
        try:
            obj = json.loads(payload)
        except Exception:
            continue
        etype = obj.get("type")
        if etype == "message_start":
            usage = (obj.get("message") or {}).get("usage") or {}
            acc.update(usage)
        elif etype == "message_delta":
            usage = obj.get("usage") or {}
            for k, v in usage.items():
                if isinstance(v, int):
                    acc[k] = max(acc.get(k, 0), v)
        elif etype == "content_block_start":
            cb = obj.get("content_block") or {}
            if cb.get("type") == "tool_use":
                saw_content = True
                idx = int(obj.get("index") or 0)
                sse_tools[idx] = {
                    "id": cb.get("id"),
                    "name": cb.get("name"),
                    "input_buf": "",
                    "input": cb.get("input") if isinstance(cb.get("input"), dict) and cb.get("input") else None,
                }
        elif etype == "content_block_delta":
            delta = obj.get("delta") or {}
            dtype = delta.get("type")
            if dtype == "input_json_delta":
                saw_content = True
                idx = int(obj.get("index") or 0)
                slot = sse_tools.get(idx)
                if slot is not None and len(slot["input_buf"]) < 4096:
                    slot["input_buf"] += str(delta.get("partial_json") or "")[: 4096 - len(slot["input_buf"])]
            elif dtype == "text_delta" and sse_text is not None:
                saw_content = True
                if sse_text["answer_len"] < 7000:
                    piece = str(delta.get("text") or "")
                    sse_text["answer"].append(piece)
                    sse_text["answer_len"] += len(piece)
            elif dtype == "thinking_delta" and sse_text is not None:
                saw_content = True
                if sse_text["thinking_len"] < 5000:
                    piece = str(delta.get("thinking") or "")
                    sse_text["thinking"].append(piece)
                    sse_text["thinking_len"] += len(piece)
    return saw_content


def parse_sse_usage(chunk: bytes, acc: dict) -> None:
    """Backward-compatible wrapper for usage-only callers."""
    parse_sse_event(chunk, acc, {}, None)


def _send_to_target(
    target: RouteTarget,
    method: str,
    rest: str,
    body: bytes,
    base_headers: dict[str, str],
    *,
    has_fallback: bool,
) -> tuple[requests.Response | None, str | None, bool]:
    """Send request to one upstream target. Returns (resp, error_text, should_failover)."""
    upstream = target.url.rstrip("/") + "/" + rest.lstrip("/")
    headers = _inject_auth_headers(base_headers, target)
    payload = _maybe_rewrite_model(body, target)
    attempts = 3 if has_fallback else 6
    last_resp: requests.Response | None = None

    for i in range(attempts):
        try:
            resp = _http_session().request(
                method,
                upstream,
                data=payload,
                headers=headers,
                stream=True,
                timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
            )
        except requests.RequestException as exc:
            if i == attempts - 1:
                return None, str(exc), True
            wait = min(2 ** (i + 1), 15)
            time.sleep(wait)
            continue

        if _is_fatal_quota_or_auth_error(resp):
            return resp, None, True
        if resp.status_code not in (429, 500, 502, 503, 504) or i == attempts - 1:
            return resp, None, (resp.status_code == 429 or resp.status_code >= 500)
        wait = min(2 ** (i + 1), 30)
        resp.close()
        print(f"[retry] {target.name} {resp.status_code} -> sleep {wait}s (attempt {i + 1}/{attempts})", flush=True)
        time.sleep(wait)
        last_resp = resp
    return last_resp, "retries exhausted", True


def forward(route: str, rest: str, request: Request, body: bytes, headers: dict[str, str]):
    global LAST_FAILOVER
    t0 = time.monotonic()
    started_wall = time.time()
    explicit_qid = request.query_params.get("qid") or request.headers.get("x-cairn-qid")
    req_meta = _extract_request_meta(body, explicit_qid=explicit_qid)
    qid = req_meta.get("qid")
    req_payload = req_meta.get("payload")
    chain = _candidate_chain(route)
    resp: requests.Response | None = None
    chosen: RouteTarget = chain[0]
    last_error: str | None = None

    for idx, target in enumerate(chain):
        has_next = idx < len(chain) - 1
        candidate_resp, err_text, should_failover = _send_to_target(
            target, request.method, rest, body, headers, has_fallback=has_next
        )
        chosen = target
        if candidate_resp is not None and not (should_failover and has_next):
            resp = candidate_resp
            break
        # Mark target in cooldown and fall over to next backup route
        COOLDOWN_UNTIL[target.name] = time.monotonic() + FAILOVER_COOLDOWN_SECONDS
        status_label = candidate_resp.status_code if candidate_resp is not None else err_text
        next_name = chain[idx + 1].name if has_next else "none"
        with LOCK:
            LAST_FAILOVER = {
                "at": round(time.time(), 3),
                "from_route": target.name,
                "to_route": next_name,
                "reason": str(status_label),
            }
        print(f"[failover] {target.name} failed ({status_label}) -> switching to {next_name}", flush=True)
        if has_next and candidate_resp is not None:
            candidate_resp.close()
        else:
            resp = candidate_resp
            last_error = err_text

    eff_requested_model = chosen.model_override or req_meta["requested_model"]
    if resp is None:
        _enqueue_telemetry(
            {
                "route": route,
                "actual_route": chosen.name,
                "path": rest,
                "model": "",
                "usage": {},
                "status": 502,
                "dur": time.monotonic() - t0,
                "ttft_sec": None,
                "started_wall": started_wall,
                "finished_wall": time.time(),
                "failover": (chosen.name != route),
                "requested_model": eff_requested_model,
                "thinking_effort": req_meta["thinking_effort"],
                "qid": qid,
                "req_payload": req_payload,
                "answer_text": f"[Upstream Error] {last_error or 'all upstreams failed'}",
                "thinking_text": "",
                "tool_uses": [],
            }
        )
        return JSONResponse({"error": last_error or "all upstreams failed"}, status_code=502)

    did_failover = chosen.name != route
    ctype = resp.headers.get("content-type", "")

    if "text/event-stream" not in ctype:
        raw = resp.content
        dur = time.monotonic() - t0
        usage: dict = {}
        model = ""
        parsed_body: Any = None
        tool_uses: list[dict[str, Any]] = []
        ans_parts: list[str] = []
        think_parts: list[str] = []
        try:
            parsed_body = json.loads(raw)
            if isinstance(parsed_body, dict):
                usage = parsed_body.get("usage") or {}
                model = parsed_body.get("model") or ""
                content = parsed_body.get("content")
                if isinstance(content, list):
                    for b in content:
                        if not isinstance(b, dict):
                            continue
                        bt = b.get("type")
                        if bt == "tool_use":
                            tool_uses.append(b)
                        elif bt == "text" and isinstance(b.get("text"), str):
                            ans_parts.append(b["text"])
                        elif bt == "thinking" and isinstance(b.get("thinking"), str):
                            think_parts.append(b["thinking"])
        except Exception:
            parsed_body = None
        _enqueue_telemetry(
            {
                "route": route,
                "actual_route": chosen.name,
                "path": rest,
                "model": model,
                "usage": usage,
                "status": resp.status_code,
                "dur": dur,
                "ttft_sec": dur,
                "started_wall": started_wall,
                "finished_wall": time.time(),
                "failover": did_failover,
                "requested_model": eff_requested_model,
                "thinking_effort": req_meta["thinking_effort"],
                "qid": qid,
                "req_payload": req_payload,
                "answer_text": "\n".join(ans_parts),
                "thinking_text": "\n".join(think_parts),
                "tool_uses": tool_uses,
            }
        )
        resp.close()
        return JSONResponse(
            content=parsed_body if parsed_body is not None else {"raw": raw.decode("utf-8", "ignore")},
            status_code=resp.status_code,
        )

    acc: dict = {}
    sse_tools: dict[int, dict[str, Any]] = {}
    sse_text: dict[str, Any] = {"answer": [], "answer_len": 0, "thinking": [], "thinking_len": 0}
    model_name = ""
    ttft_sec: float | None = None

    def streamer():
        nonlocal model_name, ttft_sec
        try:
            for chunk in resp.iter_lines(chunk_size=4096):
                if chunk is None:
                    continue
                line = chunk + b"\n"
                yield line
                stripped = line.strip()
                if stripped.startswith(b"data:"):
                    if b'"model"' in stripped and not model_name:
                        try:
                            obj = json.loads(stripped[5:].strip())
                            if isinstance(obj, dict):
                                model_name = obj.get("model") or (obj.get("message") or {}).get("model") or ""
                        except Exception:
                            pass
                    saw = parse_sse_event(stripped, acc, sse_tools, sse_text)
                    if saw and ttft_sec is None:
                        ttft_sec = time.monotonic() - t0
        finally:
            extracted_tools: list[dict[str, Any]] = []
            if sse_tools:
                for idx in sorted(sse_tools):
                    slot = sse_tools[idx]
                    inp = slot.get("input")
                    if inp is None and slot.get("input_buf"):
                        try:
                            inp = json.loads(slot["input_buf"])
                        except Exception:
                            inp = slot["input_buf"]
                    extracted_tools.append({"id": slot.get("id"), "name": slot.get("name"), "input": inp})
            _enqueue_telemetry(
                {
                    "route": route,
                    "actual_route": chosen.name,
                    "path": rest,
                    "model": model_name,
                    "usage": acc,
                    "status": resp.status_code,
                    "dur": time.monotonic() - t0,
                    "ttft_sec": ttft_sec,
                    "started_wall": started_wall,
                    "finished_wall": time.time(),
                    "failover": did_failover,
                    "requested_model": eff_requested_model,
                    "thinking_effort": req_meta["thinking_effort"],
                    "qid": qid,
                    "req_payload": req_payload,
                    "answer_text": "".join(sse_text["answer"]),
                    "thinking_text": "".join(sse_text["thinking"]),
                    "tool_uses": extracted_tools,
                }
            )
            resp.close()

    return StreamingResponse(
        streamer(),
        status_code=resp.status_code,
        media_type="text/event-stream",
        headers={"cache-control": "no-cache", "x-accel-buffering": "no"},
    )


@app.api_route("/{route}/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(route: str, rest: str, request: Request):
    if route not in ROUTES:
        return JSONResponse({"error": f"unknown route {route}"}, status_code=404)
    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
    try:
        return await run_in_threadpool(forward, route, rest, request, body, headers)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)


@app.get("/stats")
def stats():
    _drain_telemetry_brief(0.08)
    now = time.monotonic()
    with LOCK:
        by_route = {}
        for k, v in STATS.items():
            row = dict(v)
            lats = list(ROUTE_LATENCIES.get(k) or [])
            row["p50_sec"] = _percentile(lats, 0.50)
            row["p95_sec"] = _percentile(lats, 0.95)
            by_route[k] = row
        by_qid = {k: dict(v) for k, v in QID_STATS.items()}
        total = {
            "calls": sum(s["calls"] for s in by_route.values()),
            "failovers": sum(s["failovers"] for s in by_route.values()),
            "input": sum(s["input"] for s in by_route.values()),
            "output": sum(s["output"] for s in by_route.values()),
            "cache_read": sum(s["cache_read"] for s in by_route.values()),
            "cache_write": sum(s["cache_write"] for s in by_route.values()),
            "tool_calls": len(TOOL_RING_ALL),
            "llm_turns": len(LLM_TURNS_ALL),
            "telemetry_dropped": _TELEMETRY_DROPPED,
        }
        cooling = {k: round(v - now, 1) for k, v in COOLDOWN_UNTIL.items() if v > now}
        last_fo = dict(LAST_FAILOVER) if LAST_FAILOVER else None
        route_configs = {
            name: {
                "endpoint_redacted": _redact_endpoint(rt.url),
                "model_override": rt.model_override,
                "key_managed": bool(rt.api_key),
                "fallbacks": list(rt.fallbacks),
            }
            for name, rt in ROUTES.items()
        }
    return {
        "observed_at": time.time(),
        "by_route": by_route,
        "by_qid": by_qid,
        "route_configs": route_configs,
        "total": total,
        "cooling_down": cooling,
        "last_failover": last_fo,
        "log": str(LOG),
    }


@app.get("/tools")
def recent_tools(qid: str | None = None, limit: int = 50):
    """On-demand redacted tool-call summary ring buffer (zero Worker overhead)."""
    _drain_telemetry_brief(0.08)
    lim = max(1, min(int(limit or 50), 120))
    with LOCK:
        if qid:
            src = list(TOOL_RING_BY_QID.get(qid) or [])
        else:
            src = list(TOOL_RING_ALL)
        items = [
            {k: v for k, v in item.items() if not k.startswith("_")}
            for item in src[-lim:]
        ]
    return {
        "observed_at": time.time(),
        "qid": qid,
        "count": len(items),
        "tools": items,
    }


@app.get("/llm-logs")
def recent_llm_logs(qid: str | None = None, limit: int = 40):
    """On-demand redacted per-question LLM prompt/thinking/answer timeline (async off-hot-path)."""
    _drain_telemetry_brief(0.08)
    lim = max(1, min(int(limit or 40), 100))
    with LOCK:
        if qid:
            src = list(LLM_TURNS_BY_QID.get(qid) or [])
        else:
            src = list(LLM_TURNS_ALL)
        items = [dict(item) for item in src[-lim:]]
    return {
        "observed_at": time.time(),
        "qid": qid,
        "count": len(items),
        "turns": items,
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "routes": list(ROUTES),
        "key_managed": {k: bool(v.api_key) for k, v in ROUTES.items()},
        "fallbacks": {k: v.fallbacks for k, v in ROUTES.items() if v.fallbacks},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8100)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--config", default=os.environ.get("PROXY_CONFIG") or None, help="YAML 代理配置文件")
    ap.add_argument("--route", action="append", default=[], help="name=upstream_url，可重复")
    ap.add_argument("--fallback", action="append", default=[], help="primary=backup1,backup2，可重复")
    args = ap.parse_args()

    if args.config and Path(args.config).is_file():
        ROUTES.update(load_routes_from_config(Path(args.config)))

    for item in args.route:
        name, _, url = item.partition("=")
        name, url = name.strip(), url.strip()
        if name in ROUTES:
            ROUTES[name].url = url
        else:
            ROUTES[name] = RouteTarget(name=name, url=url)

    for item in args.fallback:
        primary, _, backups = item.partition("=")
        primary = primary.strip()
        if primary in ROUTES:
            ROUTES[primary].fallbacks = [b.strip() for b in backups.split(",") if b.strip()]

    if not ROUTES:
        ap.error("至少给一个 --route 或 --config")

    print(f"routes: { {k: v.url for k, v in ROUTES.items()} }")
    print(f"log: {LOG}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
