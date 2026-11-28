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
import json
import os
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
_THREAD_LOCAL = threading.local()


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


def record(
    route: str,
    actual_route: str,
    path: str,
    model: str,
    usage: dict,
    status: int,
    dur: float,
    failover: bool = False,
) -> None:
    ent = {
        "ts": time.time(),
        "route": route,
        "actual_route": actual_route,
        "failover": failover,
        "path": path,
        "model": model,
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
            {"calls": 0, "failovers": 0, "input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
        )
        s["calls"] += 1
        if failover:
            s["failovers"] += 1
        for k in ("input", "output", "cache_read", "cache_write"):
            s[k] += ent[k]


def parse_sse_usage(chunk: bytes, acc: dict) -> None:
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
        if obj.get("type") == "message_start":
            usage = (obj.get("message") or {}).get("usage") or {}
            acc.update(usage)
        elif obj.get("type") == "message_delta":
            usage = obj.get("usage") or {}
            for k, v in usage.items():
                if isinstance(v, int):
                    acc[k] = max(acc.get(k, 0), v)


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
    t0 = time.monotonic()
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
        print(f"[failover] {target.name} failed ({status_label}) -> switching to {chain[idx + 1].name if has_next else 'none'}", flush=True)
        if has_next and candidate_resp is not None:
            candidate_resp.close()
        else:
            resp = candidate_resp
            last_error = err_text

    if resp is None:
        record(route, chosen.name, rest, "", {}, 502, time.monotonic() - t0, failover=(chosen.name != route))
        return JSONResponse({"error": last_error or "all upstreams failed"}, status_code=502)

    did_failover = chosen.name != route
    ctype = resp.headers.get("content-type", "")

    if "text/event-stream" not in ctype:
        raw = resp.content
        usage: dict = {}
        model = ""
        parsed_body: Any = None
        try:
            parsed_body = json.loads(raw)
            if isinstance(parsed_body, dict):
                usage = parsed_body.get("usage") or {}
                model = parsed_body.get("model") or ""
        except Exception:
            parsed_body = None
        record(route, chosen.name, rest, model, usage, resp.status_code, time.monotonic() - t0, failover=did_failover)
        resp.close()
        return JSONResponse(
            content=parsed_body if parsed_body is not None else {"raw": raw.decode("utf-8", "ignore")},
            status_code=resp.status_code,
        )

    acc: dict = {}
    model_name = ""

    def streamer():
        nonlocal model_name
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
                    parse_sse_usage(stripped, acc)
        finally:
            record(route, chosen.name, rest, model_name, acc, resp.status_code, time.monotonic() - t0, failover=did_failover)
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
    now = time.monotonic()
    with LOCK:
        by_route = {k: dict(v) for k, v in STATS.items()}
        total = {
            "calls": sum(s["calls"] for s in by_route.values()),
            "failovers": sum(s["failovers"] for s in by_route.values()),
            "input": sum(s["input"] for s in by_route.values()),
            "output": sum(s["output"] for s in by_route.values()),
            "cache_read": sum(s["cache_read"] for s in by_route.values()),
            "cache_write": sum(s["cache_write"] for s in by_route.values()),
        }
        cooling = {k: round(v - now, 1) for k, v in COOLDOWN_UNTIL.items() if v > now}
    return {"by_route": by_route, "total": total, "cooling_down": cooling, "log": str(LOG)}


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
