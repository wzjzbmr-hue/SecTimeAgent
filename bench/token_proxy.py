#!/usr/bin/env python3
"""极简 LLM 记账代理。

作用：让 Cairn 先连到这里，再转发到真实厂商端点，同时把每次调用的
token 用量落到 jsonl。用来回答"4 小时能跑几题、每题多少钱"。

支持：
  - Anthropic 协议的流式（SSE）与非流式响应
  - 按路由前缀转发到不同厂商

用法：
  python bench/token_proxy.py --port 8100 \
      --route glm=https://open.bigmodel.cn/api/anthropic \
      --route ds=https://api.deepseek.com/anthropic

  # Cairn 里配 http://<lan-ip>:8100/glm 即可
  curl http://127.0.0.1:8100/stats
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path

import requests
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

ROOT = Path(__file__).resolve().parent
LOG = ROOT / "results" / "tokens.jsonl"
LOG.parent.mkdir(exist_ok=True)

ROUTES: dict[str, str] = {}
LOCK = threading.Lock()
STATS: dict[str, dict] = {}

app = FastAPI(title="Token Meter Proxy")

HOP_BY_HOP = {
    "host",
    "content-length",
    "connection",
    "accept-encoding",
    "transfer-encoding",
    "keep-alive",
}


def record(route: str, path: str, model: str, usage: dict, status: int, dur: float) -> None:
    ent = {
        "ts": time.time(),
        "route": route,
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
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(ent, ensure_ascii=False) + "\n")
        s = STATS.setdefault(route, {"calls": 0, "input": 0, "output": 0, "cache_read": 0, "cache_write": 0})
        s["calls"] += 1
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


def forward(route: str, rest: str, request: Request, body: bytes, headers: dict, timeout: float):
    upstream = ROUTES[route].rstrip("/") + "/" + rest.lstrip("/")
    t0 = time.monotonic()

    # 429/5xx 退避重试：把上游的限流吸收掉，避免 Cairn 反复失败重启任务
    attempts = 6
    for i in range(attempts):
        resp = requests.request(
            request.method, upstream, data=body, headers=headers, stream=True, timeout=timeout
        )
        # A depleted account cannot recover through backoff. Let the caller
        # see the error immediately instead of adding another minute of waits.
        if resp.status_code == 429:
            try:
                error = resp.json().get("error") or {}
                code = str(error.get("code", "")) if isinstance(error, dict) else ""
            except (ValueError, AttributeError):
                code = ""
            if code == "1113":
                break
        if resp.status_code not in (429, 500, 502, 503, 504) or i == attempts - 1:
            break
        wait = min(2 ** (i + 1), 30)
        resp.close()
        print(f"[retry] {route} {resp.status_code} -> sleep {wait}s (attempt {i + 1}/{attempts})", flush=True)
        time.sleep(wait)

    ctype = resp.headers.get("content-type", "")

    if "text/event-stream" not in ctype:
        raw = resp.content
        usage: dict = {}
        model = ""
        try:
            data = json.loads(raw)
            usage = data.get("usage") or {}
            model = data.get("model") or ""
        except Exception:
            pass
        record(route, rest, model, usage, resp.status_code, time.monotonic() - t0)
        resp.close()
        return JSONResponse(
            content=json.loads(raw) if raw.strip().startswith(b"{") else {"raw": raw.decode("utf-8", "ignore")},
            status_code=resp.status_code,
        )

    acc: dict = {}
    model_name = ""

    def streamer():
        nonlocal model_name
        try:
            for chunk in resp.iter_lines(chunk_size=1):
                if chunk is None:
                    continue
                line = chunk + b"\n"
                yield line
                if b'"model"' in line and not model_name:
                    try:
                        obj = json.loads(line.strip()[5:])
                        model_name = obj.get("model") or (obj.get("message") or {}).get("model") or ""
                    except Exception:
                        pass
                if b"data:" in line:
                    parse_sse_usage(line, acc)
        finally:
            record(route, rest, model_name, acc, resp.status_code, time.monotonic() - t0)
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
        return await run_in_threadpool(forward, route, rest, request, body, headers, timeout=600)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=502)


@app.get("/stats")
def stats():
    with LOCK:
        total = {
            "calls": sum(s["calls"] for s in STATS.values()),
            "input": sum(s["input"] for s in STATS.values()),
            "output": sum(s["output"] for s in STATS.values()),
            "cache_read": sum(s["cache_read"] for s in STATS.values()),
            "cache_write": sum(s["cache_write"] for s in STATS.values()),
        }
    return {"by_route": STATS, "total": total, "log": str(LOG)}


@app.get("/health")
def health():
    return {"ok": True, "routes": list(ROUTES)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8100)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--route", action="append", default=[], help="name=upstream_url，可重复")
    args = ap.parse_args()

    for item in args.route:
        name, _, url = item.partition("=")
        ROUTES[name.strip()] = url.strip()
    if not ROUTES:
        ap.error("至少给一个 --route")

    print(f"routes: {ROUTES}")
    print(f"log: {LOG}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
