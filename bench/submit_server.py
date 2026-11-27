#!/usr/bin/env python3
"""本地模拟比赛判分平台。

模拟真实平台的 POST /api/submit 行为：
  - 只认注册表里的正确 flag
  - 正确后该题锁定，重复提交返回 already_solved
  - 记录首次解出时间（TTF 的终点）

用法：
  python bench/submit_server.py --port 8099
  python bench/submit_server.py --port 8099 --token xxx   # 启用 Agent-Token 校验
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path

import uvicorn
import http.client
import socket as _socket
import yaml
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

STATE_LOCK = threading.Lock()
STATE: dict = {"expected": {}, "challenges": {}, "token": None, "started_at": time.time()}
RELOAD_PATH: list[str] = []

app = FastAPI(title="Cairn Bench Submit Server")


class SubmitBody(BaseModel):
    code: str
    flag: str


def load_challenges(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    items = data.get("challenges") or []
    expected = {}
    meta = {}
    for item in items:
        cid = item["id"]
        expected[cid] = item["flag"].strip()
        meta[cid] = {
            "category": item.get("category", "misc"),
            "difficulty": item.get("difficulty", "unknown"),
            "points": item.get("points", 100),
        }
    return {"expected": expected, "meta": meta}


@app.get("/health")
def health():
    return {"ok": True, "uptime": round(time.time() - STATE["started_at"], 1)}


@app.post("/api/submit")
def submit(body: SubmitBody, agent_token: str | None = Header(default=None, alias="Agent-Token")):
    if STATE["token"] and agent_token != STATE["token"]:
        raise HTTPException(401, "invalid agent token")

    code, flag = body.code.strip(), body.flag.strip()
    if code not in STATE["expected"]:
        return {"ok": False, "reason": "unknown_challenge", "code": code}

    with STATE_LOCK:
        record = STATE["challenges"].setdefault(
            code, {"solved": False, "attempts": 0, "first_success_at": None, "last_attempt_at": None}
        )
        record["attempts"] += 1
        record["last_attempt_at"] = time.time()

        if record["solved"]:
            return {"ok": True, "reason": "already_solved", "code": code}

        if flag != STATE["expected"][code]:
            return {"ok": False, "reason": "wrong_flag", "code": code}

        record["solved"] = True
        record["first_success_at"] = time.time()
        ttf = round(record["first_success_at"] - STATE["started_at"], 1)
        return {"ok": True, "reason": "correct", "code": code, "ttf_since_start": ttf}


@app.get("/attachment/{name}")
def attachment(name: str):
    """模拟平台的附件下载，附件放在 bench/attachments/。"""
    base = (ROOT / "attachments").resolve()
    path = (base / name).resolve()
    if base not in path.parents or not path.is_file():
        raise HTTPException(404, "attachment not found")
    from fastapi.responses import FileResponse
    return FileResponse(path, filename=name)


@app.get("/results")
def results():
    with STATE_LOCK:
        out = {}
        for cid, meta in STATE["meta"].items():
            rec = STATE["challenges"].get(cid, {})
            out[cid] = {
                **meta,
                "solved": rec.get("solved", False),
                "attempts": rec.get("attempts", 0),
                "first_success_at": rec.get("first_success_at"),
            }
        solved = sum(1 for v in out.values() if v["solved"])
        return {"solved": solved, "total": len(out), "challenges": out}


@app.post("/reload")
def reload_challenges():
    """改了 challenges.yaml 之后调一下，避免判分服务用旧题库。"""
    path = Path(RELOAD_PATH[0])
    loaded = load_challenges(path)
    with STATE_LOCK:
        STATE["expected"] = loaded["expected"]
        STATE["meta"] = loaded["meta"]
    return {"ok": True, "challenges": list(STATE["expected"])}




# ============ 靶机实例重置（模拟比赛平台的"重开实例"能力） ============
TARGET_CONTAINERS = {
    "hello-flag": ["bench-hello-flag"],
    "sqli-login": ["bench-sqli-login"],
    "jwt-forge": ["bench-jwt-forge"],
    "lfi-traversal": ["bench-lfi-traversal"],
    "pickle-rce": ["bench-pickle-rce"],
    "pwn-stack": ["bench-pwn-stack"],
    "idor-orders": ["bench-idor-orders"],
    "miniapp-sign": ["bench-miniapp-sign"],
    "os-privesc": ["bench-os-privesc"],
    "modbus-ics": ["bench-modbus-ics"],
    "redis-unauth": ["bench-redis-unauth"],
    "mw-console": ["bench-mw-console"],
    "git-leak": ["bench-git-leak"],
    "chain-full": ["bench-chain-full"],
    "mobile-bank-pro": ["bench-mobile-bank-pro"],
    "discuz-rce": ["bench-discuz-rce", "bench-discuz-rce-db"],
    "redis-rce": ["bench-redis-rce"],
    "scg-rce": ["bench-scg-rce"],
    "gitlist-rce": ["bench-gitlist-rce"],
    "weblogic-chain": ["bench-weblogic-chain", "bench-weblogic-chain-redis"],
    "ics-pro": ["bench-ics-pro"],
    "os-privesc-pro": ["bench-os-privesc-pro"],
    "jboss-rce": ["bench-jboss-rce"],
}
DOCKER_SOCK = "/var/run/docker.sock"


def _docker_request(method: str, url_path: str, timeout: float = 30) -> tuple[int, bytes]:
    """通过 unix socket 调 Docker API（不依赖 docker CLI）"""
    class UnixConnection(http.client.HTTPConnection):
        def __init__(self, timeout: float):
            super().__init__("localhost", timeout=timeout)

        def connect(self):
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(DOCKER_SOCK)
            self.sock = s

    conn = UnixConnection(timeout)
    try:
        conn.request(method, url_path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


@app.post("/api/reset-target/{code}")
def reset_target(code: str):
    """重置指定题目的靶机实例（docker restart）。靶机回到初始状态，实例内写入的文件会丢失。"""
    names = TARGET_CONTAINERS.get(code)
    if not names:
        raise HTTPException(404, f"unknown challenge code: {code}")
    results = {}
    for name in names:
        try:
            status, body = _docker_request("POST", f"/containers/{name}/restart?t=5")
            results[name] = {"ok": status in (200, 204), "http": status}
        except Exception as exc:
            results[name] = {"ok": False, "error": str(exc)}
    all_ok = all(r.get("ok") for r in results.values())
    return {"ok": all_ok, "code": code, "containers": results}

@app.post("/reset")
def reset():
    with STATE_LOCK:
        STATE["challenges"] = {}
        STATE["started_at"] = time.time()
    return {"ok": True}


@app.post("/dump")
def dump():
    payload = {"started_at": STATE["started_at"], "challenges": STATE["challenges"]}
    path = RESULTS_DIR / f"submit-{int(time.time())}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "path": str(path)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--host", default="127.0.0.1", help="用 0.0.0.0 才能被 worker 容器访问")
    ap.add_argument("--challenges", default=str(ROOT / "challenges.yaml"))
    ap.add_argument("--token", default=None)
    args = ap.parse_args()

    loaded = load_challenges(Path(args.challenges))
    STATE["expected"] = loaded["expected"]
    STATE["meta"] = loaded["meta"]
    STATE["token"] = args.token
    RELOAD_PATH.append(args.challenges)

    print(f"loaded {len(STATE['expected'])} challenges: {', '.join(STATE['expected'])}")
    print(f"listening on http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
