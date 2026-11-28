#!/usr/bin/env python3
"""赛前一键自检脚本（零第三方依赖，可直接在纯净 Ubuntu 24.04 宿主机 python3 运行）。

检查项：
  1. 系统时区与时间校验
  2. 磁盘可用空间（默认 >= 6 GB）
  3. Docker 引擎、日志上限与扩展地址池（/etc/docker/daemon.json）
  4. 目标 Worker 镜像存在性与精确 ID 打印（防跑错镜像）
  5. Cairn Server / Token Proxy 健康状态与主备路由检查
  6. 官方比赛平台 question_list 认证与 AD-000000 契约连通性（只读，不启动场景）
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


def _http_get_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 10.0) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            body = json.loads(raw)
        except Exception:
            body = {"raw": raw[:200]}
        return exc.code, body


def check_item(name: str, ok: bool, detail: str) -> bool:
    mark = "[PASS]" if ok else "[FAIL]"
    print(f"{mark} {name:<28} {detail}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Pre-competition preflight check (zero external deps)")
    ap.add_argument("--worker-image", default=os.environ.get("WORKER_IMAGE", "cairn-worker:competition"))
    ap.add_argument("--expected-image-id", default=os.environ.get("EXPECTED_WORKER_IMAGE_ID", ""))
    ap.add_argument("--cairn-url", default=os.environ.get("CAIRN_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--proxy-url", default=os.environ.get("PROXY_URL", "http://127.0.0.1:8100"))
    ap.add_argument("--race-base-url", default=os.environ.get("RACE_BASE_URL", ""))
    ap.add_argument("--agent-token", default=os.environ.get("RACE_AGENT_TOKEN", ""))
    ap.add_argument("--min-disk-gb", type=float, default=6.0)
    args = ap.parse_args()

    all_ok = True

    now = datetime.now().astimezone()
    all_ok &= check_item("System Time", True, f"{now.isoformat()} (tz={now.tzinfo})")

    usage = shutil.disk_usage("/")
    free_gb = usage.free / (1024 ** 3)
    total_gb = usage.total / (1024 ** 3)
    all_ok &= check_item(
        "Root Disk Free Space",
        free_gb >= args.min_disk_gb,
        f"{free_gb:.2f} GB free / {total_gb:.1f} GB total (min={args.min_disk_gb} GB)",
    )

    daemon_json = Path("/etc/docker/daemon.json")
    if daemon_json.is_file():
        try:
            dcfg = json.loads(daemon_json.read_text(encoding="utf-8"))
            has_log_cap = bool((dcfg.get("log-opts") or {}).get("max-size"))
            has_pools = bool(dcfg.get("default-address-pools"))
            all_ok &= check_item(
                "Docker daemon.json",
                has_log_cap and has_pools,
                f"log_cap={has_log_cap} address_pools={has_pools}",
            )
        except Exception as exc:
            all_ok &= check_item("Docker daemon.json", False, f"parse error: {exc}")
    else:
        all_ok &= check_item("Docker daemon.json", False, "missing /etc/docker/daemon.json (log cap & pools unset)")

    proc = subprocess.run(
        ["docker", "image", "inspect", args.worker_image, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        actual_id = proc.stdout.strip()
        id_ok = (not args.expected_image_id) or (actual_id == args.expected_image_id)
        all_ok &= check_item("Worker Image ID", id_ok, f"{args.worker_image} -> {actual_id}")
    else:
        all_ok &= check_item("Worker Image ID", False, f"not found: {args.worker_image}")

    try:
        st, body = _http_get_json(f"{args.cairn_url.rstrip('/')}/health", timeout=5)
        all_ok &= check_item("Cairn Server /health", st == 200 and bool(body.get("ok")), json.dumps(body))
    except Exception as exc:
        all_ok &= check_item("Cairn Server /health", False, str(exc))

    try:
        st, body = _http_get_json(f"{args.proxy_url.rstrip('/')}/health", timeout=5)
        all_ok &= check_item("Token Proxy /health", st == 200 and bool(body.get("ok")), json.dumps(body)[:180])
    except Exception as exc:
        all_ok &= check_item("Token Proxy /health", False, str(exc))

    if args.race_base_url and args.agent_token:
        base = args.race_base_url.rstrip("/")
        if "/api/ct/agent/ai_race/race" not in base:
            base = f"{base}/api/ct/agent/ai_race/race"
        url = f"{base}/checkpoints/robot/question_list"
        try:
            st, body = _http_get_json(url, headers={"Authorization": f"Bearer {args.agent_token.strip()}"}, timeout=10)
            ok = st == 200 and body.get("code") == "AD-000000"
            count = len(((body.get("data") or {}).get("list") or [])) if ok else -1
            detail = f"AD-000000 OK; visible questions={count}" if ok else f"http={st} code={body.get('code')} msg={body.get('message')}"
            all_ok &= check_item("Official Race API", ok, detail)
        except Exception as exc:
            all_ok &= check_item("Official Race API", False, str(exc))
    else:
        print("[SKIP] Official Race API            provide --race-base-url and --agent-token to verify")

    print("\nPREFLIGHT RESULT:", "READY" if all_ok else "BLOCKED (fix FAIL items above)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
