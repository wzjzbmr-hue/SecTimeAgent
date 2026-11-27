#!/usr/bin/env python3
"""比赛解题能力评测运行器。

一件事：把每道题变成一次真实比赛——
起靶场 → 在 Cairn 建 project → 等判分平台收到正确 flag → 记录指标 → 拆靶场。

用法：
  python bench/runner.py --only hello-flag --no-agent     # 只起靶场，手工验证判分
  python bench/runner.py --only hello-flag                # 端到端跑一道题
  python bench/runner.py --category web --budget 600      # 批量跑 web 类

判分以 submit server 的回执为准，不以 Cairn 的 status 为准。
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def load_challenges(path: Path) -> tuple[dict, list[dict]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("defaults") or {}, data.get("challenges") or []


def fmt(text: str, host: str) -> str:
    return text.replace("{host}", host)


def wait_port(host: str, port: int, timeout: float = 90) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def compose(action: str, cid: str, cdir: Path) -> None:
    cmd = ["docker", "compose", "-p", f"bench-{cid}", "-f", str(cdir / "docker-compose.yml")]
    if action == "up":
        cmd += ["up", "-d"]
    else:
        cmd += ["down", "-v", "--remove-orphans"]
    try:
        subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print(f"  ! compose {action} 超时")


def cairn_create(cairn: str, title: str, origin: str, goal: str, hints: list[str] | None = None) -> str | None:
    try:
        body = {"title": title, "origin": origin, "goal": goal, "bootstrap_enabled": True}
        if hints:
            body["hints"] = [{"content": h, "creator": "bench"} for h in hints]
        r = requests.post(f"{cairn}/projects", json=body, timeout=20)
        r.raise_for_status()
        return r.json()["project"]["id"]
    except Exception as exc:
        print(f"  ! 建 project 失败: {exc}")
        return None


def cairn_stats(cairn: str, pid: str) -> tuple[int, int, str]:
    try:
        d = requests.get(f"{cairn}/projects/{pid}", timeout=10).json()
        return len(d.get("facts", [])), len(d.get("intents", [])), d["project"]["status"]
    except Exception:
        return 0, 0, "unknown"


def cairn_stop(cairn: str, pid: str) -> None:
    try:
        requests.put(f"{cairn}/projects/{pid}/status", json={"status": "stopped"}, timeout=10)
    except Exception:
        pass


def solved_on_platform(submit: str) -> dict:
    return requests.get(submit, timeout=10).json()


def run_one(
    ch: dict,
    defaults: dict,
    host: str,
    cairn: str,
    submit_base: str,
    no_agent: bool,
) -> dict:
    cid = ch["id"]
    cdir = (ROOT / ch["dir"]).resolve()
    budget = int(ch.get("budget", defaults.get("budget", 600)))
    target = fmt(ch["target"], host)
    port = int(target.rsplit(":", 1)[1].strip("/"))

    print(f"\n=== [{cid}] {ch.get('category')}/{ch.get('difficulty')} 预算 {budget}s ===")
    compose("up", cid, cdir)
    if not wait_port(host, port):
        print("  ! 靶场端口未就绪")
        compose("down", cid, cdir)
        return {"id": cid, "result": "RANGE_FAIL"}

    print(f"  靶场就绪: {target}")

    pid = None
    if not no_agent:
        hints = [fmt(h, host) for h in (ch.get("hints") or [])]
        pid = cairn_create(cairn, cid, fmt(ch["origin"], host), fmt(ch["goal"], host), hints)
        if not pid:
            compose("down", cid, cdir)
            return {"id": cid, "result": "CAIRN_FAIL"}
        print(f"  project={pid} 已派单")

    t0 = time.time()
    result, ttf = "TIMEOUT", None
    while time.time() - t0 < budget:
        time.sleep(5)
        try:
            st = solved_on_platform(f"{submit_base}/results")
        except Exception:
            continue
        rec = st["challenges"].get(cid, {})
        if rec.get("solved"):
            result = "SOLVED"
            ttf = round(time.time() - t0, 1)
            print(f"  ✓ 解出，耗时 {ttf}s")
            break

    facts = intents = 0
    if pid:
        facts, intents, status = cairn_stats(cairn, pid)
        if result == "TIMEOUT":
            cairn_stop(cairn, pid)
            print(f"  × 超时（facts={facts} intents={intents} status={status}）")

    compose("down", cid, cdir)
    return {
        "id": cid,
        "category": ch.get("category"),
        "difficulty": ch.get("difficulty"),
        "result": result,
        "ttf": ttf,
        "budget": budget,
        "facts": facts,
        "intents": intents,
        "project": pid,
    }


def report(rows: list[dict]) -> None:
    print("\n" + "=" * 78)
    print(f"{'ID':<20}{'CAT':<8}{'DIFF':<9}{'RESULT':<10}{'TTF(s)':<9}{'INTENTS':<9}{'HANG'}")
    print("-" * 78)
    for r in rows:
        print(
            f"{r['id']:<20}{str(r.get('category','')):<8}{str(r.get('difficulty','')):<9}"
            f"{r['result']:<10}{str(r.get('ttf') or '-'):<9}{str(r.get('intents','-')):<9}"
            f"{'Y' if r['result'] == 'TIMEOUT' else '-'}"
        )
    total = len(rows)
    solved = sum(1 for r in rows if r["result"] == "SOLVED")
    ttfs = sorted(r["ttf"] for r in rows if r.get("ttf"))
    median = ttfs[len(ttfs) // 2] if ttfs else None
    print("-" * 78)
    print(
        f"solve {solved}/{total} ({(solved / total * 100) if total else 0:.0f}%)   "
        f"median TTF {median or '-'}s   hang {sum(1 for r in rows if r['result'] == 'TIMEOUT')}/{total}"
    )

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = RESULTS_DIR / f"run-{stamp}.json"
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果已保存: {out}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenges", default=str(ROOT / "challenges.yaml"))
    ap.add_argument("--only", default=None, help="逗号分隔的题目 id")
    ap.add_argument("--category", default=None)
    ap.add_argument("--difficulty", default=None)
    ap.add_argument("--budget", type=int, default=480, help="覆盖单题时间预算（秒），应大于任务超时+收尾")
    ap.add_argument("--host", default="127.0.0.1", help="worker 能访问到本机的地址")
    ap.add_argument("--cairn", default="http://127.0.0.1:8000")
    ap.add_argument("--submit", default=None, help="默认 http://<host>:8099")
    ap.add_argument("--no-agent", action="store_true", help="只起靶场，不建 project")
    args = ap.parse_args()

    defaults, items = load_challenges(Path(args.challenges))
    selected = items
    if args.only:
        want = {s.strip() for s in args.only.split(",")}
        selected = [c for c in items if c["id"] in want]
    if args.category:
        selected = [c for c in selected if c.get("category") == args.category]
    if args.difficulty:
        selected = [c for c in selected if c.get("difficulty") == args.difficulty]
    if not selected:
        print("没有匹配的题目")
        return 1

    if args.budget:
        for c in selected:
            c["budget"] = args.budget

    submit_base = args.submit or f"http://{args.host}:8099"
    try:
        requests.get(f"{submit_base}/health", timeout=5)
    except Exception:
        print(f"判分平台没起来：{submit_base}\n先运行  python bench/submit_server.py --host 0.0.0.0")
        return 1

    print(f"题目 {len(selected)} 道，判分平台 {submit_base}，agent {'未启用' if args.no_agent else args.cairn}")
    requests.post(f"{submit_base}/reset", timeout=10)
    rows = [run_one(c, defaults, args.host, args.cairn, submit_base, args.no_agent) for c in selected]
    report(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
