#!/usr/bin/env python3
"""Post-run capability evaluation & automated shortcoming classifier.

Aggregates:
  1. Mock platform dashboard snapshot (scores, 8 categories, submissions, compliance audit)
  2. Cairn server project graphs (Facts, Intents, Hints, Reopens)
  3. Token proxy logs (tokens.jsonl)

Outputs:
  - <out-dir>/metrics.json
  - <out-dir>/report.md
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests

TOOL_ERR_RE = re.compile(
    r"(command not found|Operation not permitted|No such file or directory|ModuleNotFoundError|QUITTING!|Permission denied)",
    re.I,
)
JSON_ERR_RE = re.compile(r"(JSONDecodeError|invalid json|parse.*fail|empty response|truncated)", re.I)
STALL_RE = re.compile(r"(CIRCUIT_BREAKER|STALL_WARNING|still unsuccessful|same error|no new evidence|timed out)", re.I)


def classify_shortcomings(q: dict[str, Any], detail: dict[str, Any] | None) -> list[dict[str, str]]:
    """Classify failure or slowdown causes into the 6-category shortcoming taxonomy."""
    findings: list[dict[str, str]] = []
    if q.get("complete") and not q.get("reopen_count"):
        return findings

    facts_text = "\n".join(str(f.get("description") or "") for f in ((detail or {}).get("facts") or []))
    intents_list = (detail or {}).get("intents") or []
    hints_text = "\n".join(str(h.get("content") or "") for h in ((detail or {}).get("hints") or []))
    combined = f"{facts_text}\n{hints_text}"

    if q.get("reopen_count", 0) > 0:
        findings.append(
            {
                "code": "MULTI_FLAG_EARLY_STOP",
                "evidence": f"Triggered /reopen {q['reopen_count']} time(s); progress {q['current_user_solved']}/{q['total_flag_num']}",
                "remediation": "强化 competition Prompt 的多 Flag 完结门禁与 [FOOTHOLDS] 留存，确保未满 total_flag_num 不停机。",
            }
        )

    if not q.get("complete"):
        if TOOL_ERR_RE.search(combined):
            m = TOOL_ERR_RE.search(combined)
            findings.append(
                {
                    "code": "TOOL_MISSING_OR_ERROR",
                    "evidence": f"Matched tool error pattern: {m.group(0) if m else 'unknown'}",
                    "remediation": "在 Worker 镜像补齐缺失工具或透明包装脚本，并同步写入 CLAUDE.md 速查表。",
                }
            )
        if JSON_ERR_RE.search(combined):
            findings.append(
                {
                    "code": "PROTOCOL_OR_PARSER_FAIL",
                    "evidence": "Detected structured output / JSON parsing failure in trajectory",
                    "remediation": "启用国产模型 max_tokens 保护与坏 JSON 带错因定向修复环（参考 Rabbit / bronezppg）。",
                }
            )
        if STALL_RE.search(combined) or len(intents_list) >= 8:
            findings.append(
                {
                    "code": "STALL_OR_LOOP",
                    "evidence": f"High intent count ({len(intents_list)}) or stall signal without full solve",
                    "remediation": "落实 [DEAD_ENDS] 失败路线黑名单与连续无进展 [STALL_WARNING] 强制换向/止损。",
                }
            )
        if len(facts_text) > 25000:
            findings.append(
                {
                    "code": "CONTEXT_BLOAT_TIMEOUT",
                    "evidence": f"Fact graph grew to {len(facts_text)} chars",
                    "remediation": "引入长局 graph overview 上下文限长（参考 xiaoju111a/Cairn）。",
                }
            )
        if not findings:
            findings.append(
                {
                    "code": "REASONING_CAPABILITY_GAP",
                    "evidence": f"Solved {q['current_user_solved']}/{q['total_flag_num']} with no obvious runtime/tool fault",
                    "remediation": "针对该题型补充专项方法卡，并用 GLM-5.3 / Qwen4-Max / 异构双路并发做 A/B 横评。",
                }
            )
    return findings


def load_token_stats(tokens_jsonl: Path | None) -> dict[str, Any]:
    if not tokens_jsonl or not tokens_jsonl.is_file():
        return {"available": False, "total_calls": 0, "by_route": {}}
    by_route: dict[str, dict[str, int]] = defaultdict(lambda: {"calls": 0, "failovers": 0, "input": 0, "output": 0, "cache_read": 0})
    total_calls = 0
    for line in tokens_jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ent = json.loads(line)
        except ValueError:
            continue
        r = str(ent.get("actual_route") or ent.get("route") or "unknown")
        by_route[r]["calls"] += 1
        by_route[r]["failovers"] += 1 if ent.get("failover") else 0
        by_route[r]["input"] += int(ent.get("input") or 0)
        by_route[r]["output"] += int(ent.get("output") or 0)
        by_route[r]["cache_read"] += int(ent.get("cache_read") or 0)
        total_calls += 1
    return {"available": True, "total_calls": total_calls, "by_route": dict(by_route)}


def generate_report(
    snapshot: dict[str, Any],
    *,
    cairn_details: dict[str, dict[str, Any]] | None = None,
    token_stats: dict[str, Any] | None = None,
    run_label: str = "eval-run",
) -> tuple[dict[str, Any], str]:
    cairn_details = cairn_details or {}
    token_stats = token_stats or {"available": False, "total_calls": 0, "by_route": {}}
    sum_d = snapshot.get("summary") or {}
    audit = snapshot.get("audit") or {}

    shortcoming_counts: Counter[str] = Counter()
    per_question_rows: list[dict[str, Any]] = []

    for q in snapshot.get("questions") or []:
        qid = q["id"]
        pid = q.get("project_id")
        detail = cairn_details.get(pid) if pid else None
        issues = classify_shortcomings(q, detail)
        for iss in issues:
            shortcoming_counts[iss["code"]] += 1
        first_solve = (
            min(s["elapsed_sec"] for s in q.get("solved_details") or [])
            if q.get("solved_details")
            else None
        )
        per_question_rows.append(
            {
                "id": qid,
                "name": q["name"],
                "category": q["category"],
                "difficulty": q["difficulty"],
                "has_scene": q["has_scene"],
                "solved_flags": q["current_user_solved"],
                "total_flags": q["total_flag_num"],
                "complete": q["complete"],
                "first_solve_sec": first_solve,
                "reopen_count": q.get("reopen_count", 0),
                "issues": issues,
            }
        )

    metrics = {
        "run_label": run_label,
        "generated_at": datetime.now().isoformat(),
        "summary": sum_d,
        "categories": snapshot.get("categories") or [],
        "audit": audit,
        "tokens": token_stats,
        "shortcoming_counts": dict(shortcoming_counts),
        "questions": per_question_rows,
    }

    lines = [
        f"# 模型仿真比赛能力评估报告 — `{run_label}`",
        "",
        f"- **生成时间**：{metrics['generated_at']}",
        f"- **总分（原始 / 152 队模拟名次分）**：**{sum_d.get('total_score', 0)}** / **{sum_d.get('ranked_score', 0)}**",
        f"- **解出率**：题目 **{sum_d.get('solved_questions', 0)}/{sum_d.get('total_questions', 0)}**，Flag **{sum_d.get('solved_flags', 0)}/{sum_d.get('total_flags', 0)}**",
        f"- **合规审计**：泄密 `{len(audit.get('credential_leaks') or [])}` · 限流触发 `{audit.get('rate_limit_hits', 0)}` · 超槽触发 `{audit.get('scene_limit_hits', 0)}` · 故障自愈 `{audit.get('scene_faults_recovered', 0)}/{audit.get('scene_faults_injected', 0)}`",
        "",
        "## 一、八大类场景能力雷达",
        "",
        "| 场景类别 | 题数（全解/总数） | Flag（已解/总数） | Flag 完成率 |",
        "| --- | :---: | :---: | :---: |",
    ]
    for c in snapshot.get("categories") or []:
        pct = round(100.0 * c["solved_flags"] / max(1, c["total_flags"]), 1)
        lines.append(f"| {c['category']} | {c['solved_q']}/{c['total_q']} | {c['solved_flags']}/{c['total_flags']} | {pct}% |")

    lines.extend(
        [
            "",
            "## 二、逐题表现与短板定位",
            "",
            "| 题号 | 类别 | 难度 | 形态 | Flag 进度 | 首解时刻 | Reopen | 诊断标签 |",
            "| --- | --- | :---: | :---: | :---: | :---: | :---: | --- |",
        ]
    )
    for r in per_question_rows:
        tags = ", ".join(i["code"] for i in r["issues"]) or "CLEAN_PASS"
        t_str = f"{r['first_solve_sec']}s" if r["first_solve_sec"] is not None else "—"
        mode = "在线" if r["has_scene"] else "纯附件"
        lines.append(
            f"| `{r['id']}` {r['name']} | {r['category']} | D{r['difficulty']} | {mode} | "
            f"{r['solved_flags']}/{r['total_flags']} | {t_str} | {r['reopen_count']} | `{tags}` |"
        )

    lines.extend(["", "## 三、暴露短板汇总与改进建议", ""])
    if not shortcoming_counts:
        lines.append("- 本轮全部题目均无显著短板标签（Clean Pass）。")
    else:
        for code, cnt in shortcoming_counts.most_common():
            lines.append(f"- **`{code}`（出现 {cnt} 次）**：")
            seen_rem = set()
            for r in per_question_rows:
                for iss in r["issues"]:
                    if iss["code"] == code:
                        lines.append(f"  - 题目 `{r['id']}`：{iss['evidence']}")
                        seen_rem.add(iss["remediation"])
            for rem in sorted(seen_rem):
                lines.append(f"  - **建议措施**：{rem}")

    if token_stats.get("available"):
        lines.extend(
            [
                "",
                "## 四、模型路由与 Token 消耗统计",
                "",
                "| 实际路由 | 请求数 | Failover | Input Tokens | Output Tokens | Cache Read |",
                "| --- | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for rname, st in (token_stats.get("by_route") or {}).items():
            lines.append(
                f"| `{rname}` | {st['calls']} | {st['failovers']} | {st['input']:,} | {st['output']:,} | {st['cache_read']:,} |"
            )

    return metrics, "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze a mock race evaluation run and classify shortcomings")
    ap.add_argument("--platform-url", default="http://127.0.0.1:18099")
    ap.add_argument("--snapshot-file", default=None, help="Optional offline snapshot JSON instead of live platform URL")
    ap.add_argument("--cairn-url", default="http://127.0.0.1:8000")
    ap.add_argument("--cairn-admin-token", default=None)
    ap.add_argument("--tokens-jsonl", default=None)
    ap.add_argument("--run-label", default="round")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    if args.snapshot_file:
        snapshot = json.loads(Path(args.snapshot_file).read_text(encoding="utf-8"))
    else:
        snapshot = requests.get(f"{args.platform_url.rstrip('/')}/api/dashboard/snapshot", timeout=10).json()

    cairn_details: dict[str, dict[str, Any]] = {}
    headers = {"Authorization": f"Bearer {args.cairn_admin_token}"} if args.cairn_admin_token else {}
    for q in snapshot.get("questions") or []:
        pid = q.get("project_id")
        if pid and args.cairn_url:
            try:
                r = requests.get(f"{args.cairn_url.rstrip('/')}/projects/{pid}", headers=headers, timeout=5)
                if r.status_code == 200:
                    cairn_details[pid] = r.json()
            except Exception:
                pass

    tok_stats = load_token_stats(Path(args.tokens_jsonl) if args.tokens_jsonl else None)
    metrics, md = generate_report(snapshot, cairn_details=cairn_details, token_stats=tok_stats, run_label=args.run_label)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "snapshot.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    print(f"Wrote evaluation report to {out_dir / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
