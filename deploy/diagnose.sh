#!/bin/bash
# 赛中 5 秒快速诊断脚本（30 分钟现场调试黄金时间使用）
set -u
echo "=== 1. TIME & DISK ==="
date "+%Y-%m-%d %H:%M:%S %Z"
df -h /
free -h

echo -e "\n=== 2. CONTAINERS ==="
docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"

echo -e "\n=== 3. SERVICE HEALTH ==="
curl -s --max-time 3 http://127.0.0.1:8000/health; echo ""
curl -s --max-time 3 http://127.0.0.1:8100/stats; echo ""
curl -s --max-time 3 http://127.0.0.1:8098/bridge/health; echo ""

echo -e "\n=== 4. ORCHESTRATOR STATE ==="
[ -f runtime/race-orchestrator-state.json ] && cat runtime/race-orchestrator-state.json || echo "(no state file yet)"

echo -e "\n=== 5. RECENT DISPATCHER LOGS ==="
docker logs --tail 25 cairn-ubuntu-dispatcher 2>&1 || true
