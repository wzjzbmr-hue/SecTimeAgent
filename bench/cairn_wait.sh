#!/bin/bash
# cairn_wait.sh —— 可靠的解题完成监听器（编码安全版）
#
# 用法: cairn_wait.sh <proj_id|-> <challenge_code> [max_wait_seconds]
#   proj_id 传 - 表示只看判分平台不看项目状态
#
# 设计要点（修复旧监控的三个缺陷）:
#   1. 所有输出标记纯 ASCII —— 旧脚本用中文"=== 最终状态 ==="作完成标记，
#      经 PowerShell->SSH 传输编码损坏导致 grep 永不匹配、外部等待死循环
#   2. 双源判定: 判分平台 solved（权威）+ 项目状态（捕捉 stopped/completed）
#   3. 5 秒轮询 + 提交活动即时通报（attempts 变化即打印 PROGRESS 行）
#
# 退出码: 0=SOLVED  1=STOPPED/TIMEOUT  2=参数或通信错误
# 输出标记（供外部脚本 grep，全 ASCII）:
#   RESULT:SOLVED / RESULT:STOPPED / RESULT:TIMEOUT / RESULT:ERROR
#   PROGRESS:ATTEMPT / WAIT:（60s 心跳）

PID="${1:?usage: cairn_wait.sh <proj_id|-> <challenge_code> [max_wait]}"
CODE="${2:?missing challenge_code}"
MAXW="${3:-1800}"
T0=$(date +%s)
LAST_ATT=0
LAST_HB=0

judge_state() {
  curl -s --max-time 4 http://127.0.0.1:8099/results 2>/dev/null | CODE="$CODE" python3 -c '
import json, sys, os
try:
    c = json.load(sys.stdin).get("challenges", {}).get(os.environ["CODE"], {})
    print(("1" if c.get("solved") else "0"), c.get("attempts", 0))
except Exception:
    print("-1", "-1")'
}

proj_status() {
  [ "$PID" = "-" ] && { echo skip; return; }
  curl -s --max-time 4 "http://127.0.0.1:8000/projects/$PID" 2>/dev/null | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin)["project"]["status"])
except Exception:
    print("unknown")'
}

while true; do
  NOW=$(( $(date +%s) - T0 ))
  read -r SOLVED ATT <<EOF
$(judge_state)
EOF
  PSTAT=$(proj_status)

  if [ "$SOLVED" = "1" ]; then
    echo "RESULT:SOLVED code=$CODE ttf=${NOW}s attempts=$ATT"
    exit 0
  fi
  if [ "$SOLVED" = "-1" ]; then
    echo "RESULT:ERROR judge_unreachable after=${NOW}s"
    exit 2
  fi
  if [ "$PSTAT" != "active" ] && [ "$PSTAT" != "skip" ] && [ "$PSTAT" != "unknown" ]; then
    echo "RESULT:STOPPED status=$PSTAT after=${NOW}s attempts=$ATT"
    exit 1
  fi
  if [ "$NOW" -ge "$MAXW" ]; then
    echo "RESULT:TIMEOUT after=${NOW}s attempts=$ATT status=$PSTAT"
    exit 1
  fi
  if [ "$ATT" != "$LAST_ATT" ] && [ "$ATT" != "0" ]; then
    echo "PROGRESS:ATTEMPT n=$ATT after=${NOW}s"
    LAST_ATT=$ATT
  fi
  if [ $(( NOW - LAST_HB )) -ge 60 ]; then
    echo "WAIT: elapsed=${NOW}s status=$PSTAT attempts=$ATT"
    LAST_HB=$NOW
  fi
  sleep 5
done
