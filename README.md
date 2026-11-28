# SecTimeAgent

面向自动化网络安全演练与 CTF 攻防场景的全自主智能体框架（基于 [oritera/Cairn](https://github.com/oritera/Cairn) 深度加固与重构），针对 **Ubuntu 24.04（8 核 / 16 GB RAM / 50 GB 磁盘）**、**长时间无人值守运行**、**一题多 Flag**、**国产大模型白名单网关** 与 **对话审计零泄密** 场景设计。

---

## 核心特性

- **官方 AI 赛全自动总控 (`cairn race`)**
  - 完整实现官方 `API_接入.md` 7 个接口与全部 `AD-xxxxxx` 业务错误码（全局令牌桶 `<= 2 req/s` 限流、`AD-002002` 动态退避、`scene_status=20` `stop -> 3 -> start` 自动自愈、附件免认证下载，另内置 `StreamableMCPClient` 备选）。
  - 支持 **分阶段放题** 周期轮询、**2 在线场景 + 2 纯附件** 双池并行（遇 `AD-162006` 自动下调场景并发）、按难度/分值/解出人数优先级队列、超时挂起与尾盘回访队列。
  - 支持 `--start-at` / `--end-at` 与 `systemd` 定时器，锁机状态下 `08:30` 自动开赛、`12:30` 自动收尾。
- **一题多 Flag 权威门禁（交一个锁一个，杜绝早退）**
  - Worker 每发现一个 Flag 立即通过 `submit-flag` 锁分；宿主机 `race_bridge` 实时拉取官方权威进度 `current_user_solved / total_flag_num`。
  - 若智能体在 `current_user_solved < total_flag_num` 时提前输出 `complete`，总控自动拦截并调用 Cairn `/reopen` 注入 `[MULTI_FLAG_GATE]` 反馈继续深挖剩余 Flag。
- **零凭据泄露安全隔离（适配公开审计日志）**
  - **模型 API Key 宿主机托管**：`bench/token_proxy.py` 在宿主机从 `.env` 注入真实 Key 并剥离占位符，Worker 容器仅持 `ANTHROPIC_AUTH_TOKEN=proxy-managed-placeholder`。
  - **比赛 `AGENT_TOKEN` 宿主机托管**：`cairn/src/cairn/race/bridge.py` 为每个项目签发一次性项目 Token（在 `create_project` 前原子预注册，消除竞态），真实 `AGENT_TOKEN` 永不进入 Worker 容器。
  - **Cairn Server 管理鉴权**：支持 `CAIRN_ADMIN_TOKEN`（仅 `/health`、`/` 与静态资源免鉴权），防止容器内横向误操作控制面。
- **国产模型多厂商自动故障转移 (`bench/token_proxy.py`)**
  - 遇 `401 / 402 / 403 / 429(code=1113|1310) / 5xx` 自动冷却 120s 并无缝切换备选国产官方白名单网关与模型（支持 `model_override` 重写）：
    `Kimi (kimi-k3.1-pro-highspeed / kimi-k2.7-code-highspeed)` -> `阿里云 TokenPlan (glm-5.3 / qwen4-max)` -> `阿里云 DashScope 保底 (glm-5.3 / qwen4-max / kimi-k3.1-pro)` -> `智谱 GLM Coding Plan`。
- **50 GB 赛场主机运行时加固**
  - 单 Worker 容器启用 `--init`（防僵尸进程）、`mem_limit` / `cpu_limit` / `pids_limit` 硬限、`stdout_max_bytes` 尾部截断防 OOM、进程组级联强杀（`-PGID` + `pkill -P`）。
  - `completed_action: remove` 在项目 `completed` 与 `stopped` 时均自动归档摘要并删除容器，配合定期孤儿容器清理，防止 50 GB 磁盘爆盘。
  - SQLite 启用 WAL + `busy_timeout=30000` + `BEGIN IMMEDIATE`；调度器增加全局异常防护、启动健康检查失败拉黑、Intent 连续失败指数退避与 `[CIRCUIT_BREAKER]` 自动熔断、单题硬预算控制。
  - 输出解析器优先提取最后一个符合 Cairn 协议格式的 JSON，避免误采前置工具回显。
- **赛题专用 Prompt 与 Worker 确定性工具**
  - 新增 `competition` Prompt 组（多 Flag 门禁、事实卫生与 `[HYPOTHESIS]` 规范、放弃纪律、防 Prompt 注入）。
  - 新增非特权 `nmap` 透明包装（自动注入 `--unprivileged`）、工控发包客户端 `ics_client.py`、PCAP 结构化解码 `pcap_summary.py`、`hashpath.py --max-seconds` 硬时限与 `submit-flag` CLI。

---

## 系统架构

```text
官方比赛平台 (API_接入.md / MCP_接入.md)
        ▲
        │ Authorization: Bearer <AGENT_TOKEN> (仅宿主机持有，全局 <= 2 req/s)
        ▼
┌──────────────────────────────────────────────────────────┐
│ 宿主机控制面                                               │
│  ├── cairn race (RaceOrchestrator + 嵌入式 race_bridge)   │
│  ├── cairn serve (SQLite WAL + CAIRN_ADMIN_TOKEN)        │
│  ├── cairn dispatch (资源隔离 + 熔断 + 50GB 容器自动清理)   │
│  └── bench/token_proxy.py (宿主机 Key 注入 + 国产多厂商切备) │
└───────────────▲──────────────────────────────▲───────────┘
                │ X-Project-Token (一次性)      │ proxy-managed-placeholder
                │ submit-flag                  │ http://127.0.0.1:8100/kimi
┌───────────────┴──────────────────────────────┴───────────┐
│ Worker 容器 (cairn-dispatch-*, --init, 3G / 2.5C / 512 PID) │
│  Claude Code CLI + nmap包装 + ics_client + pcap_summary  │
│  + hashpath + poc_catalog + submit-flag                  │
└──────────────────────────────────────────────────────────┘
```

---

## 目录结构

```text
cairn/
  src/cairn/
    race/                      官方 AI 赛总控 (orchestrator.py)、API/MCP 客户端 (client.py)、零泄密提交桥 (bridge.py)
    dispatcher/
      prompts/competition/     比赛专用 Prompt 组 (bootstrap / reason / explore / conclude)
      runtime/                 容器资源隔离与清理 (containers.py)、流截断与进程组强杀 (process.py)
      scheduler/               调度循环、熔断器、单题预算与孤儿清理 (loop.py)
      output_parser.py         协议优先末位 JSON 提取器
    server/                    SQLite WAL 并发事务 (db.py)、/health 与 Admin Token 守卫 (app.py)
  tests/                       109 项自动化单元与端到端契约测试（零真实模型费用）
bench/
  token_proxy.py               宿主机 Key 托管、Token 记账与国产白名单主备切换代理
  mock_race_platform.py        1:1 仿真官方 7 接口平台 + MCP + 动态 Docker 靶机 + 实时看板
  dashboard.html               本地零构建实时观测看板
worker/
  Dockerfile.deployed          基于 tools-ready 离线镜像增量叠加竞赛脚本并清理遗留杂项
  Dockerfile.slim              多阶段压平瘦身镜像（剔除云 CLI/.git/截图/缓存/GPU 驱动，释放 ~8+ GB）
  deployed-rootfs/             submit-flag、nmap 包装、ics_client.py、pcap_summary.py、hashpath.py、CLAUDE.md
config/
  dispatch.competition.example.yaml  8C16G50G 比赛调度配置示例（零真实 Key）
  proxy.competition.example.yaml     国产旗舰主备路由配置示例（零真实 Key）
deploy/
  preflight.py                 零依赖赛前一键自检脚本（可直接宿主机 python3 运行）
  diagnose.sh                  赛中 5 秒快速诊断脚本
  cairn-race.service           正式赛 systemd 服务单元
  cairn-race.timer             定时自动拉起任务定时器
compose.ubuntu.yaml            三服务宿主网络部署配置（server / proxy / dispatcher）
compose.build.yaml             从源码构建 cairn-app 覆盖配置
compose.dev.yaml               挂载源码热调试覆盖配置
```

> 数据库、运行日志、真实 API Key、`AGENT_TOKEN`、`config/dispatch.yaml`、`config/proxy.yaml`、`.env`、`.env.*` 均在 `.gitignore` 中排除，严禁提交到仓库。

---

## 快速部署与比赛准备（Ubuntu 24.04 / 8C 16G / 50G）

### 1. 宿主机 Docker 空间与网络池加固

在 50 GB 比赛机上先配置 `/etc/docker/daemon.json`（限制容器日志体积并扩展地址池）：

```json
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "20m", "max-file": "3" },
  "default-address-pools": [
    { "base": "172.20.0.0/14", "size": 24 }
  ]
}
```

```bash
sudo systemctl restart docker
```

### 2. 克隆仓库并导入离线 Worker 镜像

**完整离线工具环境需先导入 `cairn-worker-tools-ready-20261125.tar.gz`**（展开约 26.4 GB，建议直接流式导入，不在磁盘留存压缩包）：

```bash
git clone https://github.com/wzjzbmr-hue/SecTimeAgent.git /opt/SecTimeAgent
cd /opt/SecTimeAgent
mkdir -p config runtime/cairn runtime/bench-results runtime/archives bench/results

# 校验并流式导入基础离线镜像
sha256sum cairn-worker-tools-ready-20261125.tar.gz
# 期望：404eec1b01f2b30d2c0b9fd078a595bb1d31d68a87daa95fa243175b8e3cc64e
gunzip -c cairn-worker-tools-ready-20261125.tar.gz | docker load
# 原 OCI 镜像身份参考：sha256:81e1b018223a72bfa67b51bddf2a0df8126198a3b7530a1b524e651af6a83cf5

# 在 tools-ready 之上增量叠加竞赛脚本、submit-flag、nmap 包装与工控工具（共享底层，秒建）
docker build -f worker/Dockerfile.deployed -t cairn-worker:competition .

# 或构建压平瘦身版（释放 ~8+ GB 磁盘空间，适合 50 GB 比赛机）
docker build -f worker/Dockerfile.slim -t cairn-worker:competition-slim .
```

### 3. 配置本机密钥与代理（仅存宿主机，不入库）

```bash
cp config/dispatch.competition.example.yaml config/dispatch.yaml
cp config/proxy.competition.example.yaml config/proxy.yaml
```

创建 `.env`（权限 `chmod 600 .env`），填写本地管理 Token 与可用的国产模型 Key：

```bash
CAIRN_ADMIN_TOKEN=<随机强口令>
PROXY_CONFIG=/config/proxy.yaml
KIMI_API_KEY=<月之暗面 Key>
QWEN_TOKEN_PLAN_API_KEY=<阿里云 TokenPlan Key>
ALI_DASHSCOPE_API_KEY=<阿里云 DashScope Key>
GLM_CODING_API_KEY=<智谱 Coding Plan Key>
```

同步将同一个 `CAIRN_ADMIN_TOKEN` 写入 `config/dispatch.yaml` 的 `admin_token` 字段。

> **现场调试网关登记**：在平台「环境配置 -> 网关配置」登记官方白名单 `base_url`（`https://api.moonshot.cn/anthropic`、`https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic`、`https://dashscope.aliyuncs.com/apps/anthropic`、`https://open.bigmodel.cn/api/anthropic`），将平台生成的专属代理地址替换进 `config/proxy.yaml` 的对应 `url` 字段即可（Anthropic 协议不要省略 `/v1`，客户端会自动拼接 `/v1/messages`）。

### 4. 构建应用镜像并启动基础服务

```bash
docker build -t cairn-app:ubuntu-baseline-dev .
docker tag cairn-app:ubuntu-baseline-dev cairn-app:migration-20261119
# 仅启动 server / proxy（按需再启动 dispatcher，避免闲置消耗模型额度）
docker compose -f compose.ubuntu.yaml up -d server proxy
```

### 5. 赛前一键自检与 `08:30` 自动开赛

创建 `config/race.env`（权限 `600`）：

```bash
RACE_BASE_URL=http://<比赛平台地址>
RACE_AGENT_TOKEN=<本队 AGENT_TOKEN>
CAIRN_ADMIN_TOKEN=<同 .env>
```

运行零依赖宿主机自检（只读检查时间、磁盘余量、`daemon.json`、Worker Image ID、Server/Proxy 健康状态与官方 `AD-000000` 连通性）：

```bash
python3 deploy/preflight.py \
  --worker-image cairn-worker:competition \
  --race-base-url "$RACE_BASE_URL" \
  --agent-token "$RACE_AGENT_TOKEN"
```

确认输出 `PREFLIGHT RESULT: READY` 后，按实际开赛时间修改 `deploy/cairn-race.timer` 与 `config/race.env` 中的 `RACE_START_AT` / `RACE_END_AT`，启用自动拉起定时器：

```bash
sudo cp deploy/cairn-race.service deploy/cairn-race.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cairn-race.timer
systemctl list-timers cairn-race.timer
```

赛中如需 5 秒定位服务/容器/解题状态，运行：

```bash
bash deploy/diagnose.sh
```

---

## 本地开发与零费用验证

### 运行全量单元测试（零模型消耗）

```bash
docker run --rm --init -v "$(pwd):/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/cairn/src cairn-app:ubuntu-baseline-dev \
  /cairn/.venv/bin/python -m pytest /workspace/cairn/tests -q -p no:cacheprovider
```

或在宿主机使用 `uv` 运行：

```bash
uv sync --project cairn --frozen --group dev
uv run --project cairn --group dev pytest cairn/tests -q
```

### 启动 1:1 官方平台仿真器联调

```bash
python3 bench/mock_race_platform.py \
  --host 127.0.0.1 --port 18080 \
  --config path/to/mock_race.yaml \
  --token test-agent-token \
  --max-scenes 2 --rate-limit 3
```

### 源码挂载热调试

```bash
docker compose -f compose.ubuntu.yaml -f compose.build.yaml -f compose.dev.yaml up -d --build
# 修改 cairn/src/ 后重启对应服务
docker compose -f compose.ubuntu.yaml -f compose.build.yaml -f compose.dev.yaml restart server dispatcher
```

---

## 基线与许可证

| 内容 | 基线 |
| --- | --- |
| 初始 Ubuntu 基线提交 | `ac9ca121de880fefb333c2d9b61233a6747669d7` |
| 基础离线 Worker 镜像 | `cairn-worker:tools-ready-20261125` |
| 增量 Worker 镜像 | `cairn-worker:competition` (`worker/Dockerfile.deployed`) |
| 协作规范 | [CONTRIBUTING.md](CONTRIBUTING.md) |

源自 [oritera/Cairn](https://github.com/oritera/Cairn)，保留原始 [LICENSE](LICENSE)（AGPL-3.0）与 [上游 README](README.upstream.md)。镜像内第三方安全工具各自适用其上游许可证。
