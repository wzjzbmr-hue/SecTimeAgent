# 同类开源攻防智能体对比与可吸收优势归档

本文档基于对 `BaaRai/ARTEX`、`RuoJi6/ARTEX` 与 `Team-intN18-SoybeanSeclab/prtseek` 源码的实地核查，系统对比它们与当前 **SecTimeAgent**（基于 `oritera/Cairn` 深度加固）在实际全自主多题演练/攻防场景中的架构差异，并沉淀出**可低成本、低风险直接吸收进 SecTimeAgent 的高价值机制**与落地路线图。

---

## 一、战略定位结论：不换底座，精准吸收

| 维度 | `BaaRai/ARTEX` & `RuoJi6/ARTEX` | `Team-intN18-SoybeanSeclab/prtseek` | 当前 `SecTimeAgent` |
| --- | --- | --- | --- |
| **定位** | Go + Next.js + PostgreSQL 企业级自主渗透/资产测绘平台 | 基于 ARTEX 裁剪的 **CTF 单题深研 Agent**（人机协作、单题 4 小时深挖） | **全自动无人值守多题调度系统**（平台 API 闭环 + 离线工具容器） |
| **多题调度与平台闭环** | 无（偏单任务/资产项目） | 无（依赖人工拖入题面与附件，无放题轮询、场景槽控制、多 Flag `/reopen` 门禁） | **原生闭环**（`cairn race` + `race_bridge` + 2 场景/2 附件双池 + `scene_status=20` 自愈 + 多 Flag 防早退） |
| **安全工具生态** | 基础 CLI（curl/nmap/ripgrep 等） | `python:3.12-slim` + 预装 **Playwright/Chromium** + 基础网络工具 | **Claude Code CLI + 26.4 GB `tools-ready` 离线 Kali**（工控 `ics_client`/`pcap_summary` + 密码学 + 逆向 + 取证 + 离线 PoC/字典） |
| **密钥与模型治理** | `llmpool` 多模型轮换，未做宿主机占位符密钥隔离 | 针对单一模型深度定制，换模型效果下降 | **宿主机 `token_proxy` 托管真实 Key + 国产多厂商自动故障转移**（Kimi -> TokenPlan GLM-5.3/Qwen4-Max -> AliDashScope -> GLM-Coding） |
| **单题深研与防停滞** | 双图记忆（资产图 + 探索图）、MITM 抓包、单命令 cgroup/RSS 保护 | **极强**：多 `solver` 并行、工具结果哈希停滞自检、压缩重注状态、Flag 收敛链方法卡、父子共享调用预算 | 事实图 + `bootstrap/reason/explore` + `[CIRCUIT_BREAKER]` + 多 Flag 门禁；单题并发与停滞细粒度控制有进一步提升空间 |

**核心判断**：`SecTimeAgent` 在**全自主多题总控、零泄密隔离、50 GB 宿主机稳定性、离线专业工具链与国产模型多厂商切换**上已显著领先；**无需更换底层框架**，但应分阶段吸收 `prtseek` 与 `ARTEX` 在**单题破题效率、防原地打转与异构多路并行**上的 7 项成熟设计。

---

## 二、可吸收的 7 项核心优势（源码级拆解与映射）

### 优势 1：Flag 收敛链与 6 题型战术检查单（源自 `prtseek/agent/ctf.go`）

- **原方案设计**：
  - `CTFEvidencePriority` 强制智能体始终围绕单一主线推进：
    `flag 格式/校验器或成功条件 -> 可控输入或关键状态 -> 最小利用/解密/还原步骤 -> 实际输出 -> 独立复现`；不推进该链路的动作一律判为低优先级噪声。
  - `CTFSolverMethod` 按 **Web / Pwn / Reverse / Crypto / Forensics / Misc** 给出极简微检查单，要求每次操作遵循 `假设 -> 最小操作 -> 实际结果 -> 是否改变判断`，禁止无界扫描与原样重试。
  - 区分「候选字符串」与「真实 Flag」：发现候选后必须核对来源、校验链路与最小复现。
- **SecTimeAgent 落地点**：
  - 融入 `cairn/src/cairn/dispatcher/prompts/competition/bootstrap.md`、`explore.md`、`reason.md`。
  - 补充 **ICS/工控** 第 7 类检查单（先用 `pcap_summary.py` / `ics_client.py` 建基线，禁止手拼协议头）。
- **收益 / 成本**：**极高收益 / 极低成本**（纯 Prompt 升级，零架构风险）。

---

### 优势 2：结构化研究记忆与「Dead-Ends 失败路线黑名单」（源自 `prtseek/agent/research_memory.go` & `compaction.go`）

- **原方案设计**：
  - 上下文压缩或阶段切换后，强制重新注入结构化研究状态，至少包含四类字段：**已证实证据（含证据 ID/路径）**、**已证伪/失败路线（Dead Ends）**、**当前假设与反证**、**下一步可区分变量**。
  - 明确区分“环境/工具故障”与“漏洞不存在”，避免后续子任务重复踩同一个死胡同。
- **SecTimeAgent 落地点**：
  - 在 `bootstrap_conclude.md`、`explore_conclude.md`、`explore.md` 中规范 `fact.description` 固定四段格式：
    1. `[PROGRESS]`：`solved: k/n`, `question_complete: true|false`
    2. `[CONFIRMED]`：命令/输入 + 原始返回 + 落盘路径
    3. `[DEAD_ENDS]`：已证伪的攻击面/参数（后续 `reason` 严禁重复派发）
    4. `[FOOTHOLDS]`：存活 shell、凭证、tmux 会话、内网端口与工作区文件
- **收益 / 成本**：**高收益 / 极低成本**（直接消除 `reason -> explore` 跨轮重复探索）。

---

### 优势 3：基于输出签名的零成本「停滞自检」机制（源自 `prtseek/agent/research_progress.go`）

- **原方案设计**：
  - 维护最近 `8` 次非轮询工具调用的观察窗口，按 `SHA-256(tool_name + "\x00" + normalized_result)` 计算签名（HTTP 工具仅对 `status / body_bytes / sha256 / truncated` 归一化）。
  - 判定规则：最近 8 次中 **相同响应签名 `>= 3` 次** 或 **工具失败 `>= 4` 次** 即标记 `stalled`；每 `8` 步触发一次软复核。
  - **关键巧思**：不阻断执行、不额外消耗 LLM 调用，仅在返回上下文中注入一条复核提示（要求排查环境/代理/重定向/初始状态，设计可区分假设的对照实验；若仍无新证据则换路或明确阻塞）。
- **SecTimeAgent 落地点**：
  - **轻量版（立即可做）**：在 `reason.md` 中加入规则——若连续 `2` 个相邻 `explore` fact 均未产生新有效证据（无新端口/新端点/新漏洞/新凭证/新 Flag），强制切换完全不同的攻击面，或在无剩余方向时触发挂起让出槽位。
  - **进阶版（代码层）**：在 `cairn/src/cairn/dispatcher/scheduler/loop.py` 对同一项目连续产出相似/无进展 fact 的次数计数，达到阈值时向项目注入一条 `[STALL_WARNING]` hint 或提前触发 `revisit` 挂起。
- **收益 / 成本**：**高收益 / 低成本**（大幅减少单题卡死空耗 15–20 分钟的情况）。

---

### 优势 4：单题多视角并行破题 + 异构模型轮换（源自 `prtseek` `delegate_agents` 与 `BaaRai/ARTEX` `llmpool`）

- **原方案设计**：
  - `prtseek` 的 `command` 可同时派发 `2–6` 个互补方向的 `solver`（如一路做源码/JS 逆向、一路做接口/鉴权探测、一路做独立复核），并在主线突破后及时取消无价值分支。
  - `BaaRai/ARTEX` 支持多 LLM Profile 轮换（`llm_rotate: true`，按 `A, B, A, B` 分配给并发 Worker）：
    - 一方面分散单厂商并发限流压力；
    - 另一方面利用**不同模型的异构推理视角**（如 Kimi K3.1 与 GLM-5.3 / Qwen4-Max 互补）打破单一模型盲区。
- **SecTimeAgent 落地点**：
  - **零代码改造即可启用**：Cairn 调度器原生支持单项目多 Worker 共享同一容器工作区！
    - 在 `config/dispatch.yaml` 中将 `runtime.max_project_workers` 从 `1` 调整为 `2`（总槽位仍受 `max_workers: 4` 约束），并在 `reason.md` 明确要求派发的 2 个 `intent` 必须**方向严格互补**（禁止重叠）。
    - 在 `workers` 中配置 2 个不同国产旗舰路由（例如 `w_kimi` 走 `/kimi` -> `kimi-k3.1-pro-highspeed`，`w_glm` 走 `/tp_glm` -> `glm-5.3` 或 `/tp_qwen` -> `qwen4-max`），配合 `priority` 与 `max_running` 实现天然的异构双路并发与错峰限流。
- **收益 / 成本**：**极高收益 / 极低成本**（显著提升中难题与多 Flag 题解出率）。

---

### 优势 5：独立实验隔离与「禁止复用旧产物当复现」（源自 `prtseek` `research_experiment`）

- **原方案设计**：
  - 每次关键利用或复现实验分配独立子目录（`.research/experiments/exp-<id>`）与唯一产物前缀，执行前写明 `hypothesis / changed_variable / prediction`。
  - 硬性纪律：**工作目录隔离不等于远程靶机状态已复位；重新读取旧文件不能证明独立复现**。
- **SecTimeAgent 落地点**：
  - 写入 `worker/deployed-rootfs/home/kali/workspace/CLAUDE.md`（及 `AGENTS.md`）与 `explore.md`：要求每次 Exploit/解密验证将临时脚本和输出写入 `/tmp/exp_<intent_id>/`，避免前一次失败实验残留的 cookie/payload/临时文件污染后续判断。
- **收益 / 成本**：**中高收益 / 极低成本**。

---

### 优势 6：离线无头浏览器支持（Playwright + Chromium）（源自 `prtseek/Dockerfile`）

- **原方案设计**：
  - 在镜像构建阶段离线预装 `@playwright/mcp`、`@playwright/cli`、`playwright` 与 `chromium --with-deps`，运行时零联网直接启动无头浏览器。
  - 专克纯 `curl` 难以处理的 Web 题：前端 JS 混淆加密签名、SPA 动态路由、复杂 Cookie/LocalStorage 状态、DOM/XSS 触发与验证码前端逻辑。
- **SecTimeAgent 落地点**：
  - 先核查 `cairn-worker:tools-ready-20261125` 是否已内置 `chromium` / `playwright` / `puppeteer` / `selenium`；
  - 若已内置，直接在 `CLAUDE.md` 补充调用命令与适用场景；
  - 若未内置且 50 GB 宿主机磁盘余量充足（预留 `>= 6 GB` 安全红线），可在 `worker/Dockerfile.deployed` 增设可选构建阶段预装离线 Playwright + Chromium（约增 0.8–1.2 GB）。
- **收益 / 成本**：**高收益（针对复杂现代 Web 题）/ 中成本（需注意 50 GB 磁盘预算）**。

---

### 优势 7：共享调用次数预算 + 单命令内存软硬限（源自 `prtseek/agent/run_budget.go` & `RuoJi6/ARTEX`）

- **原方案设计**：
  - `prtseek` 的 `RunBudget` 用原子计数器让父子会话共享一个逻辑 LLM 请求总数上限（默认 200 次，可配），避免单题陷入高频小步调用烧光配额。
  - `RuoJi6/ARTEX` 对单条 Bash/Python 命令施加 `2048 MiB` 内存与 `120s` 超时保护（超时直接强杀不转后台），防止单条 `z3` / 爆破脚本拖垮整个容器。
- **SecTimeAgent 落地点**：
  - **代理层调用计数熔断**：在 `bench/token_proxy.py` 已按路由统计 `calls` 与 Token 的基础上，可扩展按项目/路由维度告警或软限流。
  - **容器内工具自律**：已在 `hashpath.py` 加入 `--max-seconds 180` 硬上限、容器层加 `mem_limit: 3g` / `pids_limit: 512`；后续可在 `CLAUDE.md` 提醒对 `z3` / `john` / `hashcat` / `ffuf` / `nuclei` 统一套 `timeout 120s` 执行。
- **收益 / 成本**：**中收益 / 低成本**。

---

## 三、推荐实施优先级（按投入产出比排序）

| 优先级 | 吸收项 | 改动范围 | 预计耗时 | 风险等级 |
| --- | --- | --- | --- | --- |
| **P0（立刻可做）** | 优势 1 + 优势 2 + 优势 5：Prompt 升级（Flag 收敛链 + 7 题型检查单 + `[DEAD_ENDS]` 规范 + `/tmp/exp_*` 隔离） | `prompts/competition/*.md`、`CLAUDE.md`、`AGENTS.md` | 20 分钟 | 极低 |
| **P0（立刻可做）** | 优势 4：单题双路并发 + 异构国产旗舰双 Worker（`kimi-k3.1-pro-highspeed` + `glm-5.3` / `qwen4-max`） | `config/dispatch.competition.example.yaml`、`reason.md` | 15 分钟 | 极低 |
| **P1（赛前可选）** | 优势 3：调度层连续无进展 fact 停滞检测与自动 `[STALL_WARNING]` 注入 | `cairn/src/cairn/dispatcher/scheduler/loop.py` + 单测 | 1 小时 | 低 |
| **P1（按需核查）** | 优势 6：检查离线镜像无头浏览器支持并写入 `CLAUDE.md`（按盘容决定是否增量预装） | `worker/Dockerfile.deployed`、`CLAUDE.md` | 30 分钟 | 低–中（关注盘容） |
| **P2（后续演进）** | 优势 7：代理层按项目请求次数预算 + `ARTEX` 式资产去重图（适合长周期多主机渗透） | `bench/token_proxy.py`、`cairn/server/` | 1–2 天 | 中 |

---

## 四、参考仓库

- [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX) — 重点参考：双图记忆（资产图 + 探索图）、多 LLM 轮换 (`llmpool`)、Prompt 注入隔离。
- [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) — 重点参考：单条命令内存与超时保护（cgroup v2 / RSS 采样）、Streamable HTTP / SSE MCP 双协议接入。
- [Team-intN18-SoybeanSeclab/prtseek](https://github.com/Team-intN18-SoybeanSeclab/prtseek) — 重点参考：`agent/ctf.go`（Flag 收敛链与题型方法卡）、`agent/research_progress.go`（哈希签名停滞自检与 `research_experiment`）、`agent/research_memory.go`（压缩状态重注与失败路线记录）、`agent/run_budget.go`（父子共享调用预算）、`Dockerfile`（离线 Playwright + Chromium）。
