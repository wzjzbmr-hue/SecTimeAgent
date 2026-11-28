# 同类开源攻防智能体对比与可吸收优势归档

本文档基于对 `BaaRai/ARTEX`、`RuoJi6/ARTEX`、`Team-intN18-SoybeanSeclab/prtseek` 以及 `oritera/Cairn` 近期活跃 Fork 与衍生项目源码的实地核查，系统对比它们与当前 **SecTimeAgent**（基于 `oritera/Cairn` 深度加固）在实际全自主多题演练/攻防场景中的架构差异，并沉淀出**可低成本、低风险直接吸收进 SecTimeAgent 的高价值机制**与落地路线图。

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

## 三、`oritera/Cairn` 近期活跃 Fork / 衍生项目调研与可吸收优势（优势 8–12）

在排查上游 `oritera/Cairn`（最新提交 `2026-09-07`）之后所有存在实质代码修改的 Fork 及非 Fork 衍生仓库后，筛选出 **7 个高度贴合国内全自主攻防演练痛点的改版**（以及 1 条供应链安全警示）。

### 3.1 重点魔改项目全景对比

| 仓库 | 最新提交 | 核心定位与特色 | 最值得关注的设计 |
| --- | --- | --- | --- |
| [guaidao2/Cairn-Local](https://github.com/guaidao2/Cairn-Local) | `2026-11-10` | 明确面向本地 Kali 虚拟机实战/演练的去 Docker 改版 | 内置 Python 子进程 Agent 循环、`read` 工具原生读图缩放（≤2048px / ≤3MB）、DeepSeek 思考链 `max_tokens=32768` 防截断、`reason` 结构化图查询工具 |
| [Shennnnnnnnnn/Cairn](https://github.com/Shennnnnnnnnn/Cairn) | `2026-10-19` | TypeScript 重写的多宿主轻量黑板（公开前移除了演练专用流程） | 18 组难题 A/B 验证（默认单会话复用 + 按需独立 Explore 省 ~39% Token）、宿主外部验收 `CAIRN_VERIFY_COMMAND`、截止时间预留 `CAIRN_DEADLINE`、`reopen` + `epoch` 隔离 |
| [Marven11/Cairn](https://github.com/Marven11/Cairn) | `2026-11-08` | 多目标建模与在线运维增强版 | 原生**多 Goal 模型**（`Allow multiple goals`）与图状态自动推导完成、Reasoner 推荐下一条 Intent、Dispatcher 热重载、单独停止异常 Worker |
| [xiaoju111a/Cairn](https://github.com/xiaoju111a/Cairn) | `2026-10-30` | 验证增强与长局防上下文爆炸版 | 新增独立 `verify` 阶段与 `intelligence.py` CVE 情报库、`graph overview` 限制 Explore/Verify 上下文长度、失败退避重试、修复 ClaudeCode 健康检查提示词 |
| [86cloudyun-afk/Cairn](https://github.com/86cloudyun-afk/Cairn) | `2026-10-25`（`11-12` 推送） | 会话恢复与工件清单持久化版 | **一次性自动恢复缺失的 Claude 会话**（解决 `claude -r` 偶发 session-not-found）、工作流计划与产物清单写入 Worker 私有快照、任务级网络控制 |
| [bronezppg-arch/Cairn](https://github.com/bronezppg-arch/Cairn) | `2026-10-28`（`11-11` 推送） | 国产大模型适配与内网横向可视化版 | 明确规避 **GLM 推理模型思考链吃光输出导致 JSON 为空**（结构化阶段禁用 `thinking` 并拉高输出预算至 `16384`）、自动发现 GLM/Qwen/DeepSeek 接口、Cytoscape 内网拓扑图 |
| [LongSang01/Cairn-E](https://github.com/LongSang01/Cairn-E) & [Rabbit0007/Rabbit](https://github.com/Rabbit0007/Rabbit)（衍生 [mastercho/Rabbit](https://github.com/mastercho/Rabbit)） | `2026-11-09` / `2026-11-26` | 融合 `Cairn-Y` 与 `ARTEX` 的执行层抗毁改版 | `Cairn-E`：默认步骤并行 + 非对称 `exclusive` 锁（爆破/撞库类才串行）、M-Token 硬预算与越界主机拦截；`Rabbit`：Fail-closed JSON 解析 + 带语法诊断的定向修复环、Worker 预装 JDK（`jdb`/`javap`）、单命令 90s 超时 + 600s 执行预算（含 60s 收尾预留）；`mastercho/Rabbit` 默认关闭会锁死在 `needs_attention` 的人工介入态 |

> **供应链安全警示**：排查中发现某近期推送的 Fork `domserviceeu/Cairn` 在 worker 镜像构建阶段注入了可疑动态载荷（`CRED-1028 v2`），**严禁拉取、复用或构建该仓库代码**。

---

### 优势 8：国产推理模型 JSON 截断防御与坏 JSON 定向修复环（源自 `bronezppg-arch/Cairn`、`guaidao2/Cairn-Local`、`Rabbit0007/Rabbit`）

- **原方案设计**：
  - `bronezppg-arch/Cairn` 与 `guaidao2/Cairn-Local` 均在实战中验证了国产推理模型（GLM / DeepSeek 等）的高频故障：**思考链（thinking/reasoning）会耗尽默认输出 Token 预算，导致结构化阶段（`reason` / `conclude`）返回空文本或截断 JSON**；解法是拉高 `max_tokens`（`16384`–`32768`）并在纯结构化输出阶段按需关闭深度思考。
  - `Rabbit0007/Rabbit` 采用 **Fail-closed JSON 解析 + 带语法诊断的定向修复环**：拒绝围栏/重复键/尾部残渣，但首次解析失败不直接判整步作废，而是附带具体解析错误向模型发起 1 次定向修复重试。
- **SecTimeAgent 落地点**：
  - 在 `cairn/src/cairn/dispatcher/contracts.py` 与 `tasks/common.py` 中，为 `reason` / `bootstrap_conclude` / `explore_conclude` 增加 **JSON 解析失败后的 1 次带错因定向修复重试**；
  - 在 `bench/token_proxy.py` 及 `config/dispatch*.yaml` 核对各国产路由（`kimi-k3.1-pro-highspeed` / `glm-5.3` / `qwen4-max`）的输出上限与思考参数，避免因思考预算耗尽触发空响应。
- **收益 / 成本**：**极高收益 / 低成本**（直接挽救跑了 5–10 分钟却因单个 JSON 语法错误作废的高价值步骤）。

---

### 优势 9：Claude 会话丢失一次性自愈 + 失败退避重试 + 无人值守防卡死（源自 `86cloudyun-afk/Cairn`、`xiaoju111a/Cairn`、`mastercho/Rabbit`）

- **原方案设计**：
  - `86cloudyun-afk/Cairn` 在 `tasks/explore.py` 中识别 Claude CLI `claude -r` 明确报会话不存在（missing conversation）的场景，自动执行**一次性新会话回退恢复**（携带已有摘要上下文），避免同一步骤反复崩溃。
  - `xiaoju111a/Cairn` 在 `scheduler/loop.py` 中对失败任务施加**退避延迟（delay failed retries）**，防止上游接口短暂抖动或限频时在几秒内连续打光重试次数与 RPM 配额。
  - `mastercho/Rabbit` 在 `2026-11-26` 将会阻塞于人工确认态 `needs_attention` 的 `step_recovery` 改回默认关闭，确保无人值守运行时失败步骤可被释放并重新调度。
- **SecTimeAgent 落地点**：
  - 在 `cairn/src/cairn/dispatcher/workers/adapters/claudecode.py` 与 `tasks/explore.py` 增加 missing-session 检测与一次性新建会话降级；
  - 在 `cairn/src/cairn/dispatcher/scheduler/loop.py` 为连续失败的 Intent 增加指数/固定退避冷却（如 `15s -> 45s`），并确保任何恢复逻辑都不引入需要人工点击的永久阻塞态。
- **收益 / 成本**：**高收益 / 低成本**（显著提升长时间全自动无人值守稳定性）。

---

### 优势 10：长探索阶段用 Graph Overview 限制上下文体积（源自 `xiaoju111a/Cairn`）

- **原方案设计**：
  - `xiaoju111a/Cairn` 在 `tasks/common.py` 与 `tasks/explore.py` 中引入有界图概览（`graph overview`），在项目执行到中后期、Fact 数量快速增长时，仅向 Explore/Verify 注入压缩后的图谱结构与强相关节点，避免上下文线性膨胀拖慢响应或触发上下文截断。
- **SecTimeAgent 落地点**：
  - 在 `cairn/src/cairn/dispatcher/tasks/common.py` 中为 `explore` 上下文构建增加 Fact 数量/字符数阈值：超过阈值时自动切换为“高优先级 Fact（含 `[PROGRESS]`/`[FOOTHOLDS]`/`[DEAD_ENDS]`）+ 其余节点一行摘要”的有界视图。
- **收益 / 成本**：**高收益（多 Flag 长局必备）/ 低成本**。

---

### 优势 11：Worker 工具链补齐 JDK（`jdb`/`javap`）与多模态图片预处理辅助（源自 `Rabbit0007/Rabbit`、`guaidao2/Cairn-Local`）

- **原方案设计**：
  - `Rabbit0007/Rabbit` 在 Worker 容器内预装 JDK 工具链，遇到 **Java JDWP 调试端口、反序列化链分析或 `.class`/`.jar` 逆向** 时可直接用 `jdb` / `javap` 破局。
  - `guaidao2/Cairn-Local` 为读取图片实现 MIME 探测、自动缩放（≤2048px）与体积压缩（≤3MB），提升 **Misc / 隐写 / 验证码 / Web 截图** 题型处理能力。
- **SecTimeAgent 落地点**：
  - 核查当前 `cairn-worker:tools-ready-20261125` 镜像是否已具备 `jdb`、`javap`、`tesseract`、`zbarimg` 及 Python `Pillow`；
  - 在 `worker/tools/` 增加轻量化图片信息摘要/缩略图转换小脚本（或在 `CLAUDE.md` 中指明可用图像与 Java 调试工具路径），在 50 GB 宿主机磁盘预算允许前提下按需补齐缺失工具。
- **收益 / 成本**：**中高收益（拓宽题型覆盖面）/ 极低成本**。

---

### 优势 12：多 Goal 原生建模 + 非对称 `exclusive` 并行锁（源自 `Marven11/Cairn`、`LongSang01/Cairn-E`、`Shennnnnnnnnn/Cairn`）

- **原方案设计**：
  - `Marven11/Cairn` 将项目模型从单 Goal 升级为**多 Goal**，并根据各 Goal 状态自动推导项目完成；`Shennnnnnnnnn/Cairn` 进一步引入 `epoch` 隔离与宿主验收回调。
  - `LongSang01/Cairn-E` 在并行执行多个步骤时，仅对带有 `exclusive` 标记（或命中爆破/密码喷洒/撞库/批量登录等高冲突关键词）的步骤加独占锁，其余信息收集与静态分析步骤全部默认并行。
- **SecTimeAgent 落地点**：
  - **短期（保持低风险）**：沿用当前已验证通过的 `race_bridge` + `/reopen` 多 Flag 门禁，在 `reason.md` 中约定“高冲突爆破步骤不同时派发、只读/静态分析步骤双路并行”；
  - **中长期（架构演进）**：在 `cairn/server/` 引入多 Goal 数据模型与非对称 `exclusive` 调度锁，并参考 `Shennnnnnnnnn/Cairn` 的 A/B 评测方法，实测单会话复用与多会话并发的 Token/解题率折中点。
- **收益 / 成本**：**高长期收益 / 中高改造成本（建议归入 P2 演进）**。

---

## 四、推荐实施优先级（按投入产出比排序）

| 优先级 | 吸收项 | 来源 | 改动范围 | 预计耗时 | 风险等级 |
| --- | --- | --- | --- | --- | --- |
| **P0（立刻可做）** | 优势 1 + 优势 2 + 优势 5：Prompt 升级（Flag 收敛链 + 7 题型检查单 + `[DEAD_ENDS]` 规范 + `/tmp/exp_*` 隔离） | `prtseek` | `prompts/competition/*.md`、`CLAUDE.md`、`AGENTS.md` | 20 分钟 | 极低 |
| **P0（立刻可做）** | 优势 4：单题双路并发 + 异构国产旗舰双 Worker（`kimi-k3.1-pro-highspeed` + `glm-5.3` / `qwen4-max`） | `prtseek` / `ARTEX` | `config/dispatch.competition.example.yaml`、`reason.md` | 15 分钟 | 极低 |
| **P0（强烈推荐）** | 优势 8：国产推理模型 JSON 截断防御（输出上限/思考参数校验）+ 坏 JSON 带错因定向修复重试 | `bronezppg` / `guaidao2` / `Rabbit` | `dispatcher/contracts.py`、`tasks/common.py`、`token_proxy.py` + 单测 | 45 分钟 | 低 |
| **P0（强烈推荐）** | 优势 9：Claude `claude -r` 会话丢失一次性自愈 + 失败退避重试（无人值守不卡人工态） | `86cloudyun` / `xiaoju111a` / `mastercho` | `adapters/claudecode.py`、`tasks/explore.py`、`scheduler/loop.py` + 单测 | 45 分钟 | 低 |
| **P1（可选强化）** | 优势 3 + 优势 10：调度层连续无进展 fact 停滞检测（`[STALL_WARNING]`）+ 长局 `graph overview` 上下文限长 | `prtseek` / `xiaoju111a` | `scheduler/loop.py`、`tasks/common.py` + 单测 | 1.5 小时 | 低 |
| **P1（按需核查）** | 优势 6 + 优势 11：核查离线镜像无头浏览器（Playwright/Chromium）、JDK（`jdb`/`javap`）与图片辅助工具并写入 `CLAUDE.md` | `prtseek` / `Rabbit` / `guaidao2` | `worker/Dockerfile.deployed`、`worker/tools/`、`CLAUDE.md` | 40 分钟 | 低–中（关注盘容） |
| **P2（后续演进）** | 优势 7 + 优势 12：代理层按项目请求次数预算 + 多 Goal 原生建模 + 非对称 `exclusive` 锁 + 资产拓扑图 | `ARTEX` / `Marven11` / `Cairn-E` / `bronezppg` / `Shennnnnnnnnn` | `bench/token_proxy.py`、`cairn/server/`、`scheduler/` | 2–3 天 | 中 |

---

## 五、参考仓库

### 1. 同类攻防智能体框架
- [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX) — 双图记忆（资产图 + 探索图）、多 LLM 轮换 (`llmpool`)、Prompt 注入隔离。
- [RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX) — 单条命令内存与超时保护（cgroup v2 / RSS 采样）、Streamable HTTP / SSE MCP 双协议接入。
- [Team-intN18-SoybeanSeclab/prtseek](https://github.com/Team-intN18-SoybeanSeclab/prtseek) — `agent/ctf.go`（Flag 收敛链与题型方法卡）、`agent/research_progress.go`（哈希签名停滞自检与 `research_experiment`）、`agent/research_memory.go`（压缩状态重注与失败路线记录）、`agent/run_budget.go`（父子共享调用预算）、`Dockerfile`（离线 Playwright + Chromium）。

### 2. `oritera/Cairn` 活跃 Fork 与衍生项目
- [guaidao2/Cairn-Local](https://github.com/guaidao2/Cairn-Local) — 去 Docker 本地子进程执行、多模态图片读取缩放、推理模型 `max_tokens=32768` 防截断。
- [Shennnnnnnnnn/Cairn](https://github.com/Shennnnnnnnnn/Cairn) — 单会话复用 vs 多会话 A/B 基准、宿主验收门禁、截止时间预留与 `epoch` 隔离。
- [Marven11/Cairn](https://github.com/Marven11/Cairn) — 多 Goal 原生建模与图推导完成、Dispatcher 热重载与单 Worker 停止。
- [xiaoju111a/Cairn](https://github.com/xiaoju111a/Cairn) — 独立 `verify` 阶段与 CVE 情报、`graph overview` 长上下文限长、失败退避重试。
- [86cloudyun-afk/Cairn](https://github.com/86cloudyun-afk/Cairn) — `claude -r` 缺失会话一次性恢复、工作流计划与产物清单持久化。
- [bronezppg-arch/Cairn](https://github.com/bronezppg-arch/Cairn) — 国产推理模型关闭 thinking 防空 JSON、自动模型发现与 Cytoscape 内网拓扑图。
- [LongSang01/Cairn-E](https://github.com/LongSang01/Cairn-E) — 步骤默认并行 + 非对称 `exclusive` 锁、M-Token 预算与范围硬校验。
- [Rabbit0007/Rabbit](https://github.com/Rabbit0007/Rabbit) / [mastercho/Rabbit](https://github.com/mastercho/Rabbit) — Fail-closed JSON 诊断修复环、JDK（`jdb`/`javap`）Worker 镜像、单命令 90s 超时与无人值守防人工态阻塞。
