# 比赛解题能力验证方案

目标：在 12/1 现场调试前，用一个可复现的本地评测流程，回答四个问题：

1. 这套 agent 在**限时**条件下能解多少题？
2. 单题**耗时**和**成本**是多少？4 小时能跑几题？
3. **卡死/拒答/格式错误**的概率有多高？无人值守会不会整体停摆？
4. 换模型 / 换 prompt / 换压缩策略，到底有没有提升？（A/B）

---

## 一、为什么不能只看"解出来了没有"

比赛的计分是 `基础分 × 名次系数`，第 1 名 +5%、第 2 名 +3%、51 名后 -10%。这意味着：

- 解得多 但很慢 → 拿不到首杀加成
- 单题成本太高 → 4 小时只跑得起 3 题
- 某一个任务卡死 → 整个 dispatcher 被占住，其他题全饿死

所以要测的是一组指标，不是一个布尔值。

## 二、必须采集的 6 个指标

| 指标 | 定义 | 用途 |
|---|---|---|
| **Solve Rate** | 解出题数 / 总题数，按类别和难度分层 | 基本能力 |
| **TTF（Time To Flag）** | 从建 project 到提交正确 flag 的秒数，取中位数 | 首杀能力 |
| **Cost / Solve** | 单题 token 消耗（或费用） | 决定 4 小时能跑几题 |
| **Hang Rate** | 超时未完成的项目占比 | 无人值守的生死指标 |
| **Context Exhaustion** | 触发上下文压缩/强制截断的比例 | CyberGym 数据显示这一项值 6 个点 |
| **Refusal / Format Error** | 输出 policy_refusal 或非法 JSON 的比例 | 直接决定分数归零 |

## 三、四层验证阶梯（成本递增，别跳级）

### L0 冒烟（5 分钟，零成本）
mock worker 跑通 bootstrap / reason / explore，验证调度、容器、协议。
**状态：已完成。**

### L1 单题端到端（30 分钟，几块钱）
挑 1 道最简单的 web 题，用真模型跑到底，确认：
- 模型能连上网关（healthcheck 200）
- 容器里能执行命令
- 能产出合法 JSON
- flag 能提交到本地 submit server 并被判分

**这一步只验证管道通不通，不验证聪明不聪明。**

### L2 小样本基准（半天，几十块）
8–10 题，覆盖 4–5 个类别（web / crypto / reverse / pwn / misc），每题 10 分钟预算。
输出：solve rate、中位 TTF、单题成本、hang rate。

### L3 全量 A/B（1–2 天，几百块）
30–50 题，跑 2–3 个模型（GLM-5.3 / Kimi K3.1 / DeepSeek V4.1 Flash），同 prompt 同预算。
输出：选型结论。

### L4 无人值守压测（半天）
按真实赛制跑 4 小时：断网、只留网关、定时任务启动、随机 kill 进程验证恢复。
输出：稳定性报告。

---

## 四、最关键的一步：用公开基线校准

**没有对照的分数没有意义。** 如果 L2 跑出 solve rate 0%，你无法判断是模型不行、prompt 不行，还是管道坏了。

用同一批题在公开榜上的成绩做锚点：

| 基准 | 题量 | 已知强基线 | 说明 |
|---|---|---|---|
| NYU CTF Bench | 200 | CRAKEN 22%、D-CIPHER 19%、EnIGMA 13.5%（Claude 3.5 Sonnet） | 难度最高，pass@1 个位数百分比起步 |
| Cybench | 40 | EnIGMA + Claude 3.5 = 20%；GLM-5.2 约 85%（34 题口径） | 专业级 CTF |
| InterCode-CTF | 100 | EnIGMA + GPT-4 Turbo = 72% | picoCTF 难度，适合验证管道 |

**校准规则**：
- 先跑 InterCode-CTF 的 10 题。如果你的 harness 拿不到 40% 以上，说明**管道有问题，别怪模型**。
- 再跑 NYU CTF Bench 子集。拿到 5–15% 属正常，20%+ 说明 harness 优秀。
- 这两个数稳定后，才可以用它们去判断模型 A/B 的差异。

---

## 五、题源怎么选（按性价比排序）

| 来源 | 优点 | 缺点 | 建议 |
|---|---|---|---|
| **InterCode-CTF** | 轻量、picoCTF、答案已知 | 太简单，区分度低 | 用于 L2 管道验证 |
| **NYU CTF Bench** | docker 化、和比赛靶场同构、200 题分难度 | 镜像大、部分题需 GPU/特殊环境 | **主力题源** |
| **Cybench** | 专业级、有 agent 脚手架参考 | 40 题，重复跑容易背题 | 用于 L3 上限测试 |
| **vulhub** | 真实 CVE、覆盖"基础平台"类 | 没有 flag，需要自己造 | 补"中间件/容器"类题 |
| **自建工控靶** | 对应"电力工控协议"类题 | 要自己写 Modbus/IEC104 服务 | **必须有，别跳过** |
| **XBOW validation** | 104 道 web 漏洞 | 判分靠浏览器行为 | 可选 |

**特别注意**：vulhub / NYU 都是"公开过的题"，模型可能背过。Cybench 的题目 flag 按实例动态轮换，能防背题。你自己搭的工控靶天然没有背题风险——这也是差异化得分点。

---

## 六、工具：bench/

```
bench/
├── challenges.yaml        题目注册表
├── submit_server.py       本地模拟平台 /api/submit（判分 + 记录）
├── runner.py              起靶场 → 建 project → 等 flag → 统计 → 清理
├── results/               每次运行的 json + markdown 报告
└── challenges/
    └── hello-flag/        示例题（nginx 静态页藏 flag）
```

### 用法

```bash
# 1. 启动模拟判分平台
python bench/submit_server.py --port 8099

# 2. 干跑：只起靶场，不起 agent，手工验证判分逻辑
python bench/runner.py --only hello-flag --no-agent

# 3. 真跑：起靶场 + 建 project + 等 flag
python bench/runner.py --only hello-flag

# 4. 批量：跑所有 easy 的 web 题，每题 10 分钟预算
python bench/runner.py --category web --difficulty easy --budget 600
```

### 结果长这样

```
ID                  CAT     DIFF   RESULT   TTF(s)  TASKS  HANG
hello-flag          web     easy   SOLVED      73      6    -
sqli-basic          web     easy   SOLVED     241     11    -
pwn-stack           pwn     medium TIMEOUT      600     14    Y
-----------------------------------------------------------------
solve 2/3 (67%)   median TTF 157s   hang 33%
```

---

## 七、12/1 现场要复验的三件事

1. **网关连通性**：`scripts/check_gateway.py` 把白名单模型逐个探一遍。
2. **判分接口**：用真实的平台 API/MCP 替换 `submit_server.py` 的地址，确认字段和鉴权头对得上。
3. **定时任务**：`systemctl enable --now cairn-bench.timer`，确认 08:30 会自动起。

---

## 八、常见误判

- **把"agent 说自己完成了"当成解出**。必须以判分接口回执为准，Cairn 的 `status=completed` 只代表它自己认为完了。
- **只跑简单题**。简单题全对不代表中档题有戏，难度要分层统计。
- **不看成本**。4 小时里成本决定能跑几轮，比单题正确率更影响总分。
- **没做断网测试**。L4 之前所有结论在断网面前都可能失效（pip 装不了、DNS 挂了）。
