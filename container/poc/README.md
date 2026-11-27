# 固定版本 PoC 资料与离线索引

`sources.lock.json` 锁定六个资料源的完整 commit。`poc-catalog` 只同步、索引、搜索和做执行前静态检查，**不执行 PoC、不启动扫描或漏洞环境**。默认不检索 exphub、2023Hvv_ 等历史源。

## 构建

主 `container/Dockerfile` 在构建时同步固定版本；不会在创建 Worker 时拉取资料。已有镜像可在 Ubuntu 上构建独立候选：

```sh
docker build -f container/Dockerfile.poc \
  --build-arg BASE_IMAGE=cairn-worker:migration-20261119 \
  -t cairn-worker:poc-candidate-20261123 container
```

先核对基线 Image ID，再构建。该命令不会切换 dispatcher 配置，旧容器也不会自动采用新镜像。正式期冻结已验收镜像；不要运行在线 sync。依赖本地测试环境的 Vulhub 镜像需另行准备，本目录不把所有漏洞环境启动或装入 Worker。

## 离线使用

```sh
poc-catalog search --cve CVE-2025-24813
poc-catalog search Jenkins --kind template --limit 5
poc-catalog search Weblogic --include-historical
poc-catalog check exphub weblogic/cve-2018-2893_cmd.py
poc-catalog sync --offline
poc-catalog validate
```

结果包含来源、固定提交、相对路径、SHA256、类型、CVE、历史标记、Python语法检查和`verification=unverified`。`search`仅返回有限元数据，不把完整脚本或请求有效载荷塞进上下文。`--prefix`、`--index`、`--lock` 为全局参数，放子命令之前。

当前已确认缺失的Crypto、art、requests-toolbelt装入`/opt/cairn-poc-runtime`，固定版本及wheel SHA256见`requirements.lock.txt`。该venv只读复用基线系统依赖，不覆盖系统Python；`poc-catalog check`默认从此环境检查，人工验证脚本时也须明确使用该解释器。仅提供依赖不是漏洞效果验收；禁止通过`sudo pip`修改全局环境。

`check`校验快照、资产哈希、Python语法和当前解释器可发现的静态导入。退出码0只表示静态前置检查通过；2表示前置检查被阻断；1表示快照/索引/调用错误。动态导入、可选导入、本地包、Java/系统库、版本、认证及网络前提仍须单独核验。

知识文档不等于脚本；复现环境不等于检测器；检测结果不等于漏洞利用成功。所有条目默认未通过漏洞效果验收。未来年份或异常CVE编号被标记，不进入有效CVE字段。

## 更新流程

调试期核对原厂公告/原始研究与官方发布，更新 lock 的完整提交，再在独立镜像中 `sync` 和 `index`。修改过的已跟踪文件、未知remote或不匹配快照会被拒绝，工具不自动丢弃现场。索引只读取固定仓库已跟踪的文本，不导入或运行脚本。同步关闭Git hooks及子模块递归。

新增/修复模板必须测试引擎兼容，以及隔离环境中的已知脆弱/修复对照；记录时间、请求和资源，不以`--version`或HTTP200判漏洞成立。历史Python2脚本不通过降低全局Python版本恢复，优先使用可验证替代或隔离移植。

```sh
python -m unittest discover -s container/poc -p 'test_*.py' -v
```

本模块不修改 Cairn 的 Fact/Intent、模型配置或比赛 AGENTS/SKILL。

## 已审阅的模板迁移与校验诊断

`review.json`锁定到当前模板commit及文件哈希。22个旧CVE文件名作为**历史检索标识**关联到改名后的模板，不把旧编号强加到新的CVE分类；查询返回`matched_by=historical_identifier`及说明。CVE-2024-28752返回被上游撤回的说明，`check`阻断执行：原模板的固定`/test`不能代表真实SOAP服务，必须按实际接口和Aegis配置定制验证。

`validate`先独立检查其余模板，再检查已定位的单个诊断模板。只接受固定引擎、固定文件哈希和已复核的诊断文本；其他模板出现任何warning均失败。完整原始日志保留，既不隐藏警告，也不修改原厂签名。

已知`randstr`诊断来自校验阶段缺少运行时随机值上下文；良性localhost回归验证请求中的随机值正常生成、跨字段一致、跨运行变化。原始`nuclei -validate`仍可能显示该诊断；这不等于该漏洞已验证或整个模板可利用。回归测试不执行文件上传PoC：

```sh
python -m unittest discover -s /opt/cairn-poc -p 'test_*.py' -v
```
