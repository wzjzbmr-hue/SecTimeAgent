# SecTimeAgent

Ubuntu 现用 Cairn 的协作开发基线。核心源码和 Worker 自研文件取自 Ubuntu 实际部署，未合入 Windows 工作区改动，也未采用 `nmap-ready` 候选镜像。

## 版本

| 内容 | 基线 |
| --- | --- |
| Ubuntu 源码提交 | `ac9ca121de880fefb333c2d9b61233a6747669d7` |
| 应用镜像 | `cairn-app:migration-20261119` |
| Worker 镜像 | `cairn-worker:tools-ready-20261125` |
| 运行配置 | `compose.ubuntu.yaml`、`config/dispatch.ubuntu.example.yaml` |

应用镜像中的 43 个 Python 文件与 Ubuntu 对应源码逐文件哈希一致。Worker 的 11 个自研脚本、指令和相关文件直接从现用镜像提取，路径、权限和 SHA-256 见 `worker/deployed-files.json`。完整身份见 `deployment/baseline.json`。

## 目录

```text
cairn/                 核心源码、测试、Python 依赖锁
bench/                 现用模型代理、提交服务和运行器
container/             Ubuntu 留存的基础 Worker 构建配方
worker/deployed-rootfs/ 现用 Worker 内的自研文件
worker/tools-ready/    tools-ready 历史增量构建材料
compose.ubuntu.yaml    Ubuntu 四服务部署配置
compose.build.yaml     从源码构建应用镜像的覆盖配置
compose.dev.yaml       挂载源码进行调试的覆盖配置
config/                脱敏后的现用配置示例
deployment/            版本身份和验证记录
```

`worker/deployed-rootfs` 是现用内容的依据；`container/` 保留基础构建来源，二者不能混同。数据库、日志、真实 Key、私有判分注册表、完整第三方工具和 PoC 分发内容不在仓库内。`bench/challenges.yaml` 默认空表，开发者需自行添加获准使用的测试题。

## 环境与启动

使用独立的 Linux x86_64 Docker 主机或 Ubuntu/WSL2 环境，安装 Docker Engine、Compose v2；宿主机运行 Python 时另需 Python 3.12+ 和 uv。当前部署采用 host 网络和固定端口 8000、8099、8100，同一 Docker 主机同时运行多套实例需要另行调整网络和端口。

```bash
git clone https://github.com/wzjzbmr-hue/SecTimeAgent.git
cd SecTimeAgent
mkdir -p config runtime/cairn runtime/bench-results bench/results
cp config/dispatch.ubuntu.example.yaml config/dispatch.yaml
```

在个人 `config/dispatch.yaml` 中填写自己的模型凭据。配置保留现用模型路由、并发和超时参数；真实凭据只在本机保存。Dispatcher 启动后会调度待执行任务并可能产生模型费用。

### 从源码构建应用

```bash
docker build -t cairn-app:ubuntu-baseline-dev .
docker compose -f compose.ubuntu.yaml -f compose.build.yaml up -d
docker compose -f compose.ubuntu.yaml -f compose.build.yaml logs -f dispatcher
```

Worker 需先按下一节准备。访问 `http://127.0.0.1:8000`。Server 维护 API、网页和事实状态；Dispatcher 通过宿主机 Docker socket 为项目创建同级 Worker 容器；Proxy 转发模型请求；Submit 提供本地提交与判分接口。

### 准备现用 Worker

**完整的现用 Worker 工具环境仍需要离线镜像。仅 clone 本仓库不能从零重建完全相同的 tools-ready 环境。** 应向维护者取得 `cairn-worker-tools-ready-20261125.tar.gz`，核对 SHA-256 后导入：

```bash
sha256sum cairn-worker-tools-ready-20261125.tar.gz
# 期望：404eec1b01f2b30d2c0b9fd078a595bb1d31d68a87daa95fa243175b8e3cc64e
gunzip -c cairn-worker-tools-ready-20261125.tar.gz | docker load
docker image inspect cairn-worker:tools-ready-20261125 --format '{{.Id}}'
```

现用环境的镜像身份是 `sha256:81e1b018223a72bfa67b51bddf2a0df8126198a3b7530a1b524e651af6a83cf5`。这是原 Docker containerd 存储显示的 OCI manifest 身份；采用经典存储的 Docker 导入后可能显示配置摘要，不能仅因该显示差异判断内容错误。离线包约 8 GB，现用 Worker 展开大小约 26.4 GB，需预留额外构建和运行空间。

在该镜像上修改自研脚本后，可构建开发标签：

```bash
docker build -f worker/Dockerfile.deployed -t cairn-worker:dev .
```

然后只修改个人 `config/dispatch.yaml` 的 `container.image` 为 `cairn-worker:dev`。该 Dockerfile 保留现用工具环境并覆盖自研文件，不会恢复出完整基础镜像的历史安装过程。`container/Dockerfile` 是基础 Kali Worker 构建配方，`worker/tools-ready/build-merged.sh` 是历史增量配方，它们都不能代替完整的现用镜像。

## 开发调试

在另一台开发主机使用以下配置组合，源码通过只读挂载映射到容器中：

```bash
docker compose -f compose.ubuntu.yaml -f compose.build.yaml -f compose.dev.yaml up -d --build
```

在宿主机编辑 `cairn/src/` 后，重启相应进程以重新加载 Python 模块：

```bash
docker compose -f compose.ubuntu.yaml -f compose.build.yaml -f compose.dev.yaml restart dispatcher
docker compose -f compose.ubuntu.yaml -f compose.build.yaml -f compose.dev.yaml restart server
```

修改 `bench/token_proxy.py` 或 `bench/submit_server.py` 后分别重启 `proxy`、`submit`；这些文件本来就通过目录挂载读取。修改依赖需要更新 `cairn/pyproject.toml`、`cairn/uv.lock` 并重建应用镜像。修改 Compose 环境、挂载或镜像后执行 `up -d`，只 restart 不会应用容器配置变化。

```bash
# 进入应用容器检查模块来源
docker compose -f compose.ubuntu.yaml -f compose.build.yaml -f compose.dev.yaml exec server \
  /cairn/.venv/bin/python -c 'import cairn; print(cairn.__file__)'

# 使用源码挂载运行核心测试
docker compose -f compose.ubuntu.yaml -f compose.build.yaml -f compose.dev.yaml run --rm --no-deps server \
  /cairn/.venv/bin/python -m pytest /cairn/tests -q -p no:cacheprovider
```

开发时在宿主机编辑 `worker/deployed-rootfs/` 下的文件，再重新构建 `cairn-worker:dev`。也可用单文件挂载单独调试，例如：

```bash
docker run --rm -it --network none \
  --mount "type=bind,src=$(pwd)/worker/deployed-rootfs/opt/cairn-poc/hashpath.py,dst=/opt/cairn-poc/hashpath.py,readonly" \
  --entrypoint bash cairn-worker:tools-ready-20261125
```

Compose 挂载不会自动传播给 Dispatcher 动态创建的 Worker。当前核心代码没有通用 Worker 开发挂载配置。更换 Worker 镜像后使用新测试项目，旧项目容器可能被复用；启动或重启旧容器不会将其变成新镜像。需要保留旧项目状态时，先自行导出再处理旧容器。

### 在宿主机运行核心代码

```bash
uv sync --project cairn --frozen --group dev
# 终端一
uv run --project cairn cairn serve --host 127.0.0.1
# 终端二；Proxy 和 Submit 需另外启动才能使用现用配置中的本地路由
uv run --project cairn cairn dispatch --config config/dispatch.yaml
# 核心测试不调用真实模型
uv run --project cairn --group dev pytest cairn/tests
```

不要与已经占用相同端口的 Compose 实例同时启动。

## 分支协作

源码在宿主机 Git 工作区中修改，Docker 用于运行和测试。分支属于 Git 仓库，不属于镜像或容器。协作步骤见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 来源与许可证

源自 [oritera/Cairn](https://github.com/oritera/Cairn)，保留原始 [LICENSE](LICENSE) 与 [上游 README](README.upstream.md)。镜像内第三方工具和资料仍各自适用其上游许可证。本仓库的初始化导入仅包含 Ubuntu 当前基线及对应打包文档，不导入原工作区的完整 Git 历史。
