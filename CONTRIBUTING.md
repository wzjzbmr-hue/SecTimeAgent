# 协作开发

在自己的 Git 工作区创建功能分支，通过 Docker 验证后提交 Pull Request。先按 README 准备配置与现用 Worker 离线镜像。

## 有仓库写权限

```bash
git switch main
git pull --ff-only
git switch -c codex/describe-your-change

# 在宿主机编辑源码，用 Docker 调试和测试
git diff
git status --short
git add 具体源码路径 具体测试路径
git commit -m "fix: describe the resulting behavior"
git push -u origin codex/describe-your-change
```

在 GitHub 创建从功能分支到 `main` 的 Pull Request，描述改动、验证结果和部署影响。维护者评审后合并。不要提交个人配置、凭据、数据库、完整日志或镜像离线包。

## 没有仓库写权限

由仓库维护者授予访问权限；支持 Fork 时，也可 Fork 后向原仓库提交 PR。若 Fork：`origin` 指向自己的 Fork，`upstream` 指向本仓库，从 `upstream/main` 同步基线。

```bash
git remote add upstream https://github.com/wzjzbmr-hue/SecTimeAgent.git
git fetch upstream
git switch -c codex/describe-your-change upstream/main
# 修改、测试并提交后
git push -u origin codex/describe-your-change
```

## 同步主分支与解决冲突

```bash
git fetch origin
git merge origin/main
# 若有冲突，编辑冲突文件并检查最终内容
git add 已解决冲突的文件
git commit
# 重跑受影响测试
git push
```

Fork 使用 `git fetch upstream` 与 `git merge upstream/main`。上例选择 merge，避免协作分支因改写历史而需要强制推送。没有发生冲突时 Git 可能已经自动创建合并提交，不需要额外 commit。

## 已在容器内部修改的代码

如果文件没有挂载，先取回当前 Git 分支的对应路径，再查看差异和测试：

```bash
docker cp 容器名:/容器内/源码文件.py ./对应源码路径/源码文件.py
git diff
```

用 `apt`、`pip` 临时安装的依赖必须补到 Dockerfile 或依赖声明中。`docker commit` 不是源码提交，也不能代替可审阅的构建配方。

## 合并后的发布

合并源码后构建新镜像，用 Git commit 标记镜像版本，例如 `cairn-app:sha-<commit>` 和 `cairn-worker:sha-<commit>`。更新个人或部署配置后重建服务，以新项目验收 Worker。推送 Git 分支本身不会更新 Ubuntu 部署，维护者应保留旧镜像和配置作为回滚点。
