<!-- fb-tool-section -->
# 隐藏路径与随机串（目录爆破没有命中时必读）
* 常规字典扫不出的隐藏路径，可能是“词或词组的哈希”。先跑现成工具：`python3 /opt/cairn-poc/hashpath.py http://<目标>`，它对常见词及其组合取 md5 后扫描，默认并发 30，命中会打印路径和页面开头
* 工具没有命中时，再用 `--words`、`--words-file`、`--digests md5,sha1`、`--prefix /admin/`、`--max-words 5` 扩大范围；`--dry-run` 先看每个阶段的候选数量
* 爆破并发不超过 50：单线程靶机在高并发下会丢请求，造成漏报；出现连接堆积时先降并发再重扫
