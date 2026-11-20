# OSEP-0023 补测工具

`integration-env.sh bench-supplemental` 在已运行的隔离 Fast Sandbox 环境中执行补测。每项测量独立选择，写入新的 `SUP_REPORT_DIR`；目录已存在时拒绝覆盖。需要 Python 3.9 以上、Bash 4 以上和现有集成环境依赖。

```bash
SUP_MEASUREMENTS='m10 m3x m5 m6 m7 m9' \
SUP_REPORT_DIR=/path/to/new-report-dir \
  ./scripts/fast-sandbox-env/integration-env.sh bench-supplemental
```

默认 CI 调用及 M1–M4 使用原入口。补测会重建本环境的 SandboxPool，活动 guest 会中断。先在任务独占的集群中运行，按所在环境的停止门监控宿主资源。每次 Pool 切换前扫描测试凭据日志，发现路径矛盾时报告 `INVALID` 并停止。

## 参数与报告

| 测量 | 主要参数及默认值 | 顶层报告 |
| --- | --- | --- |
| M3x | `BENCH_MEM_STEPS='500 1000 2000'`、`BENCH_MEM_SANDBOXES=4`、`BENCH_MEM_SETTLE_SECONDS=20`、`BENCH_EGRESS_MEMORY_LIMIT=2Gi`、`BENCH_FSB_TLS_CAPACITY=1024` | `m3x.json` |
| M5 | `SUP_CPU_LIMITS='500m 2'`、`SUP_CONCURRENCIES='1 4 16 64 256'`、`SUP_LOAD_GUESTS=4`、`SUP_BODY_BYTES='0 65536'`、`SUP_REPEATS=3`、`SUP_LOAD_S=60`、`SUP_WARMUP_S=10` | `m5.json` |
| M6 | `SUP_CHURN_S=1800`、并发 1/4/16 各三分之一时长；`SUP_RECOVERY_S=30` | `m6-all.json`、`m6-credential-bound.json` |
| M7 | `SUP_BURSTS='500 1000 2000'`、每个档位一次 | `m7-all.json`、`m7-credential-bound.json` |
| M8 | `SUP_SOAK_S=7200`、`SUP_SOAK_ANALYSIS_S=1800`、`SUP_SOAK_CONCURRENCY=16`、`SUP_RATE_B` 必须指定为 M5 校准后的总请求限速 | `m8-all.json`、`m8-credential-bound.json` |
| M9 | `SUP_SUBJECT_STEPS='256 1024 2048 4096 4097'`、`SUP_SCALE_PROBES=20` | `m9.json` |
| M10 | `SUP_BLOCKS=8`、固定 ABBAABBA 前缀；`BENCH_CREATE_ROUNDS=3`、`BENCH_CREATE_N=200`、`BENCH_CREATE_CONCURRENCY=10` | `m10.json` |

补测显式设置 `WARM_IMAGES=1`，等待模板缓存覆盖全部 `POOL_MIN` 个 Fastlet；收尾恢复原 warm 设置。`SUP_IDLE_S=20` 为 Pool warm 判据通过后的等待。`SUP_CLIENT_ATTEMPTS=7200` 是每两秒一次的结果轮询上限。M8 默认包含在完整选择中，未指定正数 `SUP_RATE_B` 时预检拒绝执行；只执行其他项目时，用 `SUP_MEASUREMENTS` 选择。

M3x 对 all/cb × bound/unbound 四条路径分别取 cgroup `memory.current` 与 `anon`，按实际完整持有数拟合 OLS。最终在同一批连接上请求并释放，释放不完整的点不参与拟合。混合比例表由实测斜率推导。

M5 的客户端按 100 次请求周期选择 5 次 bound、95 次 unbound，或全部 bound。两个 SNI 使用同一 origin 和 CA，只有主名称绑定 Vault；每次响应核对证书路径与 origin 凭据类别。不同路径的 keep-alive session 分开持有。并发分摊到同一 Fastlet Pod 上的多个 guest，报告保留实际响应计数。`body_bytes=65536` 表示完整 64 KiB JSON 响应。吞吐按 guest 的成功请求数与实际负载时长计算后相加；资源窗口保留 egress、origin 和 client CPU。CPU 候选瓶颈还须结合并发曲线的平台段判断。

M6/M8 的时间轴在每个模式单独开始，采样 memory、CPU、throttling、FD、Pod 重启及 OOM。FD 是该 egress 容器中所有进程的 FD 总和，conntrack 是 Pod 网络命名空间可读到的计数。采样写入独立文件，主进程在采样结束后组装报告。M8 每 100 次请求关闭连接，保存分钟级请求数、错误和延迟分位；长跑的总体延迟使用 0.1 ms 分箱。内存斜率单位为 B/s，后 90 分钟窗口由 `SUP_SOAK_ANALYSIS_S` 选择。

M7 在一个 guest 的同一事件循环中释放全部连接任务，成功连接持有到控制端完成 unbound 探针。释放时再次请求这些连接。只有同一隔离窗口中的服务端 `registry_exhausted` 事件与握手关闭共同存在时，才归为预算拒绝；其他 socket 错误保留为未归因。需要超过预算时，显式提供大于 `BENCH_FSB_TLS_CAPACITY` 的 burst 档位。

M9 的总数包含两个真实同置 guest，其余由 Actions v1 合成注册；每个合成对象都有独立 UID、fence、源 IP 和 attachment。SET 成功、ready Hook 成功分开计数；ready Hook 的成功受当前快照 ACK 门保护，因此 ACK 数由该门间接确认。每个规模暂停合成驱动，使用真实 guest 发 U/B 连接。合成 attachment 不创建 VM 或 veth，不能证明 4096 个真实流量源。4097 的容量日志与恢复结果单列。驱动在 `finally` 中清除全部尝试注册的对象，Pool 重建是异常中断后的清理边界。

M10 每块重建 Pool，记录首个 Pod UID、所有 Pod 的真实 mode/CPU readback、warm 就绪与切换时长。每块将 M1 成功样本的 p50 作为一个观测，按相邻 A/B 块配对计算 B−A，以 4 对块差给 Student t 95% CI。日志分段按同一 subject 关联 SET_BINDING total、policyCommit 和 data-plane-ready applyPolicy，再丢弃身份；日志缺失会显示覆盖数。报告不对 ACK 等待作归因。

## 最小参数冒烟

以下参数只用于检查工具链，报告带 `smoke=true`。每项都可单独运行；例如将 `SUP_MEASUREMENTS` 改为 `m9`。

```bash
SUP_SMOKE=true SUP_MEASUREMENTS='m10 m3x m5 m6 m7 m9 m8' \
SUP_REPORT_DIR=/path/to/new-smoke-dir \
BENCH_CREATE_N=2 BENCH_CREATE_CONCURRENCY=1 BENCH_CREATE_ROUNDS=1 \
BENCH_MEM_STEPS='2 4' BENCH_MEM_SANDBOXES=1 BENCH_MEM_SETTLE_SECONDS=1 \
BENCH_FSB_TLS_CAPACITY=8 \
SUP_BLOCKS=4 SUP_CPU_LIMITS=500m SUP_CONCURRENCIES=1 SUP_LOAD_GUESTS=1 \
SUP_BODY_BYTES=0 SUP_REPEATS=1 SUP_LOAD_S=2 SUP_WARMUP_S=1 SUP_IDLE_S=1 \
SUP_CHURN_S=3 SUP_BURSTS='2 10' SUP_SUBJECT_STEPS='4 8' SUP_SCALE_PROBES=2 \
SUP_SOAK_S=5 SUP_SOAK_ANALYSIS_S=0 SUP_SOAK_CONCURRENCY=1 SUP_RECOVERY_S=1 \
  ./scripts/fast-sandbox-env/integration-env.sh bench-supplemental
```

本地测试：

```bash
CBV_TEST_BASH=/opt/homebrew/bin/bash /path/to/python3.9-venv/bin/python3 \
  -m unittest discover -s scripts/fast-sandbox-env/tests -p 'test_*.py'
bash -n scripts/fast-sandbox-env/supplemental-bench.sh
shellcheck -S warning scripts/fast-sandbox-env/supplemental-bench.sh
```

原始 specs、连接摘要和进程日志保留在私有 `raw/` 目录，不作为公开报告。顶层报告采用闭集字段，保留统计输入与状态，不复制凭据、证书 digest、subject UID 或对端名称。
