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
| M5 | `SUP_CPU_LIMITS='500m 2'`、`SUP_CONCURRENCIES='1 16 64 256'`、`SUP_LOAD_GUESTS=4`、`SUP_BODY_BYTES='0 65536'`、`SUP_REPEATS=3`、`SUP_LOAD_S=60`、`SUP_WARMUP_S=10` | `m5.json` |
| M6 | `SUP_CHURN_S=1800`、并发 1/4/16 各三分之一时长；`SUP_RECOVERY_S=30` | `m6-all.json`、`m6-credential-bound.json` |
| M7 | `SUP_BURSTS='500 1000 2000 2049'`、`SUP_BURST_GUESTS=6`、`SUP_BURST_REPEATS=3`、`SUP_RESOURCE_RECOVERY_S=240`、`SUP_RESOURCE_INTERVAL_S=5` | `m7-all.json`、`m7-credential-bound.json` |
| M8 | `SUP_SOAK_S=7200`、`SUP_SOAK_ANALYSIS_S=1800`、`SUP_SOAK_CONCURRENCY=16`、`SUP_SOAK_RATE_ALL` 与 `SUP_SOAK_RATE_CB` 分别指定为 M5 对应模式校准后的总请求限速 | `m8-all.json`、`m8-credential-bound.json` |
| M9 | `SUP_SUBJECT_STEPS='256 1024 2048 4096 4097'`、`SUP_SCALE_PROBES=20` | `m9.json` |
| M10 | `SUP_BLOCKS=8`、固定 ABBAABBA 前缀；`BENCH_CREATE_ROUNDS=3`、`BENCH_CREATE_N=200`、`BENCH_CREATE_CONCURRENCY=10` | `m10.json` |

补测为 guest 单独计算生命周期：M5 覆盖整个 mode×CPU 组的预热、负载、逐点控制余量和收尾，至少 6 小时；M8 覆盖 7200 s 浸泡、预热、恢复和收尾，至少 3 小时；M9 的整个规模序列使用至少 6 小时。创建请求再增加 600 s，并逐个经 `sandbox get -o json` 读取 `expires_at`，确认剩余时长大于所需时长。回读保存在 `lifetime-readback.jsonl`。原 M1–M4 默认 1h。

补测显式设置 `WARM_IMAGES=1`，等待模板缓存覆盖全部 `POOL_MIN` 个 Fastlet；收尾恢复原 warm 设置。`SUP_IDLE_S=20` 为 Pool warm 判据通过后的等待。`SUP_CLIENT_ATTEMPTS=7200` 是每两秒一次的结果轮询上限。默认入口先执行 M10、M3x、M5、M6、M7、M9。M5 完成后，由总控复核两模式 500m、keep-alive、95/5、小包的完整并发曲线和全部重复，确认持续平台及 0.5×RPS 的目标速率。本轮总控已确认 `SUP_SOAK_RATE_ALL=55`、`SUP_SOAK_RATE_CB=514`（RPS）；按这两个值填写后，再用 `SUP_MEASUREMENTS=m8` 和新的报告目录执行浸泡。平台段未建立时保留待决。显式选择 M8 的完整测量要求两档正数校准速率。M8 报告保留实际 RPS 与目标速率之比。

5c 全量执行显式指定 `BENCH_MEM_STEPS='500 1000 2000 4000'`，并将 `BENCH_FSB_TLS_CAPACITY=2048`。

M3x 对 all/cb × bound/unbound 四条路径分别取 cgroup `memory.current` 与 `anon`，按实际完整持有数拟合 OLS。最终在同一批连接上请求并释放，释放不完整的点不参与拟合。每条 mode×target 路径重建 Pool，保存 Pod UID 与 egress 容器身份；跨路径复用任一身份即 INVALID。每条路径创建首个 guest 后、产生测量流量前读取新进程基线；同模式第一条路径的该读数作为模式基线。K=0 的 anon、memory.current 与这两个基线分别比较，绝对差超过 max(32 MiB, 基线的 20%) 即 INVALID。仅四条路径全部 OK 时输出混合比例推导表。

M5 的客户端按 100 次请求周期选择 5 次 bound、95 次 unbound，或全部 bound。两个 SNI 使用同一 origin 和 CA，测试叶证书的有效期起点提前 2 天，以覆盖 warm snapshot 恢复后的 guest 时钟；只有主名称绑定 Vault；每次响应核对证书路径与 origin 凭据类别。每次取回 guest 结果后立即检查路径矛盾，包括预热结果；矛盾原始文件和 INVALID 报告写盘后退出主编排，执行 EXIT 清理。不同路径的 keep-alive session 分开持有。并发分摊到同一 Fastlet Pod 上的多个 guest，报告保留实际响应计数。`body_bytes=65536` 表示完整 64 KiB JSON 响应。默认矩阵为两模式 × CPU 500m/2 × 并发 1/16/64/256 × new/keep-alive × 三种流量组合（95/5 小包、95/5 64 KiB、全 bound 小包）× 3 次，共 288 点。所有 guest 的 worker 就绪后，独立 origin 协调端口 18081 发放共同起跑时间；egress 和 origin 各自的 sampler 在同一计划边界读取 cgroup 差值。结果下载在采样后进行。客户端 CPU 除以各进程真实活跃时长，报告保留计划时间、起止时间及重叠时长；重叠不足采样窗口的 90% 时降级。吞吐按各 guest 的成功数与真实时长求和，CPU 候选还须结合有效组的平台段判断。平台候选须覆盖该点及全部更高并发的每次重复，各样本相对平台均值在 ±10% 内；显著下降或局部停滞后再上升保持 NOT_ESTABLISHED。报告状态用于辅助复核，执行者不得仅凭该字段自动注入 M8 速率。容器身份变化、重启/OOM 增加、计数回退或负值为 INVALID 并停止；缺失资源证据为 PARTIAL/MISSING，异常组不参与平台或瓶颈推导。

M6/M8 的时间轴按稳态负载阶段累计，预热、控制等待和结果下载不进入时间轴；M8 从共同测量边界开始，采样 memory、CPU、throttling、FD、Pod 重启及 OOM。FD 是该 egress 容器中所有进程的 FD 总和，conntrack 是 Pod 网络命名空间可读到的计数。采样写入独立文件，主进程在采样结束后组装报告。常驻 sampler 启动前，用 `sup_sample` 读取独立空载基线；退出后用同一路径读取恢复值，回落差值使用这两个读数。缺独立基线时不计算回落差值并降级。M8 每 100 次请求关闭连接，保存分钟级请求数、错误和延迟分位；长跑的总体延迟使用 0.1 ms 分箱。内存斜率单位为 B/s，后 90 分钟窗口由 `SUP_SOAK_ANALYSIS_S` 选择。`latency_segments` 按负载 group 和并发保存该段首尾分钟 p50 与漂移百分比；少于两个有效分钟窗口时漂移为 null。

M7 将分摊档位均分到 `SUP_BURST_GUESTS` 个同置 bound guest，默认 6 个，允许 2 至 6 个。每个 guest 使用稳定匿名 participant，报告在合并前核对 attempted、success、failed、verified、released_alive 和 allocation。每个 subject 的成功数不能超过 min(allocation, per-subject)；process 预算足够时，每个 member 精确达到各自期望。process 成为共同约束时，保留逐 subject 上界并核对合计。所有成员的计划起跑时间必须相同，各自起跑滞后在 0 至 1 s 内。

任何 burst worker 启动前，全部 guest 先完成内存预检：按每连接 384 KiB 加固定 64 MiB 与 live MemAvailable 比较；不足即写 INVALID，整档不启动负载。客户端在创建 TLS 上下文与任务前再次预检。共同起跑门的每轮等待同时检查 ready/终态文件，发现 INVALID 或释放前提前终止即写 M7 INVALID 并清理。报告保留逐 member 预检和核对结果。

单 subject 档默认 capacity=2048，构建 2 GiB bound guest，配一个原规格 unbound guest。读回 guest MemTotal、live Pool 资源策略和 Sandbox 限额/同 Pod Ready 状态，计算 CPU 与内存承诺，并执行完整 2049 条连接的内存预检。`SUP_SMOKE=true` 时可通过 `SUP_OVERFLOW_SMOKE_CAPACITY=64` 缩小边界；guest 仍为 2 GiB，完整 2049 预检仍保留。只有实测 2 GiB guest 不可调度时，才准备低容量替代并保存不可行证据。

填充使用 `SUP_FILL_BATCH_SIZE=32`、`SUP_FILL_INTERVAL_S=0.25`（秒）、`SUP_FILL_MAX_RETRIES=3`。每批完成 TLS 握手、响应凭据及证书路径验证后才计入 held；批间等待指定间隔。可重试的握手或响应错误按闭集原因计数，最多尝试 `capacity × (1 + max_retries)` 次；资源耗尽、校验错误或路径矛盾停止补足。报告保留每批 attempted、verified、failed、累计 held 和 errors。达到容量后，按批在原 Session 上再次请求，确认全部连接仍可注入；再从 egress 网络命名空间读取 ESTABLISHED TCP peer，精确匹配这些 Session 的 guest 本地 socket tuple，输出匿名连接计数。两项均达到 capacity 才发送探针。未填满或服务端计数不足时为 PARTIAL，跳过边界探针，释放已持有连接并检查恢复。

`SUP_MEASUREMENTS=m7-overflow` 只运行上述单 subject 档，两种模式分别重建 Pool，输出 `m7-overflow-all.json` 和 `m7-overflow-credential-bound.json`，可与 M8 同次选择。credential-bound 的 `expected=budget_rejection`：同 subject unbound 探针成功，new-bound 探针失败，并且在该单探针窗口新增一条服务端 `registry_exhausted`，才构成预算拒绝证据。all 的 `expected=no_per_subject_budget`：同 subject unbound 和 new-bound 探针均成功。两个探针使用独立 participant，不计入填充负载。释放时用原 Session 分批请求，确认全部既有连接存活；随后确认新 bound 连接恢复注入，观察完整资源恢复窗口。

```bash
SUP_MEASUREMENTS='m7-overflow m8' SUP_REPORT_DIR=/path/to/new-report-dir \
SUP_SOAK_RATE_ALL=55 SUP_SOAK_RATE_CB=514 BENCH_FSB_TLS_CAPACITY=2048 \
  ./scripts/fast-sandbox-env/integration-env.sh bench-supplemental
```

`SUP_MEASUREMENTS=m7` 继续运行多 guest 分摊档，随后补充 credential-bound 的单 subject 档。其 `overflow_coverage.mode=credential-bound` 表示 A4 预算证据的模式来源。独立单 subject 入口可用于下一阶段补测，无需重跑分摊档。

拒绝分为 budget、handshake_timeout、response_timeout、connection_refused、client_failure 与 unattributed；budget 需要同一隔离窗口的服务端事件及可匹配关闭。分类表示可观察失败阶段，不推断超时根因。每档保留资源基线、持有期与释放后的 memory.current/anon、FD、conntrack、重启和 OOM 序列；容差和完整恢复等待沿用原配置，以最后样本判定恢复。

M9 的总数包含两个真实同置 guest，其余由 Actions v1 合成注册；每个合成对象都有独立 UID、fence、源 IP 和 attachment。SET 成功、ready Hook 成功分开计数；ready Hook 的成功受当前快照 ACK 门保护，因此 ACK 数由该门间接确认。每个规模暂停合成驱动，使用真实 guest 发 U/B 连接。合成 attachment 不创建 VM 或 veth，不能证明 4096 个真实流量源。4097 档分别保留注册数、ACK 数和激活数。产品容量门允许 SET=200、ready=503，因此 4097/4096/4096 可以构成预期溢出。每个未激活对象保存匿名序号、SET/ready 阶段和状态码；在独占、串行操作中，以操作前后 actions/status 的容量原因变化归因恰好一个对象。初始容量日志条数在恢复开始前保存，恢复期条数另计，条数与对象数分别报告。释放已激活对象后，REMOVE=200 且该对象 ready=409 确认本地注销；对未 ACK 或注册失败的同一对象重新 SET 并验证 ready=200。对象、阶段、原因及恢复证据齐全时标为 `OK`、`outcome=expected_overflow`，其余按实际证据降级。驱动在宿主的任务 runner cgroup 中运行，经仅绑定 127.0.0.1 的 kubectl port-forward 调用 action endpoint；与 egress cgroup 分离。每级暂停后先读取 egress 资源，再枚举 nft；枚举的 CPU 计数差和墙钟单列，累计 CPU 可扣除前序枚举成本重算。报告使用 `egress_per_subject_fit`，仅拟合 egress 内存计数；夹具自身 RSS/CPU 为独立字段。驱动在 `finally` 中清除全部尝试注册的对象，Pool 重建是异常中断后的清理边界。

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
SUP_CHURN_S=3 SUP_BURST_REPEATS=1 SUP_BURSTS='2 10' SUP_SUBJECT_STEPS='4 8' SUP_SCALE_PROBES=2 \
SUP_SOAK_S=5 SUP_SOAK_ANALYSIS_S=0 SUP_SOAK_CONCURRENCY=16 SUP_RECOVERY_S=1 \
SUP_BURST_GUESTS=2 SUP_SOAK_RATE_ALL=55 SUP_SOAK_RATE_CB=514 \
  ./scripts/fast-sandbox-env/integration-env.sh bench-supplemental
```

本地测试：

```bash
CBV_TEST_BASH=/opt/homebrew/bin/bash /path/to/python3.9-venv/bin/python3 \
  -m unittest discover -s scripts/fast-sandbox-env/tests -p 'test_*.py'
bash -n scripts/fast-sandbox-env/supplemental-bench.sh
shellcheck -S warning scripts/fast-sandbox-env/supplemental-bench.sh
```

原始 specs、连接摘要和进程日志保留在私有 `raw/` 目录，不作为公开报告。顶层报告采用闭集字段，保留延迟数值直方图、M10 创建样本及日志分段数值配对，支持独立重算；不复制凭据、证书 digest、subject UID 或对端名称。
