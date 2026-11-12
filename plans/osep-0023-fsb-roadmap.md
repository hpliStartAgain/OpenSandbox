# OSEP-0023 Fast Sandbox 推进路线（issue / PR 执行文档）

> 本文件只放在 fork 的 `claude/fervent-dirac-65l11z` 分支上，供本地 agent 逐个 PR 执行，**不要提交到 upstream**。
> 基线：upstream `main` = `f6710bdd`（2026-11-12，已同步到 fork `main`）；在开 PR [#2737](https://github.com/alibaba/OpenSandbox/pull/2737) head = `4e1a6582`。
> 行号和符号名取自上述两个提交，开工时以当时的 `main` 为准重新定位。

## 1. 目标和已定结论

| 版本 | 交付 |
|---|---|
| 1.2.2（最早 11-26 前后切） | FSB 上以**实验开关**启用 credential-bound：只解密有 binding 的 host，其余直通。HTTP/1.1、Actions v1。阿里侧升级试跑 |
| 1.2.3 | fast-sandbox profile **默认开**，保留按 Pool 的 opt-out |
| 之后 | FSB HTTP/2、Pod 沙箱（sidecar）公开启用、Actions v2 等收尾 |

维护者已确认的边界，所有 PR 都要遵守：

1. 不动 `specs/`、`sdks/`、`cli/`；1.2.2 不动 `server/`。`interceptionMode` 不暴露到 SDK。
2. Pod 沙箱（sidecar profile）行为保持不变，sidecar 仍只走 `OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME`。
3. 只保证 Actions v1 域；不为 v2 域加新保证，也不能破坏 v2 现有测试。
4. extra ports、`ignore_hosts`、`allow_hosts`、`ssl_insecure` 在 FSB credential-bound 下不支持，启动即拒绝。
5. 先做 HTTP/1.1：已解密连接不协商 h2。
6. OSEP-0025 exchange 凭据的支持由维护者做（见 I1），本路线的 PR 不实现它，但不能让它静默失败。
7. 滚动升级期间新旧 Pod 混跑、沙箱跨 Pod resume 后模式变化，是预期行为，写进文档即可。

## 2. 给执行 agent 的通用约定

**开工前必读**：根目录 `AGENTS.md`；`components/egress/README.md`；`oseps/0023-credential-bound-tls-interception.md` 的 "Fast Sandbox integration contract" 一节；`docs/architecture/network/egress.md` 里 experimental 相关段落。

**分支和提交**

- 每个 PR 一个分支，从当时的 upstream `main` 切出，分支名见各 PR。
- 提交信息沿用现有风格：`feat(egress): ...` / `fix(egress): ...` / `test(egress): ...` / `docs(osep): ...`，英文，祈使句。
- PR 描述按 `.github/pull_request_template.md` 的四段（Summary / Testing / Breaking Changes / Checklist）填写，关联 tracking issue #1713。
- 单个 PR 控制在约 1k 行以内（含测试）。超了就按"机制 / 测试"拆成两个。
- 不混入无关改动，不改生成文件，不顺手重构。

**每个 PR 合入前必须本地通过**

```bash
cd components/egress && test -z "$(gofmt -l .)" && go build ./... && go vet ./... && go test ./...
```

```bash
cd components/egress && pip install -r requirements-mitmproxy.txt && python -m unittest discover -v -s tests -p "test_*.py"
```

```bash
cd components/egress && python -m unittest discover -v -s scripts -p "test_*.py"
```

改动涉及并发路径时再跑一次 `go test -race` 限定到相关测试名。

**硬性规则**

- fail-closed：状态未知一律拒绝，绝不回退到全解密，也绝不回退到按 `clientIp` 拉取凭据的旧路径。
- 开关关闭时行为必须与改动前逐字节一致：mitmdump 启动参数、子进程环境变量、请求路径都不变。每个 PR 都要有一条"开关关闭无差异"的测试。
- 不跳过、不禁用测试；环境缺失导致的 skip 不算通过，要在 PR 描述里写明 NOT_RUN。
- 指标和日志不得出现凭据值、hostname、subject UID、原始错误文本；label 只用闭集。
- 用户可见行为变化要先改 `docs/`。每个 PR 更新 `docs/architecture/network/egress.md` 里对应的边界描述，写清"这一步做了什么、没做什么"。
- 遇到与本文档描述不符的代码事实，以代码为准，在 PR 描述里写明差异，不要硬套。

## 3. 依赖关系和时间线

```text
#2737 ──► R1 ──► R2 ──► R3 ──┬──► R7 ──► (1.2.2) ──► 试跑 ──► R11 ──► R12
R0  (独立，最先)              │
R4  (独立，#2737 合入后)  ────┤
R5  (独立，先问 Q1)           │
R6  (R1 合入后可开始)     ────┘
R8  (需要 KVM 环境，R3 后)
R9  (独立，#2737 合入后)
R10 (R3、R4 合入后)
I1 exchange (维护者) ─────────────────────────────────────► R11 的前置
```

| 周 | 目标 | PR |
|---|---|---|
| 11-12 ~ 11-14 | 对齐 | R0、#2737 合入、提交 I1 / Q1 |
| 11-15 ~ 11-21 | FSB H1 闭环 | R1 → R2 → R3（串行）；R4、R5、R9 并行 |
| 11-22 ~ 11-25 | 证据和发布 | R6、R7、R8、R10 |
| 1.2.3 周期 | 试跑修复、翻默认 | R11、R12 |

**1.2.2 必须项**：R0、R1、R2、R3、R4、R6、R7、R10。R5、R8、R9 可以晚到试跑期间。

---

## 4. Issue 清单

### I1 exchange binding 在 credential-bound 下不可用（提给维护者，他负责实现）

```text
标题：egress: credential-bound 模式（OSEP-0023）的 decision snapshot 不接受 OSEP-0025 exchange binding

现象
fast-sandbox profile 打开 OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME 后，写入带 exchange binding 的 Vault：
- POST /vault/{uid} 返回 201
- subject snapshot 安装被拒，drain 状态为 subject_prepare_rejected
- 之后 data-plane-ready hook 一直返回 503（subject snapshot not acknowledged）
同样步骤换成 inline 凭据则正常。

原因
- Go 侧 pkg/credentialvault/decision_snapshot.go 接受 exchange marker binding
- Python 侧 mitmscripts/decision_snapshot.py 的 _binding 只允许 name / match / headers / substitutions
- tests/test_decision_snapshot.py::test_rejects_exchange_marker_from_newer_egress 把这个拒绝固定成了版本偏差保护

影响
OSEP-0023 在 fast-sandbox 默认启用之前必须解决，否则带 exchange binding 的沙箱不可用。sidecar 的 live 模式走同一个校验器，同样受影响。

需要做的
- 校验器接受 exchange marker，并保持"marker 与渲染内容不能共存"的规范形式
- TLS host selector 包含 exchange binding 的 host
- 请求路径在钉住的 snapshot 上按请求解析 exchange 凭据（现有 resolve 走 clientIp，需改为走 admission token）
- 明确版本偏差策略（新 Go 配旧 addon 时的行为）
- fast-sandbox 集成用例里加一条开关打开时的 exchange 用例

复现
用 fastsandbox_subject_readiness_test.go 的夹具（readinessDrain + readinessReceiver，真实 Unix IPC 和 addon 子进程），先让 subject 就绪，再 doVault POST exchangeVaultBody(deadResolverEndpoint)，观察 hook 返回码和 s.subjectDrain.degraded。
```

### Q1 fastlet 对 data-plane-ready 返回 503 的重试间隔（问维护者，决定 R5 是否要做）

```text
开关打开后，data-plane-ready hook 在 subject snapshot 确认前会返回 503，确认本身约 6ms（egress 内部实测 p50 7.2ms vs 关闭时 1.2ms）。
fastlet 收到 503 后多久重试？如果间隔在 10ms 以内我就不动；如果是几十毫秒，我在 egress 的 hook 里加一个有界等待，避免创建延迟被重试间隔主导。
```

### I2 更新 tracking issue #1713 的清单

把正文的 checklist 换成本文件第 5 节的 R0–R12，注明 1.2.2 / 1.2.3 的归属，并链接 I1。

### I3–I5 收尾阶段的占位 issue（1.2.2 发布后再提）

- **I3** `egress: HTTP/2 request admission for Fast Sandbox credential-bound subjects`：把 sidecar 的 `credential_bound_h2.py` 适配到 per-subject registry；同时关闭 H2 验证矩阵和 image runner 用例。
- **I4** `egress: operator-defined forced-decrypt host list for Pod sandboxes`：安全侧要的"必须解密的 host 列表"，加 server 级模式配置；需要先补 OSEP 设计，不进 SDK。
- **I5** `egress: credential-bound support in the Actions v2 strict domain`。

---

## 5. PR 清单

### R0 `docs(osep): stage Fast Sandbox credential-bound rollout in OSEP-0023`

- **分支**：`docs/osep0023-fsb-staged-rollout`　**依赖**：无　**只改**：`oseps/0023-credential-bound-tls-interception.md`
- **目标**：让 OSEP 正文与维护者确认的路线一致，后续 PR 才不会与 OSEP 冲突。

改动清单：

1. **Requirements 表**
   - R1：改为"sidecar profile 省略选项时保持 intercept-all；fast-sandbox profile 的模式是运维持有的 profile 级设置，首个版本实验性 opt-in，后续版本默认 credential-bound 并保留 opt-out"。
   - R8 / R9：注明 FSB 分期，首期只有 HTTP/1.1，已解密连接不协商 h2，HTTP/2 后续补齐。
   - R18：注明仅在公开字段存在时适用。
2. **Public Configuration / Effective Mode Verification**：加一段"当前状态"——公开的 `interceptionMode` 字段推迟；不暴露到 SDK；将来最多到 server 级配置。原 schema 保留为"未来设计"。
3. **Upgrade & Migration Strategy**：改第 3、4、9 步，使其允许 FSB profile 先行、允许 FSB 默认值变更，并写明 opt-out 和混跑/跨 Pod resume 的预期行为。
4. **Phased Implementation**
   - 把第 506–623 行的实现日志整体移到文末新增的 `## Appendix: Implementation Log`，内容不改。
   - 正文只留编号阶段列表，Phase 4 拆成：4a sidecar HTTP/2（已完成）；4b FSB HTTP/1.1 实验 opt-in；4c FSB 默认开；4d FSB HTTP/2；4e Pod 沙箱公开启用（另行设计）。
5. **Fast Sandbox integration contract**
   - "Implementation boundary" 段更新到当前事实：B0–B2、B3a 已合入，B3b-1 在 #2737。
   - Integration increments 表更新 B3 的拆分，并加一列"目标版本"。
   - "Open integration questions" 关闭两条：有效模式是 Pool / profile 级；首期只支持 Actions v1。
6. **Security and Privacy Model**：加一句 FSB 默认开之后未绑定 HTTPS 不再对运维 addon 和审计可见，需要全量审计的 Pool 用 opt-out。
7. **第 346 行**：`OPENSANDBOX_EGRESS_CREDENTIAL_TRANSITION_DRAIN_TIMEOUT_SECONDS` 改为代码里的 `OPENSANDBOX_EGRESS_REVISION_DRAIN_TIMEOUT_SECONDS`。
8. front matter 的 `last-updated` 改为当天。

- **不做**：不改 0022；不改任何代码；不把 status 改成 `implemented`。
- **验收**：`git diff --stat` 只有这一个文件；附录内容与移动前逐字一致（用 `git diff --color-moved` 自查）；全文不再出现 `CREDENTIAL_TRANSITION_DRAIN`。

---

### R1 `feat(egress): admit Fast Sandbox HTTP/1.1 requests against subject snapshots`

- **分支**：`feat/osep0023-fsb-h1-request-admission`　**依赖**：#2737 已合入
- **目标**：把 #2737 里"所有已解密请求一律终止"换成真正的请求级 admission，仅 HTTP/1.1。

入口代码（#2737 的树）：

- `components/egress/mitmscripts/system.py`：`requestheaders()` 开头的 `_subject_admission_runtime()` 分支（约 1929 行）；`_requestheaders_live(live, flow)`（sidecar 的 H1 实现）；`client_disconnected()`。
- `components/egress/mitmscripts/subject_admission.py`：`SubjectRegistry`、`SubjectAdmissionRuntime`（`_connections` 以 `id(client)` 存 `(registry, token, client)`）。
- `components/egress/mitmscripts/tls_registry.py`：`BoundConnectionRegistry.acquire_request / finish_request / release / drain_state`。
- `components/egress/mitmscripts/credential_bound.py`：`LiveRuntime.token_for / acquire_request / finish_request`，作为接口形状的参照。
- `components/egress/pkg/mitmproxy/launch.go`：mitmdump 参数构造（约 344 行的 `--set` 列表），`TLSAdmission` handoff。

改动清单：

1. `SubjectAdmissionRuntime` 提供与 `LiveRuntime` 同形的三个方法：`token_for(client)`、`acquire_request(token)`、`finish_request(handle)`，并提供 `h2_for(client)` 恒返回 `None`。`acquire_request` 必须路由到**握手时登记的那个 registry**，不能按当前源 IP 重新查。
2. `SubjectRegistry` 的请求 admission 要返回一个不可变 `Snapshot`，其 revision 必须等于该 registry 当前生效的 dispatch revision，且两者在同一把 registry 锁下原子取得。`publish_dispatch()` 需要同时保存 snapshot 本体。token 已被 fence、registry 已 deactivate、无 snapshot 时一律 deny。
3. `requestheaders()` 的 subject 分支改为调用 `_requestheaders_live(subject_runtime, flow)`，复用 sidecar 的 H1 authority 门（恰好一个合规 `Host`、等于 SNI 且等于 token 的 SNI、端口省略或 443、`ssl_insecure` 拒绝）和后续的 binding/path/method 匹配、注入、脱敏。若该函数内部有 sidecar 专属假设，做最小改造而不是复制一份。
4. 请求结束路径（response、error、`client_disconnected`）调用 `finish_request`，做法与 live 路径一致。
5. H2 一律不进入：`launch.go` 在 `TLSAdmission` 为真时追加 `--set http2=false`；`requestheaders` 里对 `alpn == b"h2"` 或 HTTP/2 版本的请求保留拒绝作为兜底。
6. subject admission 打开时，任何请求都不得走 `_load_active_vault_for_ip` 的拉取缓存；保留并测试这条。
7. 明文 HTTP 的行为与 sidecar live 路径保持一致（复用同一函数自然得到），不要另起语义；在文档里写明。

- **不做**：H2；host 移除后的排空和强制关闭（R2）；unload/rebind 的连接关闭（R3）；exchange。
- **测试**
  - `tests/test_subject_admission.py`：token 路由到握手 registry；fence / deactivate / 无 snapshot 时 deny；snapshot 与 dispatch revision 原子一致；只换凭据后新请求用新 snapshot、旧请求句柄不变。
  - `tests/test_subject_admission_runtime.py`（真实 mitmdump 子进程夹具）：同一 SNI，subject A 注入成功、subject B 直通；错误 `Host` 被拒；无 membership 的已解密连接被拒；源 IP 被新 subject 复用后，旧连接拿不到新 subject 的凭据；客户端提供 `h2` ALPN 时协商结果为 `http/1.1`。
  - Go：`pkg/mitmproxy` 的启动参数测试——`TLSAdmission` 为真时有 `http2=false`，为假时参数与改动前完全一致。
- **文档**：`docs/architecture/network/egress.md` 把"all decrypted requests are deliberately terminated"那段改成新的边界描述。
- **验收**：通用三条命令全绿；上述 runtime 用例在本地真实 mitmdump 下通过。

---

### R2 `feat(egress): fence and drain Fast Sandbox connections on binding transitions`

- **分支**：`feat/osep0023-fsb-transition-drain`　**依赖**：R1
- **目标**：满足 OSEP R7——删除某 host 的最后一个 binding 时，确认返回前新请求已被拦住；已放行的请求限时排空；到期强制关闭。

入口代码：`tls_registry.py` 的 `_plan_activation / _publish_activation / expired_connections / pending_requests`；`credential_bound.py` 的 `LiveRuntime._drain_loop / drain_sweep_once / _close_established`（sidecar 的清扫实现）；`subject_revision.py` 的 `_publish_index()` 和 commit 路径；`subject_runtime.py` 的 handoff 字段集合 `_ADMISSION_FIELDS`；Go 侧 `fastsandbox_subject_launch.go`、`pkg/mitmproxy/launch.go` 的 subject handoff。

改动清单：

1. 确认并用测试固定顺序：subject snapshot 的 commit 回复必须在 `SubjectRegistry.publish_dispatch()` 完成之后发出。若当前顺序不满足，调整为先发布再回复。
2. `SubjectAdmissionRuntime` 增加一个进程级清扫循环，遍历所有 subject registry 的 `expired_connections()` 分页结果，通过 membership 表找到 client 连接并关闭；关闭失败下一轮重试，不延长期限。实现方式对齐 sidecar 的 `drain_sweep_once`，能复用就复用。
3. 排空时限通过 subject handoff 下发：Go 读取现有的 `OPENSANDBOX_EGRESS_REVISION_DRAIN_TIMEOUT_SECONDS`（默认 30，范围 1–300），作为新增 handoff 字段传给子进程；`subject_runtime.py` 的严格字段校验同步更新。不新增运维环境变量。
4. 重复发布、连续轮换、删了再加，都不得延长最早的期限；删了再加不得让已退役连接复活。

- **不做**：H2 GOAWAY；unload 时的关闭（R3）。
- **测试**（Python 单测 + runtime 夹具各一组）：
  - 删除最后一个 binding：确认返回后，旧连接上的新请求立即被拒；在途请求在时限内完成；到期连接被强制关闭；下一条新连接直通。
  - 只换凭据：连接保留，新请求用新凭据。
  - 只改 policy：旧请求句柄登记期限，仍覆盖的空闲连接不被关闭。
  - 删了再加再删：期限不延长，旧连接不复活。
  - Go：handoff 字段的边界值和缺失值测试；开关关闭时子进程环境不变。
- **文档**：`egress.md` 增加 FSB 的排空语义一段。

---

### R3 `feat(egress): tear down Fast Sandbox subject transports before identity reuse`

- **分支**：`feat/osep0023-fsb-subject-teardown`　**依赖**：R2
- **目标**：unload、rebind、IP 接管、suspend 时关闭该 subject 的连接；源 IP 被新 subject 复用之前，旧 subject 的已解密连接和直通连接都已关闭。

**开工第一步是一段设计说明**（写进 PR 描述，20 行以内），回答两个问题再动手：

1. 直通连接怎么关。推荐方案：在 addon 里维护"源 IP → 活跃 client 连接集合"的索引，覆盖经 mitmproxy 的全部连接（解密和直通），在 `client_connected / client_disconnected` 维护，条目数受活跃连接数约束。备选：在 Go 侧 `unloadEnforcement` 时按源 IP 清 conntrack（`pkg/fastsandboxnft` 已有 `readConntrack`）。
2. 不经过 mitmproxy 的流量（非 443、直连 IP）在 REMOVE_BINDING 时由谁终止。读 `fastsandbox_server.go` 的 `unloadEnforcement` 和 `takeoverStaleSubject`，把现状写清楚；如果现有网络附着拆除已经覆盖，写明并只加测试。

入口代码：`subject_revision.py` 的 `_register / _unload / _suspend / close`（其中 `entry.registry.deactivate()` 的返回值目前被丢弃）；`subject_admission.py` 的 membership 表；Go 侧 `fastsandbox_subject_worker.go` 的 intent 队列（Unload 先于后继 Register 的 FIFO 已存在）。

改动清单：

1. `_unload`、`_suspend`、失败置位、`close()`：对 `deactivate()` 返回的 token 逐个关闭对应 client 连接并释放登记。
2. `_register(target, addresses)`：发布源 IP 索引之前，先关闭这些地址下属于其他 target 的全部剩余连接（解密和直通）。这条保证"身份复用前已拆除"，不依赖 Go 侧时序。
3. Unload 的回执增加关闭计数字段；如果有连接未能确认关闭，回执如实报告，Go 侧 drain worker 记录 degraded 而不是当作干净卸载。回执协议变更要同步 `subject_revision_ipc.py` 和 Go 的 `pkg/revision/subject_lifecycle_unix.go`，并保持旧字段兼容。
4. 更新 `subject_revision.py` 文件头注释里"unload 不代表连接已排空"的说法。

- **不做**：H2；Actions v2 域的新保证。
- **测试**
  - runtime 夹具：subject A 有一条解密长连接和一条直通长连接；Unload A 后两条都被关闭。用同一源 IP 注册 B，B 的新连接不继承任何状态；A 残留连接上的请求被拒。
  - suspend（Vault 状态变未知）后解密连接被关闭，恢复后新连接正常。
  - Go：Unload 回执带未关闭计数时 worker 置 degraded；rebind 和 IP 接管两条路径各一条用例；`go test -race` 跑 `TestFastSandboxSubject`。
- **文档**：`egress.md` 去掉"Do not enable this gate in production before B4"那句，换成拆除语义和已知边界。

---

### R4 `feat(egress): single Fast Sandbox interception switch with startup validation`

- **分支**：`feat/osep0023-fsb-interception-switch`　**依赖**：#2737 已合入（与 R1–R3 无依赖）
- **目标**：把两个实验 gate 收成一个受支持的开关，并在启动时拒绝不兼容配置。本 PR **不改默认值**。

入口代码：`components/egress/pkg/constants/configuration.go`（`EnvExperimentalRevisionRuntime`、`EnvExperimentalFSBTLSAdmission`、`EnvFSBTLSCapacity`、`EnvFSBProcessTLSCapacity`、`EnvMitmproxyExtraPorts`、`EnvMitmproxySslInsecure`）；`main.go` 的 `validateRevisionRuntimeStartup`；`fastsandbox_subject_launch.go` 约 115 行；`revision_runtime_startup_test.go`、`fsb_tls_admission_test.go`。

改动清单：

1. 新增环境变量 `OPENSANDBOX_EGRESS_FSB_INTERCEPTION_MODE`，取值 `all`（默认）或 `credential-bound`，仅 fast-sandbox profile 接受；sidecar profile 设置它时启动失败。名字如果维护者在 R0 评审里另有意见，以评审结论为准。
2. 在一个函数里解析出"FSB 生效模式"，其余代码只读这个结果：
   - 新变量为 `credential-bound` → 等价于两个旧 gate 都为真。
   - 两个旧 gate 都为真且新变量未设 → 仍然生效，打一条弃用日志。
   - 只有 `EXPERIMENTAL_REVISION_RUNTIME` 为真 → 保持现有的"仅安装"行为，不变。
   - 新变量为 `all` 而旧 gate 为真，或其他矛盾组合 → 启动失败，错误信息点名冲突的变量。
3. 生效模式为 `credential-bound` 时，在 profile 分发和网络设置之前校验并拒绝：非默认的 `OPENSANDBOX_EGRESS_MITMPROXY_EXTRA_PORTS`；`OPENSANDBOX_EGRESS_MITMPROXY_SSL_INSECURE`；非空的 mitmproxy `ignore_hosts` / `allow_hosts`（先查清 Go 侧这两个配置的来源再接入校验）；`OPENSANDBOX_EGRESS_UPSTREAM_PROXY`（#2737 的 `subject_runtime.py` 已在子进程里拒绝，这里提前到 Go 启动期给出明确错误）；`OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT` 不为真；`OPENSANDBOX_EGRESS_MODE` 不是 `dns+nft`。
4. 关于 upstream proxy：先确认它在 HTTP/1.1 下技术上是否可行。可行也不在本 PR 放开，在 PR 描述里记录结论，留给后续。

- **不做**：不改默认值；不动 sidecar 的 gate；不动 Pool 清单。
- **测试**：`revision_runtime_startup_test.go` 用表驱动覆盖上面每一种组合和每一条拒绝；新变量未设且旧 gate 未设时，启动参数和子进程环境与改动前逐项相等。
- **文档**：`egress.md` 和 `docs/architecture/fast-sandbox/networking.md` 说明新开关、旧 gate 的别名关系和被拒绝的配置。

---

### R5 `feat(egress): wait briefly for subject snapshot acknowledgement in data-plane-ready`

- **分支**：`feat/osep0023-fsb-ready-wait`　**依赖**：Q1 的答复。如果 fastlet 的重试间隔不超过 10ms，本项关闭不做。
- **目标**：snapshot 确认约需 6ms，不让创建延迟被调用方的重试间隔主导。

入口代码：`fastsandbox_actions.go` 的 `case constants.HookDataPlaneReady`（约 712–800 行，`!acknowledged` 时返回 503）；`fastsandbox_subject_worker.go` 里 `d.acked` 的写入点；`fastsandbox_transition.go` 的 `actionGate`。

约束（决定这个 PR 能不能做）：

- 等待期间**不得持有** `actionGate`、`policyCommitMu`、`s.mu` 或 owner stripe，否则会把并发创建串行化。先读清 hook 是否在 `actionGate` 内执行；如果无法在锁外等待，就在 PR 里说明并放弃本项，不要硬做。
- 等待有上界，常量起步 50ms，受请求 context 取消约束；超时仍返回 503，语义不变。
- 用按 subject 的通知（确认时关闭的 channel 之类）实现，不要轮询。等待结束后必须重新走一遍现有的 fence 和 ACK 校验，不能跳过。

- **测试**：确认在等待期内到达时 hook 返回 200；超时返回 503；等待期间其他 subject 的 SET / hook / Vault 中继不被阻塞（用慢 IPC 夹具）；等待期间发生 rebind 时返回 409；`-race` 通过。
- **验收数据**：在 PR 描述里给出等待前后的对比。参考基线（临时探针，真实 IPC 和 addon 子进程、fake nft）：开关关闭 p50 1.2ms，打开 p50 7.2ms、p99 11–15ms；100 个 subject 同时绑定约 0.33s 全部就绪。

---

### R6 `test(egress): Fast Sandbox subject recovery across child and egress restarts`

- **分支**：`test/osep0023-fsb-restart-recovery`　**依赖**：R1（可与 R2、R3 并行）
- **目标**：用测试证明两种重启下的恢复契约，发现缺口就在本 PR 修；修复量大则拆出单独的 `fix(egress)` PR。

要证明的契约：

| 场景 | 恢复前 | 恢复后 |
|---|---|---|
| mitmdump 子进程重启 | 带 SNI 的 TLS 被拒；ECH 和无 SNI 直通 | 所有已注册 subject 在新的 control generation 下重新注册并装回 snapshot；A/B 隔离恢复 |
| egress 进程重启 | 同上；subject 未就绪 | SET_BINDING 重放后，按 fence 匹配的 Vault 文件重新加载并装回 snapshot |
| 重启后 Vault 状态未知（文件缺失、fence 不匹配、不可读） | subject 保持未就绪 | **不得**用空 snapshot 顶替丢失的绑定状态；必须等显式恢复 |
| 首次创建且从未建 Vault | — | 自动装入权威的空 snapshot，HTTPS 立即可直通 |

入口代码：`fastsandbox_subject_worker.go` 的 `publishSubjectClient / detachSubjectClient`、`snapshots` / `unknownVaults` / `snapshotFailures`；`fastsandbox_vault_persist.go` 里 `setSubjectVaultEntryLocked` 的各调用点；现有夹具 `fastsandbox_subject_readiness_test.go`、`subject_revision_integration_test.go`、`tests/test_subject_admission_runtime.py`。

- **测试位置**：Go 用现有真实 IPC 夹具；涉及 TLS 判定的部分放 Python runtime 夹具。
- **文档**：`egress.md` 加上面这张恢复矩阵。

---

### R7 `test(fast-sandbox): credential-bound verification stage in the integration environment`

- **分支**：`test/osep0023-fsb-integration-verify`　**依赖**：R3、R4
- **目标**：在真实 FSB 环境（自托管 KVM runner）里给出 1.2.2 的发布证据。

入口代码：`scripts/fast-sandbox-env/integration-env.sh`（`run_stage` 注册点约 3991 和 4052 行，`POOL_MODE` 处理约 156 行）；`scripts/fast-sandbox-env/verify/vault.sh`（现有 `vault_lifecycle_verify`、`mitm_ca_chain_verify`、`exchange_resolver_verify` 及其辅助函数）；`scripts/fast-sandbox-env/manifests/pool/*.yaml`；`.github/workflows/fast-sandbox-test.yml`。

改动清单：

1. `integration-env.sh` 增加环境变量 `EGRESS_INTERCEPTION_MODE`（默认空）。非空时把 R4 的开关注入两个 Pool 清单里 egress 容器的 env。
2. 新增 `verify/credential-bound.sh`，提供 `credential_bound_verify()`，仅在开关为 `credential-bound` 时通过 `run_stage` 注册到 native 和 overlaybd 两条 verify 里。用例：
   1. 没建过 Vault 的沙箱访问一个证书可信的 HTTPS 端点成功，且看到的是源站证书而不是 MITM CA。
   2. 同一目的 host：沙箱 A 有 binding，请求被解密并注入；沙箱 B 没有，直通且不带凭据。
   3. 给 B 新增 binding：已有连接不带凭据，新连接注入。
   4. 删除 A 的最后一个 binding：新连接直通。
   5. 只换凭据：新请求带新值。
   6. kill 沙箱后用新沙箱复用同一 IP（或观察到 IP 复用时）：新沙箱不带旧凭据。
   7. `pkill` mitmdump 和 egress 各一次：恢复后用例 2 仍成立（可复用 `vault.sh` 里的重启手法）。
   8. 网络 deny 规则对直通目的地仍生效。
   9. egress 日志里 grep 不到凭据值。
3. 开关打开时，现有 `vault_lifecycle_verify`、`mitm_ca_chain_verify`、pause-resume、idle-pause、snapshot 用例照常跑，必须全绿。
4. `exchange_resolver_verify` 在开关打开时预期失败（I1 未修复前）。不要静默跳过：打印 `BLOCKED: exchange under credential-bound (see I1)` 并在汇总里单列，I1 修复后去掉这个分支。
5. `fast-sandbox-test.yml` 增加一条开关打开的运行。runner 容量未与维护者确认：先做成与现有 job 串行的附加步骤或矩阵维度，在 PR 描述里请维护者选；容量不够就限定为只在 `components/egress/**` 变更时触发。

- **验收**：`sudo -E ./scripts/fast-sandbox-env/integration-env.sh up --auto-clean` 后，`EGRESS_INTERCEPTION_MODE=credential-bound` 下 `verify-native` 全部 stage 通过（exchange 标记为 BLOCKED）；开关为空时输出与改动前一致。
- **需要的环境**：KVM。本地没有就在 fork 上用 runner 或请维护者触发。

---

### R8 `docs(fast-sandbox): credential-bound cost measurements and recommended budgets`

- **分支**：`docs/osep0023-fsb-benchmarks`　**依赖**：R3、R4；需要 KVM 环境
- **目标**：回答维护者的两个问题——创建延迟加多少、连接预算默认值该是多少。

测量项：

1. **创建延迟**：`scripts/fast-sandbox-env/create-bench.py`，`N=200 CONCURRENCY=10`，开关关闭和打开各跑三轮，报告 avg / p50 / p90 / p99。维护者给的参考值是端到端 130ms。
2. **握手延迟**：从 guest 内对回显端点测 TLS 建连时间，三种路径各 200 次：开关关闭（全解密）、打开且绑定（解密）、打开且未绑定（直通）。
3. **每连接内存**：从多个沙箱建立 K 条空闲的绑定 keep-alive 连接（K 取 500、1000、2000），读 egress 容器 cgroup 的内存，线性拟合出每条连接的字节数。
4. **CPU**：直通为主的负载下，开关前后 egress 的 CPU 时间对比。

产出：

- `docs/architecture/fast-sandbox/performance.md` 新增一节，给出数字、测试环境、方法。
- 推荐 Pool 配置：按 100 沙箱、egress 2c/8G 给出 `OPENSANDBOX_EGRESS_FSB_TLS_CAPACITY` 和 `OPENSANDBOX_EGRESS_FSB_PROCESS_TLS_CAPACITY`。现在的进程级默认 131072 是按 4096 沙箱设计的；按每沙箱 32 条、100 沙箱只需要 3200 条。如果实测内存表明默认值在 8G 下不安全，在本 PR 里调低默认值并更新测试。
- 如需脚本，放在 `scripts/fast-sandbox-env/` 下，与 `create-bench.py` 同风格。

---

### R9 `feat(egress): Fast Sandbox credential-bound transition and budget metrics`

- **分支**：`feat/osep0023-fsb-metrics`　**依赖**：#2737 已合入
- **目标**：试跑期间可观测。只做最小集。

入口代码：`components/egress/pkg/telemetry/metrics.go`、`tls_admission.go`；`pkg/mitmproxy/launch.go` 约 493 行（子进程日志转指标）；`fastsandbox_subject_worker.go` 的 `recordResult`；`docs/guides/telemetry.md` 约 226 行。

改动清单：

1. 命名对齐：OSEP 表写的是 `egress.mitm.registry.entries` / `egress.mitm.registry.capacity`，#2737 实现的是 `egress.mitm.tls.registry.occupancy` / `egress.mitm.tls.registry.configured_budget`。二选一统一，推荐保留已实现的名字并在 R12 里改 OSEP 表；如果维护者要求按 OSEP 名字，就改代码。
2. 新增 `egress.credential_vault.transitions_total{transition, result}`：在 Go 侧 subject 安装结果处计数。`transition` 闭集：`register`、`install`、`suspend`、`unload`、`replay`；`result` 闭集：`ok`、`rejected`、`indeterminate`、`failed`。
3. 新增 `egress.credential_vault.transition.duration{transition, result}` 直方图，取同一位置的耗时。

- **不做**：`egress.mitm.tls.active_connections`；任何带 subject、host 的 label。
- **测试**：`pkg/telemetry` 里对 label 闭集的测试；未知值归并到固定兜底值而不是透传。
- **文档**：`docs/guides/telemetry.md` 增加条目，写明这些指标不是安全证据。

---

### R10 `docs(fast-sandbox): experimental credential-bound interception guide`

- **分支**：`docs/osep0023-fsb-experimental-guide`　**依赖**：R3、R4（R8 的数字能赶上就引用）
- **目标**：1.2.2 的使用说明和发布说明。

改动清单：

1. `docs/architecture/fast-sandbox/networking.md`：新增一节，说明模式含义、如何在 Pool 的 egress 容器上打开、推荐配置、被拒绝的配置。
2. `docs/guides/credential-vault.md`：FSB 小节，写清客户端须知——binding 要在发起请求前装好；新增 binding 后要重建连接或回收连接池；`PATCH` 必须带 `expectedRevision`。
3. 限制清单：仅 HTTP/1.1（绑定 host 上的 gRPC 不可用）；exchange 凭据的状态（引用 I1）；仅 Actions v1；未绑定 HTTPS 不再对运维 addon 和审计可见；混跑和跨 Pod resume 的模式变化。
4. `scripts/fast-sandbox-env/manifests/pool/*.yaml`：在 egress env 处加一段**注释掉的**示例，不启用。
5. 发布说明：先看 `docs/releases/` 最近两个版本的提交是谁写的、`components/egress/RELEASE_NOTES.md` 是否仍在维护，按现行做法加条目；如果发布说明由维护者统一生成，就把条目文本放进 PR 描述。

- **验收**：`docs/` 站点能构建（按 `docs/` 下 README 的命令）；文中出现的每个环境变量名都能在 `components/egress/pkg/constants/configuration.go` 里 grep 到。

---

### R11 `feat(egress): default Fast Sandbox interception to credential-bound`

- **分支**：`feat/osep0023-fsb-default-on`　**目标版本**：1.2.3
- **合入条件（全部满足才开 PR）**：R7 在 CI 上全绿；R8 的创建延迟增量维护者已认可；I1（exchange）已合入且 R7 里的 BLOCKED 分支已去掉；阿里试跑没有未关闭的阻塞问题。

改动清单：

1. fast-sandbox profile 下 `OPENSANDBOX_EGRESS_FSB_INTERCEPTION_MODE` 未设置时的生效值由 `all` 改为 `credential-bound`；显式 `all` 即 opt-out。
2. 未设置且存在不兼容配置（R4 的拒绝列表）时启动失败，错误信息同时给出两条出路：去掉该配置，或显式设 `all`。不要静默降级。
3. 去掉旧 gate 的别名，或保留到再下一个版本——以维护者意见为准，在 PR 描述里问清。
4. sidecar profile 不变。
5. 更新 R4 的表驱动测试、R7 的 CI（默认即开，另加一条 `all` 的回归运行）、R10 的文档和 Pool 清单注释。
6. 发布说明里写升级提示：行为变化、opt-out 方法、混跑期间的预期。

---

### R12 `docs(osep): record Fast Sandbox credential-bound status in OSEP-0023`

- **分支**：`docs/osep0023-fsb-status`　**依赖**：R11
- 更新 Phase 4b / 4c 为已完成；Observability 表的指标名对齐实现；Test Plan 里标出已由 R6 / R7 覆盖的条目；链接 I3–I5。status 保持 `implementing`，直到 I3、I4 的去向确定。

---

## 6. 风险和需要人工判断的点

| 风险 | 影响 | 处理 |
|---|---|---|
| 评审吞吐约每天 1 个 PR | 1.2.2 之前 12 个 PR 没有余量 | R4、R5、R9 尽早并行送审；串行链 R1→R2→R3 请维护者当天评审 |
| R3 的直通连接拆除方案未定 | 阶段 1 最不确定的一项 | 先写设计说明再动手；方案有分歧时先和维护者对一下 |
| fastlet 重试间隔未知 | 决定 R5 是否必须 | 先问 Q1 |
| I1 的完成时间 | 1.2.2 试跑的 Pool 不能放带 exchange binding 的沙箱；R11 被它卡住 | R10 写明限制；R7 用 BLOCKED 显式标记 |
| 仅 HTTP/1.1 | 绑定 host 上的 gRPC 客户端失败 | R10 写明；I3 跟进 |
| KVM 环境 | R7、R8 本地跑不了 | 用自托管 runner 或阿里环境 |
| CI runner 容量未确认 | R7 可能不能每个 PR 都跑 | R7 的 PR 描述里请维护者选触发策略 |
