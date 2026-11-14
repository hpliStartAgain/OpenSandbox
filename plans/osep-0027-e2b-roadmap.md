# OSEP-0027 E2B 兼容：完整实现路线（issue / PR 执行文档）

> 执行计划文件，供 agent 逐个 PR 执行。放在 fork（`hpliStartAgain/OpenSandbox`）的计划分支 `claude/fervent-dirac-65l11z` 上，**不推到 upstream，不合入 `main`，不要带进任何实现 PR**。
> 基线：upstream `opensandbox-group/OpenSandbox` 的 `main` = `e564cd18`（2026-11-13，OSEP-0027 经 #2591 合入）。
> 设计依据：`oseps/0027-optional-e2b-compatibility.md`。本文件只负责拆解和排序，语义以 OSEP 为准；两者不一致时以 OSEP 为准，并在 PR 描述里写明。
> 本文件里对上游 SDK 的描述来自对 `e2b==2.62.1` wheel 的静态检查，对 envd 0.8.0 的描述来自 OSEP 引用，未实跑；开工时要重新核对。

## 1. 这个 OSEP 要交付什么

让**未修改的官方 E2B Python SDK**（候选 `e2b==2.62.1`，同步客户端）通过一个可选的适配层使用 OpenSandbox。结构上是两块：

- **控制面适配器**：挂在路径前缀下（例如 `/compat/e2b`），把 E2B 的生命周期请求翻译成原生 `/v1` 调用。不建自己的数据库，沙箱 ID 直接用原生 ID。
- **数据面薄路由**：SDK 的命令和文件请求原样转发到沙箱里**未修改的上游 envd 0.8.0**，转发前校验 token 和归属。不做协议翻译，不碰 execd。

验收后端只有一个：Fast Sandbox 上的 envd-only 模板。

OSEP 定的阶段：

| Gate | 内容 | 退出条件 |
|---|---|---|
| 0 | 目标对齐：范围、pin、模板和恢复方案、网络前提、框架场景 | maintainer 在 tracking issue 里确认 |
| 1a | 最小真实闭环：创建 → 命令/文件往返 → 删除 | 真实 pinned SDK 在一个 Fast Sandbox 组合上跑通 |
| 1b | 手动全状态 pause，经 connect 恢复 | 同一 ID，进程、内存、文件连续，envd token 保留 |
| 2 | 完整候选：info、运行态 connect、set-timeout、list，加框架场景 | T1–T7 对每个宣称支持的操作都通过 |
| 3 | 是否作为受支持功能发布 | maintainer 明确接受范围和维护责任 |

**当前状态**：OSEP 是 `draft`，没有任何实现代码。fork 上的 `t3/check-e2b-compatibility` 分支只有 OSEP 文档本身。

## 2. 哪些能在普通开发机验证，哪些不能

这一点决定了"最小依赖优先"的顺序。

| 类别 | 内容 | 验证环境 |
|---|---|---|
| 纯逻辑 | token 派生、模板映射、超时规则、元数据编码 | 任意机器，单测 |
| 控制面 | 七条路由的请求、响应、错误，对接假的原生后端 | 任意机器，真实 pinned SDK 可直接驱动 |
| 数据面路由 | 转发、鉴权、流式，对接假的 envd | 任意机器 |
| 开发联调 | 真实 envd 二进制本机运行，SDK 全链路 | Linux/amd64，开发辅助，**不算验收** |
| 真实后端 | envd-only 模板、原生 readiness、Gate 1a / 1b 证据 | KVM 上的 Fast Sandbox 环境 |

OSEP 明确：stub、mock、Docker 上的成功都不能替代 Fast Sandbox 验收（R3、T3）。所以前半段的 PR 只能宣称"契约和组件就绪"，不能宣称"兼容"。

## 3. 开工前要先定的事（Gate 0）

OSEP 把这些留给了评审。D2 已由 OSEP 作者决定；其余是建议的默认值，写进 I1 请 maintainer 确认。每个实现 PR 都要链接 I1 并写明 Gate 0 的当前状态；maintainer 对位置或范围提出异议时停下来，不要继续堆 PR。

| # | 待定项 | 取值 | 理由 |
|---|---|---|---|
| D1 | 代码放哪 | 建议 `components/e2b-compat/`，独立 Go module，独立发布 | R1 要求可选、可单独寻址；不往原生 server 加 E2B 路由 |
| D2 | 实现语言 | **Go（已定）** | OSB server 后续有用 Go 重构的排期；与 `components/ingress` 同类，流式反向代理成熟。代价是契约测试跨语言：Go 的服务进程由 Python 测试套件用真实 SDK 驱动 |
| D3 | 数据面路由是否与适配器同 module | 建议同 module、两个可分别启动的子命令 | 两者共享 token 派生和原生客户端；OSEP 说这不要求新增一个路由服务 |
| D4 | envd 入口形式 | 先做固定入口：`E2B_SANDBOX_URL` 加 `E2b-Sandbox-Id` / `E2b-Sandbox-Port` 头 | 不需要通配 DNS 和通配证书，最容易在集成环境里落地。SDK 把这个覆盖项标为 deprecated，要在兼容矩阵里写明 |
| D5 | 可信范围 | 单一管理范围，一把适配器 API key | OSEP 首个实验的设定 |
| D6 | 超时上限 | 取原生 `server.max_sandbox_timeout_seconds` | OSEP 要求 Gate 0 固定上限，超出即 400，不截断 |
| D7 | 框架场景（T6） | 待选，不阻塞 Gate 1a | 需要 code interpreter、自动 pause 的场景不能选 |
| D8 | envd-only 模板怎么构建、池怎么 ready | 待 Fast Sandbox 侧确认（见 I2） | 是否能在没有 execd 的情况下达到原生 READY，是 Gate 1a 的第一个集成检查 |

## 4. 给执行 agent 的通用约定

**开工前必读**：根目录 `AGENTS.md`；`oseps/0027-optional-e2b-compatibility.md` 全文（尤其 Requirements、Control Plane and Resource Identity、Timeout Semantics、Routing and Security）；`specs/sandbox-lifecycle.yml` 里 `/sandboxes`、`/sandboxes/{sandboxId}`、`/sandboxes/{sandboxId}/endpoints/{port}`、`/pause`、`/resume`、`/renew-expiration`、`/metadata` 几段。

**上游 SDK 的事实以 pin 住的包为准**：`pip download e2b==2.62.1 --no-deps` 后直接读 wheel 里的源码，不要凭记忆。已核对到的事实：

- 控制面认证头是 `X-API-KEY`。
- SDK 实际调用的七条路由（相对兼容前缀）：`POST /v2/sandboxes`、`POST /v2/sandboxes/{id}/connect`、`POST /sandboxes/{id}/pause`、`GET /sandboxes/{id}`、`GET /v2/sandboxes`、`POST /sandboxes/{id}/timeout`、`DELETE /sandboxes/{id}`。
- 创建请求体字段：`templateID`、`timeout`、`autoPause`、`autoPauseMemory`、`autoResume`、`secure`、`allow_internet_access`、`network`、`metadata`、`envVars`、`mcp`、`iam`、`volumeMounts`。
- 创建/连接响应的必填字段：`templateID`、`sandboxID`、`clientID`、`envdVersion`；可选 `alias`、`envdAccessToken`、`trafficAccessToken`、`domain`。
- 错误体：`code`、`message`，可选 `error_code`。
- envd 端口固定 `49983`；SDK 访问 envd 时总会带 `E2b-Sandbox-Id`、`E2b-Sandbox-Port`，有 token 时带 `X-Access-Token`。
- envd 地址：设置了 `E2B_SANDBOX_URL` 就用它；否则是 `https://<port>-<sandbox-id>.<domain>`。
- 相关环境变量：`E2B_API_URL`、`E2B_API_KEY`、`E2B_DOMAIN`、`E2B_SANDBOX_URL`、`E2B_HTTP_VERSION`、`E2B_CONNECTION_RETRIES`。

**原生侧已核对到的事实**：认证头 `OPEN-SANDBOX-API-KEY`；模板模式创建要求 `timeout >= 60`，且拒绝 `env`、`entrypoint`、资源、`volumes` 等覆盖；元数据遵守 Kubernetes label 规则（值不超过 63 字符，`opensandbox.io/` 前缀保留）；Fast Sandbox 的 endpoint 返回 URI 加必需的路由头（`OpenSandbox-Ingress-To`）或带 scope 的 URI，且不支持 `expires`。

**分支和提交**

- 每个 PR 一个分支，从当时的 upstream `main` 切出。fork 的 `main` 可能落后，用 `git fetch https://github.com/opensandbox-group/OpenSandbox main` 取基线。
- 提交信息：`feat(e2b-compat): ...` / `test(e2b-compat): ...` / `docs(e2b-compat): ...`，英文祈使句。
- PR 描述按 `.github/pull_request_template.md` 四段填写，写明所属 Gate 和"这一步证明了什么、没证明什么"。
- **单个 PR 不超过 2000 行（含测试和 fixture）**，超了先拆。

**Go 约定**：参照 `components/ingress` 的做法——独立 `go.mod`（module 路径沿用现有风格 `github.com/alibaba/opensandbox/e2b-compat`，Go 版本与其他组件一致）、`Makefile`、`build.sh`、`.golangci.yml`、`Dockerfile`、`README.md`、`DEVELOPMENT.md`。日志、版本信息等优先复用 `components/internal`。测试用标准库 `testing` 加 `testify`，HTTP 测试用 `httptest`。尽量只用标准库：`net/http`、`net/http/httputil`、`crypto/hmac`、`crypto/subtle`、`encoding/json`。

**每个 PR 必须本地通过**（module 建好之后）

```bash
cd components/e2b-compat && test -z "$(gofmt -l .)" && go build ./... && go vet ./... && go test ./...
```

涉及并发的改动再跑一次 `go test -race ./...`。有 Python 契约测试之后（E5 起）再加：

```bash
cd components/e2b-compat/tests/sdk && uv sync && uv run pytest
```

**硬性规则**（都来自 OSEP 的 Requirements，违反即不合格）

- 不支持的操作和选项在产生任何副作用之前明确失败。不忽略安全相关选项，不伪造元数据，不返回"看起来成功"的响应（R4）。
- 不自动重放任何变更请求。创建结果不明时返回明确的非成功（可送达时带 `Should-Retry: false`），绝不再分配一次。
- 超时值不截断、不四舍五入、不先分配后缩短。
- `envdVersion` 必须是实际运行的 envd 报告的版本，不许为了绕过 SDK 的版本判断而填一个高版本。
- 原生后端凭据、原生路由头、HMAC key 不出现在给客户端的响应、沙箱内部、日志和测试 fixture 里（R5）。
- 路由标识（主机名、ID 头）不等于授权；先校验归属和 token，再去取有特权的原生路由。
- 不改 `specs/`、原生 `server/`、原生 SDK、execd；不引入独立数据库（Gate 1a）。
- 兼容性结论只能写"通过 / 失败 / 未测"，并且要点名被测的版本组合。

## 5. 依赖关系

```text
I1 (Gate 0) ──────────────────────────────────────────────┐ 确认后才向 upstream 提实现 PR
E1 ─► E2 ─► E3 ─► E4 ─► E5                (控制面, Gate 1a)   任意机器
            └───► E6 ─► E7 ─► E8          (数据面, Gate 1a)   任意机器 / Linux
I2 ─► E9 ─► E10 ─► E11                    (真实后端, Gate 1a) 需要 KVM
E5 + E10 ─► E12 ─► E13                    (Gate 1b)
E13 ─► E14 ─► E15 ─► E16 ─► E17 ─► E18 ─► E19   (Gate 2、3)
```

E4 之后控制面和数据面两条线可以并行：E5 与 E6/E7 不改同一批文件。

| 阶段 | PR | 可在普通开发机完成 |
|---|---|---|
| 地基 | E1、E2、E3 | 是 |
| Gate 1a 组件 | E4、E5、E6、E7、E8 | 是（E8 需 Linux/amd64） |
| Gate 1a 证据 | E9、E10、E11 | 否，需要 KVM |
| Gate 1b | E12、E13 | E12 是；E13 的真实后端部分否 |
| Gate 2、3 | E14–E19 | 契约部分是；证据部分否 |

---

## 6. Issue 清单

### I1 Gate 0 tracking issue（最先提）

```text
标题：OSEP-0027 tracking: optional E2B compatibility (Gate 0 target agreement)

OSEP-0027 已合入（#2591），状态 draft。按 OSEP 的 Delivery Gates，实现前需要 Gate 0 的确认。请 maintainer 对下面几项表态，未确认的项我先按"建议"在 fork 上做可行性验证，不向主干提实现 PR。

待确认：
1. 代码位置：建议 components/e2b-compat/，独立 Go module、独立发布，不向原生 server 添加 E2B 路由。
2. 实现语言：Go（与 components/ingress 同类，也与 server 后续的 Go 重构方向一致）。契约测试用被 pin 的 Python SDK 驱动 Go 服务进程。
3. 首个版本组合：e2b==2.62.1（Python 同步客户端）、envd 0.8.0、Linux/amd64 Fast Sandbox。
4. envd 入口：先用固定入口（E2B_SANDBOX_URL + E2b-Sandbox-Id / E2b-Sandbox-Port 头），通配域名方案后置。
5. 可信范围：单一管理范围、一把适配器 API key。
6. 超时上限：沿用原生 server.max_sandbox_timeout_seconds，超出返回 400，不截断。
7. envd-only 模板：见关联 issue（模板构建和无 execd 时的池 readiness）。
8. 框架场景（T6）：征集，不阻塞 Gate 1a。
9. 评审人和发布归属：谁评审控制面，谁评审模板/数据面。

分期（每个 PR 不超过 2000 行）：
- 地基：module 骨架；token 派生、模板映射、超时规则；原生客户端和假后端
- Gate 1a：create/delete 路由；pinned SDK 契约测试；envd 可信初始化；薄路由；真实 envd 开发联调；envd-only 模板；真实后端验证；实验性文档
- Gate 1b：手动 pause、经 connect 恢复
- Gate 2/3：info、set-timeout、list、可观测性、框架场景、发布决策

Gate 1a 的"通过"只指真实 pinned SDK 在真实 Fast Sandbox 上跑通；stub 和 Docker 上的结果只算开发辅助。
```

### I2 envd-only 模板和池 readiness（提给 Fast Sandbox 侧）

```text
标题：fast-sandbox: can an envd-only template reach native READY without execd?

OSEP-0027 的 Gate 1a 需要一个只跑上游 envd 0.8.0（不带 execd）的模板。OSEP 把"无 execd 时能否达到原生聚合 READY"列为第一个集成检查。

想确认：
1. 模板构建器是否支持不注入 execd，并把探针指向 envd 的 49983 端口？需要哪些构建参数？
2. 池的 READY 聚合是否依赖 execd（guest-control、egress/action 绑定等）？有没有隐含耦合？
3. golden rootfs / 内存快照里不能带每实例的 envd 凭据。分配或恢复之后、对外开放之前，有没有一个可信路径能对实例做一次私有初始化（POST /init）？
4. envd 在 Firecracker guest 里需要的启动参数（-isnotfc、-no-cgroups、MMDS 相关）有没有已知结论？
5. 集成环境（scripts/fast-sandbox-env）里加一个 envd-only 模板，对 runner 容量有没有影响？

如果第 1、2 点需要改 fast-sandbox，请告知应该提到哪个仓库和分支。
```

### I3 框架场景征集（Gate 1a 证据出来后再提）

在 #800 下回复并链接 I1，征集一个只依赖基础 SDK（不需要 code interpreter、自动 pause）的真实框架场景，要求给出框架名、版本、配置和完整的 SDK 调用清单。

---

## 7. PR 清单

### E1 `feat(e2b-compat): scaffold the optional E2B compatibility adapter`

- **分支**：`feat/osep0027-scaffold`　**依赖**：无　**规模**：约 600 行
- **目标**：建立独立包、配置模型和 CI，不含任何 E2B 业务逻辑。

改动清单：

1. 新目录 `components/e2b-compat/`：`go.mod`、`main.go`（子命令 `adapter`、`router`，本 PR 里只需能启动并提供健康检查）、`pkg/config/`、`Makefile`、`build.sh`、`.golangci.yml`、`README.md`、`DEVELOPMENT.md`。结构和许可证头照 `components/ingress`。
2. 配置（文件加环境变量覆盖）：兼容前缀（默认 `/compat/e2b`）、适配器 API key 的引用、原生 API 地址和 key 的引用、HMAC key 的引用和 key 版本、模板映射列表、超时默认值 300 和上下限、对外返回的 `domain`、适配器身份（用于 `clientID`）。机密只通过环境变量或文件路径引用进入；配置结构体的 `String()`、`%+v` 输出和日志不得带出其值（给机密字段一个会打码的类型）。
3. 配置校验：缺 HMAC key、缺原生地址、映射重复、前缀不以 `/` 开头或为根路径，启动即失败。
4. HTTP 服务骨架和一个不需要认证的健康检查（挂在兼容前缀之外的管理路径上）。**根级别不注册任何 E2B 路由**。
5. `.github/workflows/e2b-compat-test.yml`：只在 `components/e2b-compat/**` 和 `components/internal/**` 变更时触发，跑 gofmt 检查、build、vet、test。照 `ingress-test.yaml` 的写法，Go 版本与其一致。
6. 如果仓库有许可证头检查（`verify-license.yml`）或路径标签规则（`pr-label-check.yml`、`detect-changes.yml`），把新目录接进去。

- **不做**：任何 E2B 路由；Dockerfile 和 Helm（E11）。
- **测试**：配置解析和每条校验失败；机密不出现在格式化输出里；服务能启动且 `/v2/sandboxes`、`/sandboxes` 在根路径下是 404。

---

### E2 `feat(e2b-compat): token derivation, template mappings and timeout rules`

- **分支**：`feat/osep0027-core-rules`　**依赖**：E1　**规模**：约 900 行
- **目标**：把 OSEP 里所有不依赖网络的规则做成纯函数，并用表驱动测试钉死。

改动清单：

1. **envd token 派生**：`HMAC-SHA256(key, 域分隔串 || 部署标识 || 原生 ID)`，固定编码。域分隔串带用途和版本（例如 `opensandbox-e2b-compat/envd-token/v1`），各段用不会出现在输入里的分隔符拼接。校验用常数时间比较。先读 pinned envd 0.8.0 的源码确认 token 的格式约束（长度、字符集），再定编码。
2. **模板映射**：批准的 E2B 模板 ID 或别名 → 原生 `templateId`、不可变的映射修订号、期望的 envd 版本、资源和超时策略。解析未知、未就绪、与 profile 不符的映射时返回明确错误。别名变更只影响之后的创建，所以创建时要记录"修订号"而不是别名。
3. **元数据编码**：把兼容标记、映射修订号、范围引用编码成原生元数据。键名不能用保留前缀 `opensandbox.io/`，值不超过 63 字符且符合 label 字符集。用户传入的 `metadata` 也要过同一套规则，不可表示的在分配前拒绝，不截断、不改写。解码时对缺失、被篡改、修订号未知的情况返回"不属于本适配器"而不是异常。
4. **超时规则**：按 OSEP "Timeout Semantics" 那张表实现一个纯函数，输入是操作类型和原始 JSON 值（要能区分"字段缺失"和"字段为 null"），输出是生效秒数或一个带原因的拒绝。表里每一行都是一条测试。
5. **创建选项清点**：为创建请求体的每个字段写出 Gate 1a 的处理——接受、接受但仅限默认值、拒绝。建议默认值：`autoPause` / `autoResume` 为真、`autoPauseMemory`、`network`、`mcp`、`iam`、`volumeMounts`、`secure=false`、`allow_internet_access=false` 一律拒绝；`envVars` 非空时是否经 envd 初始化下发，读完 pinned envd 的 `/init` 协议后再定，定不了就拒绝。把这张清点表写进包的 README，它后面会变成兼容矩阵的一部分。

- **不做**：HTTP、原生调用。
- **测试**：每条规则的表驱动测试；token 对同一输入稳定、对不同 ID / 部署标识 / key 不同；元数据的边界长度和非法字符。

---

### E3 `feat(e2b-compat): native lifecycle client and in-memory fake backend`

- **分支**：`feat/osep0027-native-client`　**依赖**：E2　**规模**：约 1200 行
- **目标**：适配器访问原生 API 的唯一出口，以及测试用的假后端。

改动清单：

1. 一个 `NativeLifecycle` 接口和基于 `net/http` 的实现（所有方法带 `context.Context`），覆盖：模板模式创建、get、delete、取 endpoint、patch 元数据；pause、resume、renew-expiration、list 先定义签名，实现可以留到用到它们的 PR。认证头 `OPEN-SANDBOX-API-KEY`。
2. **结果分类**是这个 PR 的核心：每次调用的结果归为"确定成功"、"确定失败（带原生状态码和错误码）"、"结果不明"（超时、连接在发出请求后断开、5xx 且无法判定是否已执行）。变更类调用不重试；只读调用可以有界重试。
3. 原生状态到内部枚举的映射，保留 `Pending`、`Running`、`Pausing`、`Paused`、`Resuming`、`Stopping`、`Terminated`、`Failed` 的区别，不在这一层做 E2B 投影。
4. 假后端：一个 Go 包（`internal/fakenative`），既能在 `httptest` 里进程内启动，也能作为独立进程监听端口（E5 的 Python 套件要用）。实现上述原生路由的子集，带可编程的故障注入——丢失响应（已执行但不回包）、延迟、状态迁移时序、指定请求返回指定错误、到期自动终止；独立进程形态下故障注入通过一个仅本机可达的控制接口设置。它要校验模板模式的原生约束（`timeout >= 60`、拒绝工作负载覆盖），这样适配器的错误映射才有东西可测。

- **不做**：E2B 路由。
- **测试**：每种结果分类至少一条用例，其中"已执行但丢响应"必须验证客户端没有重发；假后端自身的行为测试。
- **开工前核对**：原生创建、endpoint、错误体的实际形状，以 `specs/sandbox-lifecycle.yml` 和 `server/opensandbox_server/api/schema.py` 为准。

---

### E4 `feat(e2b-compat): create and delete lifecycle routes (Gate 1a control plane)`

- **分支**：`feat/osep0027-create-delete`　**依赖**：E3　**规模**：约 1500 行
- **目标**：Gate 1a 的控制面——创建和删除可用，其余五条路由明确拒绝。

改动清单：

1. 在兼容前缀下注册全部七条路由，`/v2` 和非 `/v2` 两族都要在；前缀带不带尾斜杠的配置都要正确。
2. 认证：`X-API-KEY` 常数时间比较。缺失或错误返回 401，不泄露资源是否存在。
3. 带 `Idempotency-Key` 头的请求在任何副作用前拒绝。
4. `POST /v2/sandboxes`：按 E2 的清点表校验 → 解析模板映射 → 计算超时 → 编码元数据 → 原生创建 → 等原生就绪（有界轮询，预算与沙箱 TTL 分开）→ 取 49983 端口的原生 endpoint → 调用"envd 初始化器"接口 → 调用"准入控制"接口开放该实例 → 返回 201。
5. "envd 初始化器"和"准入控制"在本 PR 里只定义接口并提供测试替身，真实实现在 E6、E7。接口要表达清楚顺序约束：初始化确认之前准入保持关闭。
6. 响应体用 pinned 模型的字段名：`sandboxID` 是原生 ID，`templateID`、`clientID`（配置里的适配器身份）、`envdVersion`（初始化器返回的实际版本）、`envdAccessToken`（派生值）、`domain`（配置值）。不返回 `trafficAccessToken`。
7. 失败处理：校验失败 400；映射未知或未就绪按 OSEP 的拒绝语义；原生确定失败映射到对应的 E2B 错误；**结果不明返回 503 加 `Should-Retry: false`，不再分配**；创建成功但后续步骤失败时，发起原生删除并如实返回失败，不留下对外可用的半成品。
8. `DELETE /sandboxes/{id}`：先确认是本适配器创建的对象（元数据解码通过）→ 关闭准入 → 原生删除。按 OSEP 的"两个条件"返回 204：准入已确认关闭，**并且**原生删除成功返回或权威状态确认已终止/不存在。任一条件不明返回 503 加 `Should-Retry: false`；确认不存在返回 404；原生冲突返回 409。
9. 其余五条路由返回明确的"本 profile 不支持"错误，使用 pinned 错误体。状态码先选一个 SDK 会把消息原样抛给用户的（建议 501），用 E5 的真实 SDK 测试确认。
10. 日志：记录操作、结果类别、耗时、安全的关联 ID；不记录 key、token、请求体里的环境变量和元数据。

- **不做**：pause、connect、info、list、set-timeout 的实现；真实 envd；真实路由。
- **测试**（对假后端，用原始 HTTP）：两族路由和尾斜杠；根路径下没有 E2B 路由；每个被拒绝的选项都在原生创建之前失败（断言假后端没收到创建请求）；创建的每种失败路径；删除的两条件矩阵；重复删除；丢响应时不重放。

---

### E5 `test(e2b-compat): pinned E2B SDK contract suite`

- **分支**：`test/osep0027-sdk-contract`　**依赖**：E4　**规模**：约 1200 行
- **目标**：用**真实的** `e2b==2.62.1` 驱动适配器，覆盖 OSEP T1、T2 的 Gate 1a 部分。这是控制面契约的主要证据。

改动清单：

1. 新目录 `components/e2b-compat/tests/sdk/`：一个只用于测试的 Python 项目（`pyproject.toml`、`uv.lock`），锁定 `e2b==2.62.1` 及其传递依赖，记录 Python 版本。它不是发布物。
2. 一个 Go 的开发栈命令（例如 `go run ./cmd/devstack`）：在本机端口上启动适配器、假后端和一个最小的假 envd（只需要让初始化和 SDK 创建后的首次握手通过），把各自的地址和故障注入控制接口打印成一行 JSON。Python 夹具负责构建并启动它、读取地址、测试结束后终止进程。环境变量：`E2B_API_URL` 指向带前缀的适配器地址、`E2B_HTTP_VERSION=1.1`、`E2B_CONNECTION_RETRIES=0`、`E2B_SANDBOX_URL` 指向假 envd。
3. 用例（T2 的 1a 子集）：不传超时时生效值是 300；超时 0、1、59 被拒绝，60 被接受，超上限被拒绝且不截断；`Sandbox.kill()` 的成功、重复删除、不存在；错误的 API key；被拒绝的选项在 SDK 侧表现为明确异常且消息可读；pause、connect、list、set_timeout、get_info 在 SDK 侧抛出明确的不支持错误。
4. 原始 JSON `null`、布尔、小数、字符串形式的超时 SDK 发不出来，这几条用原始 HTTP 测。
5. 把每类请求和响应固化为 golden fixture（去掉 token 和 key），Go 侧的路由测试也读同一份 fixture，这样两种语言的测试钉的是同一个契约。
6. `e2b-compat-test.yml` 增加一个 job：装 Go 和 uv，跑这套 Python 契约测试。

- **不做**：不 fork、不 monkeypatch SDK。SDK 行为与 OSEP 描述不一致时，记录差异并停下来报告，不要改 SDK 去迁就。
- **PR 描述必须写明**：这是对假后端的契约证据，不是 Gate 1a 验收。

---

### E6 `feat(e2b-compat): trusted envd initialization and authenticated readiness`

- **分支**：`feat/osep0027-envd-init`　**依赖**：E3（可与 E5 并行）　**规模**：约 1000 行
- **目标**：实现 E4 里的"envd 初始化器"。

**开工第一步**：从 e2b-dev/runtime 的 pin 提交（OSEP 给出的是 `f32ee8a2a50052f32e3632ceb451111a98dd5104`）读 envd 的 `/init`、`/health`、版本上报和认证中间件，把请求体字段、首次初始化与重复初始化的规则、未设 token 时的行为写进 PR 描述。OSEP 指出：首次初始化不需要 token；已知旧 token 不能随意换成新 token；存在"未设 token 即放行"的路径。

改动清单：

1. 初始化器：经原生 endpoint（URI 加必需的原生头）对该实例的 49983 端口执行私有 `POST /init`，写入派生的 token；随后用该 token 做一次**需要认证**的探测，并读取实际 envd 版本。只有"带 token 的请求成功"才算就绪，端口在听或 `/health` 返回 200 不算。
2. 版本与模板映射里期望的 envd 版本不一致时判定失败。
3. 结果分类同 E3：确定成功、确定失败、不明。不明时不重试初始化，交给 E4 的清理路径。
4. 一个忠实于 pinned 协议的假 envd（Go 包 `internal/fakeenvd`，供 E5 的开发栈和 E7 复用）：首次初始化无需 token；初始化后其余接口要求 `X-Access-Token`；用不同 token 重复初始化被拒；可模拟"重启后丢失认证状态"。

- **不做**：Gate 1b 的恢复路径（恢复时不得重跑首次初始化，留到 E12）。
- **测试**：正常初始化；token 不匹配；版本不符；初始化丢响应；重启后丢失认证状态时准入保持关闭；两个实例从同一模板分配，token 互不相同且互不可用。

---

### E7 `feat(e2b-compat): thin envd routing with token admission`

- **分支**：`feat/osep0027-envd-router`　**依赖**：E6　**规模**：约 1500 行
- **目标**：数据面薄路由和 E4 里的"准入控制"。SDK 的命令和文件请求原样到达 envd。

改动清单：

1. `router` 子命令，可与适配器分开部署，基于 `net/http/httputil.ReverseProxy`。固定入口形式：从 `E2b-Sandbox-Id` 和 `E2b-Sandbox-Port` 头取目标。主机名形式（`<port>-<id>.<domain>`）的解析一并实现，两种形式同时出现且不一致时拒绝。
2. 准入检查，全部通过才转发，顺序不能变：端口必须是 49983 → ID 对应的原生对象存在、是本适配器创建的、状态为运行且已通过初始化 → `X-Access-Token` 等于对该 ID 重新派生的值（常数时间）→ 这时才去取原生 endpoint。
3. 转发：保留方法、路径、查询串、请求体和响应体，流式透传（`FlushInterval` 设为立即刷新，不缓冲整个 body），不重试，传输层关闭自动重试和连接级重放。剥掉客户端带来的原生路由头（`OpenSandbox-Ingress-To` 等），再加上原生 endpoint 要求的头。上游地址只能来自原生 endpoint 的解析结果，任何客户端输入都不能影响它。
4. 管理类路径（`/init`、`/upgrade` 等，以 pinned envd 的路由表为准）经客户端入口一律拒绝。
5. 原生 endpoint 和状态可以短时缓存，但删除、准入关闭要立即使缓存失效。缓存过期、后端不可用、状态不明时拒绝，不放行。
6. 不做 RPC 级别的功能白名单。OSEP 明确：未测试的 envd 方法不等于被禁用，不要对外宣称它们被移除了。
7. 实现 E4 的"准入控制"接口：开放、关闭、查询某实例的准入状态；关闭后新请求立即被拒。已建立的流如何收敛要实测并写进文档，不做"立即断开"的承诺。

- **不做**：协议翻译；签名文件 URL；任意端口暴露；TLS 终止（由运维的入口负责）。
- **测试**（对假 envd）：缺 token、错 token、别的实例的 token；ID 与主机名冲突；非 49983 端口；客户端伪造原生路由头；管理路径；服务端流式响应逐块到达；二进制大文件上传下载字节一致；客户端中途断开后上游连接被释放；删除后新请求被拒；后端不可用时拒绝。

---

### E8 `test(e2b-compat): development loop against the real pinned envd`

- **分支**：`test/osep0027-real-envd-dev-loop`　**依赖**：E5、E7　**规模**：约 800 行
- **目标**：在没有 Fast Sandbox 的情况下，用**真实 envd 二进制**跑通 SDK 全链路，提前暴露协议和流式问题。OSEP 把这类检查定性为开发辅助。

改动清单：

1. 一个脚本按 pin 取 envd 0.8.0 的 Linux/amd64 二进制，校验 SHA-256（校验和写死在仓库里），失败即退出。二进制本身不进仓库。
2. 开发栈命令增加一个模式：本机启动真实 envd（按 pinned 版本支持的参数，OSEP 提到 `-isnotfc`、`-no-cgroups`，以实际帮助输出为准），假后端把 49983 的 endpoint 指向它。
3. 用例（放在 E5 的 Python 套件里，单独打标记）：`Sandbox.create()` → 前台命令的 stdout、stderr、非零退出码、命令超时 → 文本和二进制文件写入读取、覆盖、读不存在的路径 → `kill()`。全部走适配器和路由。
4. 测试打上标记，默认不在常规 CI 里跑；提供一个手动触发的 workflow。

- **PR 描述必须写明**：不是 Gate 1a 验收；Linux/amd64 以外的环境 NOT_RUN。
- **需要的环境**：Linux/amd64，且允许启动 envd 进程。

---

### E9 `feat(fast-sandbox-env): envd-only template recipe`

- **分支**：`feat/osep0027-envd-only-template`　**依赖**：I2 的答复　**需要 KVM**
- **目标**：在集成环境里构建一个只含上游 envd 的模板，并证明它能达到原生 READY。这是 Gate 1a 的第一个集成检查。

改动清单（细节取决于 I2 的答复，先读 `docs/guides/oci-templates.md` 和 `scripts/fast-sandbox-env/` 现有的模板构建流程）：

1. 模板镜像定义：基础镜像、按校验和取得的 envd 二进制、启动方式、运行用户、可写路径、指向 49983 的探针。
2. 记录来源：envd 的 release、提交、校验和、许可证，镜像摘要。
3. `integration-env.sh` 增加可选的 envd-only 模板构建和发布步骤，默认关闭。
4. 一个验证阶段：池达到 READY；从模板分配实例后 49983 可经原生 endpoint 到达；golden 产物里不含任何 envd 凭据（分配两个实例，初始化前都处于未设 token 状态）。

- **如果达不到 READY**：停下来，把观察到的耦合点写清楚，回到 I2，不要用"同时注入 execd"绕过。OSEP 明确这种耦合需要单独的范围决定。

---

### E10 `test(fast-sandbox-env): Gate 1a verification stage for E2B compatibility`

- **分支**：`test/osep0027-gate1a-verify`　**依赖**：E5、E7、E9　**需要 KVM**
- **目标**：Gate 1a 的验收证据。

改动清单：

1. 在集成环境里部署适配器和路由（先用最简单的方式，例如同机进程或一个 Deployment），配置指向环境里的原生 server。
2. 新增 `scripts/fast-sandbox-env/verify/e2b-compat.sh`，注册为可选阶段。用锁定的 SDK 跑：创建 → 命令/文件往返 → 删除。
3. T3（真实 envd 经真实路由）、T4（两个实例互不共享凭据；错 token、别的实例的 token、缺 token；直连后端和 guest 内 localhost 绕过）、T5 的 1a 子集（适配器重启、原生侧直接删除、到期、创建丢响应后的回收）。
4. 输出证据文件：完整的版本组合（SDK、envd、OpenSandbox 提交、Fast Sandbox 提交、内核和 Firecracker 版本、模板摘要）、每条用例的通过/失败/未测、观察到的收敛时间。
5. `fast-sandbox-test.yml` 增加一个可选运行，触发策略请 maintainer 定。

---

### E11 `docs(e2b-compat): experimental deployment recipe and compatibility matrix`

- **分支**：`docs/osep0027-experimental-guide`　**依赖**：E10
- `docs/guides/e2b-compatibility.md`：部署方式、客户端要设的环境变量、运维需要自备的 DNS/TLS 前提、已知限制。
- 兼容矩阵：按操作列出通过/失败/未测，点名被测组合，链接 E10 的证据。
- 容器镜像或启动方式的最小打包（如果 E10 里已经做了就只补文档）。
- OSEP 文档补一段 Gate 1a 的结果记录。状态是否从 `draft` 改动由 maintainer 决定，本 PR 不改。

---

### E12 `feat(e2b-compat): manual pause and resume through connect (Gate 1b)`

- **分支**：`feat/osep0027-pause-connect`　**依赖**：E5、E7；真实后端部分依赖 E10　**规模**：约 1800 行，超了就把 pause 和 connect 拆成两个 PR
- **目标**：`pause()` 和经 `connect()` 的全状态恢复，按 OSEP "Manual Pause and Full-State Resume" 的两张表实现。

要点：

1. `POST /sandboxes/{id}/pause`：只接受省略 `memory` 或 `memory=true`。先关闭准入并结束传输流，再提交原生 pause，轮询到 `Paused`，然后才返回 204。已经是 `Paused` 返回 409（SDK 把任何 409 都当成"已暂停"并返回 `False`，所以**其他冲突一律不能用 409**，要用 503 加 `Should-Retry: false`）。
2. `POST /v2/sandboxes/{id}/connect`：运行中的实例返回 200，只延长不缩短 TTL；暂停的实例先校验未过期，按"本次恢复尝试开始时刻"算出一个绝对截止时间并续期，再提交原生 resume，等到 `Running`、envd **用原有 token** 认证通过、重新解析出新的原生 endpoint 之后，返回 201。过渡态返回 409，失败或不明返回 503。
3. 恢复时**不得**重跑首次 `/init`，不得生成新 token，不得用"重新创建一个"顶替。检查点缺失、身份不符、认证状态丢失都判失败。
4. 续期成功但恢复失败这类部分结果要如实记录并在下次请求时对账，不假设两步都回滚了。
5. 如果发现原生状态不足以恢复某个未完成的操作，在 PR 描述里具体说明缺什么，再决定是否引入最小的持久化；不预先建通用的状态表。

- **测试**：假后端的状态机覆盖两张表的每一行；丢响应、适配器重启、原生侧并发变更、暂停期间到期。

---

### E13 `test(e2b-compat): Gate 1b SDK contract and real-backend verification`

- **依赖**：E12、E10　**真实后端部分需要 KVM**
- SDK 契约：`pause()` 返回 `True` / `False` 的两种情况、`connect()` 的 200 和 201、过期后的 connect。
- 真实后端（T7）：暂停前启动的进程和内存中的状态在恢复后仍在；可写文件连续；ID 不变；旧路由被拒绝；在另一个节点上恢复；暂停期间到期后不可复活。

---

### E14 `feat(e2b-compat): sandbox info with state projection`

- **依赖**：E13　`GET /sandboxes/{id}`。按 OSEP "SDK-visible State and Cleanup" 的投影表实现；pinned `SandboxDetail` 的必填字段（`startedAt`、`endAt`、`cpuCount`、`memoryMB`、`diskSizeMB`、`state` 等）必须来自权威数据，给不出来就不启用这个操作，不编造。

### E15 `feat(e2b-compat): positive set-timeout`

- **依赖**：E14　`POST /sandboxes/{id}/timeout` 的正值：一次性换算成绝对截止时间后续期，可缩短可延长。零值继续明确拒绝，除非先证明了 OSEP 的"两个条件"删除语义；负值 400。

### E16 `feat(e2b-compat): sandbox list`

- **依赖**：E14　`GET /v2/sandboxes`。用原生 list 加兼容元数据过滤，不建第二份清单。先定义支持的过滤器、有界枚举和翻页行为再实现；范围内只要有一个实例状态失败或不明，整个 list 返回 503，不返回看似完整的部分结果；后端不可用与实例失败要能在错误消息里区分。

### E17 `feat(e2b-compat): observability and operational behavior`

- 有界基数的指标（操作、结果类别、延迟、版本组合），不含实例 ID、key、token、命令和文件内容；适配器 readiness 依赖原生可达和受保护配置就绪；关停时处理在途请求和准入。

### E18 `docs(examples): pinned framework workflow on the E2B compatibility profile`

- **依赖**：I3 选定场景、E16　`examples/` 下一个可运行的例子，经框架的正常集成方式和文档化的配置跑通，不 fork、不 monkeypatch SDK（T6）。场景需要的任何操作不在支持范围内，就不能宣称该场景可用。

### E19 `docs(osep): record OSEP-0027 evidence and release decision inputs`

- 版本矩阵、升级和回滚步骤（含 HMAC key 变更时的排空/重建策略）、各部分的责任人、弃用策略。把 Gate 2 的证据汇总进 OSEP，供 maintainer 做 Gate 3 决定。状态变更由 maintainer 执行。

---

## 8. 风险和需要人工判断的点

| 风险 | 影响 | 处理 |
|---|---|---|
| Gate 0 未确认就提实现 PR | 位置或语言被否，返工 | 先提 I1；确认前只在 fork 上推进 |
| envd-only 模板达不到原生 READY | Gate 1a 整体卡住 | I2 尽早问；E9 失败时停下，不用双注入绕过 |
| 没有 KVM 环境 | E9、E10、E13 的证据出不来 | 用 upstream 的自托管 runner 或阿里环境；前半段先做完 |
| SDK 把 `E2B_SANDBOX_URL` 和 `E2B_API_URL` 标为 deprecated | 升级 SDK 时固定入口方案可能失效 | 兼容矩阵里写明；通配域名方案作为后续项 |
| envd 首次初始化无需 token | 初始化前若被不可信方抢先，实例被接管 | E6、E7 的顺序约束和测试；E10 在真实后端上验证竞态 |
| 契约测试跨语言（Go 服务、Python SDK 套件） | CI 和本地环境要同时有 Go 和 uv；夹具启动失败容易被误读成契约失败 | E5 的夹具对"开发栈没起来"和"用例失败"给出不同的错误；golden fixture 两边共用 |
| 兼容性被过度宣称 | 用户误以为完整兼容 | 每个 PR 和文档只写被测组合的通过/失败/未测 |
