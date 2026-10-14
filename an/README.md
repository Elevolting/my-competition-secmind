# 安全任务平台

本仓库包含统一安全任务工作台、FastAPI 后端、代码审计与应急响应能力，以及对外部
逆向/日志分析/渗透黑板服务的适配器。所有模块仅用于已授权的本地测试环境。

2026-10-01：代码审计支持每任务 `analysis_backend=auto|local|secmind`。auto 在演示模式使用本地规则，在在线模式接入独立 SecMind。上传材料保留相对路径，外部任务 ID 会持久化，重启后继续轮询；外部审批通过统一工作台回传。远程未完成、超时或降级时保留 partial 状态及已有证据，不能当作完整分析。日志使用 `logs_ir_hunting` 领域；逆向使用 `forensics_static_reverse` 领域。

统一平台的模型设置和用量只覆盖本平台。SecMind 与 Dispatcher 的模型配置、预算和用量独立；本页配置不会自动同步过去。SecMind 启用操作员认证时，在本平台配置 `SECURITY_AGENT_SECMIND_OPERATOR_TOKEN`，不要复用模型 API Key。

## 组件、端口与连接关系

| 组件 | Windows 本地开发 | Docker Compose | 用途 |
| --- | ---: | ---: | --- |
| 前端工作台 | `127.0.0.1:5173` | `127.0.0.1:5173` | Vite/Nginx 页面 |
| 统一 API | `127.0.0.1:8001` | `127.0.0.1:8000` | REST、WebSocket、任务编排 |
| SecMind 分析模块 | `127.0.0.1:8002` | 外部配置 | `/health/ready`，代码审计、日志与逆向 |
| 渗透/黑板外部模块 | `127.0.0.1:8000`（独立运行时） | 建议映射宿主机 `8011` | `/projects` 与黑板任务接口 |
| PostgreSQL | 不启用 | Compose 内部 `5432` | 持久化数据库 |
| Qdrant | 不启用 | Compose 内部 `6333` | 可选向量检索 |

本地开发时统一 API 使用 `8001`，因此可将独立黑板服务保持在 `8000`。Docker 模式的统一 API
占用宿主机 `8000`，此时需要把外部黑板服务映射到其他宿主端口，并设置对应的
`SECURITY_AGENT_PENETRATION_BASE_URL`。

## 目录与配置文件

- `src/security_agent/`：后端、任务编排、经验库和外部模块适配器。
- `frontend/`：统一工作台前端；`frontend/Dockerfile` 用于 Nginx 镜像。
- `config/`、`examples/`：运行配置和示例任务。
- `docker-compose.yml`、`Dockerfile`：前端、API、PostgreSQL、Qdrant 编排。
- `.env.example`：完整环境变量模板；本机复制为 `.env` 后修改。
- `security-runtime` 的独立实现通过 `SECURITY_AGENT_PENETRATION_BASE_URL` 接入，目标仓库的
  `codex/security_runtime-worker-full` 分支保存对应外部运行时改动。

`.env`、真实 API Key、`data/`、SQLite 数据库和 Python `.venv/` 不会提交。本分支按交付要求
包含当前 `frontend/node_modules/` 依赖快照（约 167 MB）；其他环境仍建议执行 `npm ci` 重新生成，
以便获得与 `package-lock.json` 一致的依赖。

## Test3.0 单题评测闭环

工作台支持两种运行方式：普通上传只生成安全分析报告；Test3.0 基准模式从服务端已注册的
S-Suite 题目中选择输入，并在 Agent 完成后异步调用独立评分器。浏览器只收到单题得分、
评分分量和脱敏 Markdown 报告，不会收到私有 Gold、私有目录或评分器日志。单题结果明确标记为
临时结果，不能当作 Full60 正式综合分。

本地接入可在 `.env` 中设置：

```dotenv
SECURITY_AGENT_EVALUATION_ROOT=./data/evaluations
SECURITY_AGENT_BENCHMARK_DATASET_ROOT=C:/path/to/01_候选可见题目/S-Suite_安全赛道/公开题目
SECURITY_AGENT_BENCHMARK_PRIVATE_ROOT=C:/path/to/private-gold
SECURITY_AGENT_BENCHMARK_SCORER_ROOT=C:/path/to/isolated-scorer
SECURITY_AGENT_BENCHMARK_PYTHON_EXECUTABLE=C:/path/to/scorer-venv/Scripts/python.exe
```

生产部署应把公开题库与私有评分端分开挂载；当前 Docker Compose 只透传配置，不会把宿主机
评分器工作树自动打包进 API 镜像。

`SECURITY_AGENT_BENCHMARK_DATASET_ROOT` 必须直接指向 S-Suite 的“公开题目”目录；不要指向同时包含
私有答案或 O-Suite 的发布包总目录。后端发现多个 S-Suite manifest 或目录配置错误时会安全拒绝注册。

本项目是面向“具备自主决策能力的通用网络安全智能体”赛题的 Agent 核心。当前版本完成第一条可运行基线：安全接收代码输入，使用监督式 LangGraph 规划并调用 Bandit，生成带证据引用的报告，同时将决策写入可验证的哈希链账本。

## 已实现能力

- LangGraph 监督式状态图：输入、分类、规划、校验、Guardrail、执行、分析、验证、报告和记忆门禁。
- R0-R3 分级自治与 `interrupt()` 人工审批恢复。
- 兼容模型网关：结构化输出、超时重试、熔断、主备路由和确定性降级。
- 工具注册协议与 Bandit 适配器；工具参数被限制在任务工作区内。
- ZIP 路径穿越、软链接、数量、大小和压缩比检查。
- SQLite/PostgreSQL 运行快照、append-only 哈希账本、JSONL 导出和 WebSocket 事件。
- FastAPI 上传、任务、状态、报告、审批、账本和 WebSocket API。
- Docker Compose：API、PostgreSQL、Qdrant；API 使用非 root、只读文件系统和移除 Linux capabilities。

## 虚拟环境与本地运行

Python 依赖由 `uv` 管理，首次同步会在项目根目录创建被 Git 忽略的 `.venv`；前端依赖由
`npm ci` 安装到被忽略的 `frontend/node_modules`。不要手工复制虚拟环境到仓库。

```powershell
uv sync --all-extras
Copy-Item .env.example .env
uv run security-agent-api
```

默认 `SECURITY_AGENT_DEMO_MODE=true`，不需要模型密钥。本地 API 默认监听 `http://127.0.0.1:8001`，访问 `http://127.0.0.1:8001/docs` 查看接口。

### 应急响应

安全运营菜单中的“应急响应”已内置于 API，不需要另行启动独立服务。监测由操作人开启，重启 API 不会自动开始。页面包含本地主机采集、隔离/恢复和受审批的防火墙操作；这些是实际本机操作，不能当作模拟器。普通日志分析任务走只读分析引擎，不会触发主机处置。

将待审计文件上传：

```powershell
curl.exe -F "file=@sample.py" http://127.0.0.1:8001/api/v1/uploads
```

把返回的 `ref` 放入任务：

```json
{
  "objective": "审计上传的 Python 代码并生成安全报告",
  "attachments": [{"ref": "上传接口返回的 ref"}],
  "target_scope": ["uploaded-source"],
  "constraints": ["只允许静态只读分析"],
  "expected_outputs": ["security_report"],
  "autonomy_policy": "graded"
}
```

提交到 `POST /api/v1/tasks`，再使用返回的 `run_id` 查询 `/api/v1/runs/{run_id}`、报告和账本。

## 前端

业务前端使用 `5173` 端口，后端 API 本地使用 `8001` 端口：

```powershell
Set-Location frontend
npm ci
npm run dev
```

访问 `http://127.0.0.1:5173`。Vite 默认把 REST 和 WebSocket 请求代理到 `127.0.0.1:8001`。

### 启动外部模块

外部模块在独立目录运行，统一 API 只通过配置的 HTTP 地址访问：

```powershell
# 黑板/渗透服务（Security Runtime worker）
Set-Location C:\kaifa\tool\security-runtime
uv sync --project security_runtime
docker compose -f docker-compose.yaml up -d
# 独立运行时默认地址为 http://127.0.0.1:8000

# 逆向服务（如已部署）
# 将其健康地址配置为 http://127.0.0.1:8002
```

然后在统一平台的 `.env` 中设置：

```dotenv
SECURITY_AGENT_REVERSE_BASE_URL=http://127.0.0.1:8002
SECURITY_AGENT_PENETRATION_BASE_URL=http://127.0.0.1:8000
```

若统一 API 使用 Docker Compose（宿主机 `8000` 已被占用），请将 Security Runtime compose 的端口映射
改为例如 `8011:8000`，并将上面的渗透地址改为 `http://127.0.0.1:8011`。

## Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

生产环境必须覆盖 `POSTGRES_PASSWORD`，并通过 Secret 管理 `SECURITY_AGENT_MODEL_API_KEY`。具体模型 ID 和网关 Base URL 均为部署配置，不写死在业务代码中。

## 安全边界

当前唯一启用的执行工具是只读、幂等的 Bandit。它由 Tool Broker 调用，LLM 无法直接执行命令。Compose 把整个 API 置于受限容器中；未来接入 R2/R3 工具时，仍需为单次工具执行增加独立的临时容器运行器，不能仅依赖 API 容器隔离。

系统不记录隐藏思维链。审计依据由结构化决策摘要、策略编号、模型/Prompt 版本、工具版本、证据和内容哈希组成。

## 文档

- [架构与状态图](docs/architecture.md)
- [接口契约](docs/contracts.md)
- [后续 Agent 工作包](docs/work-packages.md)
- [部署、环境变量与首次启动](DEPLOYMENT.md)

