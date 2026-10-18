# Third-Party Notices

本文件记录 SecMind v0.7 正式运行、构建和容器部署所使用的第三方组件类别。
完整传递依赖及许可证应以 `uv.lock`、最终容器镜像和交付时生成的 SBOM 为准。

## Python 运行时依赖

| 组件 | 版本约束 | 用途 |
|---|---|---|
| Alembic | `>=1.14,<2` | 数据库迁移 |
| Bandit | `>=1.7.10,<2` | Python 静态安全扫描 |
| cryptography | `>=48.0.1,<49` | 签名与密码学边界 |
| Docker SDK | `>=7.1,<8` | 受控 Runner 执行适配 |
| FastAPI / Uvicorn | `>=0.115,<1` / `>=0.34,<1` | HTTP、WebSocket 与 ASGI 服务 |
| HTTPX | `>=0.27,<1` | 受控异步 HTTP 客户端 |
| jsonschema | `>=4.23,<5` | Draft 2020-12 Schema 校验 |
| LangGraph | `>=0.4,<2` | 有界状态图编排 |
| langgraph-checkpoint-postgres | `>=2.0,<4` | PostgreSQL Checkpoint |
| Pydantic / pydantic-settings | `>=2.10,<3` / `>=2.7,<3` | 强类型契约与配置 |
| prometheus-client | `>=0.21,<1` | 运行指标 |
| psycopg | `>=3.2,<4` | PostgreSQL 驱动与连接池 |
| python-multipart | `>=0.0.18,<1` | 文件上传 |
| PyYAML | `>=6.0.2,<7` | Manifest 与配置解析 |
| SQLAlchemy | `>=2.0,<3` | 持久化与事务单元 |
| Tenacity | `>=9,<10` | 有界重试 |

构建后端为 Hatchling，依赖解析与容器构建使用 uv。

## 容器基础镜像

仓库直接引用 `python:3.11-slim`、`python:3.11-slim-bookworm`、
`busybox:1.37.0-musl` 和 `postgres:16-alpine`。比赛部署中的安全工具镜像必须固定
digest，并随提交包保留相应许可证、SBOM 和规则/数据库版本信息。

## 设计来源边界

SecMind 未复制、移植或改编 OMO / oh-my-openagent 源代码。该项目仅作为架构研究材料，
不是运行依赖、子模块、构建输入或发布物组成部分：

```text
OMO SUL copied_files = []
```

详细说明见 [DESIGN_INSPIRATIONS.md](DESIGN_INSPIRATIONS.md)、
[OMO provenance manifest](docs/provenance/omo.yaml) 和
[ADR-0601](docs/adr/ADR-0601-omo-inspired-independent-cognition.md)。

## 外部安全 Skill 元数据目录

SecMind 包含从 `mukul975/Anthropic-Cybersecurity-Skills` 固定提交
`673da1f3b0b7be34ffc9624ef3858fe45f1c3bed` 派生的 273 张元数据卡，许可为 Apache-2.0。
仓库不包含或执行其脚本、references、assets 和命令正文。逐卡来源路径、SHA-256、修改说明
和许可证副本见
[`third_party/mukul975-anthropic-cybersecurity-skills`](third_party/mukul975-anthropic-cybersecurity-skills)。
