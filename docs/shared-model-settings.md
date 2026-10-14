# 平台与渗透 Worker 的统一配置

在「模型配置与用量 → 连接与模型配置」保存服务地址、Worker 模型和 API Key。
统一平台将配置写入 `an/data/model-runtime.json`；渗透调度器通过
`security-runtime/dispatch.local.yaml` 的 `shared_model_config` 读取同一个文件。
路径相对于调度配置文件解析，也可填写绝对路径。

渗透 Worker 保持 `claudecode` 类型，CLI 适配器没有变更。
调度器将 Worker 模型和密钥分别传给 `ANTHROPIC_MODEL` 与 `ANTHROPIC_AUTH_TOKEN`。
服务地址末尾的 `/v1` 会去除，因为 Claude Code 自己追加 `/v1/messages`。
网关必须同时支持平台使用的 OpenAI 接口和 Worker 使用的 Anthropic Messages 接口；
统一配置不提供协议转换。页面原有的连接测试仅验证 OpenAI 接口。

调度器每轮派发前读取最新文件（本地默认每 3 秒），新步骤使用新配置，运行中的步骤保留原配置。
文件缺失、格式错误或密钥清空时暂停新派发并记录错误，不回退到旧 `.env` 或本机凭据。
修复并保存后自动恢复派发。启动脚本不再导入独立的模型 `.env`。

SecMind 独立分析引擎仍使用自己的配置（不读 `model-runtime.json`）；外部引擎用量未接入平台的用量账本。
**注意**：SecMind 实际以 Docker Compose 运行（`secmind/docker-compose.yml`），其 `api` / `worker` 服务的模型参数取自 `secmind/.env`。在「模型与配置」页改动共享网关后，若要让 SecMind 同步，需同时更新 `secmind/.env` 的 `SECMIND_QWEN_BASE_URL`、`SECMIND_TRUSTED_MODEL_BASE_URLS`、`SECMIND_QWEN_API_KEY`、`SECMIND_DEEPSEEK_API_KEY`，并执行 `docker compose up -d --no-deps --force-recreate api worker` 重建容器才生效。另需注意 `secmind/启动在线.ps1` 会用同名环境变量覆盖 `.env`，非容器方式启动时同样要同步该脚本。
已有历史任务中的 Worker 名称保持原样，不修改历史执行记录。
