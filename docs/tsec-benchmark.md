# TSec Challenges API 接入

统一平台已提供 TSec API 适配层、Python 异步客户端，以及桌面/命令行批量工具。批量工具负责启动容器、提交用户提供的答案和关闭容器，不调用解题 Agent 或扣分提示。

## 全自动闭环（`tsec-auto.cmd`）

`tsec-auto.cmd` 把「启动容器 → 创建本地解题任务 → 提取 flag → 提交 → 释放容器」串成一条流水线，答案不再需要手工准备。它复用批量工具的平台客户端，并通过本地工作台 API（默认 `http://127.0.0.1:8001`）创建任务，因此需要本地平台服务在运行。

```powershell
.\tsec-auto.cmd list
.\tsec-auto.cmd run c-01 c-02
.\tsec-auto.cmd --output auto-results.json run          # 省略编号即处理全部未通关题目
```

每道题的流程与安全约束：

1. 启动容器并轮询 `container_status`，直到 `available` 且拿到入口地址；超时按 `--start-timeout`（默认 180 秒）。
2. 用入口地址生成任务目标与授权范围，调用 `POST /api/v1/tasks` 创建本地渗透任务，`name` 为 `TSec-<题目编号>`。
3. 轮询该任务到终态（默认 `--solve-timeout` 660 秒），再从报告的 `verified_outputs`、已确认 finding/evidence 和渗透图谱节点里提取 `flag{...}` 形式的值。
4. 逐个提交去重后的 flag，以平台回执为准；`incorrect`、`duplicate` 都如实记录。
5. 题目被平台判定为全部通关后自动关闭容器释放槽位；未通关的容器保留，便于人工续做（`--keep-completed` 可关闭自动释放）。

关键约束：不调用会扣分的 hint 接口；网络超时等不确定的请求不自动重试；同一时间最多 3 个容器，超出的题目记为 `not_attempted` 并在结果中提示；只有平台回执（`is_completed`）能判定通关，本地报告不作数。

结果状态：`completed`（平台确认全部通关）、`incomplete`（已有正确 flag 但未通关）、`no_flag`（本地解题未产出 flag）、`error`（鉴权、任务状态或本地任务创建失败）、`not_attempted`（容量不足或未启动）。进程退出码在出现 `error`/`incomplete`/`no_flag`/`not_attempted` 时为 1。

自动化无法凭空解题：题目本身仍由本地渗透 Agent 攻破，容器入口必须能通过靶场 VPN 访问。默认 `--autonomy-policy automatic` 让受限 R2 适配器无需逐步审批；改成 `graded` 则会在审批节点暂停，需要人工批准后才继续。

## 批量工具（手动提交）

双击套件根目录的 `TSec批量工具.cmd`。程序读取现有 `an/.env` 中的评测配置，不依赖本地 API 服务。

1. 点击“刷新题目”，按 Ctrl / Shift 多选题目，然后点“启动所选”。入口地址在列表和结果区显示。
2. 得到答案后，在答案框填写 JSON 或点击“导入 JSON”。一个题目可填一个字符串或多个 Flag 的数组。
3. 点击“批量提交 Flag”，逐项查看 `correct`（正确）、`incorrect`（错误）、`duplicate`（已提交）及平台得分回执。
4. 可勾选“提交后关闭已全部通关的题目”，或选择题目后点“关闭所选”释放资源。

```json
{
  "c-01": ["实际 Flag 1", "实际 Flag 2"],
  "c-02": "实际 Flag"
}
```

题目容器**最多同时 3 个**。超过剩余容量会在启动前拒绝整批，请分批操作；程序不会关闭正在使用的容器来腾位置。pending、available、stop_pending 均占用容量，已有容器不会重复启动，已通关题目跳过启动/提交。

网络超时后启动或提交可能已在平台生效：程序不会自动重试，停止剩余批次并保留已得到的回执。刷新平台进度后再决定是否重试。批量提交前会校验整个 JSON 和全部题目编号；同批相同 Flag 去重。可导出本次结果 JSON，回执不重复记录提交的 Flag。

也可以在套件目录使用命令行：

```powershell
.\tsec-batch.cmd list
.\tsec-batch.cmd start c-01 c-02
# 将 tsec-answers.example.json 复制为 answers.json 并填入实际答案。
# 全局参数 --output 放在子命令 submit 前。
.\tsec-batch.cmd --output results.json submit answers.json --close-completed
.\tsec-batch.cmd close c-01 c-02
```

命令行相对文件路径基于当前工作目录，配置固定读取套件的 `an/.env`。部分错误、错误答案或未执行项使退出码为 1，重复正确提交不视为失败。桌面退出不会关闭题目，请先按需释放容器。

## 配置

平台下发配置后，在 `an/.env` 中填写（字段名与平台文档一致）：

```dotenv
BENCHMARK_BASE_URL=https://平台提供的地址
BENCHMARK_TOKEN=平台提供的Token
```

BASE_URL 填平台根地址，不要重复添加 `/openapi/v1/challenges`。修改配置后重启统一平台 API。连接平台下发的靶场 VPN 后，才能访问题目返回的 `container_addr`。接口连通不代表靶场 VPN 连通。

尚未配置时，普通项目功能正常工作；调用评测接口返回 503 `not_configured`。

## 本地接口

默认服务地址为 `http://127.0.0.1:8001`，在 `/docs` 的 **TSec 评测** 分组可以调用。由后端自动添加 `BENCHMARK_TOKEN` 请求头。

| 方法 | 本地路径 | 平台路径 |
|---|---|---|
| GET | `/api/v1/tsec/challenges` | `/openapi/v1/challenges` |
| POST | `/api/v1/tsec/challenges/start?unique_code=...` | `/openapi/v1/challenges/start` |
| GET | `/api/v1/tsec/challenges/hint?unique_code=...` | `/openapi/v1/challenges/hint` |
| POST | `/api/v1/tsec/challenges/submit` | `/openapi/v1/challenges/submit` |
| POST | `/api/v1/tsec/challenges/close?unique_code=...` | `/openapi/v1/challenges/close` |

提交请求体：

```json
{"unique_code": "web_sql_injection_01", "flag": "flag{实际答案}"}
```

成功响应保留平台原始字段，包括多 Flag 进度、得分和容器地址。业务异常保留 HTTP 状态、`code`、`message`、`detail`；422 参数错误保留 `detail` 数组。连接失败返回 503 `platform_unavailable`，无效 JSON/响应格式返回 502 `invalid_response`，重定向返回 502 `unexpected_redirect`。

不自动重试请求，避免网络超时后重复提交或误触提示扣分。遇到超时，应先查询题目进度和容器状态，再决定下一步。平台的 `invalid_state` 也可能表示活跃实例上限或题目已通关，需结合当前接口和 `message` 判断。

### 排查：token 有效但任务已结束

若所有接口都返回 `409 invalid_state`，且 `message` 形如 `task task_xxxx already finished`，说明 `BENCHMARK_TOKEN` 能被平台识别，但它对应的跑分任务已超时或被手动停止，不再接受任何请求。此时不是网络或 VPN 问题：

```powershell
# 不带任何本地封装，直接打平台只读接口确认返回码与错误体
$body = @{ BENCHMARK_TOKEN = $env:BENCHMARK_TOKEN }
Invoke-RestMethod "https://<平台地址>/openapi/v1/challenges" -Headers $body
```

处理方式是在 TSecBench 平台为该次跑分重新创建任务，取得新的 `BENCHMARK_BASE_URL` 和 `BENCHMARK_TOKEN`，更新 `an/.env` 后重启统一平台 API（8001）。只读 `list` 也返回 `invalid_state` 时，批量工具与 `tsec-auto` 的后续步骤都无需尝试。

## Python Agent 调用

在 `an` Python 环境中可直接使用客户端，无需启动本地 HTTP 服务：

```python
from security_agent.config import Settings
from security_agent.tsec_benchmark import TSecBenchmarkClient, TSecConfig

settings = Settings()  # 在 an 目录运行时读取 an/.env
client = TSecBenchmarkClient(TSecConfig(settings.tsec_base_url, settings.tsec_token))
challenges = await client.list_challenges()
# 以下操作由调用方按评测流程执行：
# entry = await client.start(unique_code)
# hint = await client.hint(unique_code)  # 会扣分，仅在需要时调用
# result = await client.submit(unique_code, flag)
# await client.close(unique_code)
```

调用方负责在现有解题流程中使用入口地址、逐个提交实际得到的 Flag，以及完成或失败后的容器释放（建议在 `finally` 中调用 `close`，并记录关闭失败以便补偿）。同一时间最多启动 3 道题，重复正确 Flag 返回 `duplicate`，提示接口不会被自动调用。

已通过真实平台只读查询验证鉴权，并确认 VPN 网关和靶场路由正常。批量写操作使用模拟平台验证；没有代替用户提交示例 Flag。
