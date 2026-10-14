# 跨轮规划：操作与验收

## 页面入口

在统一工作台打开任务的执行详情，切换“探索路径”。队列显示稳定步骤编号和阻塞原因；点击步骤可查看前置步骤、所需产物及已确认产物。点击前置步骤可跳到它的执行详情。搜索支持步骤编号和阻塞原因，窄屏通过队列／图视图切换查看。

这套能力适用于工作台 Planner 驱动的 Runtime 项目。旧任务没有依赖字段时继续按既有探索图运行；独立 SecMind 服务的静态 DAG 仍使用原执行路径。

## 规划与执行的职责

工作台 Planner 根据当前事实、回执和预算提出增量决策，并在运行快照中保存决策。工作台预检会移除非法依赖分支及其悬空下游，说明拒绝原因，并限制本轮独立方向数。Runtime 在应用决策和领取步骤时做最终校验，保存依赖、执行状态、attempt 与产物确认，负责租约和调度。

工作台依赖预检不替代 Runtime 校验，也不增加工具执行入口。现有任务预算、工具审批和授权范围仍在各自执行边界检查。

## 依赖与产物的含义

| 字段 | 含义 |
|---|---|
| `step_id` | 当前项目内稳定且唯一的步骤编号，跨轮、重试保留 |
| `depends_on` | 前置步骤编号列表；所有前置必须完成，后续才能领取 |
| `required_outputs` | 按前置步骤声明必需产物，例如 `{"A":["session"]}` |
| `validated_outputs` | 已确认的产物；规划决策中按步骤提交，步骤详情中保存累计结果 |
| `blocked_reasons` | 读取当前依赖状态计算的阻塞原因，包括等待、审批、失败、取消或缺少产物 |

例如 A 获取会话，B 使用会话验证访问控制，C 汇总结果。开局可以一次声明 A→B→C；只派 A。若 B 声明需要 A 的 `session`，A 执行完成后还需有该产物的观察事实、证据和工作台确认，才可派 B。

“执行完成”和“产物满足”分开判断：失败、否定、无证据或其他 attempt 的结果不能满足产物门槛。不声明 `required_outputs` 时，依赖仅要求前置完成并保存结果事实。领取下游时，Runtime 自动添加前置结果事实为来源，保留因果引用。

工作台仅从已完成步骤的事实／产物中提取 `output_key`，要求 `outcome=observed` 且存在成功工具回执；回执必须绑定当前项目、生产步骤、Worker 和当前 attempt。模型不能直接指定确认列表。Runtime 再验证产物属于该项目的已完成步骤，且有观察结果与证据引用。确认入口要求现有工作台规划凭据；Runtime 不独立核验工作台账本中的回执内容，实际证据判断以受信工作台为边界。

步骤上限为每任务 200 项；每项依赖最多 30 项，单个前置的产物编号最多 30 个，产物编号最长 120 字符。服务端拒绝重复编号、未知前置、自依赖、依赖环、跨项目引用和未声明前置的产物要求。

## 失败、审批、重试与停止

- 等待审批的前置不会解锁下游；有空闲执行槽位时独立分支可继续。审批同意与拒绝继续由现有审批流程处理，规划不能代替审批。
- 失败或超时的步骤不会自动重新执行。Planner 显式提交 `retry_intent_id`，保留原步骤编号、依赖契约与来源事实；Runtime 只接受已释放的失败／超时步骤，领取时创建新 attempt。
- 旧 attempt 的迟到回执与结果不能解锁下游。取消的步骤不能通过失败重试入口重新领取；整个项目停止后不再接受新的领取。
- 一条受阻链不会阻止其他就绪分支。全部剩余方向均无法推进时，工作台请求新的规划决策；若没有可执行的新方向或可重试步骤，则保留结果与停止原因，避免无限空转。
- 产物确认只表示满足该依赖的证据门槛，不代表漏洞已确认、目标已完成或整份报告可信；目标完成仍需既有独立复核。

## 持久化、事务与兼容

Runtime 在既有 `intents` 表幂等补充步骤编号、依赖、必需产物和已确认产物字段，旧行默认没有依赖。已有决策接口 `POST /projects/{project_id}/planning/decisions` 接收这些字段及按步骤提交的产物确认。无需修改旧任务才能读取其图。

依赖校验、产物确认、方向创建和决策保存位于同一事务。后续任一方向非法时整轮回滚，不留下部分确认。工作台保存决策后发送到 Runtime；响应丢失时使用相同 `decision_id` 和请求重放，Runtime 返回已保存结果。快照冲突要求取得新快照重新规划，不将旧快照当成最新状态。Runtime 的项目详情返回当前阻塞原因，调度器跳过受阻步骤，领取接口再次检查前置。

恢复测试使用同一独立临时数据库重建应用、连接和调度器对象；保存的待办、依赖、attempt 和确认可恢复。已完成步骤不重新派发。测试证明持久状态和调度恢复，不能据此声称真实工具在进程故障后具有严格的恰好一次外部执行保证。

## 验证命令与本地证据（2026-10-15）

从套件根目录分别进入目录运行：

```powershell
Set-Location -LiteralPath 'security-runtime/security-runtime'
.venv/Scripts/python.exe -m pytest -o addopts='' -q tests/test_planning_dependencies.py tests/test_workbench_planning.py tests/test_scheduler_logic.py
.venv/Scripts/python.exe -m pytest -o addopts='' -q
Set-Location -LiteralPath '../../an'
.venv/Scripts/python.exe -m pytest -o addopts='' -q tests/test_workbench_planning.py
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m ruff check src/security_agent/workbench_planning.py frontend/tests/blackboard-planning-browser.py
.venv/Scripts/python.exe -m mypy src/security_agent/workbench_planning.py --follow-imports=silent
Set-Location -LiteralPath 'frontend'
npm test
npm run build
Set-Location -LiteralPath '../..'
python an/frontend/tests/blackboard-planning-browser.py
git diff --check
```

- Runtime 全量此前 210 项通过、1 项跳过；最后新增审批等待场景后，受影响专项 58 项通过。
- 工作台专项此前 71 项通过；工作台全量命令本轮成功，该次输出未列完整统计数量。
- 前端测试、生产构建与浏览器夹具通过；浏览器检查依赖详情、前置跳转、390px 队列及无浏览器错误。前端仍有既有 antd 和构建体积警告。
- 新规划模块 Ruff／mypy 通过；所有修改 Python 文件与提交基线比较，无新增 Ruff 诊断。全仓存在既有静态告警，不能称全仓静态检查通过。
- 场景覆盖串行链、独立分支、审批等待、必需产物、否定或无证据结果、失败／超时显式重试、旧 attempt、取消、服务／调度器恢复、响应丢失重放、事务回滚、环与未知依赖、方向限额及旧任务。

测试使用模拟模型、Mock Worker 和独立临时库。浏览器使用模拟 API、独立 Chrome 配置及已有前端开发服务，需要系统 Python 的 `websocket-client`；不重启现有服务。尚未用真实目标、外部模型或生产并发验证本功能。实现借鉴 ARTEX 的跨轮待办与事实驱动推进，没有直接复制其源码。
