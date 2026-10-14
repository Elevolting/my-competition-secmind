# 2026-10-13 渗透任务失败排查

## 实际失败链

- `proj_029` 没有得到可执行的新方向，工作台主动停止；`proj_030` 的多轮 Pi 输出被判为协议无效，随后运行时限耗尽；`proj_031` 已有 1 个完成方向，但运行时限耗尽后另外两个 Worker 的模型预留与 heartbeat 失败。后两项不能解释为靶场没有漏洞。
- `proj_032`（渗透31_retry，18:58 创建）在旧 Dispatcher 进程中反复收到 `422 Retry must preserve the original source facts`。当前工作台源码已在 20:30 固定重试的原始事实来源，Runtime 测试覆盖原来源重试；旧 Dispatcher 于 18:36 启动，未加载该修正。该项目已停止，不能把重放失败当成一次新的探索结论。
- `proj_033`（渗透31_retry，20:56 创建）共生成 31 条探索方向，但仅有 1 条进入 `completed` 并生成 `f001`；多次日志记录 `explore parse failed ... no JSON object found in output`。同一 Pi session 文件中可以看到 Worker 最终输出了合法 JSON。随后模型请求预算达到 200，项目停止，目标 flag 未取得。
- 本机 `LocalProcess._drain` 原来使用 64 KiB 的 `TextIOWrapper.read(size)`。当 Pi 或其子进程仍持有输出管道时，小于一块的尾部流式事件会滞留，`communicate()` 在 5 秒 join 后读取不到最终 `message_end`。探索主阶段与 conclude 阶段都受影响。这解释了 session 已保存结果、Runtime 却判定空输出的矛盾。
- 部分连接工具还返回超时或等待逐次 MCP 审批；例如最新 Pi session 的 `blackboard_invoke` 返回 `MCP approval expired`。这些属于独立的能力或审批限制，不等于发现了目标漏洞。
- 自动模式下，未列入只读白名单的 MCP 工具仍要逐次审批，即使只是读取 Yakit 配置或 TscanPlus/Yakit 结果；Worker 在审批等待期间阻塞，任务终态或租约结束后审批失效。

## 本次处理

- 本机进程输出改为逐行收集 Pi 的 NDJSON 事件；保留原有结构化协议验证和事实写入门槛。
- 随后重新审查发现：按工具名豁免 Yakit/TscanPlus/Reqable 的全局记录查询会越过任务范围，可能读到其他目标的数据。该豁免已撤回；这些查询继续要求逐次审批，后续需要按工具结果及任务目标做真正的范围隔离，不能只凭“只读”标签放行。
- 增加针对短 JSON 事件的回归测试；Runtime 全套 168 项测试通过，工作台增量规划专项通过。
- 确认 Runtime 数据库没有 active 项目后，只重启 Dispatcher。22:36 启动日志显示 Pi Worker 检查通过，并加载共享模型配置；旧项目保持停止状态。
- 22:49 重启工作台 API 并通过 `/health` 就绪检查；MCP 审批专项与黑板桥接测试通过。
- 进一步核对任务创建路径发现：渗透任务默认有较长运行时间，但界面仍提交普通任务的 200 次模型请求上限；`proj_033` 正好在该上限停止。新建渗透任务的默认值现为 600 次，API 与界面一致；用户手动设置的预算继续优先，历史任务保持原值。工作台 API 重启后接口返回 `penetration_max_model_calls=600` 且 `/health` 正常。
- 旧 `proj_033` 保存的 CTF 目标在复测时 TLS 证书已过期；忽略证书后，单次 GET 在 10 秒内仍未收到响应。因此该旧地址不能作为当前端到端成功率的验收目标，需使用仍有效的授权目标。

## 验收边界

这些检查证明输出接收、预算默认值和本地状态机的回归已修复；没有对历史 CTF 靶场重新发起渗透，也没有声称找到了 flag。600 次是上限，不保证找到目标；任务仍受运行时间、授权范围、工具可用性与逐次审批约束。后续新建任务应检查每轮 `explore` 是否产生 Fact、审批是否实际被处理、模型预算是否随有效进展消耗。

## 2026-10-14 授权 CTF 复测补充

- 用户提供的新目标为 `https://1e4de4e4-706d-44c6-948f-a7d44b3fd0dc.challenge.ctf.show/`。`proj_034` 对应工作台运行 `cc7ac669-441d-5777-80f3-00d86fe1d612`，取得了 `/`、`/login`、`/message` 的工具回执，但只有少数方向写入黑板。该轮因运行代码仍丢失已完成的 Pi 最终事件而停止，不能以黑板事实数量评判目标是否存在漏洞。
- `i001`、`i002` 的首次 Pi 会话均有 `stopReason=error` 和 `errorMessage="Connection error."`；Pi CLI 退出码为 0，旧 Dispatcher 将错误当成 JSON 解析失败并进入 conclude。`i001` 的 conclude 把“没有证据”写成了 `f001`，这是错误事实。现在从末尾 assistant 事件识别 provider 错误，释放意图并标为 `unhealthy`。
- `i002` 的后一次 Pi 会话文件保存了含原始工具回执 ID 的合法最终 JSON：自定义 `session` 值登录时被服务端新 Cookie 覆盖，当前登录路径的会话固定前置条件未成立。旧 Dispatcher 再次报 `no JSON object found in output`，证实逐行读取仍未覆盖“CLI 已退出但输出管道尾部未到达”的情况。现在只在本地 Pi 会话中找到与本轮提示词完全匹配、且末尾 assistant 以 `stop` 结束的消息时恢复答案；遇到新一轮用户消息、未完成工具调用或 provider 错误则不恢复旧答案。
- `proj_034` 的 MCP 审批在意图重试或超时后仍以 `pending` 出现在运行摘要中。审批状态查询现核对 `attempt_id`，运行摘要过滤失效轮次；审批执行本身继续二次核对任务分配。
- 复测期间只有与授权目标、当前意图和当前尝试一致的调用被批准；旧轮次的请求被跳过。将 Pi 探索并发从 2 降为 1 后，重启工作台 API 和 Dispatcher，启动新重试 `f3e0f9ab-afae-5c01-bc95-b3fda8cacffe` / `proj_035`。
- 修复后的 Runtime 全套 `176 passed, 1 skipped`；工作台非 PostgreSQL 集成测试全部通过。PostgreSQL 集成测试尚缺 `SECMIND_TEST_DATABASE_URL`，端到端 CTF 新轮次仍需观察最终事实与回执。
- 首次重试 `f3e0f9ab-afae-5c01-bc95-b3fda8cacffe` / `proj_035` 暴露本机启动配置遗漏：Pi 通过系统 `pi.CMD` 启动时报告 `Unknown provider "security_runtime"`。本机 Dispatcher 配置已固定使用已安装的 Pi CLI JS 入口；再次重试 `6da3a727-6a1a-5563-bdad-e0fe8ad5e677` / `proj_036`，首轮探索在约 33 秒内写入 `f001`，证实模型、工具、回执、Pi 输出解析和黑板写入贯通。
- `proj_036` 的工具结果和手工 GET 均显示该 CTF 主机根路径现为 ctf.show 平台 404，与 `proj_034` 的 200 页面不同，靶场实例已经下线。用户明确要求先跳过靶场复测，故已取消新任务并停止后续请求；未宣称取得 flag 或完成靶场端到端验收。
- 审批轮次过滤已延伸到黑板图和渗透图，停止的项目、旧 `attempt_id` 和非运行中意图不会再显示为等待审批。
- 继续排查发现 Runtime 意图的心跳、释放、阶段记录和结论只按 Worker 名称检查。意图重试后，同名旧 Worker 的迟到请求可能修改新轮次，甚至写入错误 Fact。工作台意图现在要求认领请求声明 `claim` 并核对上一轮 `attempt_id`；认领后的每次写入都必须携带当前 `attempt_id`。Dispatcher 和黑板协调器已沿调用链传递此值，旧轮次请求返回 409。普通 Runtime 项目仍兼容原有调用格式。
- 跨轮次回归测试覆盖旧心跳、释放、阶段记录和结论均不能更改新轮次状态、事件或事实；当前轮次仍可结论。Runtime 全套 `178 passed, 1 skipped`，工作台非 PostgreSQL 集成测试及黑板专项通过，相关源码 Ruff F 检查通过。
- 确认 Runtime 没有 active 项目且工作台近期运行均未处于 running 后，重启 Runtime Server、Dispatcher 和工作台 API。Runtime OpenAPI 包含新字段；工作台健康检查通过；Dispatcher 日志显示 Pi CLI 和共享模型配置检查通过。按用户要求，未对已下线 CTF 靶场再次请求，外部目标端到端验收仍待有效靶场。
- 后续审计发现 Reason/Planner 租约也只有 Worker 名称，旧规划任务可能续租、释放新轮次，或在原项目快照仍相同时提交迟到决策。项目现在持久化 `reason_attempt_id`；认领、续租、释放和工作台规划提交都核对轮次，提交前还会处理过期租约。跨轮次和过期租约回归测试通过。
- 调度器原先无论 Reason 成功或失败都更新已规划检查点，失败后若事实数量不变就不再重试。现在工作台 Reason 认领会持久化待决策状态，决策提交或合法重放后才清除；失败保留检查点差异并短暂退避，重启时也不会把待重试项目当成已规划。丢失响应后的同快照重放和旧数据库迁移均有回归测试。Runtime 全套 `183 passed, 1 skipped`，工作台非 PostgreSQL 集成测试通过。
- 上述 Reason 修复完成时，出现新的 active 项目 `proj_037` 和 running 工作台运行。为保留用户运行，本轮未重启 Runtime Server/Dispatcher；当前进程尚未加载这项最新修复。待项目自然终态后，需重新确认状态并重启这两个服务，再检查健康与迁移后的 Reason 字段。
- 继续审计成功判定发现：TSec 自动提交器原先从报告摘要、候选发现、证据摘要和图节点提取 flag，即使没有 `verified_outputs` 也会提交。这会把 Worker 陈述或请求回显当作答案。现在自动提交仅采纳报告的 `verified_outputs`；Planner 核验器必须逐字声明目标输出，代码再核对它存在于所引用工具结果中、且不属于该次请求参数。原生工具完成事件也记录本次参数供核对。工作台全套测试通过（4 skipped），桥接、规划及自动提交专项测试与 Ruff F 检查通过；`proj_037` 仍在运行，工作台 API 尚未加载此修复。
- 部署待办：确认 Runtime 无 active 项目且工作台无 running 运行后，按仓库脚本重启 `runtime-server`、`dispatcher`、`an-api`；核对 Runtime OpenAPI 的 `reason_attempt_id`、`reason_decision_pending` 字段、两个 API 的健康状态及 Dispatcher 就绪日志。按用户要求，未对已下线靶场发起新的端到端请求。
- 又发现目标完成被排队的未执行方向双重阻塞：工作台拒绝发起独立核验，Runtime 拒绝接受已经核验的完成决策。现在已核验完成可在 Runtime 同一事务中取消未认领方向；正在执行的方向仍阻止完成，以免中途截断工具调用。规划提示也明确优先提出有证据的完成建议。Runtime 全套 `184 passed, 1 skipped`，工作台全套通过（4 skipped），两侧规划专项与源码 Ruff F 检查通过。用户选择保留 `proj_037` 运行，等它自然结束后部署；当前服务仍加载旧代码。
- 完成来源审计又发现 Planner 使用候选回执列表生成 `completion_fact_ids`，可能把独立核验器未引用的事实也连到目标。现在目标来源只取核验器实际引用、且与本轮黑板事实条目关联的回执；核验器若引用未关联回执，完成判定失败。多事实与未关联回执测试通过；`proj_037` 仍在运行，部署继续等待自然终态。
- 对明确要求取得 `flag` 的目标，核验器原先可返回 `achieved=true` 但不给出任何已核验 flag，导致项目完成而自动提交器无答案。现在这类完成决策要求至少一个由核验器逐字声明、存在于所引用工具结果中、且未出现在请求参数里的 flag。空输出与请求回显均不能完成目标；专项测试通过。
- 本地 `an-api` 日志反复出现 `Failed to parse JSONRPC message from server`，输入行以时间戳和 `WARNING ... Free模式` 开头，说明某个第三方 stdio MCP 子进程向协议 stdout 写了普通日志。当前连接目录中 Yakit、TscanPlus、Reqable 均为 stdio 且探针显示 connected，现有日志不能可靠归属具体连接。需单独定位来源并修复输出通道；不能将这类解析错误当作目标漏洞或验证证据。
- `proj_037` 后来由用户侧取消，Runtime 项目为 stopped，工作台运行为 partial，停止原因是“用户请求取消任务”。确认无其他活动项目或运行后，按仓库脚本重启 `runtime-server`、`dispatcher` 和 `an-api`。重启后 Runtime OpenAPI 已包含 `reason_attempt_id`、`reason_decision_pending`，历史项目仍为 stopped，工作台 `/health` 正常，Dispatcher 日志确认 Pi CLI 和共享模型配置就绪。至此本轮已测试的修复已加载到服务；仍未对旧靶场发起新的请求。
- 已用单独的 TscanPlus `mcp stdio` 工具目录握手定位上述 JSON-RPC 污染：该二进制把“License.lic 不存在，以 Free 模式启动”警告写到 stdout。`NO_COLOR/CI` 环境无法消除。对已通过签名校验的 TscanPlus 连接增加本机 stdio 适配器，只将带时间戳与日志级别的行转到 stderr，其余原样保留，以免掩盖未知协议错误。模拟转发测试与真实 `list_tools` 握手通过，后者返回 25 个工具且不再报 JSON-RPC 解析错误；工作台全套测试通过。重启 `an-api` 后健康检查正常，目录显示 TscanPlus connected/25 tools，新日志中该解析错误计数为 0。
- 范围校验审计发现授权 URL 带查询串时，原实现仅比较协议、主机、端口和路径，导致授权 `?tenant=one` 的目标也能请求 `?tenant=two`。现在授权范围含查询串时要求目标查询串完全一致；未指定查询串的范围仍按原路径规则处理。新增同查询串放行、不同或缺失查询串拒绝的回归测试；MCP 专项测试、Ruff F 检查与工作台全套测试通过。部署前确认 Runtime 无 active 项目、工作台运行列表第一页无 running，随后仅重启 `an-api`，`/health` 返回 `status=ok`。用户要求跳过已下线靶场的端到端复测，因此尚无外部目标成功结果。
- 黑板 MCP 调用原来把 `runtime.invoke()` 抛出的所有 `ValueError` 改写成“工作区不可用”，令调用前的参数、授权或幂等键校验原因无法被 Worker 正确识别。现在保留 `ValueError` 的具体原因，`OSError` 仍显示工作区不可用；接口回归测试和 Ruff F 检查通过。再次检查部署前状态时，发现工作台列表默认只返回 100 条，因此补查偏移量 100 的 7 条；两页均无 running，Runtime 无 active 项目。仅重启 `an-api` 后脚本就绪检查通过。
- 核对 `proj_037` 的 Pi 会话、MCP 回执与审批数据库：`i005` 的一次 TscanPlus GET 于 03:30:12 进入待审批，03:39:19 审批消费，03:39:14 开始实际调用，工具报告约 286 ms 的 HTTP 耗时。约 9 分钟主要耗在审批等待，不是网络请求；该任务的 `autonomy_policy=graded` 且审批原因是策略要求显式批准。这会占用 600 秒探索时限，解释了部分超时，但不应被报告成靶场扫描失败。此次错误映射修复后的工作台全套测试通过（4 skipped），`an-api` 健康接口返回 `status=ok`。
- MCP 文件边界审计发现 TscanPlus 的 `dir_scan.dict`、`jwt_crack.dict`、`pwd_crack.pairf`、`subdomain_scan.sub_dict` 和 `tscan_scan` 的三个字典文件参数未按文件路径检查；路径数组也未被逐项检查。已按工具和参数补充识别。第三方 stdio 工具继承 API 工作目录，原校验却按任务工作区解释相对路径，因此现在含糊的相对文件路径直接返回 422；工作区内绝对路径可用，工作区外绝对路径仍进入逐次审批。MCP 范围、黑板接口与 Agent 专项测试、工作台全套测试（4 skipped）及 Ruff F 检查通过。部署前确认 Runtime 无 active 项目、工作台全部 107 条运行记录无 running；仅重启 `an-api` 后 `/health` 返回 `status=ok`。按用户要求，未对已下线靶场进行端到端复测。
- TscanPlus 工具目录审计发现 `subdomain_scan` / `tscan_scan` 的 `domains` 和 `ak_verify` 的 `bucket_url` 未被网络目标提取器识别，导致这些目标只走普通工具审批而未标为范围例外。现在将字段纳入授权范围检查；TscanPlus 的 `domains`、`targets`、`urls` 逗号分隔值逐项校验，图谱和审批目标也逐项展示。回归测试覆盖混合授权/未授权目标与 OSS URL，工作台全套测试（4 skipped）及 Ruff F 检查通过。部署前确认 Runtime 无 active 项目、工作台 107 条运行记录无 running；仅重启 `an-api` 后 `/health` 返回 `status=ok`。仍按用户要求跳过下线靶场的端到端复测。
- MCP 幂等重放审计发现，同一 `request_id` 的并发调用可能返回仍为 `running` 的回执；审批已消费但终态回执未落库时，黑板接口还会返回 409。Worker 因而会把进行中的调用当作失败。现在两条路径都等待原调用的终态回执，最多 65 秒；超时明确要求以相同请求 ID 稍后重试，不重新执行工具。并发重放与已消费审批回放的接口测试、工作台全套测试（4 skipped）及 Ruff F 检查通过。部署前确认 Runtime 无 active 项目、工作台 107 条运行记录无 running；仅重启 `an-api` 后 `/health` 返回 `status=ok`。外部靶场复测仍按用户要求跳过。
- 审批轮次审计发现，旧审批记录缺少 `attempt_id` 时，状态接口会把它视为对任何新轮次有效，批准接口也跳过轮次检查。现在只有记录和当前意图的轮次完全相同才视为有效；两者均为空时继续兼容旧的当前轮次。回归测试验证旧记录在意图获得新轮次后过期且不能批准；工作台全套测试（4 skipped）与 Ruff F 检查通过。部署前确认 Runtime 无 active 项目、工作台 107 条运行记录无 running；仅重启 `an-api` 后 `/health` 返回 `status=ok`。仍按用户要求跳过下线靶场复测。
- 审查同一个黑板入口的代码审计/逆向原生工具分支发现，普通 MCP 的幂等重放修复未覆盖这里：并发重试会返回 `running` 回执，审批已消费时也可能提前返回。现在原生分支两条回放路径都等待终态回执，超时要求沿用相同 `request_id` 重试，且不重复执行工具。两条并发接口回归测试、工作台全套测试（4 skipped）及 Ruff F 检查通过。部署前确认 Runtime 无 active 项目、工作台 107 条记录无 running；仅重启 `an-api` 后 `/health` 返回 `status=ok`。外部靶场复测仍按用户要求跳过。
- `session_http` 原来允许与目标 URL 不一致的自定义 `Host`，且独立 Cookie 参数可携带 CR/LF。现在核对 Host 主机和有效端口；不一致时注明策略原因并进入逐次审批，含控制字符的 Cookie 或请求头直接返回 422。补齐空白 Cookie 和显式端口 0 的边界。专项测试、工作台全套测试（4 skipped）及 Ruff F 检查通过；核对 107 条工作台运行无 running 且 Runtime 无 active 项目后，仅重启 `an-api`，`/health` 为 `status=ok`。同步修正 Cairn 研究文档中已过时的统一 Planner 状态。真实靶场端到端成功仍未验证。
- 新一轮重新运行全套测试和代码检查，发现两个可用性缺口：状态读取请求会默认继承系统 HTTP 代理环境；报告刷新端点先等待完整的任务执行锁，再检查任务是否仍在运行。现在 Runtime 状态 GET 禁用隐式环境代理；报告刷新在取锁前检查任务状态并在锁内复核，活跃或等待审批的任务立即返回 409。新增三种活跃状态的接口回归测试。继续核对会话头解析，修复 Cookie 中分号被当作头分隔符的问题，同时仍识别分号后伪造的 Host 等头；新增代理环境、Cookie 多值和伪造头测试。工作台全套测试通过（4 skipped），API/渗透专项通过，Runtime 全套 `184 passed, 1 skipped`，涉及源码 Ruff F/I 检查通过。首次从仓库父目录运行 Runtime 测试时，测试模块导入错误；改从 Runtime 项目目录运行后全套正常通过。15:40 部署前确认 Runtime 无 active 项目，工作台 107 条运行均无 pending/running/waiting_approval；仅重启 `an-api`，新进程启动日志及 `/health` 均正常。没有发起靶场请求。
- 后续报告链审计发现，旧 Runtime 路径会从 Worker 的外部事实描述提取 flag，并把图节点的 confirmed 状态视作已验证输出；这些都可能仅是模型陈述。现已将 Worker 事实保留为报告记录，只有工作台独立目标核验写入的 validated_goal_outputs 能进入报告及自动提交。Reporter 在模型开关与工作台/旧路径组合下、图节点标记为 completed/confirmed 但没有工具回执等回归覆盖通过。工作台全套 629 passed, 4 skipped，涉及源码 Ruff F/I 检查通过。复核 Runtime 无活动项目、工作台 107 条运行均非 pending/running/waiting_approval 后，15:55 重启 an-api；新进程启动正常，/health 返回 status=ok，未请求外部靶场。
- 进一步发现旧 Runtime 渗透任务若目标明确要求 flag，旧报告同步仍会仅凭已完成图状态和目标 Intent 将状态设为 COMPLETED，即使没有已核验输出。现令旧任务只有在存在经工作台独立核验的 validated_goal_outputs 时才可完成；无核验输出则报告为 PARTIAL，撤回历史报告中的 flag。新增旧报告刷新回归，并覆盖 Reporter 的模型开关、旧/工作台路径组合。工作台全套最终回归 629 passed, 4 skipped；源码 Ruff F/I 通过。Runtime 无 active 项目且 107 条工作台运行均为终态后，16:14 再次重启仅 an-api 并通过 /health。外部靶场复测依用户要求跳过，真实端到端结果未验证。
