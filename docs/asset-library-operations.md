# 跨任务资产库：操作与验收

## 入口与用途

在工作台导航选择“跨任务资产库”，或打开前端 `/assets`。支持按关键词、域名／IP／服务／端点、任务编号和观测状态筛选，每页显示 20 项。点击资产查看逐任务来源、授权范围、发现编号和观测引用，点击“打开任务”回到原任务。

此页面只读取已有任务快照与 MCP 回执，不探测网络、不执行测试，也不继承其他任务的授权。列表中的任务数、观测任务数和发现数是该资产的全部历史关联数量；筛选用于选择资产，不会改变这些累计计数。

## 数据含义

- 全局身份包含资产类型及规范化值。域名忽略大小写、末尾点并转为 IDNA；IP 采用规范表示；HTTP 服务保留协议、主机和非默认端口；端点再包含路径。
- URL 查询字符串、片段和登录凭据不进入全局身份。含登录凭据的 URL 被拒绝。查询键值和 HTTP 方法不参与端点身份，因此不能据此判断特定操作是否已测。
- 来源、发现、状态、首次与最近同步时间按任务保存。同一发现编号出现在不同任务中时分别计数。时间表示入库／更新的时间，原始观测时间如有则放在来源记录中。
- `observed` 仅表示该任务存在成功的显式观测；失败调用、仅执行工具或仅引用发现均不算成功观测。它不代表端点全部方法、参数或漏洞类型已经覆盖。
- 同步会保留此前成功观测与来源；后续失败不会抹去历史。重复同步相同快照不更新时间或追加重复来源。历史记录不因当前快照缺少某项而自动删除。
- 输入文件和非网络范围标记不作为全局网络资产；它们仍可出现在任务授权范围说明中。

## 接口与兼容

`GET /api/v1/assets` 接受 `search`、`kind`、`run_id`、`coverage`、`limit`、`offset`，返回 `schema_version`、`assets` 和 `total`。`kind` 为 `domain|ip|service|endpoint`，`coverage` 为 `observed|unobserved`。分页上限为 200，非法参数返回 422。

`GET /api/v1/assets/{asset_id}` 返回资产身份与逐任务关联；不存在时返回 404。资产编号由类型与规范化身份确定。

启动时幂等创建 `global_assets`、`run_asset_observations`、`run_asset_sync` 三张附加表，不修改既有任务结构。列表和详情查询前同步现有任务及回执；首次访问会回填历史任务。当前每次查询仍需读取全部任务与回执并计算投影，数据量大时会增加延迟；快照哈希只避免重复写入，不代表已实现增量扫描。

## 本地验收（2026-10-15）

在套件根目录执行：

```powershell
Set-Location -LiteralPath 'an'
.venv/Scripts/python.exe -m pytest -o addopts='' -q tests/test_asset_library.py tests/test_asset_graph.py
.venv/Scripts/python.exe -m ruff check src/security_agent/asset_library.py src/security_agent/asset_library_api.py tests/test_asset_library.py frontend/tests/asset-library-browser.py
Set-Location -LiteralPath 'frontend'
npm test
npm run build
Set-Location -LiteralPath '..\..'
python an/frontend/tests/asset-library-browser.py
```

浏览器验收需要已有的前端开发服务和本机 Chrome、`websocket-client`。夹具使用独立临时浏览器及模拟 API，不重启现有服务，不访问真实目标。截图输出到被忽略的 `an/data/artex-dev/asset-library-mobile.png`。

已通过的验收包括：

- 后端资产库与任务资产图共 26 项：跨任务去重、范围隔离、成功／失败区分、历史保留、发现准确关联、非法查询、并发与重复同步。
- 全量 `an` 后端回归 746 项通过、4 项跳过；在该次收集后新增的“发现升级范围状态”测试也已在上述 26 项回归中通过。
- 前端 55 项测试和生产构建。
- 浏览器分页、搜索、类型／任务／观测筛选、空列表、来源展开、失败重试、关闭详情后的迟到响应、搜索响应乱序、390px 布局与任务跳转。移动端截图已人工查看。
- 新增模块与浏览器夹具 Ruff 检查通过；全仓诊断按路径、规则和消息与提交基线对比，无新增 Ruff／mypy／Bandit 问题。全仓仍有 Ruff 438 项、mypy 142 项、Bandit 20 项，不能称全仓检查通过。

验证不涉及真实目标、外部模型、生产规模性能或 PostgreSQL 并发。当前接口与已有工作台使用相同访问边界；此交付未增加多用户资产权限模型。
