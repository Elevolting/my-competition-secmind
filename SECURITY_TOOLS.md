# 项目内置安全工具

`_runtime/tools` 已内置官方版本：Yakit/Yak MCP 引擎 1.4.9-beta1、TscanPlus 3.5.2、Reqable 3.2.23，以及 Burp Suite Community 2026.3.3 和 PortSwigger MCP 扩展 1.3.0。Yakit 接入使用 Yak 引擎，无需安装 Yakit 桌面端。程序文件随项目保存；注册脚本会修正本机移动目录后的 MCP 路径。

先运行一次 `.\setup-security-tools.ps1` 做完整性检查和 MCP 注册，之后用 `.\start-security-tools.ps1` 启动 Reqable 与 Burp。也可以运行 `.\start-with-security-tools.cmd` 启动整套 SecMind。

Reqable 的桌面程序必须保持运行，项目通过内置 `mcp-server.exe --port 9001` 连接；9001 是 Reqable 当前 MCP 监听端口。在 SecMind 的 MCP 页面点击“连接并发现工具”可看到工具目录。

Burp 启动时会自动加载 `_runtime/tools/burp/burp-mcp-all.jar`。Community 版启动会显示 Burp 的项目向导，需要在桌面窗口点击 **Next → Start Burp**。打开 **MCP → Advanced Options**，确认 Server host 为 `127.0.0.1`、Server port 为 `9876`，然后打开页面顶部的 **Enabled**。扩展使用 SSE 地址 `http://127.0.0.1:9876`（不要加 `/mcp` 或 `/sse`）。Burp 的 HTTP 请求和项目数据审批选项默认保留，调用需要按 Burp 界面提示批准。

Burp 使用本机 PATH 中的 Java，本次为 Java 26，Burp 会提示该 Java 版本未经完整测试。Reqable 设置保存在当前 Windows 用户目录。此安装包不是跨机器完全免配置版；迁移电脑时还需准备项目 Python 环境和 Java，检查 Reqable MCP 端口及 Burp 启动配置。

2026-10-02 实测：

| MCP | 发现工具数 | 已完成的实际调用 |
|---|---:|---|
| Yakit/Yak | 55 | `exec_codec` |
| TscanPlus | 20 | `jwt_decode` |
| Reqable | 46 | `collection_list` |
| Burp | 24 | `base64_encode` |

访问 `http://127.0.0.1:5173/mcp` 查看连接与调用回执。已启用的服务现已接入任务 Agent：规划前自动发现工具（缓存 60 秒），模型先从目录中选出最多六个相关 MCP 工具，再按完整参数结构生成执行计划。离线或禁用的服务不会作为可用工具提供。需要已配置模型；演示模式继续使用原有内置模块。

在任务页面直接描述目标，例如“使用 Burp 的 base64_encode 将 SecMind MCP OK 编码并报告原始输出”。无需到 MCP 页面手动提交参数。当前支持基于已知参数的单步或有界多步计划；尚不支持把前一步输出自动绑定为后一步输入。

调用沿用任务预算和 `graded / approval_all / automatic` 策略。经过本地确认的纯编码工具按 R1 处理，其余 MCP 工具默认按 R2 处理；默认 graded 模式会在 R2 调用前显示任务审批。automatic 允许 R2 按现有策略运行，Burp 自己的审批仍然生效。非幂等 MCP 调用失败或服务中断后不自动重放。改变连接配置或工具协议会使原计划失效，需要重新规划。

任务会保存关联 run_id 的 MCP 回执、完整 JSON 结果文件及证据，供分析节点和最终报告使用。MCP 页也保留手动调用入口。接入的是 SecMind 主任务规划与执行器，独立 Security Runtime 内部 Worker 的工具表未修改。

端到端验收任务 `14d1820b-922f-4b1d-a0a2-d782f60fc29b` 已完成：实际模型从 149 个 MCP 工具中选中 `mcp:local-burp:base64_encode`，提交参数 `{"content":"SecMind MCP OK"}`，调用一次，报告保留了返回值 `U2VjTWluZCBNQ1AgT0s=` 和回执 `cf07f75f-547c-43cb-a23b-8a0c4b78e08f`。模型主端点当时多次超时，随后通过已配置的回退模型完成；MCP 调用本身成功。

停止由项目启动的桌面程序：`.\stop-security-tools.ps1`（请求窗口正常关闭，若有保存提示请在桌面处理）；确需强制退出时使用 `-Force`。
