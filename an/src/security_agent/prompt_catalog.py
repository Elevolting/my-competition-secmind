"""Read-only catalog for locally bundled prompts.

The catalog deliberately does not participate in the agent graph.  It is a
small compatibility layer so the prompts can be inspected and versioned
before a later migration wires them into the runtime.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PromptEntry:
    key: str
    name: str
    category: str
    purpose: str
    stage: str
    source: str
    path: Path

    def metadata(self, *, include_content: bool = False) -> dict[str, object]:
        content = self.path.read_text(encoding="utf-8")
        result: dict[str, object] = {
            "key": self.key,
            "name": self.name,
            "category": self.category,
            "purpose": self.purpose,
            "stage": self.stage,
            "source": self.source,
            "version": "1.0",
            "status": "catalogued",
            "active": False,
            "runtime_injected": False,
            "checksum": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "size_bytes": len(content.encode("utf-8")),
        }
        if include_content:
            result["content"] = content
        return result


_PROMPT_INFO: tuple[tuple[str, str, str, str, str], ...] = (
    ("assistant", "交互助手", "Agent 系统 Prompt", "处理用户交互请求", "交互会话"),
    ("primary_agent", "主控智能体", "Agent 系统 Prompt", "协调专家智能体完成子任务", "专家调度"),
    ("pentester", "渗透测试智能体", "Agent 系统 Prompt", "执行渗透测试和漏洞验证", "专家执行"),
    ("coder", "代码智能体", "Agent 系统 Prompt", "编写、修改和验证代码", "专家执行"),
    ("reporter", "报告智能体", "Agent 系统 Prompt", "汇总证据、发现和最终结论", "报告生成"),
    ("reflector", "反思智能体", "Agent 系统 Prompt", "纠正异常输出和工具协议", "异常纠正"),
)


class PromptCatalog:
    """Discover bundled prompt assets without rendering or activating them."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or Path(__file__).with_name("prompts")).resolve()

    def entries(self) -> list[PromptEntry]:
        entries: list[PromptEntry] = []
        for key, name, category, purpose, stage in _PROMPT_INFO:
            path = self.root / f"{key}.tmpl"
            if path.is_file():
                entries.append(
                    PromptEntry(
                        key=key,
                        name=name,
                        category=category,
                        purpose=purpose,
                        stage=stage,
                        source="local prompt catalog",
                        path=path,
                    )
                )
        return entries

    def list_metadata(self) -> list[dict[str, object]]:
        return [entry.metadata() for entry in self.entries()]

    def get(self, key: str, *, include_content: bool = False) -> dict[str, object] | None:
        entry = next((item for item in self.entries() if item.key == key), None)
        return entry.metadata(include_content=include_content) if entry else None
