"""Schema-validating registry for tool adapters."""

from __future__ import annotations

from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from secmind.schemas import ToolManifest
from secmind.tooling.core import BaseTool, ToolError, _validate_with


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}
        self._input_validators: dict[str, Draft202012Validator] = {}
        self._output_validators: dict[str, Draft202012Validator] = {}

    def register(self, tool: BaseTool) -> None:
        if tool.manifest.name in self._tools:
            raise ToolError(f"Duplicate tool: {tool.manifest.name}")
        try:
            Draft202012Validator.check_schema(tool.manifest.input_schema)
            Draft202012Validator.check_schema(tool.manifest.output_schema)
        except SchemaError as exc:
            raise ToolError(f"Invalid JSON Schema for tool {tool.manifest.name}: {exc.message}") from exc
        self._tools[tool.manifest.name] = tool
        self._input_validators[tool.manifest.name] = Draft202012Validator(tool.manifest.input_schema)
        self._output_validators[tool.manifest.name] = Draft202012Validator(tool.manifest.output_schema)

    def get(self, name: str) -> BaseTool:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolError(f"Unknown tool: {name}") from exc

    def manifests(self) -> list[ToolManifest]:
        return [tool.manifest for tool in self._tools.values()]

    def validate_input(self, name: str, value: Any) -> None:
        _validate_with(self._input_validators[name], value, path="input")

    def validate_output(self, name: str, value: Any) -> None:
        _validate_with(self._output_validators[name], value, path="output")
