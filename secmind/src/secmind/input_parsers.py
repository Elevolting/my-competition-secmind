"""Bounded parsers for untrusted task attachments.

The registry probes media types and returns normalized assets under explicit
size, depth, record, and text limits. Parsed content remains untrusted data and
can suggest a scenario, but it cannot create instructions or permissions.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections.abc import Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from io import StringIO
from pathlib import PurePosixPath
from typing import Any, Literal, Protocol
from uuid import NAMESPACE_URL, uuid5

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.tokens import AliasToken, AnchorToken, DirectiveToken, TagToken

from secmind.schemas import ParsedAsset, ParserManifest, ParserRun, Scenario, TaskHint, ToolHealth

_PARSER_VERSION = "1.0.0"
_PROBE_BYTES = 64 * 1024
_MAX_PATH_LENGTH = 1_024
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 100_000
_MAX_JSON_KEYS = 20_000
_MAX_JSON_STRING = 128 * 1024
_MAX_TABULAR_LINE = 64 * 1024
_MAX_TABULAR_FIELD = 64 * 1024
_MAX_TABULAR_COLUMNS = 256
_MAX_TABULAR_RECORDS = 10_000
_MAX_API_ENDPOINTS = 5_000
_MAX_HINTS = 32
_MAX_DIAGNOSTICS = 32
_MAX_YAML_TOKENS = 100_000

_CONTROL_CHARACTER = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FORMULA_PREFIXES = ("=", "+", "-", "@")
_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})


class ParserError(ValueError):
    """Base class for deterministic, typed parser failures."""


class ParserSelectionError(ParserError):
    """No allowlisted parser can safely handle the supplied asset."""


class ParserLimitError(ParserError):
    """A bounded parser limit was exceeded."""


class ParserUnavailableError(ParserError):
    """The matching parser is deliberately unavailable in this release."""


@dataclass(frozen=True)
class ProbeMatch:
    parser_id: str
    score: int
    priority: int


@dataclass(frozen=True)
class ParseOutcome:
    parser_run: ParserRun
    asset: ParsedAsset | None


@dataclass(frozen=True)
class _ParserProduct:
    asset_type: str
    hints: tuple[TaskHint, ...] = ()
    metadata: Mapping[str, Any] | None = None
    diagnostics: tuple[str, ...] = ()
    status: Literal["completed", "partial"] = "completed"


class InputParser(Protocol):
    manifest: ParserManifest

    def probe(self, *, relative_path: str, media_type: str, content_prefix: bytes) -> int:
        """Return a deterministic confidence score from 0 to 100."""

    def parse(self, *, relative_path: str, media_type: str, content: bytes) -> _ParserProduct:
        """Parse bounded bytes without performing network or code execution."""


class ParserRegistry:
    """Allowlisted deterministic parsers selected by score, priority and id.

    The registry never imports parsers from uploaded content, never follows a URL,
    and never executes scripts embedded in an API or Postman document.
    """

    def __init__(self, parsers: Iterable[InputParser] = ()) -> None:
        self._parsers: dict[str, InputParser] = {}
        for parser in parsers:
            self.register(parser)

    def register(self, parser: InputParser) -> None:
        parser_id = parser.manifest.parser_id
        if parser_id in self._parsers:
            raise ParserSelectionError(f"duplicate parser id: {parser_id}")
        self._parsers[parser_id] = parser

    def manifests(self) -> list[ParserManifest]:
        return [self._parsers[key].manifest for key in sorted(self._parsers)]

    def probe(self, *, relative_path: str, media_type: str, content: bytes) -> list[ProbeMatch]:
        _validate_relative_path(relative_path)
        prefix = content[:_PROBE_BYTES]
        matches = [
            ProbeMatch(
                parser_id=parser.manifest.parser_id,
                score=score,
                priority=parser.manifest.probe_priority,
            )
            for parser in self._parsers.values()
            if (score := parser.probe(relative_path=relative_path, media_type=media_type, content_prefix=prefix)) > 0
        ]
        return sorted(matches, key=lambda item: (-item.score, item.priority, item.parser_id))

    def select(self, *, relative_path: str, media_type: str, content: bytes) -> InputParser:
        matches = self.probe(relative_path=relative_path, media_type=media_type, content=content)
        if not matches:
            raise ParserSelectionError("no allowlisted parser matched the asset")
        parser = self._parsers[matches[0].parser_id]
        if parser.manifest.health_status == ToolHealth.UNAVAILABLE:
            raise ParserUnavailableError(f"parser is unavailable: {parser.manifest.parser_id}")
        return parser

    def parse(
        self,
        *,
        run_id: str,
        artifact_id: str,
        relative_path: str,
        media_type: str,
        content: bytes,
    ) -> ParseOutcome:
        input_digest = hashlib.sha256(content).hexdigest()
        matches = self.probe(relative_path=relative_path, media_type=media_type, content=content)
        if not matches:
            raise ParserSelectionError("no allowlisted parser matched the asset")
        parser = self._parsers[matches[0].parser_id]
        run_identity = f"secmind:parser-run:{run_id}:{artifact_id}:{parser.manifest.parser_id}:{input_digest}"
        parser_run_id = str(uuid5(NAMESPACE_URL, run_identity))
        if parser.manifest.health_status == ToolHealth.UNAVAILABLE:
            diagnostic = f"parser is unavailable: {parser.manifest.parser_id}"
            return ParseOutcome(
                parser_run=ParserRun(
                    parser_run_id=parser_run_id,
                    run_id=run_id,
                    artifact_id=artifact_id,
                    parser_id=parser.manifest.parser_id,
                    parser_version=parser.manifest.version,
                    status="skipped",
                    input_digest=input_digest,
                    diagnostics=[diagnostic],
                ),
                asset=None,
            )
        try:
            _validate_relative_path(relative_path)
            if len(content) > parser.manifest.max_input_size:
                raise ParserLimitError(
                    f"input exceeds {parser.manifest.parser_id} limit of {parser.manifest.max_input_size} bytes"
                )
            product = parser.parse(relative_path=relative_path, media_type=media_type, content=content)
            asset_identity = f"secmind:parsed-asset:{artifact_id}:{parser.manifest.parser_id}:{input_digest}"
            asset = ParsedAsset(
                parsed_asset_id=str(uuid5(NAMESPACE_URL, asset_identity)),
                parser_id=parser.manifest.parser_id,
                parser_version=parser.manifest.version,
                artifact_id=artifact_id,
                relative_path=relative_path,
                media_type=_base_media_type(media_type) or "application/octet-stream",
                asset_type=product.asset_type,
                content_digest=input_digest,
                hints=list(product.hints),
                metadata=dict(product.metadata or {}),
                diagnostics=list(product.diagnostics[:_MAX_DIAGNOSTICS]),
            )
            output_digest = hashlib.sha256(_canonical_json(asset.model_dump(mode="json")).encode()).hexdigest()
            return ParseOutcome(
                parser_run=ParserRun(
                    parser_run_id=parser_run_id,
                    run_id=run_id,
                    artifact_id=artifact_id,
                    parser_id=parser.manifest.parser_id,
                    parser_version=parser.manifest.version,
                    status=product.status,
                    parsed_asset_id=asset.parsed_asset_id,
                    input_digest=input_digest,
                    output_digest=output_digest,
                    diagnostics=asset.diagnostics,
                ),
                asset=asset,
            )
        except ParserError as exc:
            return ParseOutcome(
                parser_run=ParserRun(
                    parser_run_id=parser_run_id,
                    run_id=run_id,
                    artifact_id=artifact_id,
                    parser_id=parser.manifest.parser_id,
                    parser_version=parser.manifest.version,
                    status="failed",
                    input_digest=input_digest,
                    diagnostics=[str(exc)],
                ),
                asset=None,
            )


def _manifest(
    parser_id: str,
    *,
    media_types: tuple[str, ...],
    extensions: tuple[str, ...],
    priority: int,
    max_input_size: int,
    streaming: bool = False,
    health: ToolHealth = ToolHealth.HEALTHY,
) -> ParserManifest:
    descriptor = {
        "parser_id": parser_id,
        "version": _PARSER_VERSION,
        "media_types": media_types,
        "extensions": extensions,
        "priority": priority,
        "max_input_size": max_input_size,
        "streaming": streaming,
        "health": health.value,
    }
    return ParserManifest(
        parser_id=parser_id,
        version=_PARSER_VERSION,
        supported_media_types=list(media_types),
        extensions=list(extensions),
        probe_priority=priority,
        max_input_size=max_input_size,
        streaming=streaming,
        output_schema={"$ref": "secmind://schemas/1.4/ParsedAsset"},
        package_digest=hashlib.sha256(
            json.dumps(descriptor, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        health_status=health,
    )


class _BaseParser:
    manifest: ParserManifest

    @staticmethod
    def _extension(relative_path: str) -> str:
        return PurePosixPath(relative_path.replace("\\", "/")).suffix.lower()

    def _media_or_extension_score(self, relative_path: str, media_type: str, *, score: int = 80) -> int:
        if _base_media_type(media_type) in self.manifest.supported_media_types:
            return score
        if self._extension(relative_path) in self.manifest.extensions:
            return score - 5
        return 0


class TextParser(_BaseParser):
    manifest = _manifest(
        "text-markdown",
        media_types=("text/plain", "text/markdown"),
        extensions=(".txt", ".md", ".markdown"),
        priority=100,
        max_input_size=1024 * 1024,
    )

    def probe(self, *, relative_path: str, media_type: str, content_prefix: bytes) -> int:
        del content_prefix
        return self._media_or_extension_score(relative_path, media_type, score=70)

    def parse(self, *, relative_path: str, media_type: str, content: bytes) -> _ParserProduct:
        del media_type
        text = _decode_utf8(content)
        lines, diagnostics = _bounded_lines(text, max_records=20_000)
        normalized = [_normalize_text(line).strip() for line in lines if line.strip()]
        objectives = normalized[:1]
        hint = TaskHint(
            source_ref=relative_path,
            objectives=objectives,
            scenario_candidates=_scenario_candidates(" ".join(normalized[:20])),
            confidence=0.55 if objectives else 0.2,
            metadata={"content_is_untrusted_data": True},
        )
        return _ParserProduct(
            asset_type="text_document",
            hints=(hint,),
            metadata={"line_count": len(lines), "nonempty_line_count": len(normalized)},
            diagnostics=tuple(diagnostics),
        )


class JsonParser(_BaseParser):
    manifest = _manifest(
        "json",
        media_types=("application/json", "text/json"),
        extensions=(".json",),
        priority=60,
        max_input_size=4 * 1024 * 1024,
    )

    def probe(self, *, relative_path: str, media_type: str, content_prefix: bytes) -> int:
        return self._media_or_extension_score(relative_path, media_type, score=72)

    def parse(self, *, relative_path: str, media_type: str, content: bytes) -> _ParserProduct:
        del media_type
        value = _load_bounded_json(content)
        hint = _task_hint_from_mapping(value, relative_path) if isinstance(value, Mapping) else None
        metadata = _json_shape_metadata(value)
        return _ParserProduct(
            asset_type="structured_json",
            hints=() if hint is None else (hint,),
            metadata=metadata,
        )


class DelimitedTextParser(_BaseParser):
    manifest = _manifest(
        "csv-tsv",
        media_types=("text/csv", "text/tab-separated-values"),
        extensions=(".csv", ".tsv"),
        priority=30,
        max_input_size=4 * 1024 * 1024,
        streaming=True,
    )

    def probe(self, *, relative_path: str, media_type: str, content_prefix: bytes) -> int:
        del content_prefix
        return self._media_or_extension_score(relative_path, media_type, score=92)

    def parse(self, *, relative_path: str, media_type: str, content: bytes) -> _ParserProduct:
        text = _decode_utf8(content)
        lines, diagnostics = _bounded_lines(text, max_records=_MAX_TABULAR_RECORDS + 1)
        delimiter = "\t" if self._extension(relative_path) == ".tsv" else ","
        if _base_media_type(media_type) == "text/tab-separated-values":
            delimiter = "\t"
        try:
            reader = csv.reader(StringIO("\n".join(lines)), delimiter=delimiter, strict=True)
            rows: list[list[str]] = []
            formula_cells = 0
            for index, row in enumerate(reader):
                if index >= _MAX_TABULAR_RECORDS:
                    raise ParserLimitError(f"tabular input exceeds {_MAX_TABULAR_RECORDS} records")
                if len(row) > _MAX_TABULAR_COLUMNS:
                    raise ParserLimitError(f"tabular input exceeds {_MAX_TABULAR_COLUMNS} columns")
                if any(len(field) > _MAX_TABULAR_FIELD for field in row):
                    raise ParserLimitError(f"tabular field exceeds {_MAX_TABULAR_FIELD} characters")
                formula_cells += sum(_looks_like_formula(field) for field in row)
                rows.append(row)
        except csv.Error as exc:
            raise ParserError(f"invalid delimited text: {exc}") from exc
        if formula_cells:
            diagnostics.append(f"detected {formula_cells} formula-like cell(s); values were not executed or exported")
        header = [_normalize_text(item)[:512] for item in rows[0]] if rows else []
        return _ParserProduct(
            asset_type="tabular_records",
            metadata={
                "delimiter": "tab" if delimiter == "\t" else "comma",
                "record_count": max(len(rows) - 1, 0),
                "column_count": len(header),
                "header": header,
                "formula_like_cells": formula_cells,
            },
            diagnostics=tuple(diagnostics),
        )


class NdjsonParser(_BaseParser):
    manifest = _manifest(
        "ndjson",
        media_types=("application/x-ndjson", "application/ndjson"),
        extensions=(".ndjson", ".jsonl"),
        priority=20,
        max_input_size=8 * 1024 * 1024,
        streaming=True,
    )

    def probe(self, *, relative_path: str, media_type: str, content_prefix: bytes) -> int:
        del content_prefix
        return self._media_or_extension_score(relative_path, media_type, score=96)

    def parse(self, *, relative_path: str, media_type: str, content: bytes) -> _ParserProduct:
        del media_type
        text = _decode_utf8(content)
        lines, diagnostics = _bounded_lines(text, max_records=_MAX_TABULAR_RECORDS)
        valid = 0
        invalid = 0
        top_keys: set[str] = set()
        hints: list[TaskHint] = []
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                value = _load_bounded_json(line.encode("utf-8"))
            except ParserError as exc:
                invalid += 1
                if len(diagnostics) < _MAX_DIAGNOSTICS:
                    diagnostics.append(f"line {line_number}: {exc}")
                continue
            valid += 1
            if isinstance(value, Mapping):
                top_keys.update(str(key) for key in value)
                if len(hints) < _MAX_HINTS and (hint := _task_hint_from_mapping(value, relative_path)) is not None:
                    hints.append(hint)
        if valid == 0 and invalid:
            raise ParserError("NDJSON contains no valid records")
        status: Literal["completed", "partial"] = "partial" if invalid else "completed"
        return _ParserProduct(
            asset_type="ndjson_records",
            hints=tuple(hints),
            metadata={
                "valid_record_count": valid,
                "invalid_record_count": invalid,
                "top_level_keys": sorted(top_keys)[:256],
            },
            diagnostics=tuple(diagnostics),
            status=status,
        )


class OpenApiJsonParser(_BaseParser):
    manifest = _manifest(
        "openapi-json",
        media_types=("application/vnd.oai.openapi+json",),
        extensions=(".openapi.json", ".swagger.json"),
        priority=10,
        max_input_size=8 * 1024 * 1024,
    )

    def probe(self, *, relative_path: str, media_type: str, content_prefix: bytes) -> int:
        lowered = content_prefix.lower()
        signature = (b'"openapi"' in lowered or b'"swagger"' in lowered) and b'"paths"' in lowered
        if signature:
            return 100
        return self._media_or_extension_score(relative_path, media_type, score=98)

    def parse(self, *, relative_path: str, media_type: str, content: bytes) -> _ParserProduct:
        del media_type
        value = _load_bounded_json(content)
        if not isinstance(value, Mapping) or not isinstance(value.get("paths"), Mapping):
            raise ParserError("OpenAPI JSON must contain an object-valued paths field")
        version = value.get("openapi") or value.get("swagger")
        if not isinstance(version, str):
            raise ParserError("OpenAPI JSON must declare openapi or swagger version")
        endpoints = _openapi_operations(value["paths"], global_security=value.get("security"))
        servers = value.get("servers", [])
        server_count = len(servers) if isinstance(servers, Sequence) and not isinstance(servers, str) else 0
        diagnostics = (f"recorded {server_count} server declaration(s) as untrusted data; no URL was accessed",)
        hint = TaskHint(
            source_ref=relative_path,
            objectives=["Assess the supplied API description within explicit authorized scope."],
            scenario_candidates=[Scenario.API_ASSESSMENT],
            confidence=0.98,
            metadata={"servers_are_untrusted_data": True, "network_access_performed": False},
        )
        return _ParserProduct(
            asset_type="openapi_document",
            hints=(hint,),
            metadata={
                "specification_version": version[:64],
                "operation_count": len(endpoints),
                "operations": endpoints,
                "server_declaration_count": server_count,
                "network_access_performed": False,
            },
            diagnostics=diagnostics,
        )


class PostmanJsonParser(_BaseParser):
    manifest = _manifest(
        "postman-json",
        media_types=("application/vnd.postman.collection+json",),
        extensions=(".postman_collection.json",),
        priority=9,
        max_input_size=8 * 1024 * 1024,
    )

    def probe(self, *, relative_path: str, media_type: str, content_prefix: bytes) -> int:
        lowered = content_prefix.lower()
        if b'"schema"' in lowered and b"schema.getpostman.com" in lowered and b'"item"' in lowered:
            return 100
        return self._media_or_extension_score(relative_path, media_type, score=98)

    def parse(self, *, relative_path: str, media_type: str, content: bytes) -> _ParserProduct:
        del media_type
        value = _load_bounded_json(content)
        if not isinstance(value, Mapping) or not isinstance(value.get("item"), list):
            raise ParserError("Postman collection must contain an item array")
        info = value.get("info")
        schema = info.get("schema") if isinstance(info, Mapping) else None
        if not isinstance(schema, str) or "schema.getpostman.com" not in schema.lower():
            raise ParserError("Postman collection schema is missing or unsupported")
        request_count = 0
        script_count = 0
        methods: set[str] = set()
        stack: list[tuple[Any, int]] = [(item, 1) for item in reversed(value["item"])]
        while stack:
            item, depth = stack.pop()
            if depth > _MAX_JSON_DEPTH:
                raise ParserLimitError(f"Postman item nesting exceeds {_MAX_JSON_DEPTH}")
            if not isinstance(item, Mapping):
                continue
            children = item.get("item")
            if isinstance(children, list):
                stack.extend((child, depth + 1) for child in reversed(children))
            request = item.get("request")
            if request is not None:
                request_count += 1
                if request_count > _MAX_API_ENDPOINTS:
                    raise ParserLimitError(f"Postman collection exceeds {_MAX_API_ENDPOINTS} requests")
                if isinstance(request, Mapping) and isinstance(request.get("method"), str):
                    methods.add(request["method"].upper()[:32])
            events = item.get("event")
            if isinstance(events, list):
                script_count += len(events)
        top_events = value.get("event")
        if isinstance(top_events, list):
            script_count += len(top_events)
        variables = value.get("variable")
        variable_names = (
            sorted(
                {
                    _normalize_text(str(item.get("key")))[:256]
                    for item in variables
                    if isinstance(variables, list) and isinstance(item, Mapping) and item.get("key") is not None
                }
            )
            if isinstance(variables, list)
            else []
        )
        diagnostics = [
            f"recorded {script_count} script/event block(s) as untrusted data; none were executed",
            "request URLs were treated as untrusted data and were not accessed",
        ]
        hint = TaskHint(
            source_ref=relative_path,
            objectives=["Assess the supplied Postman collection within explicit authorized scope."],
            scenario_candidates=[Scenario.API_ASSESSMENT],
            confidence=0.98,
            metadata={"scripts_are_untrusted_data": True, "network_access_performed": False},
        )
        return _ParserProduct(
            asset_type="postman_collection",
            hints=(hint,),
            metadata={
                "request_count": request_count,
                "methods": sorted(methods),
                "script_block_count": script_count,
                "variable_names": variable_names[:512],
                "variable_values_retained": False,
                "network_access_performed": False,
            },
            diagnostics=tuple(diagnostics),
        )


class _BoundedYamlLoader(yaml.BaseLoader):
    """String-only YAML loader with duplicate mapping keys rejected.

    ``BaseLoader`` deliberately avoids application types and constructors. The
    parser also rejects aliases, anchors and tags before construction, so an
    uploaded document cannot trigger object construction or alias expansion.
    """

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        if not isinstance(node, MappingNode):
            raise ConstructorError(None, None, "expected a mapping node", node.start_mark)
        result: dict[Hashable, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConstructorError(None, None, "YAML mapping keys must be strings", key_node.start_mark)
            if key in result:
                raise ParserError(f"YAML contains duplicate key: {key[:128]}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


class YamlParser(_BaseParser):
    manifest = _manifest(
        "yaml",
        media_types=("application/yaml", "application/x-yaml", "text/yaml"),
        extensions=(".yaml", ".yml"),
        priority=1,
        max_input_size=4 * 1024 * 1024,
    )

    def probe(self, *, relative_path: str, media_type: str, content_prefix: bytes) -> int:
        del content_prefix
        return self._media_or_extension_score(relative_path, media_type, score=100)

    def parse(self, *, relative_path: str, media_type: str, content: bytes) -> _ParserProduct:
        del media_type
        text = _decode_utf8(content)
        try:
            tokens = list(yaml.scan(text, Loader=_BoundedYamlLoader))
        except yaml.YAMLError as exc:
            raise ParserError(f"invalid YAML: {type(exc).__name__}") from exc
        if len(tokens) > _MAX_YAML_TOKENS:
            raise ParserLimitError(f"YAML exceeds {_MAX_YAML_TOKENS} tokens")
        if any(isinstance(token, (AliasToken, AnchorToken, DirectiveToken, TagToken)) for token in tokens):
            raise ParserError("YAML aliases, anchors, and tags are not allowed")
        try:
            # BaseLoader constructs strings only; the subclass also rejects aliases,
            # tags, duplicate keys and bounded-depth violations before construction.
            value = yaml.load(text, Loader=_BoundedYamlLoader)  # noqa: S506  # nosec B506
        except ParserError:
            raise
        except (yaml.YAMLError, RecursionError, ValueError) as exc:
            raise ParserError(f"invalid YAML: {type(exc).__name__}") from exc
        _validate_json_limits(value)
        hint = _task_hint_from_mapping(value, relative_path) if isinstance(value, Mapping) else None
        metadata = _json_shape_metadata(value)
        asset_type = "structured_yaml"
        diagnostics: tuple[str, ...] = (
            "YAML was parsed with aliases, anchors, tags, and executable constructors disabled",
        )
        if (
            isinstance(value, Mapping)
            and isinstance(value.get("paths"), Mapping)
            and isinstance(value.get("openapi") or value.get("swagger"), str)
        ):
            asset_type = "openapi_document"
            operations = _openapi_operations(value["paths"], global_security=value.get("security"))
            servers = value.get("servers", [])
            metadata = {
                "specification_version": str(value.get("openapi") or value.get("swagger"))[:64],
                "operation_count": len(operations),
                "operations": operations,
                "server_declaration_count": (
                    len(servers) if isinstance(servers, Sequence) and not isinstance(servers, str) else 0
                ),
                "network_access_performed": False,
                "root_type": "object",
            }
            hint = TaskHint(
                source_ref=relative_path,
                objectives=["Assess the supplied API description within explicit authorized scope."],
                scenario_candidates=[Scenario.API_ASSESSMENT],
                confidence=0.98,
                metadata={"servers_are_untrusted_data": True, "network_access_performed": False},
            )
            diagnostics += ("server declarations were retained only as counts; no URL was accessed",)
        return _ParserProduct(
            asset_type=asset_type,
            hints=() if hint is None else (hint,),
            metadata=metadata,
            diagnostics=diagnostics,
        )


def default_parser_registry() -> ParserRegistry:
    return ParserRegistry(
        (
            YamlParser(),
            PostmanJsonParser(),
            OpenApiJsonParser(),
            NdjsonParser(),
            DelimitedTextParser(),
            JsonParser(),
            TextParser(),
        )
    )


def _base_media_type(media_type: str) -> str:
    return media_type.partition(";")[0].strip().lower()


def _validate_relative_path(relative_path: str) -> None:
    if not relative_path or len(relative_path) > _MAX_PATH_LENGTH:
        raise ParserError("relative path is empty or too long")
    if _CONTROL_CHARACTER.search(relative_path):
        raise ParserError("relative path contains a control character")
    normalized = relative_path.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", normalized):
        raise ParserError("relative path must not be absolute or contain traversal")


def _decode_utf8(content: bytes) -> str:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParserError("input is not valid UTF-8") from exc
    if "\x00" in text:
        raise ParserError("input contains a NUL character")
    return text


def _bounded_lines(text: str, *, max_records: int) -> tuple[list[str], list[str]]:
    lines = text.splitlines()
    if len(lines) > max_records:
        raise ParserLimitError(f"input exceeds {max_records} records")
    if any(len(line.encode("utf-8")) > _MAX_TABULAR_LINE for line in lines):
        raise ParserLimitError(f"input line exceeds {_MAX_TABULAR_LINE} bytes")
    controls = sum(len(_CONTROL_CHARACTER.findall(line)) for line in lines)
    diagnostics = [f"normalized {controls} non-printing control character(s)"] if controls else []
    return lines, diagnostics


def _normalize_text(value: str) -> str:
    return _CONTROL_CHARACTER.sub("�", value)


def _load_bounded_json(content: bytes) -> Any:
    text = _decode_utf8(content)

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ParserError(f"JSON contains duplicate key: {key[:128]}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=object_pairs)
    except ParserError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ParserError(f"invalid JSON: {type(exc).__name__}") from exc
    _validate_json_limits(value)
    return value


def _validate_json_limits(value: Any) -> None:
    nodes = 0
    keys = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ParserLimitError(f"JSON exceeds {_MAX_JSON_NODES} nodes")
        if depth > _MAX_JSON_DEPTH:
            raise ParserLimitError(f"JSON nesting exceeds {_MAX_JSON_DEPTH}")
        if isinstance(item, Mapping):
            keys += len(item)
            if keys > _MAX_JSON_KEYS:
                raise ParserLimitError(f"JSON exceeds {_MAX_JSON_KEYS} keys")
            stack.extend((child, depth + 1) for child in item.values())
            if any(len(str(key)) > _MAX_JSON_STRING for key in item):
                raise ParserLimitError("JSON key exceeds string limit")
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str) and len(item) > _MAX_JSON_STRING:
            raise ParserLimitError("JSON string exceeds string limit")


def _openapi_operations(
    paths: Mapping[Any, Any],
    *,
    global_security: Any = None,
) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(path_item, Mapping):
            continue
        safe_path = _normalize_text(raw_path)[:2_048]
        for method in sorted(str(key).lower() for key in path_item if str(key).lower() in _HTTP_METHODS):
            raw_operation: Any = next(
                (value for key, value in path_item.items() if str(key).lower() == method),
                {},
            )
            operation = raw_operation if isinstance(raw_operation, Mapping) else {}
            raw_parameters: list[Any] = []
            for source in (path_item.get("parameters"), operation.get("parameters")):
                if isinstance(source, list):
                    raw_parameters.extend(source[:_MAX_TABULAR_COLUMNS])
            parameters = sorted(
                {
                    _normalize_text(str(item.get("name")))[:128]
                    for item in raw_parameters
                    if isinstance(item, Mapping) and isinstance(item.get("name"), str)
                }
            )
            effective_security = operation.get("security", global_security)
            security: list[str] = []
            if isinstance(effective_security, list):
                security = sorted(
                    {
                        _normalize_text(str(name))[:128]
                        for requirement in effective_security[:64]
                        if isinstance(requirement, Mapping)
                        for name in requirement
                    }
                )
            request_schema_present = _request_schema_present(operation, raw_parameters)
            operations.append(
                {
                    "method": method.upper(),
                    "path": safe_path,
                    "parameters": parameters,
                    "security": security,
                    "auth_required": bool(security),
                    "request_schema_present": request_schema_present,
                }
            )
            if len(operations) > _MAX_API_ENDPOINTS:
                raise ParserLimitError(f"OpenAPI document exceeds {_MAX_API_ENDPOINTS} operations")
    return operations


def _request_schema_present(operation: Mapping[Any, Any], parameters: list[Any]) -> bool:
    request_body = operation.get("requestBody")
    if isinstance(request_body, Mapping):
        content = request_body.get("content")
        if isinstance(content, Mapping):
            return any(isinstance(media, Mapping) and "schema" in media for media in content.values())
    return any(
        isinstance(parameter, Mapping)
        and parameter.get("in") == "body"
        and isinstance(parameter.get("schema"), Mapping)
        for parameter in parameters
    )


def _json_shape_metadata(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {"root_type": "object", "top_level_keys": sorted(str(key) for key in value)[:256]}
    if isinstance(value, list):
        return {"root_type": "array", "item_count": len(value)}
    return {"root_type": type(value).__name__}


def _task_hint_from_mapping(value: Mapping[str, Any], source_ref: str) -> TaskHint | None:
    objectives = _string_list(value.get("objectives", value.get("objective")))
    scope = _string_list(value.get("authorized_scope", value.get("target_scope")))
    constraints = _string_list(value.get("constraints"))
    prohibited = _string_list(value.get("prohibited_actions"))
    outputs = _string_list(value.get("expected_outputs"))
    success = _string_list(value.get("success_criteria"))
    scenario_text = str(value.get("primary_scenario", value.get("scenario", "")))
    scenarios = _scenario_candidates(" ".join([scenario_text, *objectives]))
    if not any((objectives, scope, constraints, prohibited, outputs, success, scenarios)):
        return None
    temporal = value.get("temporal_scope")
    return TaskHint(
        source_ref=source_ref,
        objectives=objectives,
        scenario_candidates=scenarios,
        authorized_scope_candidates=scope,
        constraints=constraints,
        prohibited_actions=prohibited,
        expected_outputs=outputs,
        success_criteria=success,
        temporal_scope=_normalize_text(temporal)[:1_024] if isinstance(temporal, str) else None,
        confidence=0.85,
        metadata={"content_is_untrusted_data": True},
    )


def _string_list(value: Any) -> list[str]:
    raw: list[str]
    if isinstance(value, str):
        raw = [value]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        raw = list(value)
    else:
        return []
    return [_normalize_text(item).strip()[:2_000] for item in raw[:100] if item.strip()]


def _scenario_candidates(value: str) -> list[Scenario]:
    text = value.casefold()
    candidates: list[Scenario] = []
    terms = (
        (Scenario.CODE_AUDIT, ("代码", "审计", "code", "python", "sast", "漏洞", "audit")),
        (Scenario.LOG_ANALYSIS, ("日志", "log", "syslog", "timeline")),
        (Scenario.INCIDENT_RESPONSE, ("应急", "incident", "containment")),
        (Scenario.API_ASSESSMENT, ("openapi", "postman", "api", "接口")),
        (Scenario.REVERSE_TRIAGE, ("逆向", "reverse", "binary", "yara")),
    )
    for scenario, keywords in terms:
        if any(keyword in text for keyword in keywords):
            candidates.append(scenario)
    return candidates


def _looks_like_formula(value: str) -> bool:
    stripped = value.lstrip()
    return bool(stripped) and stripped.startswith(_FORMULA_PREFIXES)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
