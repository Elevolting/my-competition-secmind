from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel

from secmind.prompting.contracts import (
    ComplexityClass,
    PromptContext,
    PromptRole,
    RepositoryShape,
    RiskClass,
    canonical_digest,
)

_FRAMEWORK_MARKERS: dict[str, tuple[str, ...]] = {
    "spring-mvc": ("org.springframework", "@RequestMapping", "@RestController", "@Controller"),
    "servlet": ("javax.servlet", "jakarta.servlet", "HttpServletRequest", "HttpServletResponse"),
    "jdbc": ("java.sql", "PreparedStatement", "Statement", "DataSource"),
    "jpa": ("jakarta.persistence", "javax.persistence", "EntityManager", "@Query"),
    "mybatis": ("org.apache.ibatis", "@Select", "@Update", "${", "#{"),
}
_SOURCE_MARKERS = re.compile(r"\b(?:getParameter|getHeader|getCookies|getInputStream|getReader|System\.getenv)\b")
_SINK_MARKERS = re.compile(
    r"\b(?:executeQuery|executeUpdate|Runtime\.getRuntime|ProcessBuilder|Paths\.get|Path\.of|setSecure)\b"
)
_TOOL_SIGNAL_MARKERS: dict[str, re.Pattern[str]] = {
    "runtime_exec": re.compile(r"\bRuntime\s*\.\s*getRuntime\s*\("),
    "process_builder": re.compile(r"\b(?:new\s+)?ProcessBuilder\s*\("),
    "archive_entry": re.compile(r"\b(?:ZipEntry|JarEntry|TarArchiveEntry|getNextEntry)\b"),
    "file_path_api": re.compile(r"\b(?:Paths\.get|Path\.of|Files\.[A-Za-z]+|new\s+File)\b"),
}


class PromptContextProfiler:
    """Build trusted feature cards without exposing raw source to an optimizer."""

    @staticmethod
    def output_schema_ref(output_model: type[BaseModel]) -> str:
        return f"secmind://prompt-schemas/{output_model.__module__}.{output_model.__name__}"

    def profile_code_sources(
        self,
        *,
        run_id: str,
        role: PromptRole,
        phase: str,
        sources: Iterable[Any],
        support_files: Iterable[Any],
        target_cwes: Iterable[int],
        scope_digest: str,
        output_model: type[BaseModel],
        token_budget: int,
        deadline_remaining_ms: int,
        capability_profile: str = "code-audit",
        conflict_type: str | None = None,
        evidence_gap_codes: Iterable[str] = (),
        tool_signal_types: Iterable[str] = (),
    ) -> PromptContext:
        source_items = tuple(sources)
        support_items = tuple(support_files)
        paths = [self._path(item) for item in (*source_items, *support_items)]
        contents = [self._content(item) for item in source_items]
        detected_languages = {language for path in paths if (language := self._language(path)) is not None}
        languages = tuple(sorted(detected_languages))
        frameworks = tuple(
            sorted(
                framework
                for framework, markers in _FRAMEWORK_MARKERS.items()
                if any(marker in content for marker in markers for content in contents)
            )
        )
        source_count = sum(len(_SOURCE_MARKERS.findall(content)) for content in contents)
        sink_count = sum(len(_SINK_MARKERS.findall(content)) for content in contents)
        signals = {str(signal).strip().casefold() for signal in tool_signal_types if str(signal).strip()}
        signals.update(
            signal
            for signal, pattern in _TOOL_SIGNAL_MARKERS.items()
            if any(pattern.search(content) for content in contents)
        )
        shape = self._shape(paths)
        total_bytes = sum(len(content.encode("utf-8")) for content in contents)
        complexity = (
            ComplexityClass.HIGH
            if len(source_items) > 5 or total_bytes > 80_000
            else ComplexityClass.MEDIUM
            if len(source_items) > 1 or total_bytes > 20_000
            else ComplexityClass.LOW
        )
        feature_digest = canonical_digest(
            {
                "source_digests": [self._digest(item) for item in source_items],
                "support_digests": [self._digest(item) for item in support_items],
                "paths": sorted(paths),
                "frameworks": frameworks,
                "source_count": source_count,
                "sink_count": sink_count,
                "tool_signal_types": sorted(signals),
            }
        )
        gaps = set(evidence_gap_codes)
        is_code_profile = capability_profile in {"code-audit", "source_code_security"}
        if is_code_profile and not frameworks:
            gaps.add("framework_unknown")
        if not support_items:
            gaps.add("support_context_absent")
        return PromptContext.create(
            run_id=run_id,
            role=role,
            phase=phase,
            languages=languages or ("unknown",),
            frameworks=frameworks,
            target_cwes=tuple(target_cwes),
            capability_profile=(
                "java-source-review"
                if capability_profile in {"code-audit", "source_code_security"} and "java" in languages
                else capability_profile
            ),
            repository_shape=shape,
            evidence_gap_codes=tuple(gaps),
            conflict_type=conflict_type,
            parser_coverage=1.0 if source_items else 0.0,
            tool_signal_types=tuple(sorted(signals)),
            source_count=source_count,
            sink_count=sink_count,
            support_file_count=len(support_items),
            complexity_class=complexity,
            risk_class=(
                RiskClass.HIGH_IMPACT
                if set(target_cwes).intersection({22, 78, 89, 90, 502, 611, 918})
                else RiskClass.NORMAL
            ),
            token_budget=token_budget,
            deadline_remaining_ms=max(0, deadline_remaining_ms),
            trusted_feature_digest=feature_digest,
            scope_digest=scope_digest,
            output_schema_ref=self.output_schema_ref(output_model),
        )

    @staticmethod
    def _path(item: Any) -> str:
        unit = getattr(item, "unit", None)
        return str(getattr(unit, "primary_path", getattr(item, "path", "unknown"))).replace("\\", "/")

    @staticmethod
    def _content(item: Any) -> str:
        return str(getattr(item, "content", ""))

    def _digest(self, item: Any) -> str:
        unit = getattr(item, "unit", None)
        known = getattr(unit, "source_sha256", getattr(item, "sha256", None))
        if isinstance(known, str) and re.fullmatch(r"[a-f0-9]{64}", known):
            return known
        return hashlib.sha256(self._content(item).encode("utf-8")).hexdigest()

    @staticmethod
    def _language(path: str) -> str | None:
        suffix = PurePosixPath(path).suffix.casefold()
        return {
            ".java": "java",
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".go": "go",
            ".php": "php",
            ".cs": "csharp",
        }.get(suffix)

    @staticmethod
    def _shape(paths: list[str]) -> RepositoryShape:
        if not paths:
            return RepositoryShape.PARTIAL
        module_manifest_names = {
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "pyproject.toml",
            "package.json",
            "go.mod",
            "composer.json",
        }
        module_roots = {
            path.rsplit("/", 1)[0] if "/" in path else "."
            for path in paths
            if path.rsplit("/", 1)[-1].casefold() in module_manifest_names
            or path.casefold().endswith((".csproj", ".sln"))
        }
        if len(module_roots) >= 4:
            return RepositoryShape.MONOREPO
        if len(module_roots) >= 2:
            return RepositoryShape.MULTI_MODULE
        return RepositoryShape.SINGLE


__all__ = ["PromptContextProfiler"]
