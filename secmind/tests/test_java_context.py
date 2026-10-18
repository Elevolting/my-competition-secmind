from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from secmind.audit_kernel.java_context import dependency_closed_support, load_java_source_units
from secmind.schemas import InputArtifact


def _artifact(root: Path, relative_path: str, content: str) -> InputArtifact:
    encoded = content.encode("utf-8")
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(encoded)
    return InputArtifact(
        original_name=target.name,
        relative_path=relative_path,
        sha256=hashlib.sha256(encoded).hexdigest(),
        size_bytes=len(encoded),
    )


def test_java_context_closes_imports_and_configuration(tmp_path: Path) -> None:
    controller = _artifact(
        tmp_path,
        "src/app/Controller.java",
        "package app; import app.Helper; class Controller { Helper helper; }",
    )
    helper = _artifact(tmp_path, "src/app/Helper.java", "package app; class Helper {}")
    xml = _artifact(tmp_path, "src/resources/routes.xml", "<routes><route path='/admin'/></routes>")

    cases, support = load_java_source_units(str(tmp_path), [xml, helper, controller], ["src"])
    support_by_source = dependency_closed_support(cases, support)

    assert [item.path for item in cases] == ["src/app/Controller.java", "src/app/Helper.java"]
    assert [item.path for item in support] == ["src/resources/routes.xml"]
    assert "src/app/Helper.java" in support_by_source["src/app/Controller.java"]
    assert "src/resources/routes.xml" in support_by_source["src/app/Controller.java"]


def test_java_context_rejects_unsafe_scope(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unsafe path"):
        load_java_source_units(str(tmp_path), [], ["../outside"])
