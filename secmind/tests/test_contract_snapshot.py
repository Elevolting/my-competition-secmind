from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from pydantic import BaseModel

import secmind.schemas as public_schemas
from secmind.api import create_app
from secmind.config import Settings
from secmind.investigation.prompts import PromptRegistry
from secmind.prompting import PromptCatalog
from secmind.schemas import SCHEMA_VERSION, LedgerEvent, ToolContext, ToolManifest, ToolResult


def canonical_sha256(value: object) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def test_historical_contract_snapshots_remain_available() -> None:
    for name, version in (
        ("public-v1.2.json", "1.2"),
        ("golden-v1.2.json", "1.2"),
        ("public-v1.3.json", "1.3"),
        ("golden-v1.3.json", "1.3"),
        ("public-v1.4.json", "1.4"),
        ("golden-v1.4.json", "1.4"),
        ("public-v1.5.json", "1.5"),
        ("golden-v1.5.json", "1.5"),
        ("public-v1.6.json", "1.6"),
        ("golden-v1.6.json", "1.6"),
    ):
        historical = json.loads((Path("contracts") / name).read_text(encoding="utf-8"))
        assert historical["schema_version"] == version


def test_public_v17_contract_snapshot(tmp_path: Path) -> None:
    expected = json.loads(Path("contracts/public-v1.7.json").read_text(encoding="utf-8"))
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'contract.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        unsafe_development_tools=True,
    )
    app = create_app(settings)
    route_paths = {getattr(route, "path", "") for route in app.routes}
    v08_paths = {
        "/api/v1/runs/{run_id}/admission",
        "/api/v1/runs/{run_id}/evidence-gaps",
    }
    assert expected["schema_version"] == SCHEMA_VERSION
    assert v08_paths <= set(expected["paths"])
    assert v08_paths <= route_paths
    assert set(expected["paths"]) <= route_paths
    assert sorted(ToolContext.model_fields) == expected["tool_context_fields"]
    assert sorted(ToolResult.model_fields) == expected["tool_result_fields"]


def test_openapi_schema_manifest_event_and_migration_golden(tmp_path: Path) -> None:
    expected = json.loads(Path("contracts/golden-v1.7.json").read_text(encoding="utf-8"))
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'golden.db').as_posix()}",
        input_root=tmp_path / "inputs",
        upload_root=tmp_path / "uploads",
        run_root=tmp_path / "runs",
        artifact_root=tmp_path / "artifacts",
        unsafe_development_tools=True,
    )
    models = {
        name: model.model_json_schema()
        for name, model in inspect.getmembers(public_schemas, inspect.isclass)
        if model.__module__ == public_schemas.__name__ and issubclass(model, BaseModel)
    }
    migration_heads = sorted(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())
    v08_models = {
        "BaselineAdmission",
        "EvidenceGapTicket",
        "PublishedBaselineProjection",
        "RawPrimaryReceipt",
        "SealedAdmissionSnapshot",
    }

    assert v08_models <= set(models)
    assert expected == {
        "schema_version": SCHEMA_VERSION,
        "openapi_sha256": canonical_sha256(create_app(settings).openapi()),
        "public_models_sha256": canonical_sha256(models),
        "tool_manifest_sha256": canonical_sha256(ToolManifest.model_json_schema()),
        "ledger_event_sha256": canonical_sha256(LedgerEvent.model_json_schema()),
        "prompt_manifest_sha256": canonical_sha256(PromptRegistry.builtin().manifest()),
        "adaptive_prompt_catalog_sha256": canonical_sha256(PromptCatalog.builtin().manifest()),
        "migration_heads": migration_heads,
    }
