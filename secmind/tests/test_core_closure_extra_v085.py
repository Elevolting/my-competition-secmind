from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import secmind.orchestration.evidence_compiler_runtime as evidence_compiler_runtime
import secmind.orchestration.primary_runtime as primary_runtime
from secmind.answer_revision_contracts import (
    ApiOperationPatch,
    ExactAnswerPatch,
    FindingPatch,
    ProviderIdentity,
    ReceiptBinding,
    RevisionError,
    RevisionOperation,
    ScoringMode,
)
from secmind.answer_revision_materializer import (
    _apply_exact_answer,
    _apply_list_patch,
    _extension_container,
    _item_id,
    _merge_evidence,
    _supplement_item,
    _supplement_value,
    apply_revision,
    validate_revision,
)
from secmind.answer_revisions import make_revision
from secmind.artifact_store import ContentAddressedArtifactStore
from secmind.published_answer_models import PublishedAnswer
from secmind.sandbox import (
    CREATED_LABEL,
    FENCE_LABEL,
    INVOCATION_LABEL,
    RESOURCE_LABEL,
    RUN_LABEL,
    DockerSandboxBackend,
    MockSandboxBackend,
    SandboxArtifact,
    SandboxError,
    SandboxInputFile,
    SandboxInvocation,
    SandboxLimits,
    SandboxLog,
    SandboxResult,
    SandboxRunner,
    SandboxToolSpec,
    collect_sandbox_input_files,
    default_allowlist,
    invocation_input_sha256,
    token_matches,
    validate_relative_path,
)
from secmind.schemas import (
    AgentReport,
    AgentState,
    Claim,
    ClaimStatus,
    Evidence,
    EvidenceLink,
    EvidenceRelation,
    InputArtifact,
    ParsedAsset,
    ParserRun,
    RunStatus,
    TaskHint,
    TaskRequest,
)
from secmind.task_contract import canonical_digest, compile_resolved_task_contract


def _published(mode: ScoringMode, payload: dict[str, Any]) -> PublishedAnswer:
    provider = ProviderIdentity(
        provider="test-provider",
        model_id="test-model",
        request_id="request-1",
        request_digest="a" * 64,
        response_digest="b" * 64,
        response_schema_digest="c" * 64,
        provider_requests=1,
    )
    receipt = ReceiptBinding.create(
        receipt_id="receipt-1",
        provider=provider.provider,
        model_id=provider.model_id,
        request_digest=provider.request_digest,
        response_digest=provider.response_digest,
        response_schema_digest=provider.response_schema_digest,
    )
    domains = {
        ScoringMode.SECURITY_FINDING: "code_audit_and_patch",
        ScoringMode.FORENSIC_ATTRIBUTION: "logs_ir_hunting",
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE: "complex_input_understanding",
    }
    task_id = f"task-{mode.value}"
    return PublishedAnswer(
        answer_id=f"answer-{mode.value}",
        run_id="run-materializer",
        task_id=task_id,
        scoring_mode=mode,
        domain=domains.get(mode, mode.value),
        provider=provider,
        receipt=receipt,
        answer={"task_id": task_id, "status": "completed", **payload},
    )


def test_revision_materializer_covers_append_only_list_modes_and_validation() -> None:
    base = _published(
        ScoringMode.SECURITY_FINDING,
        {
            "findings": [{"finding_id": "f-1", "rule_id": "CWE-79", "fields": {"old": True}, "evidence_ids": ["e-1"]}],
            "evidence": ["e-1"],
        },
    )
    supplement = make_revision(
        base,
        operation="supplement",
        field="findings",
        target_id="f-1",
        payload=FindingPatch(
            finding_id="f-1",
            rule_id="CWE-79",
            severity="HIGH",
            path="app.py",
            line=1,
            evidence_ids=("e-2",),
        ),
        reason="independent corroboration",
        evidence_ids=("e-2", "e-1"),
    )
    revised = apply_revision(base, supplement)
    assert revised.answer.findings[0]["severity"] == "HIGH"
    assert revised.answer.findings[0]["evidence_ids"] == ["e-1", "e-2"]
    assert revised.answer.extensions["evidence_ids"] == ["e-1", "e-2"]

    append = make_revision(
        revised,
        operation="supplement",
        field="findings",
        payload=FindingPatch(finding_id="f-2", cwe=89, path="db.py", line=2),
        reason="new bounded claim",
    )
    appended = apply_revision(revised, append)
    assert appended.answer.findings[-1]["finding_id"] == "f-2"

    absent_retract = make_revision(
        appended,
        operation="retract",
        field="findings",
        target_id="missing",
        reason="invalidated",
    )
    assert validate_revision(appended, absent_retract)[0] is False
    with pytest.raises(RevisionError, match="cannot retract absent"):
        apply_revision(appended, absent_retract)

    absent_replace = make_revision(
        appended,
        operation="replace",
        field="findings",
        target_id="missing",
        payload=FindingPatch(finding_id="missing", cwe=1, path="missing.py", line=1),
        reason="invalid replacement",
    )
    with pytest.raises(RevisionError, match="cannot replace absent"):
        apply_revision(appended, absent_replace)


def test_revision_materializer_covers_api_container_and_exact_answer_paths() -> None:
    api_base = _published(
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE,
        {
            "values": "inventory",
            "extensions": {"api_operations": [{"operation_id": "op-1", "method": "GET", "path": "/items"}]},
        },
    )
    api_revision = make_revision(
        api_base,
        operation="replace",
        field="api_operation",
        target_id="op-1",
        payload=ApiOperationPatch(operation_id="op-1", method="PATCH", path="/items"),
        reason="operation normalized",
    )
    api_revised = apply_revision(api_base, api_revision)
    assert api_revised.answer.extensions["api_operations"][0]["method"] == "PATCH"

    exact = _published(
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE,
        {
            "values": {"count": 1},
            "mapping": {"key": "old"},
            "items": [{"id": "item-1", "value": "old"}],
            "extensions": {"custom": {"value": 1}},
        },
    )
    replace_mapping = make_revision(
        exact,
        operation="replace",
        field="exact_answer",
        target_id="key",
        payload=ExactAnswerPatch(answer_id="key", value="new"),
        reason="mapping correction",
    )
    exact = apply_revision(exact, replace_mapping)
    assert exact.answer.mapping["key"] == "new"

    supplement_values = make_revision(
        exact,
        operation="supplement",
        field="exact_answer",
        target_id="values",
        payload=ExactAnswerPatch(answer_id="values", value={"extra": 2}),
        reason="add exact field",
    )
    exact = apply_revision(exact, supplement_values)
    assert exact.answer.values == {"count": 1, "extra": 2}

    supplement_item = make_revision(
        exact,
        operation="supplement",
        field="exact_answer",
        target_id="items",
        payload=ExactAnswerPatch(answer_id="items", value={"id": "item-2", "value": "new"}),
        reason="add exact item",
    )
    exact = apply_revision(exact, supplement_item)
    assert {item["id"] for item in exact.answer.items} == {"item-1", "item-2"}

    retract_item = make_revision(
        exact,
        operation="retract",
        field="exact_answer",
        target_id="item-1",
        reason="item withdrawn",
    )
    exact = apply_revision(exact, retract_item)
    assert [item["id"] for item in exact.answer.items] == ["item-2"]

    retract_extension = make_revision(
        exact,
        operation="retract",
        field="exact_answer",
        target_id="custom",
        reason="extension withdrawn",
    )
    exact = apply_revision(exact, retract_extension)
    assert "custom" not in exact.answer.extensions

    with pytest.raises(RevisionError, match="cannot retract absent exact"):
        apply_revision(
            exact,
            make_revision(
                exact,
                operation="retract",
                field="exact_answer",
                target_id="missing",
                reason="not present",
            ),
        )

    with pytest.raises(RevisionError, match="cannot replace absent exact"):
        apply_revision(
            exact,
            make_revision(
                exact,
                operation="replace",
                field="exact_answer",
                target_id="missing",
                payload=ExactAnswerPatch(answer_id="missing", value=1),
                reason="not present",
            ),
        )


def test_revision_materializer_exact_supplement_conflicts_and_low_level_containers() -> None:
    answer = {"mapping": {}, "extensions": {"evidence": ["e-1"]}, "evidence": ["e-0"]}
    _merge_evidence(answer, ["e-2", "", "e-1"])
    assert answer["evidence"] == ["e-0", "e-1", "e-2"]
    assert answer["extensions"]["evidence_ids"] == ["e-0", "e-1", "e-2"]
    assert _extension_container({}, ("operations", "api_operations"))[1] == "operations"
    assert _extension_container({"api_operations": []}, ("operations", "api_operations"))[1] == "api_operations"
    assert _supplement_item(
        {"id": "x", "fields": {"a": 1}, "evidence_ids": ["e-1"]},
        {"fields": {"b": 2}, "evidence_ids": ["e-2"], "ignored": None},
    ) == {"id": "x", "fields": {"a": 1, "b": 2}, "evidence_ids": ["e-1", "e-2"]}
    assert _supplement_value(None, "x") == "x"
    assert _supplement_value([1], [1, 2]) == [1, 2]
    assert _supplement_value("same", "same") == "same"
    with pytest.raises(RevisionError, match="cannot replace"):
        _supplement_value({"a": 1}, {"a": 2})
    with pytest.raises(RevisionError, match="compatible"):
        _supplement_value("a", "b")
    payload: dict[str, Any] = {"mapping": {"k": 1}, "values": "v", "items": [{"id": "i"}], "extensions": {"x": 1}}
    _apply_list_patch(
        payload,
        "absent",
        SimpleNamespace(
            operation="supplement",
            target_id=None,
            payload=SimpleNamespace(model_dump=lambda **_: {"id": "new"}),
        ),
    )
    assert payload["absent"][0]["id"] == "new"


def test_revision_materializer_rejects_stale_chain_metadata_and_handles_exact_low_level_paths() -> None:
    base = _published(
        ScoringMode.EXACT_ANSWER_WITH_EVIDENCE,
        {"values": "value", "mapping": {"key": "old"}, "items": [], "extensions": {}},
    )
    valid = make_revision(
        base,
        operation="supplement",
        field="exact_answer",
        target_id="key",
        payload=ExactAnswerPatch(answer_id="key", value="old"),
        reason="replay validation",
    )
    assert validate_revision(base, valid) == (True, None)
    for update, message in (
        ({"answer_id": "other"}, "another answer"),
        ({"base_answer_digest": "f" * 64}, "base_answer_digest"),
        ({"revision_number": valid.revision_number + 1}, "revision number"),
    ):
        with pytest.raises(RevisionError, match=message):
            apply_revision(base, valid.model_copy(update=update))
    duplicate_base = base.model_copy(update={"revision_ids": (valid.revision_id,)})
    with pytest.raises(RevisionError, match="already present"):
        apply_revision(duplicate_base, valid)

    missing_payload = SimpleNamespace(
        operation=RevisionOperation.SUPPLEMENT,
        target_id="new",
        payload=None,
    )
    with pytest.raises(RevisionError, match="typed payload"):
        _apply_list_patch({}, "events", missing_payload)

    mapping = {"mapping": {"key": "value"}, "values": "scalar", "items": [{"id": "item"}]}
    _apply_exact_answer(
        mapping,
        SimpleNamespace(operation=RevisionOperation.RETRACT, target_id="key", payload=None),
    )
    assert "key" not in mapping["mapping"]
    _apply_exact_answer(
        mapping,
        SimpleNamespace(operation=RevisionOperation.RETRACT, target_id="values", payload=None),
    )
    assert mapping["values"] is None
    _apply_exact_answer(
        mapping,
        SimpleNamespace(operation=RevisionOperation.RETRACT, target_id="item", payload=None),
    )
    assert mapping["items"] == []
    _apply_exact_answer(
        mapping,
        SimpleNamespace(
            operation=RevisionOperation.SUPPLEMENT,
            target_id="new-key",
            payload=ExactAnswerPatch(answer_id="new-key", value=1),
        ),
    )
    assert mapping["mapping"]["new-key"] == 1
    _apply_exact_answer(
        {"values": None},
        SimpleNamespace(
            operation=RevisionOperation.SUPPLEMENT,
            target_id="items",
            payload=ExactAnswerPatch(answer_id="items", value={"id": "new"}),
        ),
    )
    container: dict[str, Any] = {}
    _apply_exact_answer(
        container,
        SimpleNamespace(
            operation=RevisionOperation.SUPPLEMENT,
            target_id="values",
            payload=ExactAnswerPatch(answer_id="values", value=[1]),
        ),
    )
    assert container["values"] == [1]
    assert _item_id({}) is None
    _merge_evidence({"evidence": []}, ["e-1"])


def _resolved_contract(run_id: str) -> Any:
    return compile_resolved_task_contract(
        {
            "task_spec_id": "spec-compiler",
            "run_id": run_id,
            "revision": 1,
            "content_digest": "1" * 64,
            "objectives": ["compile parser evidence"],
            "primary_scenario": "unknown",
            "primary_domain": "complex_input_understanding",
            "secondary_scenarios": [],
            "secondary_capabilities": [],
            "scoring_mode": "exact_answer_with_evidence",
            "interaction_mode": "unattended",
            "autonomy_policy": "automatic",
            "authorized_scope": ["artifact:file.txt"],
            "constraints": [],
            "prohibited_actions": [],
            "expected_outputs": [],
            "success_criteria": [],
            "output_contract": {},
            "asset_ids": ["asset-1"],
        },
        input_manifest_digest="2" * 64,
    )


@pytest.mark.asyncio
async def test_evidence_compiler_handles_missing_contract_reuse_lfs_and_parser_gaps() -> None:
    state = AgentState(run_id="compiler-run", task=TaskRequest(objective="compile"))
    checkpoints: list[str] = []

    async def checkpoint(*args: Any) -> Any:
        checkpoints.append(str(args[1]))
        return args[0]

    missing_host = SimpleNamespace(_state=lambda _value: state, _checkpoint=checkpoint)
    await evidence_compiler_runtime.compile_evidence(missing_host, {})
    assert state.status == RunStatus.RECOVERY_REQUIRED
    assert checkpoints[-1] == "evidence_compiler.contract_missing"

    state.resolved_task_contract = _resolved_contract(state.run_id)
    receipt_payload = {
        "run_id": state.run_id,
        "contract_digest": state.resolved_task_contract.contract_digest,
        "input_manifest_digest": state.resolved_task_contract.input_manifest_digest,
        "facts": [],
    }
    from secmind.task_contract import EvidenceCompilerReceipt

    state.evidence_compiler_receipt = EvidenceCompilerReceipt.model_validate(
        {**receipt_payload, "output_digest": canonical_digest(receipt_payload)}
    )
    reused_host = SimpleNamespace(_state=lambda _value: state, _checkpoint=checkpoint)
    await evidence_compiler_runtime.compile_evidence(reused_host, {})
    assert checkpoints[-1] == "evidence_compiler.reused"
    state.evidence_compiler_receipt = None

    content = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"a" * 64 + b"\nsize 123\n"
    digest = hashlib.sha256(content).hexdigest()
    lfs = InputArtifact(
        artifact_id="artifact-lfs",
        original_name="large.bin",
        relative_path="large.bin",
        sha256=digest,
        size_bytes=len(content),
        media_type="application/octet-stream",
    )
    normal_content = b"ordinary content"
    normal_digest = hashlib.sha256(normal_content).hexdigest()
    normal = InputArtifact(
        artifact_id="artifact-normal",
        original_name="normal.txt",
        relative_path="normal.txt",
        sha256=normal_digest,
        size_bytes=len(normal_content),
        media_type="text/plain",
    )
    oversized = InputArtifact(
        artifact_id="artifact-big",
        original_name="big.bin",
        relative_path="big.bin",
        sha256="3" * 64,
        size_bytes=4097,
        media_type="application/octet-stream",
    )
    state.input_artifacts = [lfs, normal, oversized]
    asset = ParsedAsset(
        parsed_asset_id="parsed-1",
        parser_id="text-parser",
        parser_version="1",
        artifact_id=normal.artifact_id,
        relative_path=normal.relative_path,
        media_type=normal.media_type,
        asset_type="text",
        content_digest=normal_digest,
        hints=[TaskHint(source_ref="normal.txt", confidence=0.7)],
        diagnostics=["parsed"],
    )
    missing_asset = asset.model_copy(update={"parsed_asset_id": "parsed-missing", "artifact_id": "missing"})
    parser_runs = [
        ParserRun(
            run_id=state.run_id,
            artifact_id=normal.artifact_id,
            parser_id="text-parser",
            parser_version="1",
            status="failed",
            input_digest=normal_digest,
            diagnostics=["bad encoding"],
        ),
        ParserRun(
            run_id=state.run_id,
            artifact_id=lfs.artifact_id,
            parser_id="lfs-parser",
            parser_version="1",
            status="partial",
            input_digest=digest,
        ),
    ]

    class Store:
        def read(self, ref: str) -> bytes:
            if ref == digest:
                return content
            if ref == normal_digest:
                return normal_content
            raise ValueError("not found")

    host = SimpleNamespace(
        _state=lambda _value: state,
        _checkpoint=checkpoint,
        artifact_store=Store(),
        task_spec_repository=SimpleNamespace(
            parsed_assets=lambda _run: [missing_asset, asset],
            parser_runs=lambda _run: parser_runs,
        ),
    )
    await evidence_compiler_runtime.compile_evidence(host, {})
    assert state.evidence_compiler_receipt is not None
    assert state.audit_coverage["evidence_compiler"]["fact_count"] == 2
    assert state.audit_coverage["evidence_compiler"]["unavailable_count"] == 2
    assert state.audit_coverage["deterministic_evidence_gaps"]["git_lfs_pointer_sources"] == ["large.bin"]
    assert len(state.claims) == 1
    await evidence_compiler_runtime.compile_evidence(host, {})
    assert len(state.claims) == 1


def test_append_verified_scenario_evidence_is_bounded_and_report_safe() -> None:
    state = AgentState(run_id="evidence-report", task=TaskRequest(objective="evidence"))
    state.report = AgentReport(run_id=state.run_id, status=RunStatus.PARTIAL, executive_summary="report")
    evidence = Evidence(
        evidence_id="e-verified",
        source="parser:test",
        summary="verified",
        metadata={"assurance_level": "deterministic"},
    )
    state.evidence = [evidence]
    claim = Claim(
        claim_id="claim-scenario",
        claim_type="exact_value_observed",
        statement="exact value",
        subject_ref="x",
        status=ClaimStatus.VERIFIED,
        confidence=1,
        producer="deterministic-scenario-analyzer",
    )
    state.claims = [claim]
    state.evidence_links = [
        EvidenceLink(
            link_id="link-scenario",
            claim_id=claim.claim_id,
            evidence_id=evidence.evidence_id,
            relation=EvidenceRelation.SUPPORTS,
            weight=1,
            verifier_status=ClaimStatus.VERIFIED,
            grader_id="deterministic",
        )
    ]
    evidence_compiler_runtime.append_verified_scenario_evidence(state)
    assert state.report.evidence[0].evidence_id == evidence.evidence_id
    assert state.report.claim_ids == [claim.claim_id]


def test_primary_runtime_duplicate_digest_path_is_explicitly_deduplicated() -> None:
    state = AgentState(run_id="primary-dedup", task=TaskRequest(objective="merge"))
    state.audit_coverage["pre_primary_scenario_projection"] = {
        "answer_payload": {
            "answer_kind": "timeline",
            "events": [{"event_id": "same"}, {"event_id": "same"}],
            "facts": [],
        }
    }

    class Answer:
        def model_dump(self, mode: str = "json") -> dict[str, Any]:
            del mode
            return {"answer_kind": "timeline", "events": [{"event_id": "same"}], "facts": []}

        @classmethod
        def model_validate(cls, payload: dict[str, Any]) -> dict[str, Any]:
            return payload

    assert primary_runtime.fuse_pre_primary_scenario_answer(state, Answer())["events"] == [{"event_id": "same"}]


def test_sandbox_path_collection_and_runner_terminal_guards(tmp_path: Path) -> None:
    assert validate_relative_path("src/app.py", description="path") == "src/app.py"
    for bad in ("", ".", "../escape", "a\\b", "a/./b"):
        with pytest.raises(ValueError):
            validate_relative_path(bad, description="path")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_bytes(b"print(1)")
    files = collect_sandbox_input_files(tmp_path)
    assert files[0].path == "src/app.py"
    assert files[0].decoded() == b"print(1)"
    assert token_matches("secret", "secret")
    assert not token_matches("secret", "wrong")
    assert not token_matches("", "secret")

    spec = SandboxToolSpec(
        name="bandit_python_audit",
        image_digest="sha256:" + "a" * 64,
        entrypoint=("run",),
        limits=SandboxLimits(max_parallelism=1),
    )
    invocation = SandboxInvocation(
        run_id="run-terminal",
        invocation_id="invoke-terminal",
        tool_name=spec.name,
        lease_fence=2,
        files=[SandboxInputFile(path="app.py", content_base64=base64.b64encode(b"x").decode())],
    )
    runner = SandboxRunner(MockSandboxBackend(), {spec.name: spec}, max_parallelism=1)
    result = asyncio.run(runner.execute(invocation))
    assert result.status == "success"
    with pytest.raises(SandboxError, match="terminal"):
        asyncio.run(runner.execute(invocation))
    stale = invocation.model_copy(update={"invocation_id": "invoke-stale", "lease_fence": 1})
    with pytest.raises(SandboxError, match="stale"):
        asyncio.run(runner.execute(stale))
    too_large = invocation.model_copy(
        update={
            "invocation_id": "invoke-large",
            "files": [SandboxInputFile(path="x", content_base64=base64.b64encode(b"xx").decode())],
        }
    )
    small_spec = spec.__class__(
        name=spec.name,
        image_digest=spec.image_digest,
        entrypoint=spec.entrypoint,
        limits=SandboxLimits(max_input_bytes=1, max_parallelism=1),
    )
    with pytest.raises(SandboxError, match="input"):
        asyncio.run(SandboxRunner(MockSandboxBackend(), {spec.name: small_spec}).execute(too_large))


def test_sandbox_output_and_docker_helper_failure_branches() -> None:
    def tar_payload(files: dict[str, bytes]) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return stream.getvalue()

    raw = tar_payload({"./result.json": b'{"ok": true}', "./out.txt": b"payload"})
    container = SimpleNamespace(get_archive=lambda _path: (iter([raw]), {}))
    artifacts, body = DockerSandboxBackend._read_outputs(container, 10_000)
    assert body == {"ok": True}
    assert artifacts[0].relative_path == "out.txt"
    assert DockerSandboxBackend._resource_already_gone(RuntimeError("404 not found"))
    assert DockerSandboxBackend._resource_already_gone(RuntimeError("already in progress"))
    assert not DockerSandboxBackend._resource_already_gone(RuntimeError("permission denied"))
    assert DockerSandboxBackend._exec_exit_code((7, b"")) == 7
    assert DockerSandboxBackend._exec_exit_code(SimpleNamespace(exit_code=3)) == 3
    assert DockerSandboxBackend._is_timeout(TimeoutError("deadline"))
    assert not DockerSandboxBackend._is_timeout(RuntimeError("other"))
    log = DockerSandboxBackend._collect_logs(SimpleNamespace(logs=lambda **_kwargs: iter([b"abc", b"def"])), 3)
    assert log.tail == "def"
    assert log.truncated
    assert (
        invocation_input_sha256(
            SandboxInvocation(invocation_id="hash", tool_name="bandit_python_audit", files=[], run_id="hash-run")
        )
        == hashlib.sha256(b"").hexdigest()
    )


def test_sandbox_allowlist_uses_only_pinned_opt_in_images(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECMIND_SANDBOX_BANDIT_IMAGE", raising=False)
    monkeypatch.setenv("SECMIND_SANDBOX_SEMGREP_IMAGE", "sha256:" + "b" * 64)
    assert set(default_allowlist()) == {"semgrep_sast"}
    monkeypatch.setenv("SECMIND_SANDBOX_GITLEAKS_IMAGE", "sha256:" + "0" * 64)
    with pytest.raises(ValueError, match="zero sha256"):
        default_allowlist()


@pytest.mark.parametrize(
    "limits",
    [
        {"timeout_seconds": 0},
        {"cpu_cores": 0},
        {"memory_bytes": 0},
        {"pids_limit": 0},
        {"tmpfs_bytes": 0},
        {"max_input_bytes": 0},
        {"max_output_bytes": 0},
        {"max_log_tail_bytes": 0},
        {"max_parallelism": 0},
        {"max_artifacts": 0},
    ],
)
def test_sandbox_limits_reject_every_unbounded_dimension(limits: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        SandboxLimits(**limits)


def test_sandbox_input_collection_rejects_size_file_count_and_symlink(tmp_path: Path) -> None:
    target = tmp_path / "input.txt"
    target.write_bytes(b"12345")
    with pytest.raises(ValueError, match="exceeds"):
        collect_sandbox_input_files(target, max_file_bytes=4)
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "a").write_bytes(b"a")
    (folder / "b").write_bytes(b"b")
    with pytest.raises(ValueError, match="too many"):
        collect_sandbox_input_files(folder, max_files=1)
    with pytest.raises(ValueError, match="invalid"):
        SandboxInputFile(path="a.txt", content_base64="not-base64")
    link = folder / "link"
    try:
        link.symlink_to(folder / "a")
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError, match="symbolic"):
        collect_sandbox_input_files(folder)


@pytest.mark.asyncio
async def test_sandbox_runner_rejects_busy_mismatch_cleanup_and_scope_states() -> None:
    spec = SandboxToolSpec(
        name="bandit_python_audit",
        image_digest="sha256:" + "a" * 64,
        entrypoint=("run",),
        limits=SandboxLimits(max_parallelism=1),
    )
    invocation = SandboxInvocation(
        run_id="runner-branches",
        invocation_id="invoke-branches",
        tool_name=spec.name,
        files=[SandboxInputFile(path="app.py", content_base64=base64.b64encode(b"x").decode())],
    )

    class Backend:
        def __init__(self, result: SandboxResult | None = None) -> None:
            self.result = result
            self.resources: list[Any] = []

        async def execute(self, _spec: Any, request: SandboxInvocation) -> SandboxResult:
            if self.result is not None:
                return self.result
            return SandboxResult(
                invocation_id=request.invocation_id,
                status="success",
                cleanup_confirmed=True,
                logs=SandboxLog(sha256="0" * 64),
            )

        async def cancel(self, _invocation_id: str) -> bool:
            return False

        async def cleanup_orphans(self, **_kwargs: Any) -> int:
            return 0

        async def list_resources(self, _run_id: str) -> list[Any]:
            return self.resources

    with pytest.raises(SandboxError, match="registered"):
        await SandboxRunner(Backend(), {}).execute(invocation)

    global_runner = SandboxRunner(Backend(), {spec.name: spec}, max_parallelism=1)
    await global_runner._global_slots.acquire()
    try:
        with pytest.raises(SandboxError, match="concurrency"):
            await global_runner.execute(invocation)
    finally:
        global_runner._global_slots.release()

    tool_runner = SandboxRunner(Backend(), {spec.name: spec})
    await tool_runner._tool_slots[spec.name].acquire()
    try:
        with pytest.raises(SandboxError, match="tool concurrency"):
            await tool_runner.execute(invocation)
    finally:
        tool_runner._tool_slots[spec.name].release()

    cancelled_runner = SandboxRunner(Backend(), {spec.name: spec})
    cancelled_runner._cancel_requested.add(invocation.invocation_id)
    with pytest.raises(SandboxError, match="cancelled"):
        await cancelled_runner.execute(invocation)

    active_runner = SandboxRunner(Backend(), {spec.name: spec})
    active_runner._active_invocations[invocation.invocation_id] = invocation
    with pytest.raises(SandboxError, match="already running"):
        await active_runner.execute(invocation)

    mismatch_runner = SandboxRunner(
        Backend(
            SandboxResult(
                invocation_id="other",
                status="success",
                cleanup_confirmed=True,
                logs=SandboxLog(sha256="0" * 64),
            )
        ),
        {spec.name: spec},
    )
    with pytest.raises(SandboxError, match="different invocation"):
        await mismatch_runner.execute(invocation)

    not_clean_runner = SandboxRunner(
        Backend(
            SandboxResult(
                invocation_id=invocation.invocation_id,
                status="success",
                cleanup_confirmed=False,
                logs=SandboxLog(sha256="0" * 64),
            )
        ),
        {spec.name: spec},
    )
    with pytest.raises(SandboxError, match="cleanup"):
        await not_clean_runner.execute(invocation)

    scope_runner = SandboxRunner(Backend(), {spec.name: spec})
    scope_runner._backend.resources = [
        {
            "run_id": "other-run",
            "resource_id": "resource",
            "invocation_id": "invoke",
            "fence": 0,
            "active": True,
        }
    ]
    with pytest.raises(SandboxError, match="outside"):
        await scope_runner._backend_resources("runner-branches")
    with pytest.raises(SandboxError, match="invalid"):
        await scope_runner.list_resources("")
    assert await scope_runner.readiness() == {"backend": "Backend", "tools": 1}


def test_sandbox_runner_persistence_and_docker_fixed_entrypoint_helpers(tmp_path: Path) -> None:
    spec = SandboxToolSpec(
        name="bandit_python_audit",
        image_digest="sha256:" + "a" * 64,
        entrypoint=("run",),
        limits=SandboxLimits(max_output_bytes=10, max_log_tail_bytes=3),
    )
    artifact = SandboxArtifact(
        artifact_id="raw",
        relative_path="out.txt",
        sha256=hashlib.sha256(b"ok").hexdigest(),
        size_bytes=2,
        content_base64=base64.b64encode(b"ok").decode(),
    )
    result = SandboxResult(
        invocation_id="persist",
        status="success",
        artifacts=[artifact],
        logs=SandboxLog(sha256="0" * 64),
    )
    runner = SandboxRunner(
        MockSandboxBackend(),
        {spec.name: spec},
        artifact_store=ContentAddressedArtifactStore(tmp_path),
    )
    persisted = runner._persist_artifacts(result, limits=spec.limits)
    assert persisted.artifacts[0].content_base64 is None
    with pytest.raises(SandboxError, match="size"):
        runner._persist_artifacts(
            result.model_copy(update={"artifacts": [artifact.model_copy(update={"size_bytes": 3})]})
        )
    with pytest.raises(SandboxError, match="content"):
        runner._persist_artifacts(
            result.model_copy(update={"artifacts": [artifact.model_copy(update={"content_base64": None})]})
        )

    class Api:
        def exec_create(self, *_args: Any, **_kwargs: Any) -> str:
            return "exec-1"

        def exec_start(self, *_args: Any, **_kwargs: Any):
            return iter([(b"ab", b"cd"), b"ef"])

        def exec_inspect(self, _exec_id: str) -> dict[str, int]:
            return {"ExitCode": 0}

    class Container:
        id = "container"

        def kill(self) -> None:
            return None

        def exec_run(self, *_args: Any, **_kwargs: Any) -> SimpleNamespace:
            return SimpleNamespace(exit_code=0)

    client = SimpleNamespace(api=Api())
    request = SandboxInvocation(
        run_id="docker-helper",
        invocation_id="docker-helper",
        tool_name=spec.name,
        files=[
            SandboxInputFile(path="empty.txt", content_base64=""),
            SandboxInputFile(path="filled.txt", content_base64=base64.b64encode(b"filled").decode()),
        ],
    )
    backend = DockerSandboxBackend(client=client)
    backend._populate_tmpfs_input(Container(), request)
    code, timed_out, log = backend._run_fixed_entrypoint(client, Container(), spec, timeout_seconds=1)
    assert (code, timed_out, log.bytes_seen, log.tail) == (0, False, 6, "def")
    assert DockerSandboxBackend._make_input_tar(request)


def test_sandbox_docker_resource_listing_and_safe_archive_guards() -> None:
    class Resource:
        def __init__(self, identifier: str, labels: dict[str, str], *, container: bool) -> None:
            self.id = identifier
            self.name = identifier
            self.attrs = (
                {"Config": {"Labels": labels}, "State": {"Running": container}} if container else {"Labels": labels}
            )

    labels = {
        RESOURCE_LABEL: "true",
        RUN_LABEL: "run-list",
        INVOCATION_LABEL: "inv-list",
        FENCE_LABEL: "4",
        CREATED_LABEL: "bad",
    }
    client = SimpleNamespace(
        containers=SimpleNamespace(list=lambda **_kwargs: [Resource("c", labels, container=True)]),
        volumes=SimpleNamespace(list=lambda **_kwargs: [Resource("v", labels, container=False)]),
    )
    backend = DockerSandboxBackend(client=client)
    resources = backend._list_resources_sync("run-list")
    assert [item.resource_id for item in resources] == ["container:c", "volume:v"]
    assert DockerSandboxBackend._label_epoch({CREATED_LABEL: "bad"}) == 0
    assert DockerSandboxBackend._label_fence({FENCE_LABEL: "-2"}) == 0

    def archive(files: dict[str, bytes]) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as tar:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        return stream.getvalue()

    for name, expected in (("../escape", "unsafe"), ("/absolute", "unsafe")):
        raw = archive({name: b"x"})
        container = SimpleNamespace(get_archive=lambda _path, raw=raw: (iter([raw]), {}))
        with pytest.raises(SandboxError, match=expected):
            DockerSandboxBackend._read_outputs(container, 100)
    with pytest.raises(SandboxError, match="invalid"):
        DockerSandboxBackend._read_outputs(
            SimpleNamespace(get_archive=lambda _path: (iter([archive({"result.json": b"{}"})]), {})),
            100,
            max_artifacts=0,
        )


@pytest.mark.asyncio
async def test_sandbox_remaining_validation_and_control_plane_guards(tmp_path: Path) -> None:
    import secmind.sandbox as sandbox

    with pytest.raises(ValueError, match="configured limits"):
        sandbox._read_bounded_regular_file(tmp_path / "missing", -1)
    with pytest.raises(ValueError, match="readable"):
        sandbox._read_bounded_regular_file(tmp_path / "missing", 10)
    folder = tmp_path / "directory"
    folder.mkdir()
    with pytest.raises(ValueError, match="regular"):
        sandbox._read_bounded_regular_file(folder, 10)
    regular = tmp_path / "regular"
    regular.write_bytes(b"12345")
    with pytest.raises(ValueError, match="exceeds"):
        sandbox._read_bounded_regular_file(regular, 4)
    with pytest.raises(ValueError, match="duplicate"):
        SandboxInvocation(
            invocation_id="duplicate",
            tool_name="bandit_python_audit",
            files=[
                SandboxInputFile(path="same", content_base64=""),
                SandboxInputFile(path="same", content_base64=""),
            ],
        )
    with pytest.raises(ValueError, match="digest"):
        SandboxToolSpec(name="tool", image_digest="tag:latest", entrypoint=("run",))
    with pytest.raises(ValueError, match="entrypoint"):
        SandboxToolSpec(name="tool", image_digest="sha256:" + "a" * 64, entrypoint=())

    class NoInventoryBackend:
        async def execute(self, _spec: Any, request: SandboxInvocation) -> SandboxResult:
            return SandboxResult(
                invocation_id=request.invocation_id,
                status="success",
                cleanup_confirmed=True,
                logs=SandboxLog(sha256="0" * 64),
            )

        async def cancel(self, _invocation_id: str) -> bool:
            return False

        async def cleanup_orphans(self) -> int:
            return 0

    spec = SandboxToolSpec(name="tool", image_digest="sha256:" + "a" * 64, entrypoint=("run",))
    control = SandboxRunner(NoInventoryBackend(), {spec.name: spec})
    with pytest.raises(NotImplementedError, match="inventory"):
        await control._backend_resources_for_invocation("unknown")
    with pytest.raises(SandboxError, match="invalid"):
        await control.cancel("")
    assert await control.cancel("unknown") is False
    assert await control.cleanup_orphans() == 0
    assert await control.readiness() == {"backend": "NoInventoryBackend", "tools": 1}
    with pytest.raises(SandboxError, match="registered"):
        control.capability_policy("missing")

    class HugeInventory(NoInventoryBackend):
        async def list_resources(self, _run_id: str) -> list[Any]:
            return [
                {
                    "run_id": "run",
                    "resource_id": str(index),
                    "invocation_id": str(index),
                    "fence": 0,
                    "active": False,
                }
                for index in range(10_001)
            ]

    huge = SandboxRunner(HugeInventory(), {spec.name: spec})
    with pytest.raises(SandboxError, match="safety bound"):
        await huge._backend_resources("run")

    rootless_client = SimpleNamespace(info=lambda: {"SecurityOptions": []})
    with pytest.raises(SandboxError, match="rootless"):
        DockerSandboxBackend._assert_rootless(rootless_client)
    with pytest.raises(SandboxError, match="Docker could"):
        DockerSandboxBackend._create_bounded_volume(
            SimpleNamespace(
                volumes=SimpleNamespace(create=lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("disk")))
            ),
            labels={},
            size_bytes=10,
        )


def test_sandbox_docker_exec_failure_timeout_and_input_sealing_branches() -> None:
    spec = SandboxToolSpec(
        name="tool",
        image_digest="sha256:" + "a" * 64,
        entrypoint=("run",),
        limits=SandboxLimits(max_log_tail_bytes=2),
    )
    container = SimpleNamespace(id="container", kill=lambda: None)

    class FailingApi:
        def exec_create(self, *_args: Any, **_kwargs: Any) -> str:
            return "exec-fail"

        def exec_start(self, *_args: Any, **_kwargs: Any):
            raise RuntimeError("stream broke")

        def exec_inspect(self, _exec_id: str) -> dict[str, int]:
            return {"ExitCode": 1}

    with pytest.raises(SandboxError, match="process failed"):
        DockerSandboxBackend._run_fixed_entrypoint(
            SimpleNamespace(api=FailingApi()), container, spec, timeout_seconds=1
        )

    class SlowApi(FailingApi):
        def exec_start(self, *_args: Any, **_kwargs: Any):
            import time

            time.sleep(0.05)
            return iter([b"done"])

        def exec_inspect(self, _exec_id: str) -> dict[str, int]:
            return {"ExitCode": 137}

    code, timed_out, _log = DockerSandboxBackend._run_fixed_entrypoint(
        SimpleNamespace(api=SlowApi()), container, spec, timeout_seconds=0
    )
    assert code == 137
    assert timed_out

    invocation = SandboxInvocation(
        run_id="seal",
        invocation_id="seal",
        tool_name="tool",
        files=[SandboxInputFile(path="empty", content_base64="")],
    )

    class ExitContainer:
        def __init__(self, exit_codes: list[int]) -> None:
            self.exit_codes = iter(exit_codes)

        def exec_run(self, *_args: Any, **_kwargs: Any) -> SimpleNamespace:
            return SimpleNamespace(exit_code=next(self.exit_codes))

    backend = DockerSandboxBackend(client=SimpleNamespace())
    for codes, message in (
        ([1], "prepare"),
        ([0, 1], "seal sandbox input file"),
        ([0, 0, 1], "seal sandbox input directory"),
    ):
        with pytest.raises(SandboxError, match=message):
            backend._populate_tmpfs_input(ExitContainer(codes), invocation)
    filled = invocation.model_copy(
        update={"files": [SandboxInputFile(path="filled", content_base64=base64.b64encode(b"filled").decode())]}
    )
    with pytest.raises(SandboxError, match="prepare"):
        backend._populate_tmpfs_input(ExitContainer([1]), filled)


def test_sandbox_tmpfs_output_and_preflight_receipts() -> None:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        info = tarfile.TarInfo("./result.json")
        body = b'{"status": "success"}'
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
    raw = stream.getvalue()

    class Api:
        def __init__(self, exit_code: int = 0) -> None:
            self.exit_code = exit_code

        def exec_create(self, *_args: Any, **_kwargs: Any) -> str:
            return "export"

        def exec_start(self, *_args: Any, **_kwargs: Any):
            return iter([(raw, b"warning"), b""])

        def exec_inspect(self, _exec_id: str) -> dict[str, int]:
            return {"ExitCode": self.exit_code}

    exported, result_body = DockerSandboxBackend._read_outputs_tmpfs(
        SimpleNamespace(api=Api()), SimpleNamespace(id="container"), 10_000
    )
    assert exported == []
    assert result_body["status"] == "success"
    with pytest.raises(SandboxError, match="exported"):
        DockerSandboxBackend._read_outputs_tmpfs(
            SimpleNamespace(api=Api(exit_code=1)), SimpleNamespace(id="container"), 10_000
        )

    class Probe:
        def __init__(self, status: int) -> None:
            self.status = status
            self.removed = False

        def start(self) -> None:
            return None

        def wait(self, timeout: int) -> dict[str, int]:
            del timeout
            return {"StatusCode": self.status}

        def remove(self, force: bool = False) -> None:
            self.removed = force

    class DockerProbe:
        def __init__(self, status: int) -> None:
            self.probe = Probe(status)
            self.containers = SimpleNamespace(create=lambda *_args, **_kwargs: self.probe)

        def ping(self) -> None:
            return None

        def info(self) -> dict[str, Any]:
            return {"SecurityOptions": ["rootless"]}

    success_client = DockerProbe(0)
    success_backend = DockerSandboxBackend(client=success_client)
    success_backend._ensure_bounded_volume_support(success_client)
    success_backend._ensure_bounded_volume_support(success_client)
    assert success_backend._volume_preflight is True
    assert success_client.probe.removed

    failed_client = DockerProbe(1)
    failed_backend = DockerSandboxBackend(client=failed_client)
    with pytest.raises(SandboxError, match="preflight"):
        failed_backend._ensure_bounded_volume_support(failed_client)
    assert failed_backend._volume_preflight is False


def test_sandbox_archive_directory_symlink_and_artifact_count_guards() -> None:
    def make_archive() -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            directory = tarfile.TarInfo("output/")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            result = tarfile.TarInfo("output/result.json")
            result_body = b"{}"
            result.size = len(result_body)
            archive.addfile(result, io.BytesIO(result_body))
            for name in ("output/a", "output/b"):
                item = tarfile.TarInfo(name)
                item.size = 1
                archive.addfile(item, io.BytesIO(b"x"))
        return stream.getvalue()

    raw = make_archive()
    with pytest.raises(SandboxError, match="too many"):
        DockerSandboxBackend._read_outputs(
            SimpleNamespace(get_archive=lambda _path: (iter([raw]), {})), 10_000, max_artifacts=1
        )

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        link = tarfile.TarInfo("output/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        archive.addfile(link)
    link_raw = stream.getvalue()
    with pytest.raises(SandboxError, match="unsafe"):
        DockerSandboxBackend._read_outputs(
            SimpleNamespace(get_archive=lambda _path, raw=link_raw: (iter([raw]), {})), 10_000
        )
