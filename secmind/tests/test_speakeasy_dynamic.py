from __future__ import annotations

import json
from pathlib import Path

import pytest

from secmind.schemas import Scenario, ToolContext, ToolStatus
from secmind.speakeasy_dynamic import (
    approved_safe_fixture_sha256,
    format_speakeasy_runner_output,
    initialize_mingw_acmdln,
    initialize_safe_fixture_argv,
    mingw_iob_func_hook,
    normalize_speakeasy_report,
    profile_argv,
    resolve_safe_target,
)
from secmind.tooling.builtin_reverse_dynamic import SpeakeasyDynamicAnalysisTool
from secmind.tools import default_registry


def _safe_fixture_bytes() -> bytes:
    return (
        Path(__file__).resolve().parents[1]
        / "reverse_evaluation"
        / "fixtures"
        / "safe-demo-v1"
        / "build"
        / "reverse_demo.exe"
    ).read_bytes()


def test_runner_bundle_preserves_native_and_normalized_reports() -> None:
    native = {"sha256": "a" * 64, "entry_points": []}
    observation = normalize_speakeasy_report(native, profile_id="wrong_token")

    payload = format_speakeasy_runner_output(native, observation, output_format="bundle")

    assert payload["native"] == native
    assert payload["normalized"]["source"] == "speakeasy"


def test_profiles_are_fixed_and_callers_cannot_supply_arbitrary_argv() -> None:
    assert profile_argv("wrong_token") == ["NOT-THE-TOKEN"]
    assert profile_argv("correct_token") == ["SECMIND-REVERSE-OK"]
    with pytest.raises(ValueError, match="profile"):
        profile_argv("--download https://example.test")


def test_only_repository_safe_fixture_digest_is_approved_for_emulation() -> None:
    assert approved_safe_fixture_sha256("efb6050e10a8d548ae454034120a233283b33d5d679e6fc06147549441f82c38")
    assert not approved_safe_fixture_sha256("b" * 64)


def test_dynamic_tool_is_registered_in_the_default_runtime() -> None:
    assert default_registry().get("speakeasy_dynamic_analysis").manifest.requires_network is False


def test_sandbox_profile_allows_only_required_tool_and_source_roots(tmp_path: Path) -> None:
    tool_root = tmp_path / "tool"
    python = tool_root / "bin" / "python"
    runner = tmp_path / "repo" / "reverse_evaluation" / "tools" / "runner.py"
    target = tmp_path / "repo" / "sample.exe"
    python.parent.mkdir(parents=True)
    runner.parent.mkdir(parents=True)
    (runner.parents[2] / "src").mkdir()
    python.write_text("", encoding="utf-8")
    runner.write_text("", encoding="utf-8")
    target.write_bytes(b"MZ")

    profile = SpeakeasyDynamicAnalysisTool._sandbox_profile(target, python, runner)
    source_root = runner.parents[2] / "src"

    assert f'(subpath "{tool_root}")' in profile
    assert f'(subpath "{source_root}")' in profile
    assert '(literal "/")' in profile
    assert "network" not in profile


def test_target_must_remain_in_workspace_and_be_a_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    assert resolve_safe_target("sample.exe", tmp_path) == sample.resolve()
    with pytest.raises(ValueError, match="workspace"):
        resolve_safe_target("../escape.exe", tmp_path)
    with pytest.raises(ValueError, match="file"):
        resolve_safe_target("missing.exe", tmp_path)


def test_report_normalizer_is_bounded_and_marks_runtime_calls() -> None:
    raw = {
        "sha256": "a" * 64,
        "arch": "amd64",
        "entry_points": [
            {
                "ep_type": "module_entry",
                "ret_val": "0x2",
                "events": [
                    {"event": "api", "api_name": "msvcrt.strcmp", "args": ["wrong", "secret"]},
                    {
                        "event": "api",
                        "api_name": "msvcrt.fopen",
                        "args": ["reverse_demo_result.txt", "w"],
                        "ret_val": "0x1234",
                    },
                    {
                        "event": "api",
                        "api_name": "msvcrt.fputc",
                        "args": ["0x41", "0x1234"],
                        "ret_val": "0x41",
                    },
                ]
                * 400,
            }
        ],
    }

    observation = normalize_speakeasy_report(raw, profile_id="wrong_token", event_limit=50)

    assert observation.source == "speakeasy"
    assert observation.status == "completed"
    assert observation.coverage["runtime_calls_observed"] is True
    assert observation.coverage["events_total"] == 1200
    assert observation.coverage["events_retained"] == 50
    assert observation.artifacts["exit_code"] == 2
    assert observation.artifacts["created_files"] == ["reverse_demo_result.txt"]
    assert len(observation.events) == 50


def test_report_normalizer_does_not_call_failed_fopen_a_created_file() -> None:
    observation = normalize_speakeasy_report(
        {
            "sha256": "a" * 64,
            "entry_points": [
                {
                    "ep_type": "module_entry",
                    "events": [
                        {
                            "event": "api",
                            "api_name": "msvcrt.fopen",
                            "args": ["not-created.txt", "w"],
                            "ret_val": "0x0",
                        }
                    ],
                }
            ],
        },
        profile_id="wrong_token",
    )

    assert observation.artifacts["file_open_attempts"] == ["not-created.txt"]
    assert observation.artifacts["created_files"] == []


def test_report_normalizer_marks_unsupported_api_as_partial() -> None:
    observation = normalize_speakeasy_report(
        {
            "sha256": "a" * 64,
            "entry_points": [
                {
                    "ep_type": "module_entry",
                    "error": "Unsupported API: example.unsupported",
                    "events": [],
                }
            ],
        },
        profile_id="wrong_token",
    )

    assert observation.status == "partial"
    assert observation.error is not None
    assert observation.error["code"] == "SPEAKEASY_RUNTIME_ERROR"


def test_mingw_iob_hook_allocates_a_stable_three_stream_table() -> None:
    class Emulator:
        def __init__(self) -> None:
            self.maps: list[tuple[int, str]] = []

        def mem_map(self, size: int, tag: str) -> int:
            self.maps.append((size, tag))
            return 0x7000

        def mem_write(self, address: int, data: bytes) -> None:
            assert address == 0x7000
            assert len(data) == 144

    emulator = Emulator()
    state: dict[str, int] = {}

    first = mingw_iob_func_hook(state)(emulator, "msvcrt.__iob_func", None, [])
    second = mingw_iob_func_hook(state)(emulator, "msvcrt.__iob_func", None, [])

    assert first == second == 0x7000
    assert emulator.maps == [(144, "secmind.mingw.iob")]


def test_mingw_acmdln_initializes_only_the_emulated_import_slot() -> None:
    class Mapping:
        base = 0x1000
        tag = "api.msvcrt._acmdln.0x1000"

    class Emulator:
        def __init__(self) -> None:
            self.writes: list[tuple[int, bytes]] = []

        def get_mem_maps(self):
            return [Mapping()]

        def get_ptr_size(self) -> int:
            return 8

        def mem_map(self, size: int, tag: str) -> int:
            assert size == len(b"reverse_demo.exe NOT-THE-TOKEN\x00")
            assert tag == "secmind.mingw.acmdln"
            return 0x8000

        def mem_write(self, address: int, data: bytes) -> None:
            self.writes.append((address, data))

    emulator = Emulator()

    assert initialize_mingw_acmdln(emulator, "reverse_demo.exe NOT-THE-TOKEN") is True
    assert emulator.writes == [
        (0x8000, b"reverse_demo.exe NOT-THE-TOKEN\x00"),
        (0x1000, (0x8000).to_bytes(8, "little")),
    ]


def test_safe_fixture_argv_shim_is_sha_bound() -> None:
    class Emulator:
        def __init__(self) -> None:
            self.writes: list[tuple[int, bytes]] = []

        def get_ptr_size(self) -> int:
            return 8

        def mem_map(self, size: int, tag: str) -> int:
            assert tag == "secmind.safe_fixture.argv"
            assert size > 24
            return 0x9000

        def mem_write(self, address: int, data: bytes) -> None:
            self.writes.append((address, data))

    emulator = Emulator()
    expected_sha = "efb6050e10a8d548ae454034120a233283b33d5d679e6fc06147549441f82c38"

    assert initialize_safe_fixture_argv(emulator, 0x140000000, "b" * 64, ["NOT-THE-TOKEN"]) is False
    assert emulator.writes == []
    assert initialize_safe_fixture_argv(emulator, 0x140000000, expected_sha, ["NOT-THE-TOKEN"]) is True
    assert (0x14000C038, (2).to_bytes(4, "little")) in emulator.writes
    assert (0x14000C030, (0x9000).to_bytes(8, "little")) in emulator.writes


@pytest.mark.asyncio
async def test_dynamic_tool_uses_fixed_runner_contract(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_safe_fixture_bytes())
    runner = tmp_path / "fake_runner.py"
    runner.write_text(
        "import hashlib,json,sys\n"
        "target=sys.argv[sys.argv.index('--target')+1]\n"
        "print(json.dumps({'source':'speakeasy','status':'completed','sample_sha256':'"
        "'+hashlib.sha256(open(target,'rb').read()).hexdigest()+'','tool_identity':{'name':'speakeasy'},'profile_id':sys.argv[4],"
        "'coverage':{'real_network_requests':0,'host_pe_executions':0},'events':[],"
        "'artifacts':{},'evidence_refs':[],'error':None}))\n",
        encoding="utf-8",
    )
    tool = SpeakeasyDynamicAnalysisTool(
        python_executable=Path(__import__("sys").executable),
        runner_script=runner,
        sandbox_enabled=False,
    )
    monkeypatch.setenv("SECMIND_OUTER_SANDBOX_ENFORCED", "1")

    result = await tool.invoke(
        {
            "target": "sample.exe",
            "profile_id": "wrong_token",
            "timeout_seconds": 5,
            "max_instructions": 1000,
            "max_api_count": 100,
        },
        ToolContext(run_id="run", step_id="dynamic", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert tool.manifest.scenarios == [Scenario.REVERSE_TRIAGE]
    assert "argv" not in tool.manifest.input_schema["properties"]
    assert "url" not in tool.manifest.input_schema["properties"]
    assert result.status == ToolStatus.SUCCESS
    assert result.data["profile_id"] == "wrong_token"
    assert json.loads(result.model_dump_json())["data"]["coverage"]["real_network_requests"] == 0
    assert result.data["coverage"]["sandbox_enforced"] is False


@pytest.mark.asyncio
async def test_dynamic_tool_denies_escape_and_reports_unavailable_runtime(tmp_path: Path) -> None:
    (tmp_path / "sample.exe").write_bytes(b"MZ")
    tool = SpeakeasyDynamicAnalysisTool(
        python_executable=tmp_path / "missing-python",
        runner_script=tmp_path / "missing-runner.py",
        sandbox_enabled=False,
    )
    context = ToolContext(run_id="run", step_id="dynamic", workspace=str(tmp_path), allowed_paths=[str(tmp_path)])

    escaped = await tool.invoke({"target": "../outside.exe", "profile_id": "wrong_token"}, context)
    unavailable = await tool.invoke({"target": "sample.exe", "profile_id": "wrong_token"}, context)

    assert escaped.status == ToolStatus.DENIED
    assert unavailable.status == ToolStatus.ERROR
    assert unavailable.error_code == "SPEAKEASY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_dynamic_tool_default_fails_closed_without_reviewed_platform_sandbox(
    tmp_path: Path, monkeypatch
) -> None:
    import sys

    sample = tmp_path / "sample.exe"
    sample.write_bytes(_safe_fixture_bytes())
    runner = tmp_path / "runner.py"
    runner.write_text("print('must not run')\n", encoding="utf-8")
    monkeypatch.setattr(sys, "platform", "linux")
    tool = SpeakeasyDynamicAnalysisTool(
        python_executable=Path(sys.executable),
        runner_script=runner,
    )

    result = await tool.invoke(
        {"target": "sample.exe", "profile_id": "wrong_token"},
        ToolContext(run_id="run", step_id="dynamic", workspace=str(tmp_path), allowed_paths=[str(tmp_path)]),
    )

    assert result.error_code == "SPEAKEASY_SANDBOX_UNAVAILABLE"


@pytest.mark.asyncio
async def test_dynamic_tool_fails_closed_on_timeout_and_output_limit(tmp_path: Path, monkeypatch) -> None:
    import asyncio
    import sys

    (tmp_path / "sample.exe").write_bytes(_safe_fixture_bytes())
    runner = tmp_path / "runner.py"
    runner.write_text("print('ok')\n", encoding="utf-8")
    context = ToolContext(run_id="run", step_id="dynamic", workspace=str(tmp_path), allowed_paths=[str(tmp_path)])
    tool = SpeakeasyDynamicAnalysisTool(
        python_executable=Path(sys.executable),
        runner_script=runner,
        sandbox_enabled=False,
    )

    async def immediate_timeout(awaitable, **kwargs):
        del kwargs
        awaitable.close()
        raise TimeoutError

    monkeypatch.setattr(asyncio, "wait_for", immediate_timeout)
    timed_out = await tool.invoke({"target": "sample.exe", "profile_id": "wrong_token"}, context)
    assert timed_out.error_code == "SPEAKEASY_TIMEOUT"

    monkeypatch.undo()
    runner.write_text("print('x' * 600000)\n", encoding="utf-8")
    oversized = await tool.invoke({"target": "sample.exe", "profile_id": "wrong_token"}, context)
    assert oversized.error_code == "SPEAKEASY_OUTPUT_LIMIT"
