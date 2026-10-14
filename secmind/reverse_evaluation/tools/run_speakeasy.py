"""Pinned Speakeasy runner. This script must run inside the isolated tool venv."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from secmind.reverse_analysis_observation import ReverseAnalysisObservation  # noqa: E402
from secmind.speakeasy_dynamic import (  # noqa: E402
    approved_safe_fixture_sha256,
    format_speakeasy_runner_output,
    initialize_mingw_acmdln,
    initialize_safe_fixture_argv,
    mingw_iob_func_hook,
    normalize_speakeasy_report,
    profile_argv,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", required=True, choices=("wrong_token", "correct_token"))
    parser.add_argument("--timeout", required=True, type=int)
    parser.add_argument("--max-instructions", required=True, type=int)
    parser.add_argument("--max-api-count", required=True, type=int)
    parser.add_argument("--output-format", choices=("normalized", "bundle"), default="normalized")
    args = parser.parse_args()

    sample_sha256 = hashlib.sha256(Path(args.target).read_bytes()).hexdigest()
    if not approved_safe_fixture_sha256(sample_sha256):
        observation = ReverseAnalysisObservation(
            source="speakeasy",
            status="unavailable",
            sample_sha256=sample_sha256,
            tool_identity={
                "name": "speakeasy",
                "version": "2.0.0b6",
                "commit": "b364d53ce9364e1f8aa898b9ed53597be39b23cb",
            },
            profile_id=args.profile,
            coverage={"real_network_requests": 0, "host_pe_executions": 0},
            error={"code": "SPEAKEASY_SAMPLE_NOT_APPROVED"},
        )
        native = {"runner_error": observation.error, "sample_sha256": sample_sha256, "stage": "admission"}
        print(json.dumps(format_speakeasy_runner_output(native, observation, output_format=args.output_format)))
        return 0

    stage = "import_speakeasy"
    import speakeasy  # type: ignore[import-not-found]
    from speakeasy.config import get_default_config_dict  # type: ignore[import-not-found]

    stage = "configure"
    config = get_default_config_dict()
    config["timeout"] = max(1, min(args.timeout, 30))
    config["max_instructions"] = max(1000, min(args.max_instructions, 5_000_000))
    config["max_api_count"] = max(100, min(args.max_api_count, 10_000))
    stage = "create_emulator"
    emulator = speakeasy.Speakeasy(config=config, argv=profile_argv(args.profile))
    emulator.add_api_hook(mingw_iob_func_hook({}), "msvcrt", "__iob_func", argc=0)
    try:
        stage = "load_module"
        module = emulator.load_module(args.target)
        command_line = "reverse_demo.exe " + " ".join(profile_argv(args.profile))
        stage = "initialize_compatibility"
        initialize_mingw_acmdln(emulator.emu, command_line)
        if not initialize_safe_fixture_argv(
            emulator.emu,
            module.base,
            sample_sha256,
            profile_argv(args.profile),
        ):
            raise RuntimeError("fixture-bound MinGW argv shim is unavailable for this sample")
        stage = "run_module"
        emulator.run_module(module, all_entrypoints=True, emulate_children=False)
        stage = "normalize_report"
        native = json.loads(emulator.get_json_report())
        observation = normalize_speakeasy_report(native, profile_id=args.profile)
    except Exception as exc:  # noqa: BLE001 - convert emulator failure into a bounded observation
        digest = hashlib.sha256(Path(args.target).read_bytes()).hexdigest()
        observation = ReverseAnalysisObservation(
            source="speakeasy",
            status="partial",
            sample_sha256=digest,
            tool_identity={
                "name": "speakeasy",
                "version": "2.0.0b6",
                "commit": "b364d53ce9364e1f8aa898b9ed53597be39b23cb",
            },
            profile_id=args.profile,
            coverage={"real_network_requests": 0, "host_pe_executions": 0},
            error={"code": "SPEAKEASY_RUNTIME_ERROR", "message": type(exc).__name__, "stage": stage},
        )
        native = {
            "runner_error": observation.error,
            "sample_sha256": observation.sample_sha256,
            "stage": stage,
        }
    print(json.dumps(format_speakeasy_runner_output(native, observation, output_format=args.output_format)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
