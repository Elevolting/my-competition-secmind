"""Export native and normalized reports for the two fixed safe profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from secmind.tooling.builtin_reverse_dynamic import SpeakeasyDynamicAnalysisTool  # noqa: E402
from secmind.tooling.core import public_evidence_id  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-output-dir", required=True)
    parser.add_argument("--normalized-output-dir", required=True)
    args = parser.parse_args()
    raw_output_dir = Path(args.raw_output_dir).resolve()
    normalized_output_dir = Path(args.normalized_output_dir).resolve()
    for output_dir in (raw_output_dir, normalized_output_dir):
        output_dir.relative_to(REPO_ROOT)
        output_dir.mkdir(parents=True, exist_ok=True)

    target = REPO_ROOT / "reverse_evaluation/fixtures/safe-demo-v1/build/reverse_demo.exe"
    python = REPO_ROOT / ".reverse-tools/speakeasy/bin/python"
    runner = REPO_ROOT / "reverse_evaluation/tools/run_speakeasy.py"
    expected_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    for profile in ("wrong_token", "correct_token"):
        command = [
            str(python.resolve()),
            str(runner),
            "--target",
            str(target),
            "--profile",
            profile,
            "--timeout",
            "15",
            "--max-instructions",
            "1000000",
            "--max-api-count",
            "2000",
            "--output-format",
            "bundle",
        ]
        if sys.platform == "darwin":
            command = [
                "/usr/bin/sandbox-exec",
                "-p",
                SpeakeasyDynamicAnalysisTool._sandbox_profile(target, python, runner),
                *command,
            ]
        env = {
            "PATH": str(python.parent),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
        if sys.platform == "darwin":
            env["__PYVENV_LAUNCHER__"] = str(python)
        completed = subprocess.run(command, check=True, capture_output=True, env=env, timeout=25)  # noqa: S603
        if len(completed.stdout) > 8 * 1024 * 1024:
            raise RuntimeError("native Speakeasy report exceeded 8 MiB")
        payload = json.loads(completed.stdout)
        (raw_output_dir / f"speakeasy-{profile}-native.json").write_text(
            json.dumps(payload["native"], ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        normalized = payload["normalized"]
        digest = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
        normalized["evidence_refs"] = [public_evidence_id(digest)]
        (normalized_output_dir / f"speakeasy-{profile}.json").write_text(
            json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if hashlib.sha256(target.read_bytes()).hexdigest() != expected_hash:
        raise RuntimeError("safe fixture changed during emulation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
