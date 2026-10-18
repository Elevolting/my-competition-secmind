from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    executable = shutil.which("semgrep")
    if executable is None:
        raise RuntimeError("semgrep is required to validate the candidate rules")
    return subprocess.run(  # noqa: S603 - executable is resolved from the developer environment
        [
            executable,
            "--config",
            str(root / "rules" / "reviewed"),
            "--test",
            str(root / "tests"),
            "--metrics",
            "off",
            "--disable-version-check",
        ],
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
