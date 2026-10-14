from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    process = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", "/input", "-f", "json", "-q"],
        capture_output=True,
        check=False,
        text=True,
        timeout=110,
    )
    if process.returncode not in {0, 1}:
        print(process.stderr[-4096:])
        return process.returncode
    body = json.loads(process.stdout or "{}")
    output = {
        "status": "success",
        "data": {"findings": body.get("results", []), "metrics": body.get("metrics", {})},
        "summary": f"Bandit completed with {len(body.get('results', []))} finding(s).",
    }
    Path("/output/result.json").write_text(json.dumps(output, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
