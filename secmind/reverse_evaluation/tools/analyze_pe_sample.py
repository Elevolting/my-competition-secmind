from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[2]
src_path = repo_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from secmind.reverse_pe_analysis import build_report, render_markdown  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Enhanced static reverse analysis for a PE sample.")
    parser.add_argument("--input", required=True, type=Path, help="Path to the PE sample.")
    parser.add_argument("--output", required=True, type=Path, help="Directory for report.json and report.md.")
    args = parser.parse_args()

    report = build_report(args.input)
    args.output.mkdir(parents=True, exist_ok=True)

    (args.output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (args.output / "report.md").write_text(render_markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
