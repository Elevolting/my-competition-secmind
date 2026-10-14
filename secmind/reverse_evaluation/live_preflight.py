"""Validate both sealed DeepSeek Live arms without reading gold or calling the network."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from secmind.config import Settings
from secmind.reverse_live_evaluation import preflight_live_pair


def main() -> int:
    parser = argparse.ArgumentParser(description="SecMind paired DeepSeek Live preflight")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--current-evidence", required=True, type=Path)
    parser.add_argument("--current-seal", required=True, type=Path)
    parser.add_argument("--optimized-evidence", required=True, type=Path)
    parser.add_argument("--optimized-seal", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = preflight_live_pair(
        args.manifest,
        {
            "current": (args.current_evidence, args.current_seal),
            "optimized": (args.optimized_evidence, args.optimized_seal),
        },
        settings=Settings(),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"ready": result["ready"], "reason": result["reason"]}, sort_keys=True))
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
