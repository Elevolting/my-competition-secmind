"""Four-stage CLI: predict -> seal -> score -> render."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from secmind.reverse_evaluation import predict_suite, score_predictions, seal_predictions
from secmind.reverse_report import render_audit_report


def main() -> int:
    parser = argparse.ArgumentParser(description="SecMind safe reverse evaluation")
    commands = parser.add_subparsers(dest="command", required=True)
    predict = commands.add_parser("predict")
    predict.add_argument("--manifest", required=True, type=Path)
    predict.add_argument("--output", required=True, type=Path)
    predict.add_argument("--arm", required=True, choices=("old", "current", "optimized"))
    predict.add_argument("--implementation-root", required=True, type=Path)
    predict.add_argument("--suite-root", required=True, type=Path)
    seal = commands.add_parser("seal")
    seal.add_argument("--predictions", required=True, type=Path)
    seal.add_argument("--output", required=True, type=Path)
    score = commands.add_parser("score")
    score.add_argument("--predictions", required=True, type=Path)
    score.add_argument("--seal", required=True, type=Path)
    score.add_argument("--gold", required=True, type=Path)
    score.add_argument("--metrics", required=True, type=Path)
    score.add_argument("--cases", required=True, type=Path)
    render = commands.add_parser("render")
    render.add_argument("--results-root", required=True, type=Path)
    render.add_argument("--output-dir", required=True, type=Path)
    render.add_argument("--live-status", default="not_run")
    render.add_argument("--gold", type=Path)
    render.add_argument("--live-root", type=Path)
    args = parser.parse_args()
    if args.command == "predict":
        predict_suite(
            args.manifest,
            args.output,
            arm=args.arm,
            implementation_root=args.implementation_root,
            suite_root=args.suite_root,
        )
    elif args.command == "seal":
        seal_predictions(args.predictions, args.output)
    elif args.command == "score":
        metrics, rows = score_predictions(args.predictions, args.seal, args.gold)
        args.metrics.write_text(
            json.dumps(metrics, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with args.cases.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]) if rows else ["case_id"])
            writer.writeheader()
            writer.writerows(rows)
    else:
        render_audit_report(
            args.results_root,
            args.output_dir,
            live_status=args.live_status,
            gold_path=args.gold,
            live_root=args.live_root,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
