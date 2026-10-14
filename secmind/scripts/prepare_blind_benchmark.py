from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from blind_benchmark_common import (
    DEFAULT_SAMPLE_SIZE,
    DEFAULT_SEED,
    PROTOCOL,
    canonical_hash,
    now,
    sha256_bytes,
    write_json,
)


def _rank(seed: str, relative_path: str) -> bytes:
    return hashlib.sha256(f"{seed}\0{relative_path}".encode()).digest()


def _entry(path: Path, relative_path: str, *, case_id: str | None = None) -> dict[str, object]:
    raw = path.read_bytes()
    item: dict[str, object] = {
        "path": relative_path,
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
    }
    if case_id is not None:
        item["case_id"] = case_id
    return item


def prepare(benchmark: Path, output: Path, *, seed: str, sample_size: int) -> None:
    if output.exists() and any(output.iterdir()):
        raise SystemExit("blind input directory must be new and empty")
    source_root = benchmark / "src" / "main" / "java" / "org" / "owasp" / "benchmark"
    candidates = [(path, f"testcode/{path.name}") for path in (source_root / "testcode").glob("BenchmarkTest*.java")]
    if sample_size < 20 or sample_size > len(candidates):
        raise SystemExit("sample size is outside the supported range")
    selected = sorted(candidates, key=lambda item: (_rank(seed, item[1]), item[1]))[:sample_size]
    support: list[tuple[Path, str]] = [
        (path, f"helpers/{path.name}") for path in sorted((source_root / "helpers").glob("*.java"))
    ]
    properties = benchmark / "src" / "main" / "resources" / "thing.properties"
    if properties.exists():
        support.append((properties, "resources/thing.properties"))

    case_entries: list[dict[str, object]] = []
    support_entries: list[dict[str, object]] = []
    for path, relative in selected:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        case_entries.append(_entry(target, relative, case_id=path.stem))
    for path, relative in support:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        support_entries.append(_entry(target, relative))

    material = {
        "protocol": PROTOCOL,
        "seed": seed,
        "selection_algorithm": "sort SHA256(seed + NUL + relative_path), take first N; no gold read",
        "cases": case_entries,
        "support_files": support_entries,
    }
    manifest = {
        "schema_version": "1.0",
        **material,
        "sample_size": sample_size,
        "created_at": now(),
        "input_bundle_sha256": canonical_hash(material),
        "prohibited_inputs": [
            "expected results",
            "gold labels",
            "scorecards",
            "solutions",
            "tests",
            "tutorials",
            "README files",
            "historical reports",
            "repository metadata",
        ],
    }
    write_json(output / "blind-manifest.json", manifest)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a gold-blind OWASP Benchmark source bundle")
    parser.add_argument("--benchmark-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    parser.add_argument("--sample-size", type=int, default=DEFAULT_SAMPLE_SIZE)
    args = parser.parse_args()
    prepare(args.benchmark_root.resolve(), args.output_dir.resolve(), seed=args.seed, sample_size=args.sample_size)


if __name__ == "__main__":
    main()
