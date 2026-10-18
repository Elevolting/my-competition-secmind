from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from secmind.audit_kernel import (
    EXTENDED_TARGET_CWES,
    AuditUnit,
    FlowVerdict,
    JavaConfigurationEvidenceExtractor,
    JavaEvidenceExtractor,
)
from secmind.audit_kernel.pipeline import (
    JAVA_CONFIGURATION_RULE_BUNDLE_DIGEST,
    JAVA_CONFIGURATION_TOOL,
    JAVA_CONFIGURATION_VERSION,
    JAVA_EVIDENCE_TOOL,
    JAVA_EVIDENCE_VERSION,
    JAVA_RULE_BUNDLE_DIGEST,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _score(gold: Mapping[str, tuple[bool, int]], predictions: Mapping[str, set[int]]) -> dict[str, Any]:
    tp = fp = tn = fn = 0
    by_cwe: dict[int, Counter[str]] = defaultdict(Counter)
    for case_id, (expected, cwe) in gold.items():
        predicted_cwes = predictions.get(case_id, set())
        predicted = cwe in predicted_cwes
        if expected and predicted:
            tp += 1
            by_cwe[cwe]["tp"] += 1
        elif expected:
            fn += 1
            by_cwe[cwe]["fn"] += 1
        elif predicted:
            fp += 1
            by_cwe[cwe]["fp"] += 1
        else:
            tn += 1
            by_cwe[cwe]["tn"] += 1
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "per_cwe": {
            str(cwe): {key: counts[key] for key in ("tp", "fp", "tn", "fn")} for cwe, counts in sorted(by_cwe.items())
        },
    }


def evaluate(blind_root: Path, gold_path: Path) -> dict[str, Any]:
    manifest_path = blind_root / "blind-manifest.json"
    manifest = _load(manifest_path)
    gold_document = _load(gold_path)
    gold = {
        str(item["case_id"]): (bool(item["vulnerable"]), int(item["cwe"])) for item in gold_document.get("cases", [])
    }
    manifest_cases = manifest.get("cases", [])
    if not isinstance(manifest_cases, list) or set(gold) != {str(item["case_id"]) for item in manifest_cases}:
        raise ValueError("blind manifest and gold case identities do not match")

    profile_digest = hashlib.sha256(json.dumps(EXTENDED_TARGET_CWES, separators=(",", ":")).encode()).hexdigest()
    flow_extractor = JavaEvidenceExtractor(
        tool_name=JAVA_EVIDENCE_TOOL,
        tool_version=JAVA_EVIDENCE_VERSION,
        rule_bundle_digest=JAVA_RULE_BUNDLE_DIGEST,
    )
    configuration_extractor = JavaConfigurationEvidenceExtractor(
        tool_name=JAVA_CONFIGURATION_TOOL,
        tool_version=JAVA_CONFIGURATION_VERSION,
        rule_bundle_digest=JAVA_CONFIGURATION_RULE_BUNDLE_DIGEST,
    )
    predictions: dict[str, dict[str, set[int]]] = {
        "configuration": {},
        "taint_flow": {},
        "combined": {},
    }
    candidate_counts: Counter[str] = Counter()
    for item in manifest_cases:
        case_id = str(item["case_id"])
        relative_path = Path(str(item["path"]))
        source_path = blind_root / relative_path
        if _sha256(source_path) != str(item["sha256"]):
            raise ValueError(f"source digest mismatch for {case_id}")
        with source_path.open("r", encoding="utf-8", newline="") as stream:
            source = stream.read()
        unit = AuditUnit.create(
            run_id="offline-static-signal-diagnostic",
            input_manifest_digest=_sha256(manifest_path),
            profile_digest=profile_digest,
            primary_path=relative_path.as_posix(),
            source_sha256=str(item["sha256"]),
            target_cwes=EXTENDED_TARGET_CWES,
        )
        configuration = {
            flow.cwe
            for flow in configuration_extractor.extract(unit, source)
            if flow.verdict == FlowVerdict.CANDIDATE_POSITIVE
        }
        taint = {
            flow.cwe for flow in flow_extractor.extract(unit, source) if flow.verdict == FlowVerdict.CANDIDATE_POSITIVE
        }
        predictions["configuration"][case_id] = configuration
        predictions["taint_flow"][case_id] = taint
        predictions["combined"][case_id] = configuration | taint
        candidate_counts["configuration"] += len(configuration)
        candidate_counts["taint_flow"] += len(taint)
        candidate_counts["combined"] += len(configuration | taint)

    positive_distribution = Counter(cwe for vulnerable, cwe in gold.values() if vulnerable)
    negative_distribution = Counter(cwe for vulnerable, cwe in gold.values() if not vulnerable)
    return {
        "schema_version": "1.0",
        "protocol": "secmind-v0.7-static-candidate-diagnostic",
        "interpretation": (
            "Candidate-only diagnostic after gold isolation. It measures generic static "
            "signal coverage, not authoritative Agent or Direct F1, and cannot pass the "
            "v0.7 release gate without paired sealed predictions."
        ),
        "network_requests": 0,
        "model_requests": 0,
        "target_cwes": list(EXTENDED_TARGET_CWES),
        "inputs": {
            "case_count": len(gold),
            "blind_manifest_sha256": _sha256(manifest_path),
            "gold_sha256": _sha256(gold_path),
            "positive_distribution": {str(cwe): positive_distribution[cwe] for cwe in EXTENDED_TARGET_CWES},
            "negative_distribution": {str(cwe): negative_distribution[cwe] for cwe in EXTENDED_TARGET_CWES},
        },
        "tools": {
            "configuration": {
                "name": JAVA_CONFIGURATION_TOOL,
                "version": JAVA_CONFIGURATION_VERSION,
                "rule_bundle_digest": JAVA_CONFIGURATION_RULE_BUNDLE_DIGEST,
            },
            "taint_flow": {
                "name": JAVA_EVIDENCE_TOOL,
                "version": JAVA_EVIDENCE_VERSION,
                "rule_bundle_digest": JAVA_RULE_BUNDLE_DIGEST,
            },
        },
        "candidate_counts": dict(candidate_counts),
        "scores": {name: _score(gold, values) for name, values in predictions.items()},
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Measure SecMind v0.7 deterministic Java candidate signals offline")
    parser.add_argument("--blind-root", type=Path, required=True)
    parser.add_argument("--gold", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = evaluate(args.blind_root, args.gold)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
