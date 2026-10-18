from __future__ import annotations

import base64
import json
import os
import urllib.parse
from pathlib import Path

import pytest
from test_reverse_api_score import _complete_tree

from secmind.reverse_api_score import score_api_runs


def _test_secret() -> str:
    return "-".join(("unit", "test", "key", "123456789"))


def _matrix(tmp_path: Path) -> tuple[Path, Path, dict[str, object], list[dict[str, object]]]:
    from secmind.reverse_api_score import score_api_runs

    run_root, gold_path = _complete_tree(tmp_path)
    gold_dir = tmp_path / "reverse_evaluation" / "gold"
    gold_dir.mkdir(parents=True)
    moved_gold = gold_dir / "expected.json"
    gold_path.rename(moved_gold)
    metrics, rows = score_api_runs(run_root, moved_gold)
    return run_root, moved_gold, metrics, rows


def _manifest() -> dict[str, object]:
    return {"suite_id": "suite-api-12", "cases": [{"id": f"case-{index:02d}"} for index in range(12)]}


def _render(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, object], list[dict[str, object]]]:
    from secmind.reverse_api_overview import render_api_overview

    run_root, gold_path, metrics, rows = _matrix(tmp_path)
    delivery = tmp_path / "delivery"
    render_api_overview(
        metrics=metrics,
        case_rows=rows,
        run_root=run_root,
        output_dir=delivery,
        manifest=_manifest(),
        gold_path=gold_path,
    )
    return run_root, gold_path, delivery, metrics, rows


def _legacy_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    import secmind.reverse_api_overview as overview

    monkeypatch.setattr(overview, "_workspace_root", lambda: tmp_path.resolve())
    report = tmp_path / "docs" / "reports" / "reverse-analysis-audit-2026-08-24"
    results = tmp_path / "reverse_evaluation" / "results" / "audit-2026-08-24"
    report.mkdir(parents=True)
    results.mkdir(parents=True)
    (report / "legacy.txt").write_text("legacy", encoding="utf-8")
    (results / "legacy.txt").write_text("legacy", encoding="utf-8")
    return report, results


def test_overview_is_api_only_complete_and_uses_public_paths(tmp_path: Path) -> None:
    _run_root, _gold, delivery, _metrics, _rows = _render(tmp_path)

    html = (delivery / "index.html").read_text(encoding="utf-8")
    markdown = (delivery / "index.md").read_text(encoding="utf-8")
    csv_text = (delivery / "api-case-results.csv").read_text(encoding="utf-8")
    assert html.count('data-slot="') == 48
    for value in (
        "current · repeat 1",
        "optimized · repeat 2",
        "exact_fact_accuracy",
        "evidence_reference_coverage",
        "recommendation_priority_agreement",
        "Content-Security-Policy",
        "四维指标对比（双次重复均值）",
        'id="case"',
        "conservative_estimated_cny",
    ):
        assert value in html
    assert "## 四个运行 lane" in markdown
    assert "## 重复稳定性" in markdown
    assert "## 失败与人类决策" in markdown
    assert "## 优化版本相对当前版本" in markdown
    assert "/api-runs/" not in csv_text
    assert "reports/current/run-1/case-00/report.html" in csv_text
    assert (delivery / "scoring-receipt.json").is_file()


def test_overview_wraps_unbounded_narrative_without_removing_table_scroll(tmp_path: Path) -> None:
    """Mobile prose/list identifiers may wrap; wide evidence tables remain locally scrollable."""

    _run_root, _gold, delivery, _metrics, _rows = _render(tmp_path)

    html = (delivery / "index.html").read_text(encoding="utf-8")
    assert ".panel p,.panel li{overflow-wrap:anywhere;word-break:break-word}" in html
    assert ".table-wrap{overflow:auto}" in html
    assert "table{border-collapse:collapse;min-width:760px;width:100%}" in html


@pytest.mark.parametrize("mutation", ["run", "gold"])
def test_quarantine_reproves_run_and_canonical_gold_before_moving_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=secret
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    changed = run_root / "changed-after-receipt.txt" if mutation == "run" else gold_path
    if mutation == "run":
        changed.write_text("changed", encoding="utf-8")
    else:
        changed.write_text(changed.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="(run tree|gold|sealed score)"):
        overview.quarantine_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=secret)
    assert report.exists() and results.exists()


def test_render_and_gate_reject_forged_score_and_duplicate_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, metrics, rows = _render(tmp_path)
    _legacy_workspace(tmp_path, monkeypatch)
    forged = dict(metrics)
    forged["overall"] = {"macro_obligation_score": 123.456}
    with pytest.raises(ValueError, match="metrics"):
        overview.render_api_overview(
            metrics=forged,
            case_rows=rows,
            run_root=run_root,
            output_dir=tmp_path / "forged",
            manifest=_manifest(),
            gold_path=gold_path,
        )
    inventory_path = delivery / "artifact-inventory.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory["artifacts"] = [inventory["artifacts"][0]] * 336
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    with pytest.raises(ValueError, match="inventory"):
        overview.build_deletion_gate_receipt(
            run_root=run_root,
            delivery_root=delivery,
            gold_path=gold_path,
            active_secret=_test_secret(),
        )


@pytest.mark.parametrize(
    "variant",
    [
        lambda value: value,
        lambda value: json.dumps(value),
        lambda value: urllib.parse.quote(value, safe=""),
        lambda value: base64.b64encode(value.encode("utf-8")).decode("ascii"),
    ],
)
def test_gate_requires_and_scans_exact_secret_encodings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: object
) -> None:
    import secmind.reverse_api_overview as overview

    secret = _test_secret()
    run_root, gold_path, metrics, rows = _matrix(tmp_path)
    (run_root / "top-level-secret.txt").write_text(variant(secret), encoding="utf-8")  # type: ignore[operator]
    delivery = tmp_path / "delivery"
    overview.render_api_overview(
        metrics=metrics,
        case_rows=rows,
        run_root=run_root,
        output_dir=delivery,
        manifest=_manifest(),
        gold_path=gold_path,
    )
    _legacy_workspace(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="secret"):
        overview.build_deletion_gate_receipt(
            run_root=run_root,
            delivery_root=delivery,
            gold_path=gold_path,
            active_secret=secret,
        )


def test_gate_scans_the_canonical_gold_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, metrics, rows = _matrix(tmp_path)
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    gold["ignored_secret_fixture"] = _test_secret()
    gold_path.write_text(json.dumps(gold), encoding="utf-8")
    delivery = tmp_path / "delivery"
    overview.render_api_overview(
        metrics=metrics,
        case_rows=rows,
        run_root=run_root,
        output_dir=delivery,
        manifest=_manifest(),
        gold_path=gold_path,
    )
    _legacy_workspace(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="secret"):
        overview.build_deletion_gate_receipt(
            run_root=run_root,
            delivery_root=delivery,
            gold_path=gold_path,
            active_secret=_test_secret(),
        )
    with pytest.raises(ValueError, match="non-empty"):
        overview.build_deletion_gate_receipt(
            run_root=run_root,
            delivery_root=delivery,
            gold_path=gold_path,
            active_secret="",
        )


@pytest.mark.parametrize(
    "unsafe_html",
    [
        "<img src='//example.invalid/a'>",
        "<img src='file:///tmp/a'>",
        "<img src='ftp://example.invalid/a'>",
        "<img srcset='https://example.invalid/a 1x'>",
        "<div style=\"background:url(https://example.invalid/a)\"></div>",
        "<form action='https://example.invalid/a'></form>",
        "<meta http-equiv='refresh' content='0;url=https://example.invalid/a'>",
        "<script>fetch('https://example.invalid/a')</script>",
        "<img src='safe.png' onerror='fetch(\"https://example.invalid/a\")'>",
        "<svg><a xlink:href='https://example.invalid/a'></a></svg>",
        "<div style=\"background:u\\72l(https://example.invalid/a)\"></div>",
        "<img src='missing-local.png'>",
    ],
)
def test_renderer_rejects_external_resource_forms(tmp_path: Path, unsafe_html: str) -> None:
    from secmind.reverse_api_overview import render_api_overview

    run_root, gold_path, metrics, rows = _matrix(tmp_path)
    source = run_root / "current" / "run-1" / "case-00" / "report.html"
    source.write_text(
        "<!doctype html><html><head>"
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\">"
        f"</head><body>{unsafe_html}</body></html>",
        encoding="utf-8",
    )
    seal_path = source.parent / "seal.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal["report_html_sha256"] = __import__("hashlib").sha256(source.read_bytes()).hexdigest()
    seal_path.write_text(json.dumps(seal), encoding="utf-8")
    metrics, rows = score_api_runs(run_root, gold_path)
    with pytest.raises(ValueError, match="resource policy"):
        render_api_overview(
            metrics=metrics,
            case_rows=rows,
            run_root=run_root,
            output_dir=tmp_path / "delivery",
            manifest=_manifest(),
            gold_path=gold_path,
        )


def test_closed_allowlist_quarantine_delete_and_changed_target_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root,
        delivery_root=delivery,
        gold_path=gold_path,
        active_secret=secret,
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    (report / "changed.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="changed"):
        overview.delete_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=secret)
    assert report.exists() and results.exists()

    (report / "changed.txt").unlink()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root,
        delivery_root=delivery,
        gold_path=gold_path,
        active_secret=secret,
    )
    receipt_path.unlink()
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    quarantined = overview.quarantine_approved_legacy_artifacts(
        receipt, receipt_path=receipt_path, active_secret=secret
    )
    assert not report.exists() and not results.exists()
    assert set(quarantined.quarantined_targets) == {str(report.resolve()), str(results.resolve())}
    assert all(
        path.exists() and (path / "legacy.txt").read_text(encoding="utf-8") == "legacy"
        for path in quarantined.quarantined_targets.values()
    )


def test_substituted_legacy_directory_is_not_quarantined_or_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root,
        delivery_root=delivery,
        gold_path=gold_path,
        active_secret=secret,
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    parked = report.with_name("parked-original")
    report.rename(parked)
    report.mkdir()
    with pytest.raises(ValueError, match="changed"):
        overview.quarantine_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=secret)
    assert report.exists() and parked.exists() and results.exists()


def test_post_rename_digest_exception_restores_original_without_orphan_or_fd_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=secret
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    original_digest = overview._tree_digest
    native_parent_open = overview._open_quarantine_parent
    opened_parent_fds: list[int] = []

    def track_parent_open(path: Path) -> int:
        descriptor = native_parent_open(path)
        opened_parent_fds.append(descriptor)
        return descriptor

    def fail_quarantine_digest(path: Path, **kwargs: object) -> str:
        if ".secmind-quarantine-" in str(path):
            raise OSError("injected post-rename digest failure")
        return original_digest(path, **kwargs)

    monkeypatch.setattr(overview, "_tree_digest", fail_quarantine_digest)
    monkeypatch.setattr(overview, "_open_quarantine_parent", track_parent_open)
    with pytest.raises(OSError, match="injected"):
        overview.quarantine_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=secret)
    assert report.exists() and results.exists()
    assert not list(tmp_path.rglob(".secmind-quarantine-*"))
    assert opened_parent_fds
    for descriptor in opened_parent_fds:
        if os.name == "nt":
            with pytest.raises(OSError):
                overview._windows_inode(descriptor)
        else:
            with pytest.raises(OSError):
                os.fstat(descriptor)


def test_stat_failure_after_parent_open_leaves_targets_and_descriptors_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=secret
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    native_stat = overview._anchor_stat
    native_parent_open = overview._open_quarantine_parent
    opened_parent_fds: list[int] = []

    def track_parent_open(path: Path) -> int:
        descriptor = native_parent_open(path)
        opened_parent_fds.append(descriptor)
        return descriptor

    def fail_target_stat(parent: Path, descriptor: int, name: str) -> object:
        if parent == report.parent and name == report.name:
            raise OSError("injected target stat failure")
        return native_stat(parent, descriptor, name)

    monkeypatch.setattr(overview, "_anchor_stat", fail_target_stat)
    monkeypatch.setattr(overview, "_open_quarantine_parent", track_parent_open)
    with pytest.raises(OSError, match="injected"):
        overview.quarantine_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=secret)
    assert report.exists() and results.exists()
    assert not list(tmp_path.rglob(".secmind-quarantine-*"))
    assert opened_parent_fds
    for descriptor in opened_parent_fds:
        if os.name == "nt":
            with pytest.raises(OSError):
                overview._windows_inode(descriptor)
        else:
            with pytest.raises(OSError):
                os.fstat(descriptor)


def test_parent_substitution_at_open_cannot_move_unrelated_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=secret
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    native_open = overview._open_quarantine_parent
    victim = report.parent
    parked = report.parent.with_name("reports-parked")

    def substitute_parent(path: Path) -> int:
        path.rename(parked)
        path.mkdir()
        (path / "valuable.txt").write_text("keep", encoding="utf-8")
        return native_open(path)

    monkeypatch.setattr(overview, "_open_quarantine_parent", substitute_parent)
    with pytest.raises((OSError, ValueError)):
        overview.quarantine_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=secret)
    assert (victim / "valuable.txt").read_text(encoding="utf-8") == "keep"
    assert (parked / report.name).exists() and results.exists()


def test_parent_moved_after_anchor_cannot_quarantine_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=secret
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    native_rename = overview._anchor_rename
    parked = report.parent.with_name("reports-parked")

    def move_parent(parent: Path, descriptor: int, source: str, destination: str, *, inode: int) -> None:
        if source == report.name:
            parent.rename(parked)
            parent.mkdir()
            replacement = parent / source
            replacement.mkdir()
            (replacement / "valuable.txt").write_text("keep", encoding="utf-8")
        native_rename(parent, descriptor, source, destination, inode=inode)

    monkeypatch.setattr(overview, "_anchor_rename", move_parent)
    with pytest.raises((OSError, ValueError)):
        overview.quarantine_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=secret)
    assert (parked / report.name / "legacy.txt").read_text(encoding="utf-8") == "legacy"
    assert (report / "valuable.txt").read_text(encoding="utf-8") == "keep"
    assert results.exists()
    assert not list(tmp_path.rglob(".secmind-quarantine-*"))


def test_failed_outer_rollback_returns_exact_recovery_locator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=secret
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    native_anchor = overview._open_parent_anchor
    native_rename = overview._anchor_rename

    def fail_second(target: Path, digest: str) -> object:
        if target == results.resolve():
            raise OSError("injected second target failure")
        return native_anchor(target, digest)

    def fail_first_rollback(parent: Path, descriptor: int, source: str, destination: str, *, inode: int) -> None:
        if source.startswith(".secmind-quarantine-") and destination == report.name:
            raise OSError("injected rollback failure")
        native_rename(parent, descriptor, source, destination, inode=inode)

    monkeypatch.setattr(overview, "_open_parent_anchor", fail_second)
    monkeypatch.setattr(overview, "_anchor_rename", fail_first_rollback)
    with pytest.raises(overview.QuarantineRecoveryError) as raised:
        overview.quarantine_approved_legacy_artifacts(receipt, receipt_path=receipt_path, active_secret=secret)
    recovery = raised.value.recovery_targets
    assert str(report.resolve()) in recovery
    quarantine = recovery[str(report.resolve())]
    assert quarantine.exists() and not report.exists() and results.exists()
    record = quarantine.with_name(f"{quarantine.name}.recovery.json")
    payload = json.loads(record.read_text(encoding="utf-8"))
    assert payload["original"] == str(report.resolve())
    assert payload["quarantine"] == str(quarantine)
    assert payload["inode"] == quarantine.stat().st_ino


def test_rollback_inode_mismatch_persists_exact_recovery_locator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    parent = tmp_path / "parent"
    quarantine = parent / ".secmind-quarantine-fixture"
    quarantine.mkdir(parents=True)
    entry = quarantine.stat()
    item = overview._Quarantine(
        parent, overview._open_quarantine_parent(parent), "original", quarantine.name,
        entry.st_dev, entry.st_ino, "a" * 64,
    )
    native_stat = overview._anchor_stat

    def mismatched_stat(directory: Path, descriptor: int, name: str) -> object:
        if name == quarantine.name:
            return type("Entry", (), {"st_dev": entry.st_dev, "st_ino": entry.st_ino + 1})()
        return native_stat(directory, descriptor, name)

    monkeypatch.setattr(overview, "_anchor_stat", mismatched_stat)
    recovery = overview._rollback([item])
    assert recovery == {str(parent / "original"): quarantine}
    payload = json.loads((parent / f"{quarantine.name}.recovery.json").read_text(encoding="utf-8"))
    assert payload["device"] == entry.st_dev and payload["inode"] == entry.st_ino


def test_failed_recovery_record_write_leaves_no_partial_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import secmind.reverse_api_overview as overview

    parent = tmp_path / "parent"
    parent.mkdir()
    descriptor = overview._open_quarantine_parent(parent)

    def fail_write(_fd: int, _data: object) -> int:
        raise OSError("injected write failure")

    monkeypatch.setattr(overview.os, "write", fail_write)
    try:
        with pytest.raises(OSError, match="injected write failure"):
            overview._anchor_create(parent, descriptor, "recovery.json", b"record")
    finally:
        overview._close_quarantine_parent(descriptor)
    assert not (parent / "recovery.json").exists()


def test_public_deletion_gate_receipt_is_workspace_relative_and_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    _legacy_workspace(tmp_path, monkeypatch)
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=_test_secret()
    )
    public_path = overview.write_deletion_gate_receipt(receipt, active_secret=_test_secret())
    payload = json.loads(public_path.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "3.0"
    assert (
        overview._canonical_sha256({key: value for key, value in payload.items() if key != "public_binding_sha256"})
        == payload["public_binding_sha256"]
    )
    assert str(tmp_path) not in public_path.read_text(encoding="utf-8")
    for key in ("delivery_root", "run_root", "gold_path", "scoring_receipt_path"):
        assert not Path(payload[key]).is_absolute()
    assert all(not Path(item).is_absolute() for item in payload["approved_deletion_targets"])


def test_successful_quarantine_persists_relative_recovery_receipt_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=_test_secret()
    )
    receipt_path = overview.write_deletion_gate_receipt(receipt, active_secret=_test_secret())
    quarantined = overview.quarantine_approved_legacy_artifacts(
        receipt, receipt_path=receipt_path, active_secret=_test_secret()
    )
    durable_path = overview._quarantine_receipt_path()
    payload = json.loads(durable_path.read_text(encoding="utf-8"))

    assert not report.exists() and not results.exists()
    assert payload["gate_binding_sha256"] == receipt.binding_sha256
    assert payload["binding_sha256"] == quarantined.binding_sha256
    assert str(tmp_path) not in durable_path.read_text(encoding="utf-8")
    assert {entry["original_path"] for entry in payload["targets"]} == {
        "docs/reports/reverse-analysis-audit-2026-08-24",
        "reverse_evaluation/results/audit-2026-08-24",
    }
    assert all(not Path(entry["quarantine_path"]).is_absolute() for entry in payload["targets"])


def test_reconstruct_existing_quarantine_never_renames_and_finalizes_public_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    report, results = _legacy_workspace(tmp_path, monkeypatch)
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=_test_secret()
    )
    legacy_public_path = overview.write_deletion_gate_receipt(receipt, active_secret=_test_secret())
    overview.quarantine_approved_legacy_artifacts(
        receipt, receipt_path=legacy_public_path, active_secret=_test_secret()
    )
    overview._quarantine_receipt_path().unlink()
    native_rename = overview.os.rename

    def refuse_rename(*args: object, **kwargs: object) -> None:
        raise AssertionError("reconstruction must not rename or delete")

    monkeypatch.setattr(overview.os, "rename", refuse_rename)
    reconstructed = overview.reconstruct_existing_quarantine(
        receipt_path=legacy_public_path, active_secret=_test_secret()
    )
    final_path = overview.write_quarantine_finalization(
        receipt_path=legacy_public_path, quarantine_receipt=reconstructed, active_secret=_test_secret()
    )

    assert not report.exists() and not results.exists()
    assert final_path.is_file()
    assert native_rename is not overview.os.rename
    final = json.loads(final_path.read_text(encoding="utf-8"))
    assert final["gate_receipt_path"] in {
        "docs/reports/deletion-gate-receipt.json",
        "delivery/deletion-gate-receipt.json",
    }
    assert final["quarantine_receipt_binding_sha256"] == reconstructed.binding_sha256
    assert all(
        str(tmp_path) not in path.read_text(encoding="utf-8")
        for path in delivery.rglob("*")
        if path.is_file()
    )


def test_legacy_gate_loader_accepts_json_arrays_but_rejects_unclosed_or_confused_shapes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    _legacy_workspace(tmp_path, monkeypatch)
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=_test_secret()
    )
    payload = json.loads(json.dumps(receipt.to_dict()))

    assert overview._internal_receipt_from_payload(payload).binding_sha256 == receipt.binding_sha256

    payload["unexpected"] = "reject"
    with pytest.raises(ValueError, match="unregistered"):
        overview._internal_receipt_from_payload(payload)
    payload.pop("unexpected")
    payload["approved_deletion_targets"] = payload["approved_deletion_targets"][0]
    with pytest.raises(ValueError, match="invalid"):
        overview._internal_receipt_from_payload(payload)


def test_public_gate_and_local_quarantine_receipt_loaders_reject_extra_or_type_confused_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, _metrics, _rows = _render(tmp_path)
    _legacy_workspace(tmp_path, monkeypatch)
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=_test_secret()
    )
    gate_path = overview.write_deletion_gate_receipt(receipt, active_secret=_test_secret())
    quarantined = overview.quarantine_approved_legacy_artifacts(
        receipt, receipt_path=gate_path, active_secret=_test_secret()
    )
    local_path = overview._quarantine_receipt_path()

    public_payload = json.loads(gate_path.read_text(encoding="utf-8"))
    public_payload["unbound"] = "reject"
    gate_path.write_text(json.dumps(public_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        overview._load_public_gate_receipt(gate_path)

    local_payload = json.loads(local_path.read_text(encoding="utf-8"))
    local_payload["targets"] = local_payload["targets"][0]
    local_path.write_text(json.dumps(local_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="schema"):
        overview._load_quarantine_receipt(local_path, verify_live_paths=True)
    assert quarantined.binding_sha256


def test_delivery_verifier_rejects_tampered_or_cross_bound_finalization_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, metrics, rows = _render(tmp_path)
    _legacy_workspace(tmp_path, monkeypatch)
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=_test_secret()
    )
    gate_path = overview.write_deletion_gate_receipt(receipt, active_secret=_test_secret())
    quarantine = overview.quarantine_approved_legacy_artifacts(
        receipt, receipt_path=gate_path, active_secret=_test_secret()
    )
    final_path = overview.write_quarantine_finalization(
        receipt_path=gate_path, quarantine_receipt=quarantine, active_secret=_test_secret()
    )
    _slots, scored_metrics, scored_rows, inventory, scoring = overview._scored_truth(
        run_root=run_root, gold_path=gold_path, metrics=metrics, case_rows=rows
    )
    original = json.loads(final_path.read_text(encoding="utf-8"))
    original["unbound"] = "reject"
    original["binding_sha256"] = overview._canonical_sha256(
        {key: value for key, value in original.items() if key != "binding_sha256"}
    )
    final_path.write_text(json.dumps(original), encoding="utf-8")

    with pytest.raises(ValueError, match="finalization"):
        overview._verify_delivery(
            delivery,
            source_inventory=inventory,
            metrics=scored_metrics,
            scored_rows=scored_rows,
            scoring_receipt=scoring,
            active_secret=_test_secret(),
        )


def test_post_quarantine_finalization_refresh_preserves_pre_action_gate_and_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A presentation-only delivery fix gets a new final binding, never a new gate."""

    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, metrics, rows = _render(tmp_path)
    _legacy_workspace(tmp_path, monkeypatch)
    secret = _test_secret()
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=secret
    )
    gate_path = overview.write_deletion_gate_receipt(receipt, active_secret=secret)
    quarantine = overview.quarantine_approved_legacy_artifacts(
        receipt, receipt_path=gate_path, active_secret=secret
    )
    final_path = overview.write_quarantine_finalization(
        receipt_path=gate_path, quarantine_receipt=quarantine, active_secret=secret
    )
    original_final = json.loads(final_path.read_text(encoding="utf-8"))
    gate_bytes = gate_path.read_bytes()
    quarantine_path = overview._quarantine_receipt_path()
    quarantine_bytes = quarantine_path.read_bytes()

    overview_path = delivery / "index.html"
    overview_path.write_text(
        overview_path.read_text(encoding="utf-8").replace(
            ".panel{background", ".panel p{overflow-wrap:anywhere;word-break:break-word}.panel{background"
        ),
        encoding="utf-8",
    )

    refreshed = overview.refresh_quarantine_finalization(receipt_path=gate_path, active_secret=secret)
    refreshed_payload = json.loads(refreshed.read_text(encoding="utf-8"))
    assert gate_path.read_bytes() == gate_bytes
    assert quarantine_path.read_bytes() == quarantine_bytes
    assert refreshed_payload["schema_version"] == "3.0"
    assert refreshed_payload["pre_quarantine_core_delivery_sha256"] == receipt.delivery_sha256
    assert refreshed_payload["core_delivery_sha256"] != receipt.delivery_sha256
    assert refreshed_payload["previous_finalization_binding_sha256"] == original_final["binding_sha256"]

    _slots, scored_metrics, scored_rows, inventory, scoring = overview._scored_truth(
        run_root=run_root, gold_path=gold_path, metrics=metrics, case_rows=rows
    )
    overview._verify_delivery(
        delivery,
        source_inventory=inventory,
        metrics=scored_metrics,
        scored_rows=scored_rows,
        scoring_receipt=scoring,
        active_secret=secret,
    )


def test_finalization_rejects_a_self_bound_quarantine_receipt_from_another_gate_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import secmind.reverse_api_overview as overview

    run_root, gold_path, delivery, metrics, rows = _render(tmp_path)
    _legacy_workspace(tmp_path, monkeypatch)
    receipt = overview.build_deletion_gate_receipt(
        run_root=run_root, delivery_root=delivery, gold_path=gold_path, active_secret=_test_secret()
    )
    gate_path = overview.write_deletion_gate_receipt(receipt, active_secret=_test_secret())
    quarantine = overview.quarantine_approved_legacy_artifacts(
        receipt, receipt_path=gate_path, active_secret=_test_secret()
    )
    final_path = overview.write_quarantine_finalization(
        receipt_path=gate_path, quarantine_receipt=quarantine, active_secret=_test_secret()
    )
    _slots, scored_metrics, scored_rows, inventory, scoring = overview._scored_truth(
        run_root=run_root, gold_path=gold_path, metrics=metrics, case_rows=rows
    )
    local_path = overview._quarantine_receipt_path()
    local = json.loads(local_path.read_text(encoding="utf-8"))
    local["gate_binding_sha256"] = "a" * 64
    local["binding_sha256"] = overview._canonical_sha256(
        {key: value for key, value in local.items() if key != "binding_sha256"}
    )
    local_path.write_text(json.dumps(local), encoding="utf-8")
    final = json.loads(final_path.read_text(encoding="utf-8"))
    final["quarantine_receipt_binding_sha256"] = local["binding_sha256"]
    final["quarantine_receipt_sha256"] = overview._file_sha256(local_path)
    final["binding_sha256"] = overview._canonical_sha256(
        {key: value for key, value in final.items() if key != "binding_sha256"}
    )
    final_path.write_text(json.dumps(final), encoding="utf-8")

    with pytest.raises(ValueError, match="finalization"):
        overview._verify_delivery(
            delivery,
            source_inventory=inventory,
            metrics=scored_metrics,
            scored_rows=scored_rows,
            scoring_receipt=scoring,
            active_secret=_test_secret(),
        )
