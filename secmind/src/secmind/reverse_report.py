"""Self-contained forensic-style audit report for the reverse evaluation."""

from __future__ import annotations

import csv
import hashlib
import html
import json
import platform
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secmind.reverse_evaluation import verify_prediction_seal

ARMS = ("old", "current", "optimized")


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _case_ids(payload: dict[str, Any]) -> list[str]:
    cases = payload.get("cases", [])
    values = [str(item.get("id", "")) for item in cases if isinstance(item, dict)]
    if len(values) != len(cases) or not all(values) or len(values) != len(set(values)):
        raise ValueError("report input case IDs must be present and unique")
    return values


def _load_live_pair(live_root: Path, live_status: str) -> dict[str, Any]:
    if live_status != "completed_exploratory_pair":
        return {"status": live_status, "exploratory": True, "arms": {}}
    arms: dict[str, Any] = {}
    for arm in ("current", "optimized"):
        prediction = live_root / f"live-{arm}.json"
        seal = live_root / f"live-{arm}.seal.json"
        metrics = live_root / f"live-{arm}.metrics.json"
        cases = live_root / f"live-{arm}-case-results.csv"
        missing = [path.name for path in (prediction, seal, metrics, cases) if not path.is_file()]
        if missing:
            raise ValueError(f"completed Live pair is missing {arm} artifacts: {', '.join(missing)}")
        verified = verify_prediction_seal(prediction, seal)
        metric_payload = _load(metrics)
        if metric_payload.get("prediction_sha256") != verified.get("prediction_sha256"):
            raise ValueError(f"{arm} Live metrics are not bound to the sealed prediction")
        run = _load(prediction)
        run_cases = run.get("cases", [])
        if not isinstance(run_cases, list):
            raise ValueError(f"{arm} Live cases must be a list")
        arms[arm] = {
            "metrics": metric_payload,
            "aggregate_receipt": run.get("aggregate_receipt", {}),
            "pricing": run.get("pricing", {}),
            "prediction_sha256": verified.get("prediction_sha256"),
            "case_results_sha256": _sha256(cases),
            "model_receipt_count": sum(
                1 for item in run_cases if isinstance(item, dict) and item.get("model_receipt") is not None
            ),
            "model_failure_count": sum(
                1
                for item in run_cases
                if isinstance(item, dict)
                and isinstance(item.get("error"), dict)
                and item["error"].get("code") == "LIVE_MODEL_CALL_FAILED"
            ),
        }
    return {"status": live_status, "exploratory": True, "arms": arms}


def _copy_live_artifacts(live_root: Path, output_dir: Path) -> None:
    raw_dir = output_dir / "raw-reports"
    normalized_dir = output_dir / "normalized-reports"
    raw_dir.mkdir(parents=True, exist_ok=True)
    normalized_dir.mkdir(parents=True, exist_ok=True)
    for arm in ("current", "optimized"):
        copies = (
            (live_root / f"live-{arm}.json", raw_dir / f"live-{arm}.json"),
            (live_root / f"live-{arm}.seal.json", raw_dir / f"live-{arm}.seal.json"),
            (live_root / f"live-{arm}.metrics.json", normalized_dir / f"live-{arm}.metrics.json"),
            (
                live_root / f"live-{arm}-case-results.csv",
                normalized_dir / f"live-{arm}-case-results.csv",
            ),
        )
        for source, destination in copies:
            if not source.is_file():
                raise ValueError(f"completed Live pair is missing artifact: {source.name}")
            shutil.copy2(source, destination)


def _load_live_preflight(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    payload = _load(path)
    arms = payload.get("arms")
    if not isinstance(arms, dict):
        raise ValueError("Live preflight arms must be an object")
    return {
        "ready": payload.get("ready") is True,
        "reason": str(payload.get("reason", "unknown")),
        "case_count": int(payload.get("case_count", 0)),
        "gold_read": payload.get("gold_read") is True,
        "network_requests_made": int(payload.get("network_requests_made", -1)),
        "arms": {
            arm: {
                "seal_verified": receipt.get("seal_verified") is True,
                "prediction_sha256": receipt.get("prediction_sha256"),
            }
            for arm, receipt in arms.items()
            if isinstance(receipt, dict)
        },
    }


def _pct(value: Any) -> str:
    return f"{float(value or 0):.3f}"


def _stamp(status: str) -> str:
    return f'<span class="stamp {html.escape(status.casefold())}">{html.escape(status)}</span>'


def _report_artifacts(output_dir: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for directory_name in ("raw-reports", "normalized-reports"):
        directory = output_dir / directory_name
        if not directory.is_dir():
            continue
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            payload = path.read_bytes()
            inventory.append(
                {
                    "path": path.relative_to(output_dir).as_posix(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            )
    return inventory


def render_audit_report(
    results_root: Path,
    output_dir: Path,
    *,
    live_status: str,
    gold_path: Path | None = None,
    live_root: Path | None = None,
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    repository_root = Path(__file__).resolve().parents[2]
    gold_path = gold_path or repository_root / "reverse_evaluation" / "gold" / "expected.json"
    gold = _load(gold_path)
    metrics = {arm: _load(results_root / arm / "metrics.json") for arm in ARMS}
    predictions = {arm: _load(results_root / arm / "predictions.json") for arm in ARMS}
    seals = {arm: _load(results_root / arm / "predictions.seal.json") for arm in ARMS}
    gold_ids = _case_ids(gold)
    raw_dir = output_dir / "raw-reports"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for arm in ARMS:
        prediction_path = results_root / arm / "predictions.json"
        seal_path = results_root / arm / "predictions.seal.json"
        verified = verify_prediction_seal(prediction_path, seal_path)
        if metrics[arm].get("prediction_sha256") != verified.get("prediction_sha256"):
            raise ValueError(f"{arm} metrics are not bound to the sealed prediction")
        if metrics[arm].get("gold_sha256") != _sha256(gold_path):
            raise ValueError(f"{arm} metrics are not bound to the selected gold file")
        if _case_ids(predictions[arm]) != gold_ids:
            raise ValueError(f"{arm} prediction case IDs do not match gold")
        shutil.copy2(prediction_path, raw_dir / f"{arm}-predictions.json")
    speakeasy_lock = _load(repository_root / "reverse_evaluation" / "tooling" / "speakeasy.lock.json")
    resolved_live_root = live_root or results_root
    live_payload = _load_live_pair(resolved_live_root, live_status)
    if live_status == "completed_exploratory_pair":
        _copy_live_artifacts(resolved_live_root, output_dir)
    live_preflight_path = output_dir / "live-preflight.json"
    live_preflight = _load_live_preflight(live_preflight_path)
    for arm, payload in live_payload.get("arms", {}).items():
        if payload.get("metrics", {}).get("gold_sha256") != _sha256(gold_path):
            raise ValueError(f"{arm} Live metrics are not bound to the selected gold file")
    cases: list[dict[str, Any]] = []
    for arm in ARMS:
        for case in predictions[arm].get("cases", []):
            cases.append(
                {
                    "arm": arm,
                    "case_id": case.get("id"),
                    "status": case.get("status"),
                    "behavior_count": len(case.get("behaviors", [])),
                    "evidence_count": len(case.get("evidence_refs", [])),
                    "error_code": (case.get("error") or {}).get("code", ""),
                }
            )
    safety_verified = all(item.get("safety_gate_passed") for item in metrics.values())
    aggregate = {
        "schema_version": "1.0",
        "offline": metrics,
        "live": live_payload,
        "success_gate": {
            "macro_strictly_improved": metrics["optimized"]["macro_obligation_score"]
            > metrics["current"]["macro_obligation_score"],
            "behavior_f1_not_decreased": metrics["optimized"]["behavior_f1"] >= metrics["current"]["behavior_f1"],
            "safety_gate_passed": safety_verified,
        },
    }
    safety_label = "0 · RECEIPTS VERIFIED" if safety_verified else "FAIL / UNKNOWN"
    metrics_path = output_dir / "metrics.json"
    metrics_path.write_text(
        json.dumps(aggregate, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    csv_path = output_dir / "case-results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(cases[0]) if cases else ["arm", "case_id"])
        writer.writeheader()
        writer.writerows(cases)
    manifest = {
        "schema_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "suite_id": "secmind-reverse-safe-12-v1",
        "arms": {arm: dict(predictions[arm].get("run_identity", {})) for arm in ARMS},
        "platform": predictions["optimized"].get(
            "platform",
            {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        ),
        "sample_sha256": next(
            (
                case.get("facts", {}).get("sha256")
                for case in predictions["optimized"].get("cases", [])
                if case.get("facts", {}).get("sha256")
            ),
            "unavailable",
        ),
        "speakeasy": {
            **speakeasy_lock,
            "sandbox_receipt": predictions["optimized"].get("safety_receipts", {}).get(
                "real_network_requests", {}
            ),
        },
        "planned_live_model": {
            "provider": "deepseek",
            "base_url": "https://api.deepseek.com",
            "model": "deepseek-v4-flash",
            "thinking_enabled": True,
            "reasoning_effort": "high",
            "structured_output": "json_object",
            "live_status": live_status,
            "cost_status": "not_run" if live_status.startswith("blocked_") or live_status == "not_run" else "recorded",
            "credential_persisted": False,
            **(
                {
                    "preflight": live_preflight,
                    "preflight_sha256": _sha256(live_preflight_path),
                }
                if live_preflight is not None
                else {}
            ),
        },
        "report_artifacts": _report_artifacts(output_dir),
        "prediction_seals": {arm: seals[arm].get("prediction_sha256") for arm in ARMS},
        "gold": {
            "path": gold_path.name,
            "sha256": _sha256(gold_path),
            "schema_version": gold.get("schema_version"),
            "case_ids_sha256": hashlib.sha256(json.dumps(gold_ids, separators=(",", ":")).encode()).hexdigest(),
        },
        "safety": {
            "gate_passed": safety_verified,
            "network_scope": "sample_and_reverse_tools_only",
            "approved_model_api_calls_excluded": True,
            "approved_model_api_provider_requests": sum(
                int(payload.get("aggregate_receipt", {}).get("provider_requests", 0))
                for payload in live_payload.get("arms", {}).values()
                if isinstance(payload, dict)
            ),
            "receipt_status": {
                arm: {
                    "complete": metrics[arm].get("safety_receipts_complete", False),
                    "counts": metrics[arm].get("safety", {}),
                }
                for arm in ARMS
            },
        },
    }
    manifest_path = output_dir / "run-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    table_rows = "".join(
        "<tr>"
        f"<td>{html.escape(arm)}</td>"
        f"<td class='num'>{_pct(metrics[arm]['macro_obligation_score'])}</td>"
        f"<td class='num'>{_pct(metrics[arm]['behavior_f1'])}</td>"
        f"<td class='num'>{_pct(metrics[arm]['exact_fact_accuracy'])}</td>"
        f"<td class='num'>{_pct(metrics[arm]['evidence_coverage'])}</td>"
        f"<td>{_stamp('PASS' if metrics[arm]['safety_gate_passed'] else 'FAIL')}</td>"
        "</tr>"
        for arm in ARMS
    )
    case_rows = "".join(
        f"<tr data-arm='{html.escape(str(row['arm']))}' data-status='{html.escape(str(row['status']))}'>"
        f"<td><code>{html.escape(str(row['case_id']))}</code></td><td>{html.escape(str(row['arm']))}</td>"
        f"<td>{_stamp(str(row['status']).upper())}</td><td class='num'>{row['behavior_count']}</td>"
        f"<td class='num'>{row['evidence_count']}</td><td><code>{html.escape(str(row['error_code']))}</code></td></tr>"
        for row in cases
    )
    capability_rows = [
        ("PE headers / sections / imports", "OBSERVED", "纯 Python 解析；导入仅表示 static_presence。"),
        ("ASCII 与单字节 XOR 恢复", "OBSERVED", "候选去 padding 噪声并标置信度；仍是启发式。"),
        ("完整源码 API 链识别", "OBSERVED", "进程镂空、DLL 注入、APC、RC4、Native API、反调试。"),
        ("Speakeasy 双 profile API 仿真", "OBSERVED", "安全样本 SHA 绑定；错误/正确口令路径已实测。"),
        ("CAPE JSON 与 HTTP 契约", "PARTIAL", "MockTransport 与样本哈希绑定的签名 R2 receipt 已测；真实提交默认关闭，本机无 Windows VM。"),
        ("ELF / Mach-O / APK", "ABSENT", "没有格式解析器或主链路实现。"),
        ("通用反汇编 / 函数识别", "ABSENT", "主项目未集成；Speakeasy 的传递依赖不等于 Agent 能力。"),
        ("CFG / 调用图 / 参数与数据流", "ABSENT", "无实现与测试证据。"),
        ("脱壳 / 反编译 / 符号恢复", "ABSENT", "无实现与测试证据。"),
        ("完整 VM 沙箱 / 网络与内存监控", "ABSENT", "API 仿真不是 Windows VM；未部署 CAPE 客体。"),
    ]
    capability_html = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{_stamp(status)}</td><td>{html.escape(note)}</td></tr>"
        for name, status, note in capability_rows
    )
    external_rows = [
        ("Speakeasy 2.0.0b6", "LOCAL", "固定 commit/归档哈希；sandbox-exec；真实网络 deny。"),
        ("CAPE v2", "INTERFACE", "归一化 + Mock HTTP + 签名审批 receipt；未部署 Windows VM，真实 submit off。"),
        ("/usr/bin/objdump", "AVAILABLE", "本机存在，未接入 Agent 证据链。"),
        ("llvm-objdump", "ABSENT", "本机未发现。"),
        ("Capstone", "TRANSITIVE", "只存在于隔离 Speakeasy 环境，不能宣称静态反汇编能力。"),
        ("Ghidra / radare2 / Wine / Docker", "ABSENT", "本机未发现或未接入。"),
    ]
    external_html = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{_stamp(status)}</td><td>{html.escape(note)}</td></tr>"
        for name, status, note in external_rows
    )
    optimized_macro = _pct(metrics["optimized"]["macro_obligation_score"])
    current_macro = _pct(metrics["current"]["macro_obligation_score"])
    optimized_f1 = _pct(metrics["optimized"]["behavior_f1"])
    current_f1 = _pct(metrics["current"]["behavior_f1"])
    live_safe = html.escape(live_status)
    live_label = "待独立凭据" if live_status == "blocked_missing_deepseek_credential" else live_status
    live_label_safe = html.escape(live_label)
    live_arms = live_payload.get("arms", {})
    live_pair_html = ""
    if isinstance(live_arms, dict) and live_arms:
        live_rows = "".join(
            "<tr>"
            f"<td>{html.escape(arm)}</td>"
            f"<td class='num'>{_pct(payload['metrics'].get('macro_obligation_score'))}</td>"
            f"<td class='num'>{_pct(payload['metrics'].get('behavior_f1'))}</td>"
            f"<td class='num'>{_pct(payload['metrics'].get('completion_rate'))}</td>"
            f"<td class='num'>{html.escape(str(payload['model_receipt_count']))}/12</td>"
            f"<td class='num'>{html.escape(str(payload['model_failure_count']))}</td>"
            f"<td class='num'>{html.escape(str(payload['aggregate_receipt'].get('total_tokens', 0)))}</td>"
            f"<td class='num'>{html.escape(str(payload['pricing'].get('estimated_cny', 0)))}</td>"
            "</tr>"
            for arm, payload in live_arms.items()
        )
        live_pair_html = (
            "<h4>DeepSeek 配对 Live（探索性）</h4><div class='table-wrap'><table><thead><tr>"
            "<th>Arm</th><th>Macro obligations</th><th>Behavior F1</th><th>Completion</th>"
            "<th>Model receipts</th><th>Model failures</th><th>Total tokens</th>"
            f"<th>Estimated CNY</th></tr></thead><tbody>{live_rows}</tbody></table></div>"
        )
    live_note = (
        "两组 sealed Live 指标、Token 与费用已核验并展示。"
        if live_pair_html
        else "未执行的 Live 结果没有被伪装成 0 分或离线结果；待安全注入独立 DeepSeek key 后才可形成探索性结论。"
    )
    live_preflight_html = ""
    if live_preflight is not None:
        preflight_arms = live_preflight.get("arms", {})
        seals_verified = isinstance(preflight_arms, dict) and all(
            isinstance(receipt, dict) and receipt.get("seal_verified") is True
            for receipt in preflight_arms.values()
        )
        seal_label = "封印已验证" if seals_verified else "封印未完整验证"
        live_preflight_html = (
            "<div class='callout'><b>Live 预检</b> · "
            f"{int(live_preflight.get('case_count', 0))} 题{seal_label}；"
            f"gold_read={str(bool(live_preflight.get('gold_read'))).lower()}；"
            f"network_requests={int(live_preflight.get('network_requests_made', -1))}；"
            f"状态 <code>{html.escape(str(live_preflight.get('reason', 'unknown')))}</code>。"
            "</div>"
        )
    data_blob = html.escape(json.dumps(aggregate, ensure_ascii=False, separators=(",", ":")))
    report_html = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">
<title>SecMind 逆向分析研发审计</title>
<style>
:root{{--ink:#0b1320;--muted:#516274;--paper:#fcfdfe;--blueprint:#eaf0f6;--line:#bdd0df;--cyan:#137f8b;--amber:#aa6b06;--red:#a43838;--green:#26734d;--shadow:0 14px 40px rgba(11,19,32,.09)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;color:var(--ink);background:var(--blueprint);font-family:"Avenir Next","PingFang SC",system-ui,sans-serif;line-height:1.6}}
body:before{{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(19,127,139,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(19,127,139,.045) 1px,transparent 1px);background-size:24px 24px}}
.shell{{display:grid;grid-template-columns:260px minmax(0,1fr);max-width:1480px;margin:auto;position:relative}}aside{{position:sticky;top:0;height:100vh;padding:34px 24px;border-right:1px solid var(--line);background:rgba(234,240,246,.92);backdrop-filter:blur(10px)}}
.folio{{font:700 12px/1.2 "SFMono-Regular",monospace;letter-spacing:.14em;color:var(--cyan)}}aside h1{{font:700 25px/1.15 Georgia,"Songti SC",serif;margin:12px 0 28px}}nav a{{display:block;color:var(--muted);text-decoration:none;padding:8px 0;border-bottom:1px dotted var(--line);font-size:14px}}nav a:hover{{color:var(--ink)}}main{{padding:38px clamp(24px,5vw,72px) 90px;min-width:0}}
.hero{{background:var(--paper);border:1px solid var(--line);box-shadow:var(--shadow);padding:clamp(28px,5vw,64px);position:relative;overflow:hidden}}.hero:after{{content:"EVIDENCE BOUND";position:absolute;right:-42px;top:28px;transform:rotate(8deg);border:3px double var(--cyan);color:var(--cyan);padding:7px 48px;font:800 12px monospace;opacity:.65}}
h2{{font:700 clamp(34px,5vw,66px)/1.02 Georgia,"Songti SC",serif;max-width:900px;margin:12px 0 22px;letter-spacing:-.025em}}.lead{{max-width:820px;color:var(--muted);font-size:18px}}.kicker{{font:700 12px monospace;letter-spacing:.18em;color:var(--cyan)}}
.cards{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-top:32px}}.card{{border-top:3px solid var(--ink);background:#fff;padding:18px;min-width:0}}.card .value{{font:700 28px/1.2 "SFMono-Regular",monospace;overflow-wrap:anywhere}}.card small{{color:var(--muted)}}section{{scroll-margin-top:20px;margin-top:52px}}section>h3{{font:700 30px/1.15 Georgia,"Songti SC",serif;margin:0 0 12px}}.section-note{{color:var(--muted);max-width:860px}}
.spine{{display:grid;grid-template-columns:repeat(4,1fr);gap:0;margin:26px 0;background:var(--paper);border:1px solid var(--line)}}.spine article{{padding:24px;border-right:1px solid var(--line);position:relative}}.spine article:last-child{{border:0}}.spine b{{display:block;font-family:Georgia,serif;font-size:19px}}.spine code,code{{font-family:"SFMono-Regular",monospace;font-size:.86em}}
.table-wrap{{overflow:auto;border:1px solid var(--line);background:var(--paper);box-shadow:0 8px 24px rgba(11,19,32,.05)}}table{{width:100%;border-collapse:collapse;min-width:720px}}th,td{{padding:13px 15px;text-align:left;border-bottom:1px solid #dce6ed;vertical-align:top}}th{{position:sticky;top:0;background:#dfeaf1;font:700 11px monospace;letter-spacing:.08em;text-transform:uppercase}}.num{{font-family:"SFMono-Regular",monospace;font-variant-numeric:tabular-nums}}.stamp{{display:inline-block;border:1px solid currentColor;padding:2px 7px;font:800 10px monospace;letter-spacing:.08em;transform:rotate(-1deg);color:var(--cyan)}}.stamp.pass,.stamp.observed,.stamp.local,.stamp.available,.stamp.completed{{color:var(--green)}}.stamp.fail,.stamp.absent,.stamp.error{{color:var(--red)}}.stamp.partial,.stamp.interface,.stamp.transitive,.stamp.unavailable{{color:var(--amber)}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}}button{{border:1px solid var(--line);background:var(--paper);padding:8px 12px;color:var(--ink);font:700 12px monospace;cursor:pointer}}button[aria-pressed="true"]{{background:var(--ink);color:white}}.callout{{border-left:4px solid var(--amber);background:#fff8e8;padding:18px 22px;margin:20px 0}}.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:22px}}ul{{padding-left:20px}}footer{{margin-top:58px;padding-top:22px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}}
@media(max-width:980px){{.shell{{display:block}}aside{{position:relative;height:auto;border-right:0;border-bottom:1px solid var(--line)}}nav{{display:flex;gap:14px;overflow:auto}}nav a{{white-space:nowrap}}.cards{{grid-template-columns:1fr 1fr}}.spine{{grid-template-columns:1fr 1fr}}.spine article{{border-bottom:1px solid var(--line)}}}}
@media(max-width:620px){{main{{padding:20px 14px 60px}}.hero{{padding:26px 20px}}.hero:after{{display:none}}.cards,.grid2,.spine{{grid-template-columns:1fr}}.spine article{{border-right:0}}}}
</style></head><body><div class="shell"><aside><div class="folio">SECMIND / RA-12 / 2026-08-24</div><h1>逆向分析<br>研发审计卷宗</h1><nav><a href="#verdict">结论</a><a href="#flow">证据链</a><a href="#metrics">离线评分</a><a href="#cases">逐题结果</a><a href="#capabilities">代码能力</a><a href="#tools">外部工具</a><a href="#safety">安全边界</a><a href="#changes">修改摘要</a></nav></aside><main>
<header class="hero" id="verdict"><div class="kicker">FORENSIC DEVELOPMENT AUDIT · SELF-CONTAINED</div><h2>从“只能静态看见”到“能安全观测两条运行路径”</h2><p class="lead">12 个仓库自制/合成安全用例已完成三臂离线封存评测。优化版义务宏平均从当前版 <b>{current_macro}</b> 提升到 <b>{optimized_macro}</b>；行为 F1 从 <b>{current_f1}</b> 提升到 <b>{optimized_f1}</b>。结果只证明本题集，不代表通用恶意软件沙箱能力。</p>
<div class="cards"><div class="card"><small>优化版义务宏平均</small><div class="value">{optimized_macro}</div></div><div class="card"><small>优化版行为 F1</small><div class="value">{optimized_f1}</div></div><div class="card"><small>安全门</small><div class="value" style="font-size:18px">{html.escape(safety_label)}</div></div><div class="card"><small>DeepSeek Live</small><div class="value" style="font-size:18px">{live_label_safe}</div></div></div></header>
<section id="flow"><h3>证据脊线</h3><p class="section-note">事实不会跨层“升级”：导入存在不是调用，仿真事件不是宿主行为，模型总结也不能覆盖工具证据。</p><div class="spine"><article><span class="kicker">01 STATIC</span><b>PE / 源码规则</b><small>结构、导入、字符串、XOR、完整 API 链</small></article><article><span class="kicker">02 EMULATION</span><b>Speakeasy</b><small>错误/正确口令；API 与指令有界</small></article><article><span class="kicker">03 FUSION</span><b>Observation</b><small>本题集实际产生 static_only / dynamic_only；通用 conflict helper 另有单测</small></article><article><span class="kicker">04 SCORE</span><b>Seal → Gold</b><small>先 SHA256 封存，再读取金标评分</small></article></div></section>
<section id="metrics"><h3>三组离线指标</h3><p class="section-note">旧版与当前版从固定 commit 加载，优化版来自内容摘要绑定的工作树。安全字段或审计回执缺失会 fail-closed，并把主分数清零；Fact accuracy 只统计金标中显式标为 exact_fact 的义务。</p><div class="table-wrap"><table><thead><tr><th>Arm</th><th>Macro obligations</th><th>Behavior F1</th><th>Exact fact accuracy</th><th>Evidence-ref coverage</th><th>Safety</th></tr></thead><tbody>{table_rows}</tbody></table></div><div class="callout">DeepSeek 配对 Live 状态：<code>{live_safe}</code>。{html.escape(live_note)}</div>{live_preflight_html}{live_pair_html}</section>
<section id="cases"><h3>逐题运行索引</h3><div class="filters" role="group" aria-label="筛选 arm"><button data-filter="all" aria-pressed="true">ALL</button><button data-filter="old">OLD</button><button data-filter="current">CURRENT</button><button data-filter="optimized">OPTIMIZED</button></div><div class="table-wrap"><table><thead><tr><th>Case</th><th>Arm</th><th>Status</th><th>Behaviors</th><th>Evidence</th><th>Error</th></tr></thead><tbody id="case-body">{case_rows}</tbody></table></div></section>
<section id="capabilities"><h3>代码能力矩阵</h3><p class="section-note">只按当前代码与测试可证明的能力定级；此前文档中的 Capstone、函数识别、CFG、调用图声明已撤回。</p><div class="table-wrap"><table><thead><tr><th>能力</th><th>状态</th><th>证据边界</th></tr></thead><tbody>{capability_html}</tbody></table></div></section>
<section id="tools"><h3>外部工具矩阵</h3><div class="table-wrap"><table><thead><tr><th>工具</th><th>状态</th><th>边界</th></tr></thead><tbody>{external_html}</tbody></table></div><p class="section-note">上游身份：Speakeasy repository / commit 与 CAPEv2 repository 均记录在 <code>run-manifest.json</code>；报告离线展示不发起外部请求。</p></section>
<section id="safety"><h3>失败模式与安全边界</h3><div class="grid2"><div class="callout"><b>回执验证</b><ul><li>宿主原生 PE 执行：按固定 Python runner/API emulator 命令契约核验</li><li>样本/逆向工具真实网络：静态臂无网络工具；动态臂要求 sandbox-exec 且观察计数为 0</li><li>获批 DeepSeek 控制面请求不计入上述样本网络字段；实际请求数、Token 与费用由 Live 回执单列</li><li>目标写入：题集目标文件运行前后 SHA256 对比</li><li>密钥泄漏：序列化输出 marker 及密钥原值扫描</li><li>缺字段、回执 unknown 或计数非零均 fail-closed</li></ul></div><div class="callout"><b>明确不能做</b><ul><li>不能替代完整 Windows VM</li><li>不能分析真实恶意样本</li><li>不能证明未覆盖路径的运行行为</li><li>不能从导入表断言 API 已调用</li><li>动态失败只能降级，不能删除静态结果</li></ul></div></div></section>
<section id="changes"><h3>修改摘要与路线图</h3><div class="grid2"><div><h4>本轮已完成</h4><ul><li>修正样本 SHA256、PE 工具场景和 XOR 排序。</li><li>新增兼容 v1.7 的 ReverseAnalysisObservation 投影。</li><li>固定 Speakeasy 归档；双 profile、CRT hook、SHA 绑定 argv shim。</li><li>新增 CAPE normalizer 与 R2/HTTPS/allowlist Mock 契约。</li><li>新增 predict → seal → score → render 及 12 题报告。</li><li>完成 DeepSeek 首次 24 题配对 Live；显式保留成功回执、失败状态、Token 与费用。</li></ul></div><div><h4>后续路线</h4><ul><li>按密钥管理制度轮换本次使用的 DeepSeek key。</li><li>在独立基础设施部署 CAPE Windows 客体后做批准制验证。</li><li>引入真正的反汇编/函数/CFG 能力并建立独立金标。</li><li>扩展 ELF、Mach-O、APK 与脱壳题集。</li></ul></div></div></section>
<footer>Machine truth: <code>metrics.json</code> · <code>case-results.csv</code> · <code>run-manifest.json</code>. Embedded aggregate: <span id="truth-sha" data-json="{data_blob}">loaded</span>.</footer></main></div>
<script>document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{{document.querySelectorAll('[data-filter]').forEach(x=>x.setAttribute('aria-pressed','false'));b.setAttribute('aria-pressed','true');const f=b.dataset.filter;document.querySelectorAll('#case-body tr').forEach(r=>r.hidden=f!=='all'&&r.dataset.arm!==f)}}));</script></body></html>"""
    html_path = output_dir / "report.html"
    html_path.write_text(report_html, encoding="utf-8")
    markdown = (
        "# SecMind 逆向分析研发审计摘要\n\n"
        f"- 当前版义务宏平均：`{current_macro}`\n"
        f"- 优化版义务宏平均：`{optimized_macro}`\n"
        f"- 当前版行为 F1：`{current_f1}`\n"
        f"- 优化版行为 F1：`{optimized_f1}`\n"
        f"- DeepSeek Live：`{live_status}`\n"
        f"- 安全门：`{safety_label}`\n\n"
        "完整能力边界、逐题状态和修改摘要见同目录 `report.html`。\n"
    )
    markdown_path = output_dir / "report.md"
    markdown_path.write_text(markdown, encoding="utf-8")
    return {
        "html": html_path,
        "metrics": metrics_path,
        "csv": csv_path,
        "manifest": manifest_path,
        "markdown": markdown_path,
    }
