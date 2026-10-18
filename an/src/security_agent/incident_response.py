from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import subprocess
from collections import deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from security_agent.host_collector import collect_host, collect_security_events
from security_agent.operations import OperationsStore


def _now():
    return datetime.now(UTC).isoformat()


def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


class IncidentManager:
    """Persistent host collection and explicitly approved, bounded response actions."""

    def __init__(self, root: Path | None = None, allowed_roots: list[Path] | None = None):
        self.root = (root or Path("data/incident")).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        for name in ("evidence", "quarantine", "samples"):
            (self.root / name).mkdir(exist_ok=True)
        self.allowed_roots = [p.resolve() for p in (allowed_roots or [])] + [self.root / "samples"]
        self.store = OperationsStore(self.root / "operations.db")
        saved = self.store.get("incident", {})
        self.running = False
        self.started_at = None
        self.last_scan_at = saved.get("last_scan_at")
        self._inventory = saved.get("inventory")
        self._baseline = saved.get("baseline")
        self._actions = saved.get("actions", [])
        self._approvals = saved.get("approvals", {})
        self._logs = deque(saved.get("logs", []), maxlen=500)
        self.store.restore_incident_logs(list(self._logs))
        self._sequence = saved.get("sequence", 0)
        self._subscribers = set()
        self._monitor_task = None
        self._lock = asyncio.Lock()
        for action in self._actions:
            if action["status"] in {"executing", "approved", "queued"}:
                action.update(status="interrupted", error="服务在动作结束前重启，请核对证据及隔离清单，不会自动重放")
        self._save()

    def _save(self):
        self.store.put("incident", {"actions": self._actions, "approvals": self._approvals,
            "logs": list(self._logs), "sequence": self._sequence, "inventory": self._inventory,
            "baseline": self._baseline, "last_scan_at": self.last_scan_at})

    @staticmethod
    def command_catalog():
        return [{"id": "monitoring", "label": "本机采集", "commands": [
            {"value": key, "label": label, "risk_level": 0} for key, label in [
                ("scan_assets", "采集本机资产与监听端口"), ("inspect_processes", "采集本机进程"),
                ("collect_indicators", "检查监听暴露与基线变化"), ("refresh_baseline", "将当前采集设为基线"),
                ("collect_evidence", "保存本机取证快照"), ("collect_security_events", "采集 Windows 登录失败日志")]]},
            {"id": "response", "label": "审批后实际执行", "commands": [
                {"value": key, "label": label, "risk_level": 2} for key, label in [
                    ("isolate_sample", "隔离上传的文件"), ("restore_snapshot", "恢复已隔离文件"),
                    ("block_indicator", "Windows 防火墙阻断远端 IP"),
                    ("unblock_indicator", "撤销本平台创建的阻断规则")]]}]

    def snapshot(self):
        return {"schema_version": "1.0", "running": self.running, "started_at": self.started_at,
            "last_scan_at": self.last_scan_at, "pending_approvals": sum(a["status"] == "pending" for a in self._approvals.values()),
            "active_phase": "monitoring" if self.running else "idle", "safe_mode": True,
            "mode": "local_host", "collector_connected": True, "execution_enabled": True,
            "allowed_roots": [str(p) for p in self.allowed_roots],
            "inventory": self._inventory, "baseline_at": (self._baseline or {}).get("collected_at"),
            "quarantines": self.quarantines(), "firewall_platform_supported": platform.system() == "Windows"}

    def logs(self, limit=100, offset=0):
        return self.store.recent('incident', limit, offset)

    def actions(self, limit=100, offset=0):
        return self._actions[::-1][offset:offset + limit]

    def approvals(self, limit=100, offset=0):
        approvals = list(self._approvals.values())
        pending = [item for item in approvals if item["status"] == "pending"]
        resolved = [item for item in approvals if item["status"] != "pending"]
        return [*pending[::-1], *resolved[::-1]][offset:offset + limit]

    def pending_approvals(self):
        return [item for item in reversed(list(self._approvals.values())) if item['status'] == 'pending']

    def eligible_unblocks(self):
        pending_or_done = {a['target'] for a in self._actions if a['command'] == 'unblock_indicator' and
                           a['status'] in {'completed', 'awaiting_approval', 'approved', 'queued', 'executing'}}
        return [{'action_id': a['action_id'], 'target': a['target'], 'status': a['status']}
                for a in reversed(self._actions) if a['command'] == 'block_indicator' and
                a['status'] in {'completed', 'interrupted', 'failed'} and a['action_id'] not in pending_or_done]

    def quarantines(self):
        return [json.loads(p.read_text(encoding="utf-8")) for p in (self.root / "quarantine").glob("*/manifest.json")]

    def verified_evidence(self, evidence_id):
        try:
            evidence_id = str(UUID(evidence_id))
        except ValueError as exc:
            raise KeyError(evidence_id) from exc
        action = next((item for item in self._actions if item["action_id"] == evidence_id
                       and item["command"] == "collect_evidence"), None)
        if not action or action["status"] not in {"completed", "partial"}:
            raise KeyError(evidence_id)
        receipt = action.get("result") or {}
        path = self.root / "evidence" / (evidence_id + ".json")
        if not path.is_file():
            raise FileNotFoundError(evidence_id)
        content = path.read_bytes()
        if not receipt.get("sha256") or hashlib.sha256(content).hexdigest() != receipt["sha256"]:
            raise ValueError("取证文件 SHA-256 与执行回执不一致")
        return content, receipt, evidence_id

    def _source(self, target):
        raw = Path(target)
        path = raw.resolve(strict=True)
        if raw.is_symlink() or any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in [raw, *raw.parents]):
            raise ValueError("不允许隔离符号链接或目录联接")
        if not path.is_file() or not any(path.is_relative_to(root) for root in self.allowed_roots):
            raise ValueError("文件必须位于已授权的上传/样本目录内")
        if path.stat().st_size > 100 * 1024 * 1024:
            raise ValueError("单个隔离文件不得超过 100 MiB")
        return path

    def _manifest(self, key):
        try:
            key = str(UUID(key))
        except ValueError as exc:
            raise ValueError("恢复目标必须是隔离记录 ID") from exc
        path = self.root / "quarantine" / key / "manifest.json"
        if not path.is_file():
            raise ValueError("隔离记录不存在")
        return path, json.loads(path.read_text(encoding="utf-8"))

    async def start(self):
        async with self._lock:
            if not self.running:
                await self._scan()
                self.running = True
                self.started_at = _now()
                self._monitor_task = asyncio.create_task(self._monitor_loop())
                await self._record("monitor.started", "本机采集已启动，每 15 秒刷新", "info", "监测")
        return self.snapshot()

    async def stop(self):
        self.running = False
        task, self._monitor_task = self._monitor_task, None
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            await self._record("monitor.stopped", "本机采集已停止", "info", "监测")
        return self.snapshot()

    async def shutdown(self):
        await self.stop()

    async def submit_command(self, command, target="local", reason=""):
        async with self._lock:
            catalog = {x["value"]: x for group in self.command_catalog() for x in group["commands"]}
            if command not in catalog:
                raise ValueError("未知命令，不接受任意系统命令")
            item = catalog[command]
            action = {"action_id": str(uuid4()), "command": command, "label": item["label"],
                "risk_level": item["risk_level"], "target": target, "reason": reason,
                "created_at": _now(), "status": "awaiting_approval" if item["risk_level"] else "queued"}
            if command == "isolate_sample":
                source = self._source(target)
                action.update(target=str(source), expected_sha256=await asyncio.to_thread(file_hash, source))
            elif command == "restore_snapshot":
                _, manifest = self._manifest(target)
                if manifest["status"] == "restored":
                    raise ValueError("文件已经恢复")
            elif command == "block_indicator":
                ip = ipaddress.ip_address(target.strip())
                if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
                    raise ValueError("不能阻断回环、未指定或多播地址")
                action["target"] = str(ip)
                action["rule_name"] = "SecMind-" + action["action_id"]
            elif command == "unblock_indicator":
                original = next((a for a in self._actions if a["action_id"] == target and a["command"] == "block_indicator"), None)
                if original is None or original["status"] not in {"completed", "interrupted", "failed"}:
                    raise ValueError("目标必须是本平台的阻断动作 ID")
                prior_unblocks = [
                    a for a in self._actions
                    if a["command"] == "unblock_indicator" and a["target"] == target
                ]
                if any(a["status"] == "completed" for a in prior_unblocks):
                    raise ValueError("该阻断动作已经撤销")
                if any(a["status"] in {"awaiting_approval", "approved", "queued", "executing"}
                       for a in prior_unblocks):
                    raise ValueError("该阻断动作已有待处理的撤销请求")
                action["rule_name"] = original["rule_name"]
            elif target not in {"", "local", "localhost", "本机", "测试环境"}:
                raise ValueError("当前采集器只支持本机，目标请填写 local")
            self._actions.append(action)
            approval = None
            if item["risk_level"]:
                approval = {"approval_id": str(uuid4()), "action_id": action["action_id"],
                    "command": action["label"], "target": action["target"], "risk_level": 2,
                    "reason": reason or "该动作会实际修改文件或防火墙", "status": "pending", "created_at": _now()}
                self._approvals[approval["approval_id"]] = approval
                await self._record("approval.requested", f"等待审批：{action['label']}", "warning", "审批", approval)
            else:
                await self._execute(action)
            return {"schema_version": "1.0", "action": action, "approval": approval}

    async def resolve_approval(self, approval_id, decision, note=""):
        async with self._lock:
            approval = self._approvals.get(approval_id)
            if approval is None:
                raise KeyError(approval_id)
            if approval["status"] != "pending" or decision not in {"approve", "deny"}:
                raise ValueError("审批已处理或 decision 无效")
            action = next(a for a in self._actions if a["action_id"] == approval["action_id"])
            approval.update(status="approved" if decision == "approve" else "denied", resolved_at=_now(), note=note)
            action["status"] = approval["status"]
            await self._record("approval.resolved", f"{action['label']}：{approval['status']}", "info", "审批", approval)
            if decision == "approve":
                await self._execute(action)
            return {"schema_version": "1.0", "action": action, "approval": approval}

    async def _scan(self):
        inventory = await asyncio.to_thread(collect_host)
        if self._inventory and self._inventory.get("security_events"):
            inventory["security_events"] = self._inventory["security_events"]
        if self._baseline:
            before = {(x["address"], x["port"]) for x in self._baseline["listeners"]}
            inventory["new_listeners"] = [x for x in inventory["listeners"] if (x["address"], x["port"]) not in before]
        else:
            inventory["new_listeners"] = []
        self._inventory = inventory
        self.last_scan_at = inventory["collected_at"]
        await self._record("host.collected", f"采集 {len(inventory['processes'])} 个进程、{len(inventory['listeners'])} 个监听端口",
            "info" if inventory["complete"] else "warning", "监测",
            {"collected_at": self.last_scan_at, "errors": inventory["errors"], "new_listeners": inventory["new_listeners"]})
        return inventory

    async def _monitor_loop(self):
        while self.running:
            await asyncio.sleep(15)
            try:
                async with self._lock:
                    await self._scan()
            except Exception as exc:
                await self._record("collector.failed", str(exc), "error", "监测")

    def _file_action(self, action):
        if action["command"] == "isolate_sample":
            source = self._source(action["target"])
            if file_hash(source) != action["expected_sha256"]:
                raise ValueError("审批后文件内容发生变化，必须重新提交")
            folder = self.root / "quarantine" / action["action_id"]
            folder.mkdir(exist_ok=False)
            sample = folder / "sample.bin"
            manifest = {"id": action["action_id"], "original_path": str(source), "sha256": action["expected_sha256"],
                        "created_at": _now(), "status": "preparing"}
            manifest_path = folder / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
            with source.open("rb") as src, sample.open("xb") as dst:
                shutil.copyfileobj(src, dst)
                dst.flush(); os.fsync(dst.fileno())
            if file_hash(sample) != manifest["sha256"] or file_hash(source) != manifest["sha256"]:
                raise ValueError("隔离拷贝校验失败，原文件未删除")
            source.unlink()
            manifest.update(status="quarantined", completed_at=_now())
        else:
            manifest_path, manifest = self._manifest(action["target"])
            sample = manifest_path.parent / "sample.bin"
            destination = Path(manifest["original_path"])
            if not any(destination.resolve().is_relative_to(root) for root in self.allowed_roots):
                raise ValueError("恢复路径已离开授权目录")
            if destination.exists():
                raise ValueError("原路径已有文件，拒绝覆盖")
            if file_hash(sample) != manifest["sha256"]:
                raise ValueError("隔离文件 SHA-256 不匹配")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with sample.open("rb") as src, destination.open("xb") as dst:
                shutil.copyfileobj(src, dst)
                dst.flush(); os.fsync(dst.fileno())
            if file_hash(destination) != manifest["sha256"]:
                raise ValueError("恢复校验失败，保留隔离副本供核对")
            manifest.update(status="restored", restored_at=_now())
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        return manifest

    def _firewall_action(self, action):
        if platform.system() != "Windows":
            raise RuntimeError("当前防火墙执行器仅支持 Windows")
        command = ["netsh", "advfirewall", "firewall"]
        if action["command"] == "block_indicator":
            command += ["add", "rule", "name=" + action["rule_name"], "dir=out", "action=block", "remoteip=" + action["target"], "enable=yes"]
        else:
            command += ["delete", "rule", "name=" + action["rule_name"]]
        result = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=20,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if result.returncode:
            raise RuntimeError("防火墙操作失败（需要管理员权限）：" + (result.stdout + result.stderr).strip())
        return {"rule_name": action["rule_name"], "direction": "outbound", "exit_code": result.returncode,
                "receipt": result.stdout.strip()}

    async def _execute(self, action):
        action["status"] = "executing"
        await self._record("action.started", action["label"], "info", "执行", {"action_id": action["action_id"]})
        try:
            command = action["command"]
            if command in {"isolate_sample", "restore_snapshot"}:
                result = await asyncio.to_thread(self._file_action, action)
            elif command in {"block_indicator", "unblock_indicator"}:
                result = await asyncio.to_thread(self._firewall_action, action)
            else:
                inventory = await self._scan()
                if command == "collect_security_events":
                    inventory["security_events"] = await asyncio.to_thread(collect_security_events)
                    if not inventory["security_events"]["complete"]:
                        raise RuntimeError("安全日志读取失败：" + "; ".join(inventory["security_events"]["errors"]))
                if command == "refresh_baseline":
                    if not inventory["complete"]:
                        raise ValueError("采集不完整，不能替换基线")
                    self._baseline = inventory
                result = {"collected_at": inventory["collected_at"], "process_count": len(inventory["processes"]),
                          "listener_count": len(inventory["listeners"]), "findings": inventory["findings"], "errors": inventory["errors"]}
                if command == "scan_assets":
                    result.update(hostname=inventory["hostname"], platform=inventory["platform"],
                                  listeners=inventory["listeners"], interfaces=inventory["interfaces"])
                elif command == "inspect_processes":
                    result["processes"] = inventory["processes"]
                elif command == "collect_indicators":
                    result.update(new_listeners=inventory["new_listeners"],
                                  baseline_at=(self._baseline or {}).get("collected_at"),
                                  listeners=inventory["listeners"])
                if command == "collect_security_events":
                    result["security_events"] = inventory["security_events"]
                if command == "collect_evidence":
                    path = self.root / "evidence" / (action["action_id"] + ".json")
                    path.write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
                    result.update(evidence_id=action["action_id"], sha256=file_hash(path), bytes=path.stat().st_size)
            action.update(status="partial" if result.get("errors") else "completed", result=result)
        except Exception as exc:
            action.update(status="failed", error=str(exc))
        action["completed_at"] = _now()
        await self._record("action." + action["status"], action["label"] + "：" + action["status"],
            "success" if action["status"] == "completed" else "error", "执行", action)

    async def _record(self, event_type, message, level, phase, payload=None):
        self._sequence += 1
        event = {"sequence": self._sequence, "event_type": event_type, "message": message,
                 "level": level, "phase": phase, "timestamp": _now(), "payload": payload or {}}
        # Snapshot the payload: later status changes must not rewrite historical events.
        event = json.loads(json.dumps(event, ensure_ascii=False))
        self._logs.append(event)
        self._save()
        self.store.append("incident", event)
        for queue in tuple(self._subscribers):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait({"type": "incident.event", "payload": event})

    @asynccontextmanager
    async def subscribe(self):
        queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(queue)
        try:
            yield queue
        finally:
            self._subscribers.discard(queue)
