from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
import zipfile
from collections import Counter, defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from security_agent.config import Settings
from security_agent.llm import ModelGateway, ModelGatewayError
from security_agent.schemas import (
    AttachmentRef,
    DirectoryScanProposal,
    QuestionBankConfirmRequest,
    QuestionBankInspectRequest,
    QuestionClassificationBatch,
)


class QuestionBankError(ValueError):
    pass


TYPE_LABELS = {
    "web": "Web 安全",
    "pwn": "二进制利用",
    "reverse": "逆向工程",
    "crypto": "密码学",
    "forensics": "取证分析",
    "mobile": "移动安全",
    "blockchain": "区块链安全",
    "ai_security": "AI 安全",
    "code_audit": "代码审计",
    "misc": "综合题",
    "unknown": "未知",
}
QUESTION_TYPE_MODULES = {
    "reverse": "reverse",
    "web": "penetration",
    "pwn": "penetration",
    "crypto": "code_audit",
    "forensics": "code_audit",
    "mobile": "reverse",
    "blockchain": "penetration",
    "ai_security": "code_audit",
    "code_audit": "code_audit",
    "misc": "code_audit",
    "unknown": "code_audit",
}
MANIFEST_NAMES = {"question-bank.json", "question_bank.json", "manifest.json"}
FORMATTED_METADATA_JSON_NAMES = {
    "question-bank.json", "question_bank.json", "manifest.json", "metadata.json",
    "question-meta.json", "question_metadata.json", "题库.json", "题库信息.json",
}
FORMATTED_METADATA_TEXT_NAMES = {
    "question-bank.txt", "question_bank.txt", "metadata.txt", "question-meta.txt",
    "question_metadata.txt", "题库.txt", "题库信息.txt",
}
SUMMARY_NAMES = {"readme.md", "readme.txt", "problem.md", "description.md", "题目.md", "题目.txt"}
SECRET_PATTERN = re.compile(r"(?i)(?:flag|htb|ctf)\{[^}\r\n]+\}|(?:api[_-]?key|secret|token)\s*[:=]\s*\S+")
WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
DIRECTORY_ROLES = {"wrapper", "container", "question_root", "internal", "ignore", "uncertain"}
EXPAND_ROLES = {"wrapper", "container"}
BOUNDARY_PROMPT_VERSION = "question-bank-directory-scan-v3"
CLASSIFICATION_PROMPT_VERSION = "question-bank-classification-v1"


class QuestionBankService:
    def __init__(self, settings: Settings, gateway: ModelGateway | None = None) -> None:
        self.settings = settings
        self.gateway = gateway
        self.settings.question_bank_root.mkdir(parents=True, exist_ok=True)
        self._tasks: set[asyncio.Task[Any]] = set()
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}

    def create_inspection(self, request: QuestionBankInspectRequest) -> dict[str, Any]:
        bank_id = str(uuid4())
        record: dict[str, Any] = {
            "schema_version": "1.1",
            "bank_id": bank_id,
            "name": request.name,
            "analysis_mode": request.analysis_mode,
            "status": "inspecting",
            "stage": "queued",
            "attachments": [item.model_dump(mode="json") for item in request.attachments],
            "statistics": {},
            "type_distribution": {},
            "questions": [],
            "directory_options": [],
            "directory_tree": [],
            "unassigned_files": [],
            "warnings": [],
            "model_trace": {"boundary_calls": [], "classification_calls": []},
            "checkpoint": {"completed_stages": []},
            "created_at": datetime.now(UTC).isoformat(),
            "confirmed_at": None,
        }
        self._save(record)
        task = asyncio.create_task(self._inspect(bank_id, request))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return record

    async def inspect_now(self, request: QuestionBankInspectRequest) -> dict[str, Any]:
        record = self.create_inspection(request)
        while True:
            result = self.get(record["bank_id"])
            if result["status"] != "inspecting":
                return result
            await asyncio.sleep(0.01)

    async def recover_incomplete(self) -> None:
        for path in self.settings.question_bank_root.glob("*.json"):
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("status") == "inspecting":
                record["status"] = "needs_manual_mapping"
                record["stage"] = "manual_mapping"
                record.setdefault("warnings", []).append(
                    "服务重启中断了自动预检，请从已生成的目录树人工选择题目根目录。"
                )
                self._save(record)
            elif record.get("boundary_source") in {"directory_heuristic", "nested_archives"}:
                record["status"] = "needs_manual_mapping"
                record["stage"] = "manual_mapping"
                record["questions"] = []
                record["boundary_source"] = "legacy_invalidated"
                record.setdefault("warnings", []).append("旧版路径推断结果已失效，请重新人工映射题目根目录。")
                self._save(record)

    async def shutdown(self) -> None:
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    @asynccontextmanager
    async def subscribe(self, bank_id: str) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        self.get(bank_id)
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        self._subscribers.setdefault(bank_id, set()).add(queue)
        try:
            yield queue
        finally:
            self._subscribers.get(bank_id, set()).discard(queue)

    async def _inspect(self, bank_id: str, request: QuestionBankInspectRequest) -> None:
        try:
            await self._stage(bank_id, "extracting", "正在递归安全解压题库")
            inventory = self._extract_inventory(bank_id, request.attachments)
            record = self.get(bank_id)
            record.update(inventory["public"])
            self._complete_checkpoint(record, "extracting")
            self._save(record)

            await self._stage(bank_id, "tree_building", "正在构建真实目录树并计算层数")
            tree = self._build_directory_tree(inventory["files"])
            (self._workspace(bank_id) / "directory-tree.json").write_text(
                json.dumps({"schema_version": "1.0", "directories": tree}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            record = self.get(bank_id)
            record["directory_tree"] = tree
            record["statistics"].update(self._tree_statistics(tree))
            self._complete_checkpoint(record, "tree_building")
            self._save(record)
            await self._publish(
                bank_id,
                "inventory.completed",
                {"statistics": record["statistics"], "directory_count": len(tree)},
            )

            formatted = self._formatted_metadata(bank_id, inventory["files"])
            authoritative_formatted = bool(
                formatted
                and isinstance(formatted.get("body"), dict)
                and isinstance(formatted["body"].get("questions"), list)
                and formatted["body"].get("questions")
                and all(
                    isinstance(item, dict)
                    and item.get("id")
                    and item.get("type")
                    and item.get("root")
                    for item in formatted["body"]["questions"]
                )
            )
            if request.analysis_mode == "formatted" or authoritative_formatted:
                if formatted is None:
                    raise QuestionBankError(
                        "题库格式化文件分析需要压缩包内提供 question-bank.json、metadata.json 或对应 TXT 元数据文件"
                    )
                proposals, metadata = self._formatted_proposals(formatted, inventory["files"])
                boundary_source = "formatted_metadata"
                unresolved = []
                record = self.get(bank_id)
                record["formatted_metadata"] = metadata
                self._save(record)
            else:
                manifest_questions = self._manifest_questions(inventory["manifests"], inventory["files"])
                if manifest_questions is not None:
                    proposals = manifest_questions
                    boundary_source = "manifest"
                    unresolved = []
                    # Preserve the authoritative manifest for batch execution.
                    for manifest in inventory["manifests"]:
                        body = manifest.get("body") if isinstance(manifest, dict) else None
                        if isinstance(body, dict) and isinstance(body.get("questions"), list):
                            record = self.get(bank_id)
                            record["formatted_metadata"] = {
                                "format": "json", "source_path": manifest.get("path"), "body": body
                            }
                            self._save(record)
                            break
                else:
                    await self._stage(bank_id, "directory_scanning", "正在由大模型逐层判断题目边界")
                    proposals, unresolved = await self._scan_directory_levels(bank_id, tree)
                    proposals, _ = self._validate_proposal_data(proposals, inventory["files"])
                    boundary_source = "llm_layered"

            questions = self._describe(proposals, inventory["files"], boundary_source)
            await self._stage(bank_id, "classifying", "正在按已识别边界逐题分类")
            if any(item["question_type"] == "unknown" for item in questions):
                questions = await self._classify_questions(bank_id, questions, inventory["files"])

            record = self.get(bank_id)
            record["questions"] = questions
            record["boundary_source"] = boundary_source
            record["unassigned_files"] = self._unassigned(questions, inventory["files"])
            record["type_distribution"] = dict(Counter(item["question_type"] for item in questions))
            distribution = Counter(QUESTION_TYPE_MODULES.get(item["question_type"], "code_audit") for item in questions)
            record["dispatch_plan"] = [
                {
                    "module_route": module_route,
                    "module_label": {"code_audit": "代码审计", "reverse": "逆向分析", "penetration": "渗透测试"}[module_route],
                    "question_ids": [
                        question["candidate_id"]
                        for question in questions
                        if QUESTION_TYPE_MODULES.get(question["question_type"], "code_audit") == module_route
                    ],
                    "question_count": count,
                }
                for module_route, count in distribution.items()
            ]
            record["statistics"].update(
                {
                    "detected_question_count": len(questions),
                    "ambiguous_question_count": sum(
                        item["type_confidence"] < self.settings.question_bank_type_confidence
                        or item.get("needs_human_review", False)
                        for item in questions
                    ),
                    "duplicate_question_count": self._duplicates(questions),
                    "unassigned_file_count": len(record["unassigned_files"]),
                    "unresolved_directory_count": len(unresolved),
                }
            )
            self._complete_checkpoint(record, "directory_scanning")
            self._complete_checkpoint(record, "classifying")
            if boundary_source not in {"manifest", "formatted_metadata"}:
                record["warnings"].append("题目边界由大模型逐层辅助提出，必须经过人工确认。")
            if unresolved:
                record["warnings"].append(f"有 {len(unresolved)} 个目录的语义无法自动确认。")
            if record["unassigned_files"]:
                record["warnings"].append(f"有 {len(record['unassigned_files'])} 个文件尚未归属于任何候选题目。")
            record["status"] = "awaiting_confirmation"
            record["stage"] = "complete"
            self._save(record)
            await self._publish(bank_id, "inspection.completed", record)
        except Exception as exc:
            record = self.get(bank_id)
            extraction_failed = record.get("stage") in {"extracting", "tree_building"}
            record["status"] = "failed" if extraction_failed else "needs_manual_mapping"
            record["stage"] = "failed" if extraction_failed else "manual_mapping"
            record["questions"] = []
            record["boundary_source"] = "inventory_failed" if extraction_failed else "manual_required"
            message = (
                f"题库安全解压或目录建树失败，已停止预检（{type(exc).__name__}）。"
                if extraction_failed
                else f"自动目录判断未产生可验证结果，请人工选择题目根目录（{type(exc).__name__}）。"
            )
            record.setdefault("warnings", []).append(message)
            record["error_code"] = type(exc).__name__
            self._save(record)
            await self._publish(
                bank_id,
                "inspection.failed" if extraction_failed else "inspection.manual_required",
                record,
            )

    def get(self, bank_id: str) -> dict[str, Any]:
        path = self._path(bank_id)
        if not path.is_file():
            raise KeyError(bank_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def confirm(self, bank_id: str, request: QuestionBankConfirmRequest) -> dict[str, Any]:
        record = self.get(bank_id)
        # Confirmation is intentionally idempotent.  A double click or a
        # retry after a network timeout must not turn a successfully confirmed
        # bank into a misleading "status not allowed" error.
        if record["status"] == "confirmed":
            submitted = request.model_dump(mode="json")
            original = record.get("confirmation_request")
            if original is not None:
                if submitted != original:
                    raise QuestionBankError("题库已按另一份映射确认，不能更改已确认结果")
            else:
                # Records confirmed before confirmation_request was stored
                # still have an authoritative question snapshot to compare.
                submitted_mapping = sorted(
                    (item.root, item.name or PurePosixPath(item.root).name, item.question_type or "unknown")
                    for item in request.questions if item.confirmed
                )
                saved_mapping = sorted(
                    (item["root"], item["name"], item["question_type"])
                    for item in record.get("questions", [])
                )
                if submitted_mapping != saved_mapping:
                    raise QuestionBankError("题库已按另一份映射确认，不能更改已确认结果")
            return record
        if record["status"] not in {"awaiting_confirmation", "needs_manual_mapping"}:
            raise QuestionBankError("当前题库状态不允许确认")
        files = record.get("file_inventory", [])
        proposals = []
        for item in request.questions:
            if not item.confirmed:
                continue
            question_type = item.question_type or "unknown"
            if question_type not in TYPE_LABELS:
                raise QuestionBankError(f"不支持的题型：{question_type}")
            proposals.append(
                {
                    "root": item.root,
                    "name": item.name or PurePosixPath(item.root).name,
                    "question_type": question_type,
                    "boundary_confidence": 1.0,
                    "type_confidence": 1.0,
                    "rationale_summary": "用户已在预检确认页确认该题目边界和类型。",
                }
            )
        questions, _ = self._validate_proposal_data(proposals, files)
        confirmed_files = self._snapshot_files(bank_id, files)
        record["questions"] = self._describe(questions, files, "user_confirmed")
        record["confirmation_request"] = request.model_dump(mode="json")
        record["confirmed_files"] = confirmed_files
        record["unassigned_files"] = self._unassigned(record["questions"], files)
        record["type_distribution"] = dict(Counter(item["question_type"] for item in record["questions"]))
        distribution = Counter(QUESTION_TYPE_MODULES.get(item["question_type"], "code_audit") for item in record["questions"])
        record["dispatch_plan"] = [
            {
                "module_route": module_route,
                "module_label": {"code_audit": "代码审计", "reverse": "逆向分析", "penetration": "渗透测试"}[module_route],
                "question_ids": [
                    question["candidate_id"]
                    for question in record["questions"]
                    if QUESTION_TYPE_MODULES.get(question["question_type"], "code_audit") == module_route
                ],
                "question_count": count,
            }
            for module_route, count in distribution.items()
        ]
        record["status"] = "confirmed"
        record["stage"] = "confirmed"
        record["confirmed_at"] = datetime.now(UTC).isoformat()
        record["statistics"]["confirmed_question_count"] = len(record["questions"])
        record["statistics"]["unassigned_file_count"] = len(record["unassigned_files"])
        self._save(record)
        return record

    def execution_questions(self, bank_id: str) -> list[dict[str, Any]]:
        """Return the immutable, execution-ready question definitions.

        Batch execution never trusts client supplied paths.  Definitions are
        reconstructed from the confirmed inspection snapshot and the
        user-authored formatted metadata when it contains stable question IDs.
        """
        record = self.get(bank_id)
        if record.get("status") != "confirmed":
            raise QuestionBankError("题库尚未完成人工确认")
        metadata = record.get("formatted_metadata") or {}
        body = metadata.get("body") if isinstance(metadata, dict) else None
        raw = body.get("questions") if isinstance(body, dict) else None
        files = record.get("file_inventory", [])
        confirmed_files = record.get("confirmed_files")
        if not isinstance(confirmed_files, dict) or set(confirmed_files) != {
            entry.get("path") for entry in files if isinstance(entry, dict)
        }:
            raise QuestionBankError("题库缺少完整的确认时材料摘要，请重新预检并确认")
        extracted = self._workspace(bank_id) / "extracted"
        extracted_root = extracted.resolve()
        if not isinstance(raw, list) or not raw:
            raise QuestionBankError("批量执行要求 metadata.json.questions 提供稳定题目定义")
        confirmed_roots = {str(item.get("root", "")).strip("/") for item in record.get("questions", []) if isinstance(item, dict)}
        if len(record.get("questions", [])) != len(raw):
            raise QuestionBankError("题库确认题目数量与权威 JSON 不一致")
        ids: set[str] = set()
        roots: list[str] = []
        result: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                raise QuestionBankError("题目定义必须是对象")
            question_id = str(item.get("id") or "").strip()
            if not question_id or question_id in ids or len(question_id) > 80:
                raise QuestionBankError("题目 ID 缺失或重复")
            if "/" in question_id or "\\" in question_id or ".." in question_id:
                raise QuestionBankError("题目 ID 含有非法路径字符")
            ids.add(question_id)
            question_type = str(item.get("type") or "").strip().lower()
            if question_type not in TYPE_LABELS or question_type == "unknown":
                raise QuestionBankError(f"不支持的题型：{question_type or '<empty>'}")
            root = self._resolve_metadata_root(str(item.get("root") or ""), files)
            root = self._normalize_root(root)
            if not any(root == candidate or root.startswith(candidate + "/") or candidate.startswith(root + "/") for candidate in confirmed_roots):
                raise QuestionBankError(f"题目未经过确认：{question_id}")
            directories = set(self._directory_options(files))
            if root not in directories:
                raise QuestionBankError(f"题目 root 不存在：{root}")
            for existing in roots:
                if root == existing or root.startswith(existing + "/") or existing.startswith(root + "/"):
                    raise QuestionBankError(f"题目目录发生包含冲突：{existing} / {root}")
            roots.append(root)
            target_scope = item.get("target_scope") or item.get("allowlist") or []
            if question_type in {"web", "pwn", "blockchain"} and not target_scope:
                raise QuestionBankError(f"在线题 {question_id} 缺少 target_scope/allowlist")
            selected = [f for f in files if f["path"].startswith(root.rstrip("/") + "/")]
            if not selected:
                raise QuestionBankError(f"题目 root 没有输入文件：{root}")
            owned: list[dict[str, Any]] = []
            for entry in selected:
                path = extracted / PurePosixPath(entry["path"])
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(extracted_root)
                except (OSError, ValueError) as exc:
                    raise QuestionBankError(f"题库输入文件路径越界或不可用：{entry['path']}") from exc
                if not path.is_file() or path.is_symlink():
                    raise QuestionBankError(f"题库输入文件不可用：{entry['path']}")
                digest = self._file_digest(resolved)
                if digest != confirmed_files.get(entry["path"]):
                    raise QuestionBankError(f"题库输入文件在确认后已变化：{entry['path']}")
                owned.append({"path": entry["path"], "size_bytes": entry["size_bytes"], "sha256": digest})
            normalized_scope = []
            for scope in (target_scope if isinstance(target_scope, list) else [target_scope]):
                if isinstance(scope, dict):
                    normalized_scope.append(str(scope.get("host") or scope.get("url") or ""))
                else:
                    normalized_scope.append(str(scope))
            normalized_scope = [value for value in normalized_scope if value]
            if question_type in {"web", "pwn", "blockchain"}:
                for value in normalized_scope:
                    parsed = urlparse(value if "://" in value else f"https://{value}")
                    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                        raise QuestionBankError(f"在线题 {question_id} 的 allowlist 无效")
            result.append({
                "id": question_id,
                "name": str(item.get("name") or question_id),
                "type": question_type,
                "root": root,
                "objective": str(item.get("objective") or ""),
                "constraints": list(item.get("constraints") or []),
                "target_scope": normalized_scope,
                "expected_outputs": list(item.get("expected_outputs") or ["security_report"]),
                "depends_on": [str(value) for value in (item.get("depends_on") or item.get("dependencies") or [])],
                "files": owned,
            })
        if len(result) > self.settings.max_question_bank_questions:
            raise QuestionBankError("题目数量超过限制")
        return result

    @staticmethod
    def _file_digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _snapshot_files(self, bank_id: str, files: list[dict[str, Any]]) -> dict[str, str]:
        extracted = self._workspace(bank_id) / "extracted"
        extracted_root = extracted.resolve(strict=True)
        result: dict[str, str] = {}
        for entry in files:
            name = entry.get("path")
            if not isinstance(name, str) or not name or name in result:
                raise QuestionBankError("题库文件清单含有无效或重复路径")
            path = extracted / PurePosixPath(name)
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(extracted_root)
            except (OSError, ValueError) as exc:
                raise QuestionBankError(f"题库输入文件路径越界或不可用：{name}") from exc
            if not path.is_file() or path.is_symlink() or resolved.stat().st_size != entry.get("size_bytes"):
                raise QuestionBankError(f"题库输入文件在预检后已变化：{name}")
            digest = self._file_digest(resolved)
            if digest != entry.get("sha256"):
                raise QuestionBankError(f"题库输入文件在预检后已变化：{name}")
            result[name] = digest
        return result

    def require_confirmed(self, bank_id: str, attachments: list[AttachmentRef]) -> None:
        record = self.get(bank_id)
        if record["status"] != "confirmed":
            raise QuestionBankError("题库尚未完成人工确认")
        expected = {item["ref"] for item in record["attachments"]}
        actual = {item.ref for item in attachments}
        if expected != actual:
            raise QuestionBankError("任务附件与已确认的题库预检结果不一致")

    def _extract_inventory(self, bank_id: str, attachments: list[AttachmentRef]) -> dict[str, Any]:
        workspace = self._workspace(bank_id)
        staging = workspace / "extracting"
        extracted = workspace / "extracted"
        workspace.mkdir(parents=True, exist_ok=True)
        if staging.exists():
            self._remove_tree(staging)
        staging.mkdir()
        files: list[dict[str, Any]] = []
        manifests: list[dict[str, Any]] = []
        nested_archives: list[str] = []
        budget: dict[str, Any] = {"bytes": 0, "files": 0, "seen": set()}
        total_upload_bytes = sum(self._resolve(item.ref).stat().st_size for item in attachments)
        if total_upload_bytes > self.settings.max_question_bank_bytes:
            raise QuestionBankError("题库上传总量超过限制")
        archive_count = 0
        try:
            for attachment in attachments:
                source = self._resolve(attachment.ref)
                prefix = self._safe_stem(attachment.name or source.name)
                if source.suffix.lower() == ".zip" and not zipfile.is_zipfile(source):
                    raise QuestionBankError(f"压缩包损坏或格式无效：{attachment.name or source.name}")
                if zipfile.is_zipfile(source):
                    archive_count += 1
                    self._extract_zip(
                        source,
                        staging,
                        prefix,
                        0,
                        files,
                        manifests,
                        nested_archives,
                        budget,
                    )
                else:
                    size = source.stat().st_size
                    self._reserve_file(prefix, size, budget)
                    destination = self._physical_path(staging, prefix)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
                    files.append(self._file_record(prefix, size, source_archive=None))
            if extracted.exists():
                self._remove_tree(extracted)
            staging.replace(extracted)
        except PermissionError as exc:
            if staging.exists():
                self._remove_tree(staging)
            raise QuestionBankError(
                "题库工作目录无写权限或被其他进程占用，请关闭正在读取该目录的程序后重试"
            ) from exc
        except Exception:
            if staging.exists():
                self._remove_tree(staging)
            raise
        for item in files:
            item["sha256"] = self._file_digest(extracted / PurePosixPath(item["path"]))
        directories = self._directory_options(files)
        inventory_document = {"files": files, "nested_archives": nested_archives}
        (workspace / "inventory.json").write_text(
            json.dumps(inventory_document, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return {
            "files": files,
            "manifests": manifests,
            "public": {
                "file_inventory": [
                    {key: item[key] for key in ("path", "size_bytes", "sha256", "source_archive") if key in item}
                    for item in files
                ],
                "directory_options": directories,
                "extraction": {"complete": True, "workspace": f"{bank_id}/extracted"},
                "statistics": {
                    "archive_count": archive_count,
                    "nested_archive_count": len(nested_archives),
                    "total_file_count": len(files),
                    "total_upload_bytes": total_upload_bytes,
                    "total_uncompressed_bytes": budget["bytes"],
                },
                "warnings": (
                    [f"已安全递归解压 {len(nested_archives)} 个内层压缩包。"] if nested_archives else []
                ),
            },
        }

    def _extract_zip(
        self,
        source: Path,
        staging: Path,
        prefix: str,
        depth: int,
        files: list[dict[str, Any]],
        manifests: list[dict[str, Any]],
        nested_archives: list[str],
        budget: dict[str, Any],
    ) -> None:
        try:
            archive = zipfile.ZipFile(source)
        except zipfile.BadZipFile as exc:
            raise QuestionBankError(f"压缩包损坏：{prefix}") from exc
        with archive:
            entries = [item for item in archive.infolist() if not item.is_dir()]
            compressed = max(1, sum(item.compress_size for item in entries))
            if sum(item.file_size for item in entries) / compressed > self.settings.max_zip_ratio:
                raise QuestionBankError("检测到异常压缩比，已拒绝题库")
            for item in entries:
                parts = self._safe_member_parts(item)
                virtual_path = PurePosixPath(prefix, *parts).as_posix()
                if virtual_path.lower().endswith(".zip"):
                    if depth >= self.settings.max_question_bank_archive_depth:
                        raise QuestionBankError("题库压缩包嵌套层数超过限制")
                    if item.file_size > self.settings.max_upload_bytes:
                        raise QuestionBankError("内层压缩包超过单文件限制")
                    nested_archives.append(virtual_path)
                    temporary = staging / f".nested-{uuid4()}.zip"
                    with archive.open(item) as reader, temporary.open("wb") as writer:
                        shutil.copyfileobj(reader, writer, length=1024 * 1024)
                    try:
                        self._extract_zip(
                            temporary,
                            staging,
                            virtual_path.removesuffix(".zip"),
                            depth + 1,
                            files,
                            manifests,
                            nested_archives,
                            budget,
                        )
                    finally:
                        temporary.unlink(missing_ok=True)
                    continue
                self._reserve_file(virtual_path, item.file_size, budget)
                destination = self._physical_path(staging, virtual_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(item) as reader, destination.open("xb") as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)
                summary = None
                if parts[-1].lower() in SUMMARY_NAMES and item.file_size <= 16 * 1024:
                    summary = self._safe_summary(destination.read_bytes())
                record = self._file_record(virtual_path, item.file_size, summary, prefix)
                files.append(record)
                if parts[-1].lower() in MANIFEST_NAMES and item.file_size <= 1024 * 1024:
                    try:
                        manifests.append({"path": virtual_path, "body": json.loads(destination.read_text("utf-8"))})
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        pass

    def _reserve_file(self, path: str, size: int, budget: dict[str, Any]) -> None:
        key = path.casefold()
        if key in budget["seen"]:
            raise QuestionBankError(f"解压后路径发生重复或大小写冲突：{path}")
        budget["seen"].add(key)
        budget["bytes"] += size
        budget["files"] += 1
        if budget["bytes"] > self.settings.max_question_bank_bytes:
            raise QuestionBankError("题库解压后总量超过限制")
        if budget["files"] > self.settings.max_question_bank_files:
            raise QuestionBankError("题库文件总数超过限制")

    @staticmethod
    def _remove_tree(path: Path) -> None:
        """Remove an inspection staging tree even when antivirus marks files read-only."""
        if not path.exists():
            return
        def onerror(func: Any, target: str, _exc: Any) -> None:
            try:
                Path(target).chmod(0o700)
            except OSError:
                pass
            func(target)
        shutil.rmtree(path, onerror=onerror)

    @staticmethod
    def _safe_member_parts(item: zipfile.ZipInfo) -> tuple[str, ...]:
        normalized = PurePosixPath(item.filename.replace("\\", "/"))
        if normalized.is_absolute() or not normalized.parts or ".." in normalized.parts:
            raise QuestionBankError("压缩包包含路径穿越")
        if item.flag_bits & 0x1:
            raise QuestionBankError("暂不支持加密压缩包")
        if item.external_attr >> 16 & 0o170000 == 0o120000:
            raise QuestionBankError("压缩包包含符号链接")
        for part in normalized.parts:
            if not part or part in {".", ".."} or "\x00" in part or ":" in part:
                raise QuestionBankError("压缩包包含无效路径")
            if part.rstrip(" .") != part or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED:
                raise QuestionBankError("压缩包包含 Windows 不安全文件名")
        return tuple(str(part) for part in normalized.parts)

    @staticmethod
    def _physical_path(root: Path, virtual_path: str) -> Path:
        destination = root.joinpath(*PurePosixPath(virtual_path).parts).resolve()
        resolved_root = root.resolve()
        if resolved_root not in destination.parents:
            raise QuestionBankError("解压目标超出题库隔离目录")
        return destination

    def _build_directory_tree(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        nodes: dict[str, dict[str, Any]] = {}
        children: dict[str | None, set[str]] = defaultdict(set)
        for item in files:
            file_path = PurePosixPath(item["path"])
            parent = file_path.parent
            directory_paths: list[str] = []
            while parent.as_posix() not in {"", "."}:
                directory_paths.append(parent.as_posix())
                parent = parent.parent
            extension = file_path.suffix.lower() or "[无扩展名]"
            for path in directory_paths:
                node = nodes.setdefault(
                    path,
                    {
                        "path": path,
                        "depth": len(PurePosixPath(path).parts) - 1,
                        "parent": self._parent_path(path),
                        "direct_file_count": 0,
                        "recursive_file_count": 0,
                        "recursive_size_bytes": 0,
                        "extensions": Counter(),
                        "summary_files": [],
                        "representative_files": [],
                    },
                )
                node["recursive_file_count"] += 1
                node["recursive_size_bytes"] += item["size_bytes"]
                node["extensions"][extension] += 1
                if len(node["representative_files"]) < 12:
                    node["representative_files"].append(item["path"])
                if item.get("summary") and len(node["summary_files"]) < 3:
                    node["summary_files"].append({"path": item["path"], "summary": item["summary"]})
            direct = file_path.parent.as_posix()
            if direct in nodes:
                nodes[direct]["direct_file_count"] += 1
        for path, node in nodes.items():
            children[node["parent"]].add(path)
        result: list[dict[str, Any]] = []
        for path in sorted(nodes, key=lambda value: (nodes[value]["depth"], value)):
            node = nodes[path]
            node["child_directory_count"] = len(children.get(path, set()))
            node["extensions"] = dict(node["extensions"].most_common(20))
            result.append(node)
        return result

    @staticmethod
    def _tree_statistics(tree: list[dict[str, Any]]) -> dict[str, Any]:
        distribution = Counter(item["depth"] for item in tree)
        return {
            "directory_count": len(tree),
            "max_directory_depth": max(distribution, default=0),
            "directory_depth_distribution": {str(key): value for key, value in sorted(distribution.items())},
        }

    async def _scan_directory_levels(
        self, bank_id: str, tree: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        nodes = {item["path"]: item for item in tree}
        children: dict[str | None, list[str]] = defaultdict(list)
        for node in tree:
            children[node["parent"]].append(node["path"])
        frontier = sorted(children[None])
        questions: list[dict[str, Any]] = []
        unresolved: list[str] = []
        processed: set[str] = set()
        level = 0
        while frontier:
            level += 1
            current = [path for path in frontier if path not in processed]
            frontier = []
            for offset in range(0, len(current), self.settings.question_bank_scan_batch_size):
                batch_paths = current[offset : offset + self.settings.question_bank_scan_batch_size]
                decisions, traces = await self._scan_directory_batch_with_split(
                    bank_id, [nodes[path] for path in batch_paths]
                )
                for trace in traces:
                    self._append_trace(bank_id, "boundary_calls", trace)
                decision_map = {item["path"]: item for item in decisions}
                for path in batch_paths:
                    processed.add(path)
                    decision = decision_map.get(path)
                    if decision is None or decision["confidence"] < self.settings.question_bank_boundary_confidence:
                        unresolved.append(path)
                        continue
                    role = decision["role"]
                    if role == "question_root":
                        questions.append(
                            {
                                "root": path,
                                "name": decision.get("name") or PurePosixPath(path).name,
                                "question_type": "unknown",
                                "boundary_confidence": decision["confidence"],
                                "type_confidence": 0.0,
                                "rationale_summary": decision["rationale_summary"],
                            }
                        )
                    elif role in EXPAND_ROLES:
                        descendants = sorted(children.get(path, []))
                        if descendants:
                            frontier.extend(descendants)
                        elif nodes[path]["direct_file_count"]:
                            unresolved.append(path)
                    elif role == "uncertain":
                        unresolved.append(path)
                await self._publish(
                    bank_id,
                    "directory.level_completed",
                    {
                        "level": level,
                        "processed_directory_count": len(processed),
                        "detected_question_count": len(questions),
                        "unresolved_directory_count": len(unresolved),
                    },
                )
        if not questions:
            raise QuestionBankError("分层目录扫描没有产生可验证的候选题目")
        return questions, sorted(set(unresolved))

    async def _scan_directory_batch_with_split(
        self, bank_id: str, nodes: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            decisions, trace = await self._scan_directory_batch(bank_id, nodes)
            return decisions, [trace]
        except Exception:
            if len(nodes) <= 1:
                raise
            middle = len(nodes) // 2
            left, left_traces = await self._scan_directory_batch_with_split(bank_id, nodes[:middle])
            right, right_traces = await self._scan_directory_batch_with_split(bank_id, nodes[middle:])
            return left + right, left_traces + right_traces

    async def _scan_directory_batch(
        self, bank_id: str, nodes: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if self.gateway is None:
            raise ModelGatewayError("题库目录扫描模型未配置")
        allowed = {item["path"] for item in nodes}
        proposal, meta = await self.gateway.structured(
            role="planner",
            call_purpose="auxiliary",
            system_prompt=(
                "你是题库目录结构识别智能体。后端已经完成安全解压和精确层数计算。"
                "你只负责判断当前层每个目录的语义角色，不能修改 path、depth 或任何统计值。"
                "wrapper/container 表示应继续查看直接子目录；question_root 表示一道完整题目的最上层根目录；"
                "internal 表示已知内部材料；ignore 表示无关目录；不确定必须使用 uncertain。"
                "源码子目录、frontend/backend/src/assets/templates 不是独立题目的充分证据。"
                "每个输入 path 必须恰好返回一次，path 必须逐字复制。所有依据使用简体中文，不输出隐藏推理。"
            ),
            user_prompt=json.dumps(
                {"directories": nodes, "allowed_roles": sorted(DIRECTORY_ROLES)},
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            output_model=DirectoryScanProposal,
            prompt_version=BOUNDARY_PROMPT_VERSION,
            stage="question_bank_directory_scan",
            stream_observer=self._model_stream_observer(bank_id),
            timeout_seconds=self.settings.question_bank_model_timeout_seconds,
        )
        rows = [item.model_dump(mode="json") for item in proposal.decisions]
        returned = [item["path"] for item in rows]
        if len(returned) != len(set(returned)) or set(returned) != allowed:
            raise QuestionBankError("目录模型返回的路径集合与当前扫描批次不一致")
        return rows, self._trace(meta)

    async def _classify_questions(
        self, bank_id: str, questions: list[dict[str, Any]], files: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        targets = [item for item in questions if item["question_type"] == "unknown"]
        completed = 0
        for offset in range(0, len(targets), self.settings.question_bank_classification_batch_size):
            batch = targets[offset : offset + self.settings.question_bank_classification_batch_size]
            results = await self._classify_with_split(bank_id, batch, files)
            by_id = {item["candidate_id"]: item for item in results}
            for question in questions:
                result = by_id.get(question["candidate_id"])
                if result:
                    try:
                        self._apply_classification(question, result, files)
                    except QuestionBankError:
                        question.update(
                            {
                                "question_type": "unknown",
                                "question_type_label": TYPE_LABELS["unknown"],
                                "secondary_types": [],
                                "type_confidence": 0.0,
                                "type_evidence": [],
                                "type_rationale_summary": "分类结果未通过证据路径校验，请人工选择题型。",
                                "needs_human_review": True,
                            }
                        )
            completed += len(batch)
            await self._publish(
                bank_id,
                "classification.batch_completed",
                {"completed": completed, "total": len(targets)},
            )
        return questions

    async def _classify_with_split(
        self, bank_id: str, questions: list[dict[str, Any]], files: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        cached: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []
        for question in questions:
            value = self._load_classification_cache(question)
            (cached if value else pending).append(value or question)
        if not pending:
            return cached
        try:
            results, trace = await self._classify_batch(bank_id, pending, files)
            self._append_trace(bank_id, "classification_calls", trace)
            for question, result in zip(pending, results, strict=True):
                self._save_classification_cache(question, result)
            return cached + results
        except Exception:
            if len(pending) > 1:
                middle = len(pending) // 2
                left = await self._classify_with_split(bank_id, pending[:middle], files)
                right = await self._classify_with_split(bank_id, pending[middle:], files)
                return cached + left + right
            question = pending[0]
            return cached + [
                {
                    "candidate_id": question["candidate_id"],
                    "primary_type": "unknown",
                    "secondary_types": [],
                    "confidence": 0.0,
                    "evidence_paths": [],
                    "rationale_summary": "自动分类调用失败，请人工选择题型。",
                    "needs_human_review": True,
                }
            ]

    def _formatted_metadata(self, bank_id: str, files: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Load a small user-authored JSON/TXT metadata document from the extracted bank."""
        extracted = self._workspace(bank_id) / "extracted"
        metadata_names = FORMATTED_METADATA_JSON_NAMES | FORMATTED_METADATA_TEXT_NAMES
        candidates = [
            item for item in files if Path(item["path"]).name.casefold() in metadata_names
        ]
        for item in candidates:
            path = extracted / PurePosixPath(item["path"])
            if item.get("size_bytes", 0) > 256 * 1024 or not path.is_file():
                continue
            try:
                raw = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            name = Path(item["path"]).name.casefold()
            if name in FORMATTED_METADATA_JSON_NAMES:
                try:
                    body = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if isinstance(body, dict) and any(
                    key in body
                    for key in (
                        "questions", "count", "quantity", "题目数量", "types", "type", "question_type"
                    )
                ):
                    return {"format": "json", "source_path": item["path"], "body": body}
            else:
                body = self._parse_formatted_text(raw)
                if body:
                    return {"format": "txt", "source_path": item["path"], "body": body}
        return None

    @staticmethod
    def _parse_formatted_text(raw: str) -> dict[str, Any] | None:
        values: dict[str, Any] = {}
        rows: list[dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "//", ";")):
                continue
            match = re.match(r"^(?:题目|question)\s*(\d+)\s*[:：=]\s*(.+)$", line, re.I)
            if match:
                tokens = [part.strip() for part in re.split(r"[|,，]", match.group(2)) if part.strip()]
                rows.append(
                    {
                        "name": tokens[0] if tokens else f"题目 {match.group(1)}",
                        "type": tokens[1] if len(tokens) > 1 else tokens[0] if tokens else "unknown",
                        "root": tokens[2] if len(tokens) > 2 else None,
                    }
                )
                continue
            match = re.match(r"^([^:=：]+)\s*[:：=]\s*(.+)$", line)
            if not match:
                continue
            key = match.group(1).strip().casefold().replace(" ", "_")
            value = match.group(2).strip()
            if key in {"题目类型", "类型", "type", "question_type", "question_types"}:
                values["types"] = [item.strip() for item in re.split(r"[,，、|]", value) if item.strip()]
            elif key in {"数量", "题目数量", "count", "quantity", "题目数"}:
                try:
                    values["count"] = int(re.search(r"\d+", value).group())
                except (AttributeError, ValueError):
                    pass
            elif key in {"目标", "目标范围", "target", "target_scope"}:
                values["target"] = value
            elif key in {"名称", "题库名称", "name", "title"}:
                values["title"] = value
        if rows:
            values["questions"] = rows
        return values if any(key in values for key in ("questions", "count", "types", "target")) else None

    def _formatted_proposals(
        self, document: dict[str, Any], files: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        body = document["body"]
        raw_questions = body.get("questions") if isinstance(body.get("questions"), list) else []
        types = self._metadata_types(body)
        count = self._metadata_count(body, raw_questions, types)
        inferred_roots = self._infer_question_roots(files, count)
        proposals: list[dict[str, Any]] = []
        for index in range(max(count, len(raw_questions))):
            item = raw_questions[index] if index < len(raw_questions) and isinstance(raw_questions[index], dict) else {}
            explicit_root = item.get("root") or item.get("path") or item.get("directory")
            root = str(explicit_root or (inferred_roots[index] if index < len(inferred_roots) else "")).strip()
            if not root:
                continue
            root = self._resolve_metadata_root(root, files)
            question_type = self._normalize_question_type(
                item.get("type")
                or item.get("question_type")
                or (types[index % len(types)] if types else "unknown")
            )
            proposals.append(
                {
                    "root": root,
                    "name": str(item.get("name") or item.get("title") or f"题目 {index + 1}"),
                    "question_type": question_type,
                    "boundary_confidence": 1.0 if explicit_root else 0.82,
                    "type_confidence": 1.0 if question_type != "unknown" else 0.0,
                    "rationale_summary": "题目边界和类型来自题库格式化元数据。",
                    "explicit_root": bool(explicit_root),
                }
            )
        if not proposals:
            raise QuestionBankError("格式化元数据没有提供可匹配的题目目录；请为每题填写 root/path")
        normalized, _ = self._validate_proposal_data(proposals, files)
        metadata = {
            "title": body.get("title") or body.get("name"),
            "count": count,
            "target": body.get("target") or body.get("target_scope"),
            "types": types,
            "source_path": document["source_path"],
            "format": document["format"],
            "module_distribution": dict(Counter(item["question_type"] for item in normalized)),
            "inferred_root_count": sum(1 for item in proposals if not item.get("explicit_root")),
            "body": body,
        }
        return normalized, metadata

    @staticmethod
    def _resolve_metadata_root(root: str, files: list[dict[str, Any]]) -> str:
        normalized = root.replace("\\", "/").strip("/")
        directories = set(QuestionBankService._directory_options(files))
        if normalized in directories:
            return normalized
        prefixes = sorted({PurePosixPath(item["path"]).parts[0] for item in files})
        for prefix in prefixes:
            candidate = f"{prefix}/{normalized}"
            if candidate in directories:
                return candidate
        return normalized

    @staticmethod
    def _metadata_count(body: dict[str, Any], questions: list[Any], types: list[str]) -> int:
        for key in ("count", "quantity", "题目数量", "题目数"):
            value = body.get(key)
            if isinstance(value, int) and value > 0:
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        distribution = body.get("type_distribution") or body.get("module_distribution")
        if isinstance(distribution, dict):
            return sum(int(value) for value in distribution.values() if str(value).isdigit())
        return len(questions) or len(types) or 1

    @staticmethod
    def _metadata_types(body: dict[str, Any]) -> list[str]:
        raw = (
            body.get("types")
            or body.get("question_types")
            or body.get("type")
            or body.get("question_type")
            or body.get("type_distribution")
            or body.get("module_distribution")
        )
        if isinstance(raw, dict):
            result: list[str] = []
            for key, value in raw.items():
                if str(value).isdigit():
                    result.extend([str(key)] * int(value))
            return result
        if isinstance(raw, list):
            return [str(item) for item in raw]
        return [str(raw)] if raw else []

    @staticmethod
    def _normalize_question_type(value: Any) -> str:
        text = str(value or "unknown").strip().casefold()
        aliases = {
            "web安全": "web", "web": "web", "pwn": "pwn", "二进制利用": "pwn",
            "逆向": "reverse", "逆向工程": "reverse", "reverse": "reverse", "密码学": "crypto",
            "crypto": "crypto", "取证": "forensics", "取证分析": "forensics", "移动安全": "mobile",
            "mobile": "mobile", "区块链": "blockchain", "ai安全": "ai_security", "代码审计": "code_audit",
            "审计": "code_audit", "综合题": "misc", "misc": "misc",
        }
        return aliases.get(text, text if text in TYPE_LABELS else "unknown")

    def _infer_question_roots(self, files: list[dict[str, Any]], count: int) -> list[str]:
        directories = set(self._directory_options(files))
        paths = [row["path"] for row in files]
        candidates: set[str] = set()
        for item in files:
            parent = PurePosixPath(item["path"]).parent.as_posix()
            if parent not in {"", "."}:
                candidates.add(self._lift_single_branch_root(parent, directories, paths))
        return sorted(candidates, key=lambda value: (value.count("/"), value))[:count]

    async def _classify_batch(
        self, bank_id: str, questions: list[dict[str, Any]], files: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if self.gateway is None:
            raise ModelGatewayError("题目分类模型未配置")
        evidence = [self._classification_evidence(item, files) for item in questions]
        proposal, meta = await self.gateway.structured(
            role="worker",
            call_purpose="auxiliary",
            system_prompt=(
                "你是网络安全题型分类智能体。题目边界已经锁定，禁止增加、删除或更改边界。"
                "只能依据脱敏题面摘要、文件类型统计和真实代表路径判断主类型与最多三个次要类型。"
                "证据不足使用 unknown；evidence_paths 必须逐字选自该题 available_evidence_paths。"
                "不得执行或索取源码内容。所有依据使用简体中文，不输出隐藏推理。"
            ),
            user_prompt=json.dumps(
                {"questions": evidence, "allowed_question_types": list(TYPE_LABELS)},
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            output_model=QuestionClassificationBatch,
            prompt_version=CLASSIFICATION_PROMPT_VERSION,
            stage="question_bank_classification",
            stream_observer=self._model_stream_observer(bank_id),
            timeout_seconds=self.settings.question_bank_model_timeout_seconds,
        )
        rows = [item.model_dump(mode="json") for item in proposal.classifications]
        expected = [item["candidate_id"] for item in questions]
        actual = [item["candidate_id"] for item in rows]
        if len(actual) != len(set(actual)) or set(actual) != set(expected):
            raise QuestionBankError("分类模型返回的 candidate_id 与当前批次不一致")
        by_id = {item["candidate_id"]: item for item in rows}
        return [by_id[candidate_id] for candidate_id in expected], self._trace(meta)

    def _classification_evidence(
        self, question: dict[str, Any], files: list[dict[str, Any]]
    ) -> dict[str, Any]:
        root_prefix = question["root"].rstrip("/") + "/"
        selected = [item for item in files if item["path"].startswith(root_prefix)]
        extensions = Counter(PurePosixPath(item["path"]).suffix.lower() or "[无扩展名]" for item in selected)
        summaries = [
            {"path": item["path"], "summary": item["summary"]}
            for item in selected
            if item.get("summary")
        ][:5]
        representative = [item["path"] for item in sorted(selected, key=lambda row: -row["size_bytes"])[:20]]
        return {
            "candidate_id": question["candidate_id"],
            "name": question["name"],
            "root": question["root"],
            "file_count": len(selected),
            "size_bytes": sum(item["size_bytes"] for item in selected),
            "extensions": dict(extensions.most_common(30)),
            "summaries": summaries,
            "available_evidence_paths": representative,
        }

    def _apply_classification(
        self, question: dict[str, Any], result: dict[str, Any], files: list[dict[str, Any]]
    ) -> None:
        prefix = question["root"].rstrip("/") + "/"
        valid_paths = {item["path"] for item in files if item["path"].startswith(prefix)}
        evidence = result.get("evidence_paths", [])
        if any(path not in valid_paths for path in evidence):
            raise QuestionBankError("分类模型引用了题目根目录之外的证据路径")
        confidence = float(result["confidence"])
        needs_review = bool(result.get("needs_human_review")) or not evidence
        primary = result["primary_type"]
        if confidence < self.settings.question_bank_type_confidence:
            primary = "unknown"
            needs_review = True
        question.update(
            {
                "question_type": primary,
                "question_type_label": TYPE_LABELS[primary],
                "secondary_types": result.get("secondary_types", []),
                "type_confidence": confidence,
                "type_evidence": evidence,
                "type_rationale_summary": result["rationale_summary"],
                "needs_human_review": needs_review,
            }
        )

    def _manifest_questions(
        self, manifests: list[dict[str, Any]], files: list[dict[str, Any]]
    ) -> list[dict[str, Any]] | None:
        for manifest in manifests:
            raw = manifest["body"].get("questions") if isinstance(manifest["body"], dict) else None
            if not isinstance(raw, list):
                continue
            base = PurePosixPath(manifest["path"]).parent
            proposals = []
            for index, item in enumerate(raw, 1):
                if not isinstance(item, dict) or not item.get("root"):
                    raise QuestionBankError("Manifest 中存在无效题目根目录")
                root = PurePosixPath(base, str(item["root"])).as_posix().strip("/")
                question_type = str(item.get("type") or "unknown")
                if question_type not in TYPE_LABELS:
                    question_type = "unknown"
                proposals.append(
                    {
                        "root": root,
                        "name": str(item.get("name") or PurePosixPath(root).name or f"题目 {index}"),
                        "question_type": question_type,
                        "boundary_confidence": 1.0,
                        "type_confidence": 1.0 if item.get("type") in TYPE_LABELS else 0.0,
                        "rationale_summary": "题目边界来自已校验的 Manifest。",
                    }
                )
            questions, _ = self._validate_proposal_data(proposals, files)
            return questions
        return None

    def _validate_proposal_data(
        self, proposals: list[dict[str, Any]], files: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[str]]:
        if len(proposals) > self.settings.max_question_bank_questions:
            raise QuestionBankError("识别出的题目数量超过限制")
        directories = set(self._directory_options(files))
        all_paths = [item["path"] for item in files]
        normalized: list[dict[str, Any]] = []
        roots: list[str] = []
        for proposal in proposals:
            root = self._normalize_root(str(proposal["root"]))
            if root not in directories:
                raise QuestionBankError(f"候选根目录不存在：{root}")
            root = self._lift_single_branch_root(root, directories, all_paths)
            if root in roots:
                raise QuestionBankError(f"候选根目录重复：{root}")
            for existing in roots:
                if root.startswith(existing + "/") or existing.startswith(root + "/"):
                    raise QuestionBankError(f"候选根目录发生包含冲突：{existing} / {root}")
            roots.append(root)
            normalized.append({**proposal, "root": root})
        if not normalized:
            raise QuestionBankError("没有可验证的候选题目")
        return normalized, roots

    @staticmethod
    def _lift_single_branch_root(root: str, directories: set[str], file_paths: list[str]) -> str:
        current = PurePosixPath(root)
        while current.parent.as_posix() not in {"", "."}:
            parent = current.parent.as_posix()
            if parent not in directories:
                break
            prefix = parent.rstrip("/") + "/"
            descendants = [path for path in file_paths if path.startswith(prefix)]
            direct_files = [path for path in descendants if "/" not in path[len(prefix) :]]
            child_names = {
                path[len(prefix) :].split("/", 1)[0]
                for path in descendants
                if "/" in path[len(prefix) :]
            }
            if direct_files or len(child_names) != 1:
                break
            current = PurePosixPath(parent)
        return current.as_posix()

    def _describe(
        self, proposals: list[dict[str, Any]], files: list[dict[str, Any]], source: str
    ) -> list[dict[str, Any]]:
        results = []
        for index, proposal in enumerate(proposals, 1):
            root = proposal["root"]
            selected = [item for item in files if item["path"].startswith(root.rstrip("/") + "/")]
            fingerprint_rows = (
                f"{item['path']}:{item['size_bytes']}"
                for item in sorted(selected, key=lambda row: row["path"])
            )
            fingerprint = hashlib.sha256("\n".join(fingerprint_rows).encode()).hexdigest()
            question_type = proposal.get("question_type", "unknown")
            results.append(
                {
                    "candidate_id": f"candidate-{index:04d}",
                    "name": proposal["name"],
                    "root": root,
                    "question_type": question_type,
                    "question_type_label": TYPE_LABELS[question_type],
                    "secondary_types": [],
                    "type_confidence": float(proposal.get("type_confidence", 0)),
                    "boundary_confidence": float(proposal.get("boundary_confidence", 0)),
                    "file_count": len(selected),
                    "size_bytes": sum(item["size_bytes"] for item in selected),
                    "signals": [proposal.get("rationale_summary", "")],
                    "warnings": [] if selected else ["候选目录没有匹配到文件"],
                    "content_fingerprint": fingerprint,
                    "source": source,
                }
            )
        return results

    @staticmethod
    def _directory_options(files: list[dict[str, Any]]) -> list[str]:
        directories: set[str] = set()
        for item in files:
            parent = PurePosixPath(item["path"]).parent
            while parent.as_posix() not in {"", "."}:
                directories.add(parent.as_posix())
                parent = parent.parent
        return sorted(directories, key=lambda value: (value.count("/"), value))

    @staticmethod
    def _parent_path(path: str) -> str | None:
        parent = PurePosixPath(path).parent.as_posix()
        return None if parent in {"", "."} else parent

    @staticmethod
    def _unassigned(questions: list[dict[str, Any]], files: list[dict[str, Any]]) -> list[str]:
        roots = [item["root"].rstrip("/") + "/" for item in questions]
        public_names = {"metadata.json", "readme.md", "runbook.md"}
        unassigned = []
        for item in files:
            path = item["path"]
            normalized = path.casefold()
            if any(path.startswith(root) for root in roots):
                continue
            # Shared metadata is intentionally not owned by an individual
            # question; it is a valid package-level ownership class.
            if "/shared/" in f"/{normalized}" or "/schemas/" in f"/{normalized}":
                continue
            if PurePosixPath(path).name.casefold() in public_names:
                continue
            unassigned.append(path)
        return unassigned

    @staticmethod
    def _duplicates(questions: list[dict[str, Any]]) -> int:
        counts = Counter(item["content_fingerprint"] for item in questions)
        return sum(1 for count in counts.values() if count > 1)

    async def _stage(self, bank_id: str, stage: str, message: str) -> None:
        record = self.get(bank_id)
        record["stage"] = stage
        record["stage_message"] = message
        self._save(record)
        await self._publish(bank_id, "inspection.stage", {"bank_id": bank_id, "stage": stage, "message": message})

    async def _publish(self, bank_id: str, event_type: str, payload: dict[str, Any]) -> None:
        event = {"type": event_type, "bank_id": bank_id, "payload": payload}
        for queue in tuple(self._subscribers.get(bank_id, ())):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(event)

    def _model_stream_observer(self, bank_id: str):
        async def observer(event_type: str, payload: dict[str, Any]) -> None:
            await self._publish(bank_id, event_type, payload)

        return observer

    def _append_trace(self, bank_id: str, key: str, trace: dict[str, Any]) -> None:
        record = self.get(bank_id)
        record.setdefault("model_trace", {}).setdefault(key, []).append(trace)
        self._save(record)

    @staticmethod
    def _trace(meta: Any) -> dict[str, Any]:
        return {
            "model_id": meta.model_id,
            "prompt_version": meta.prompt_version,
            "response_sha256": meta.response_sha256,
            "duration_ms": meta.duration_ms,
            "usage": meta.usage,
            "used_fallback": meta.used_fallback,
        }

    def _classification_cache_key(self, question: dict[str, Any]) -> str:
        model = getattr(self.settings, "worker_model", "unknown")
        taxonomy = ",".join(TYPE_LABELS)
        raw = f"{question['content_fingerprint']}:{CLASSIFICATION_PROMPT_VERSION}:{taxonomy}:{model}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _load_classification_cache(self, question: dict[str, Any]) -> dict[str, Any] | None:
        path = self._cache_root() / f"{self._classification_cache_key(question)}.json"
        if not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            value["candidate_id"] = question["candidate_id"]
            return value
        except (OSError, json.JSONDecodeError):
            return None

    def _save_classification_cache(self, question: dict[str, Any], result: dict[str, Any]) -> None:
        root = self._cache_root()
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{self._classification_cache_key(question)}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)

    @staticmethod
    def _complete_checkpoint(record: dict[str, Any], stage: str) -> None:
        values = record.setdefault("checkpoint", {}).setdefault("completed_stages", [])
        if stage not in values:
            values.append(stage)
        record["checkpoint"]["updated_at"] = datetime.now(UTC).isoformat()

    def _resolve(self, reference: str) -> Path:
        candidate = Path(reference)
        roots = [self.settings.input_root.resolve(), self.settings.upload_root.resolve()]
        resolved = candidate.resolve() if candidate.is_absolute() else (self.settings.upload_root / candidate).resolve()
        if not resolved.exists():
            resolved = (self.settings.input_root / candidate).resolve()
        if not resolved.is_file() or not any(resolved == root or root in resolved.parents for root in roots):
            raise QuestionBankError("题库附件不存在或超出允许目录")
        return resolved

    @staticmethod
    def _normalize_root(value: str) -> str:
        normalized = PurePosixPath(value.replace("\\", "/"))
        if normalized.is_absolute() or ".." in normalized.parts:
            raise QuestionBankError("候选根目录无效")
        result = normalized.as_posix().strip("/")
        if result in {"", "."}:
            raise QuestionBankError("候选根目录不能是题库整体根目录")
        return result

    @staticmethod
    def _safe_summary(raw: bytes) -> str | None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        text = SECRET_PATTERN.sub("[敏感内容已隐藏]", text)
        return " ".join(text.split())[:800] or None

    @staticmethod
    def _safe_stem(name: str) -> str:
        value = Path(name).stem.replace("\x00", "").strip().rstrip(" .") or "attachment"
        if value.split(".", 1)[0].casefold() in WINDOWS_RESERVED or ":" in value:
            raise QuestionBankError("题库附件名称不安全")
        return value

    @staticmethod
    def _file_record(
        path: str, size_bytes: int, summary: str | None = None, source_archive: str | None = None
    ) -> dict[str, Any]:
        record: dict[str, Any] = {"path": path.replace("\\", "/").strip("/"), "size_bytes": size_bytes}
        if summary:
            record["summary"] = summary
        if source_archive:
            record["source_archive"] = source_archive
        return record

    def _workspace(self, bank_id: str) -> Path:
        normalized = str(UUID(bank_id))
        return self.settings.question_bank_root / normalized

    def _cache_root(self) -> Path:
        return self.settings.question_bank_root / "classification-cache"

    def _path(self, bank_id: str) -> Path:
        try:
            normalized = str(UUID(bank_id))
        except ValueError as exc:
            raise KeyError(bank_id) from exc
        return self.settings.question_bank_root / f"{normalized}.json"

    def _save(self, record: dict[str, Any]) -> None:
        path = self._path(record["bank_id"])
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
