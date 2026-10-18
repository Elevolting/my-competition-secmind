"""One-run authorization and request validation for a local CTF form endpoint."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit
from uuid import NAMESPACE_URL, uuid5

from security_agent.schemas import AgentState

POLICY = "scoped_file_post"
CONSTRAINT = "仅对授权 URL 原路径允许 file 表单 POST（本地文件或只读 php://filter）；其他请求限 GET/HEAD，不发送其他请求体或跟随跳转"
SOURCE_RUN_ID = "2d692bbe-953a-4ab8-84b6-dff7036ae9d3"
REQUEST_ID = "scoped-file-post-2d692bbe-953a-4ab8-84b6-dff7036ae9d3"
LOCAL_FILE = re.compile(r"(?!//)[A-Za-z0-9_./-]{1,1024}\Z")
FILTER_PREFIX = "php://filter/convert.base64-encode/resource="


@dataclass(frozen=True)
class Grant:
    source_run_id: str
    target_url: str
    request_id: str

    @property
    def child_run_id(self) -> str:
        return str(uuid5(NAMESPACE_URL, f"run-retry:{self.source_run_id}:{self.request_id}"))


def grant_path(settings) -> Path:
    return settings.run_root.parent / "scoped-file-post-grant.json"


def load_grant(settings) -> Grant | None:
    try:
        data = json.loads(grant_path(settings).read_text(encoding="utf-8"))
        grant = Grant(**data)
    except (OSError, ValueError, TypeError):
        return None
    parsed = urlsplit(grant.target_url)
    if (grant.source_run_id != SOURCE_RUN_ID or grant.request_id != REQUEST_ID
            or parsed.scheme != "https" or not parsed.hostname
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        return None
    return grant


def state_has_grant(state: AgentState, grant: Grant | None) -> bool:
    return bool(grant and state.retry_of == grant.source_run_id
                and state.run_id == grant.child_run_id
                and scope_matches_grant(state.task.target_scope, grant)
                and state.task.network_policy == POLICY)


def scope_matches_grant(target_scope: list[str], grant: Grant) -> bool:
    urls = [value for value in target_scope if value.startswith(("http://", "https://"))]
    return urls == [grant.target_url]


def validate_post(arguments: dict, grant: Grant) -> None:
    if arguments.get("url") != grant.target_url:
        raise ValueError("POST URL 必须与本次授权 URL 完全相同")
    body = arguments.get("body")
    if not isinstance(body, str) or not body or len(body.encode("utf-8")) > 2048:
        raise ValueError("POST 表单请求体无效或超过 2 KB")
    if re.search(r"%(?![0-9a-fA-F]{2})", body):
        raise ValueError("POST 表单编码无效")
    try:
        fields = parse_qsl(body, keep_blank_values=True, strict_parsing=True,
                           encoding="utf-8", errors="strict", max_num_fields=2)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("POST 表单编码无效") from exc
    if len(fields) != 1 or fields[0][0] != "file":
        raise ValueError("POST 仅允许一个 file 表单字段")
    value = fields[0][1]
    if value.startswith(FILTER_PREFIX):
        value = value.removeprefix(FILTER_PREFIX)
    if not LOCAL_FILE.fullmatch(value):
        raise ValueError("file 仅允许本地文件路径或只读 php://filter")
