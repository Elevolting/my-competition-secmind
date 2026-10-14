"""Bounded MCP tools backed by the local Kali Docker container.

The blackboard remains the authorization boundary.  This process only accepts
fixed tool arguments and invokes the named binaries through ``docker exec``;
there is deliberately no generic shell or command argument.
"""
from __future__ import annotations

import asyncio
import os
import re
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("SecMind Kali scanners")
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)
REVIEW_REQUIRED = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=True)
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
_PORTS = re.compile(r"^[0-9]{1,5}(?:[-,][0-9]{1,5})*$")
_TOOLS = {
    "nmap", "nuclei", "katana", "naabu", "whatweb", "ffuf", "nikto",
    "dirsearch", "gobuster", "sqlmap",
}
_WORDLISTS = {
    # This file is shipped by the Kali image and contains only ordinary,
    # relative path names.  The distro wordlist also contains traversal and
    # cross-origin payloads, so it is intentionally not exposed here.
    "common": "/opt/secmind/common-paths.txt",
}


def _container() -> str:
    value = os.environ.get("SECMIND_KALI_CONTAINER", "security-runtime-kali").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ValueError("Kali container name is invalid")
    return value


def _target(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 2048 or any(ch in value for ch in "\r\n\x00;&|`$()<>\\"):
        raise ValueError("target is invalid")
    parsed = urlparse(value if "://" in value else "//" + value)
    host = parsed.hostname
    if host is None or not _HOST.fullmatch(host) or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("target must be a host, IP, or URL without credentials or fragments")
    return value


def _ports(value: str) -> str:
    if not _PORTS.fullmatch(value) or len(value) > 80:
        raise ValueError("ports must be a numeric port/range list")
    count = 0
    for part in value.split(","):
        bounds = [int(item) for item in part.split("-")]
        if any(not 1 <= port <= 65535 for port in bounds) or bounds[-1] < bounds[0]:
            raise ValueError("ports must be between 1 and 65535")
        count += bounds[-1] - bounds[0] + 1
    if count > 1000:
        raise ValueError("a scan may cover at most 1000 ports")
    return value


async def _run(tool: str, args: list[str], timeout: int = 70) -> dict:
    if tool not in _TOOLS:
        raise ValueError("unsupported Kali tool")
    command = ["docker", "exec", _container(), "timeout", "-k", "3s", f"{timeout - 5}s", tool, *args]
    process = await asyncio.create_subprocess_exec(
        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.communicate()
        raise ValueError(f"{tool} exceeded its execution deadline") from None
    output = stdout.decode("utf-8", errors="replace")
    error = stderr.decode("utf-8", errors="replace")
    return {
        "tool": tool,
        "returncode": process.returncode,
        "output": output[-64000:],
        "stderr": error[-8000:],
        "truncated": len(output) > 64000,
    }


@mcp.tool(annotations=READ_ONLY)
async def kali_tool_version(tool: str) -> dict:
    """Return the installed version of an allowlisted Kali scanner."""
    versions = {
        "nmap": ["--version"], "nuclei": ["-version"], "katana": ["-version"],
        "naabu": ["-version"], "whatweb": ["--version"], "ffuf": ["-V"],
        "nikto": ["-Version"], "dirsearch": ["--version"],
        "gobuster": ["--version"], "sqlmap": ["--version"],
    }
    if tool not in versions:
        raise ValueError("unsupported Kali tool")
    result = await _run(tool, versions[tool])
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or f"{tool} failed")
    return result


@mcp.tool(annotations=READ_ONLY)
async def nmap_scan(target: str, ports: str = "80,443") -> dict:
    """Run a bounded, read-only Nmap service scan against the authorized target."""
    target = _target(target)
    ports = _ports(ports)
    host = urlparse(target).hostname if "://" in target else target
    result = await _run("nmap", ["-sT", "-Pn", "-T2", "--max-retries", "1", "--host-timeout", "60s", "-p", ports, host])
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "nmap failed")
    return result


@mcp.tool(annotations=READ_ONLY)
async def naabu_scan(target: str, ports: str = "80,443") -> dict:
    """Enumerate authorized host TCP ports with bounded rate and port count."""
    target = _target(target)
    ports = _ports(ports)
    host = urlparse(target).hostname if "://" in target else target
    result = await _run("naabu", ["-host", host, "-p", ports, "-s", "c", "-rate", "50",
                                   "-c", "5", "-retries", "0", "-timeout", "1000ms", "-silent", "-no-color"])
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "naabu failed")
    return result


@mcp.tool(annotations=READ_ONLY)
async def whatweb_fingerprint(target: str) -> dict:
    """Identify web technology with one request and no redirect following."""
    target = _target(target)
    if urlparse(target).scheme not in {"http", "https"}:
        raise ValueError("WhatWeb requires an HTTP or HTTPS URL")
    result = await _run("whatweb", ["--aggression=1", "--follow-redirect=never", "--no-cookies",
                                     "--max-threads=1", "--open-timeout=5", "--read-timeout=10",
                                     "--colour=never", target])
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "whatweb failed")
    return result


@mcp.tool(annotations=READ_ONLY)
async def katana_crawl(target: str, depth: int = 2) -> dict:
    """Crawl an authorized URL with a short duration and bounded depth."""
    target = _target(target)
    if type(depth) is not int or not 1 <= depth <= 3:
        raise ValueError("depth must be between 1 and 3")
    if urlparse(target).scheme not in {"http", "https"}:
        raise ValueError("Katana requires an HTTP or HTTPS URL")
    parsed = urlparse(target)
    base = target.split("?", 1)[0].rstrip("/")
    scope = "^" + re.escape(base) + ("(?:/|\\?|$)" if parsed.path.rstrip("/") else "(?:/|\\?|$)")
    result = await _run("katana", ["-u", target, "-silent", "-depth", str(depth),
                                    "-crawl-duration", "30s", "-rate-limit", "10", "-concurrency", "2",
                                    "-disable-redirects", "-crawl-scope", scope, "-jsonl"], timeout=75)
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "katana failed")
    return result


def _http_target(value: str) -> str:
    value = _target(value)
    if urlparse(value).scheme not in {"http", "https"}:
        raise ValueError("此工具需要 HTTP 或 HTTPS URL")
    return value


def _directory_target(value: str) -> str:
    value = _http_target(value)
    if urlparse(value).query:
        raise ValueError("目录枚举目标不能包含查询参数")
    return value


def _wordlist(value: str) -> str:
    if value not in _WORDLISTS:
        raise ValueError("wordlist 只允许使用已内置的字典")
    return _WORDLISTS[value]


def _extensions(value: str) -> str:
    if not isinstance(value, str) or len(value) > 80 or not re.fullmatch(r"[A-Za-z0-9.,_-]*", value):
        raise ValueError("extensions 参数无效")
    return value


@mcp.tool(annotations=REVIEW_REQUIRED)
async def nuclei_scan(target: str, severity: str = "info,low,medium,high,critical") -> dict:
    """Run HTTP Nuclei templates with bounded rate and no OAST or redirects. Requires approval."""
    target = _http_target(target)
    allowed = {"info", "low", "medium", "high", "critical", "unknown"}
    levels = [item.strip() for item in severity.split(",") if item.strip()]
    if not levels or len(levels) > len(allowed) or any(item not in allowed for item in levels):
        raise ValueError("severity 只能是 info/low/medium/high/critical/unknown 的逗号列表")
    result = await _run("nuclei", ["-target", target, "-templates", "/opt/secmind/nuclei-http-headers.yaml",
                                    "-jsonl", "-silent", "-no-interactsh",
                                    "-disable-redirects", "-disable-update-check", "-type", "http",
                                    "-no-stdin",
                                    "-severity", ",".join(levels), "-rate-limit", "10",
                                    "-concurrency", "5", "-bulk-size", "1", "-timeout", "5",
                                    "-retries", "0"], timeout=75)
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "nuclei failed")
    return result


@mcp.tool(annotations=REVIEW_REQUIRED)
async def ffuf_directory(target: str, wordlist: str = "common", extensions: str = "") -> dict:
    """Discover paths with the bundled dictionary, low concurrency and no redirects."""
    target = _directory_target(target).rstrip("/") + "/FUZZ"
    wordlist_path = _wordlist(wordlist)
    extensions = _extensions(extensions)
    args = ["-u", target, "-w", wordlist_path, "-t", "5", "-rate", "10", "-timeout", "5",
            "-maxtime", "45", "-noninteractive", "-s", "-json", "-mc", "200-299,301,302,307,401,403"]
    if extensions:
        args.extend(["-e", extensions])
    result = await _run("ffuf", args, timeout=55)
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "ffuf failed")
    return result


@mcp.tool(annotations=REVIEW_REQUIRED)
async def nikto_scan(target: str) -> dict:
    """Run a bounded Nikto web server audit without DNS lookups or interactive prompts."""
    target = _http_target(target)
    result = await _run("nikto", ["-host", target, "-nointeractive", "-nolookup",
                                   "-maxtime", "45s", "-timeout", "5", "-ask", "no"], timeout=55)
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "nikto failed")
    return result


@mcp.tool(annotations=REVIEW_REQUIRED)
async def dirsearch_scan(target: str, wordlist: str = "common") -> dict:
    """Enumerate paths with the bundled Dirsearch dictionary and bounded runtime."""
    target = _directory_target(target)
    result = await _run("dirsearch", ["-u", target, "-w", _wordlist(wordlist), "-t", "5",
                                       "--max-time=45", "--timeout=5", "--no-color",
                                       "--format=simple", "--full-url"], timeout=55)
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "dirsearch failed")
    return result


@mcp.tool(annotations=REVIEW_REQUIRED)
async def gobuster_directory(target: str, wordlist: str = "common") -> dict:
    """Enumerate paths with Gobuster using the bundled dictionary and bounded concurrency."""
    target = _directory_target(target)
    result = await _run("gobuster", ["dir", "-u", target, "-w", _wordlist(wordlist), "-t", "5",
                                      "--timeout", "5s", "--no-error", "--no-progress", "--quiet",
                                      "--status-codes", "200,204,301,302,307,401,403"], timeout=55)
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "gobuster failed")
    return result


@mcp.tool(annotations=REVIEW_REQUIRED)
async def sqlmap_audit(target: str) -> dict:
    """Run a bounded SQLMap audit against one authorized URL. Requires approval."""
    target = _http_target(target)
    result = await _run("sqlmap", ["-u", target, "--batch", "--smart", "--level=1", "--risk=1",
                                    "--threads=1", "--timeout=5", "--retries=0", "--crawl=0",
                                    "--ignore-redirects", "--disable-coloring", "--flush-session"], timeout=75)
    if result["returncode"] != 0:
        raise ValueError(result["stderr"] or "sqlmap failed")
    return result


if __name__ == "__main__":
    mcp.run(transport="stdio")
