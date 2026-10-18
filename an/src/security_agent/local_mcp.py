"""Bundled, genuinely executable MCP server for bounded local analysis."""
from __future__ import annotations

import ast
import base64
import hashlib
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP('SecMind local analysis')
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)


def artifact_path(value: str) -> Path:
    path = Path(value).resolve(strict=True)
    roots = [Path(p).resolve() for p in os.environ.get('SECMIND_MCP_ROOTS', '').split(os.pathsep) if p]
    if not roots or not any(path.is_relative_to(root) for root in roots) or not path.is_file():
        raise ValueError('File must be inside an authorized input/upload/run directory')
    if path.stat().st_size > 50 * 1024 * 1024:
        raise ValueError('File exceeds 50 MiB')
    return path


@mcp.tool(annotations=READ_ONLY)
def hash_file(path: str) -> dict:
    """Compute SHA-256 and size of an uploaded artifact; never executes its contents."""
    target = artifact_path(path)
    with target.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
    return {'path': str(target), 'bytes': target.stat().st_size, 'sha256': digest}


@mcp.tool(annotations=READ_ONLY)
def inspect_python(path: str) -> dict:
    """Parse Python source into an AST and return imports/functions without executing code."""
    target = artifact_path(path)
    tree = ast.parse(target.read_text(encoding='utf-8-sig'))
    return {'path': str(target), 'functions': [{'name': n.name, 'line': n.lineno} for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))],
            'imports': sorted({n.module or '' for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} |
                              {alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names})}


@mcp.tool(annotations=READ_ONLY)
def audit_python(path: str) -> dict:
    """Run Bandit against one authorized Python file; return rule IDs, locations and findings without executing the sample."""
    target = artifact_path(path)
    if target.suffix.lower() != '.py':
        raise ValueError('Bandit requires a .py source file')
    from bandit.core.config import BanditConfig
    from bandit.core.manager import BanditManager

    # Run the library inside the bounded MCP worker. This avoids a second
    # Windows Python launcher whose children could outlive a CLI timeout.
    manager = BanditManager(BanditConfig(), 'file', quiet=True)
    manager.discover_files([str(target)])
    manager.run_tests()
    skipped = manager.get_skipped()
    if skipped:
        raise ValueError('Bandit could not analyze the file: ' + str(skipped))
    findings = [issue.as_dict() for issue in manager.get_issue_list()]
    return {'path': str(target), 'findings': findings, 'errors': [],
            'metrics': manager.metrics.data, 'scanner': 'bandit'}


@mcp.tool(annotations=READ_ONLY)
def decode_base64(text: str) -> dict:
    """Strictly decode Base64 text and return UTF-8 text, length and SHA-256."""
    if len(text) > 100_000:
        raise ValueError('Input exceeds 100000 characters')
    data = base64.b64decode(text, validate=True)
    return {'text': data.decode('utf-8', errors='replace'), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


if __name__ == '__main__':
    mcp.run(transport='stdio')
