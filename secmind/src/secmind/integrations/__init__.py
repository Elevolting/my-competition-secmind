"""Versioned integration adapters kept outside the SecMind control plane."""

from .test3 import (
    ProjectionCursorError,
    ProjectionPage,
    ProjectionPageReader,
    ProjectionPageStore,
    build_trusted_task_payload,
    project_domain_result,
    read_page,
    read_projection_page,
)

__all__ = [
    "ProjectionCursorError",
    "ProjectionPage",
    "ProjectionPageReader",
    "ProjectionPageStore",
    "build_trusted_task_payload",
    "project_domain_result",
    "read_page",
    "read_projection_page",
]
