"""Defaults for new tasks and request limits shared by API and settings.

Persisted BudgetState defaults remain unchanged for historical runs. Resource
budgets do not grant network or tool permissions.
"""

DEFAULT_TOOL_CALLS = 600
DEFAULT_MODEL_CALLS = 200
DEFAULT_PENETRATION_MODEL_CALLS = 600
MAX_TOOL_CALLS = 100_000
MAX_MODEL_CALLS = 10_000
MAX_RUNTIME_SECONDS = 7200

TASK_BUDGET_LIMITS = {
    "max_runtime_seconds": {"min": 60, "max": MAX_RUNTIME_SECONDS},
    "max_tool_calls": {"min": 1, "max": MAX_TOOL_CALLS},
    "max_model_calls": {"min": 1, "max": MAX_MODEL_CALLS},
}
