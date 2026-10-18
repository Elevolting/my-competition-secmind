"""Filter unusable planning branches before persisting a callback decision.

Runtime still validates the full graph transaction and owns all claims. This
preflight keeps a malformed model branch from poisoning a durable decision.
"""
from collections import Counter

from security_agent.schemas import PlanningIntent


def _normalize_output_gates(item: PlanningIntent, known_steps: set[str],
                            notes: list[str]) -> None:
    """Re-anchor ``required_outputs`` the Planner keyed by the wrong step.

    The field is a gate keyed by the *prerequisite* step, but the model
    routinely reads it as "what this step will produce" and keys it by its own
    ``step_id``. Rejecting such a direction removed every direction of a round
    and stopped the whole task (渗透33 / a98a1c48). A gate on the step itself
    can never gate anything, so it is dropped; a gate naming another declared
    step is a real dependency, so that dependency is declared explicitly.
    Unknown keys keep failing the strict rule below.
    """
    if not item.required_outputs or item.retry_intent_id:
        # Retries must echo the stored contract byte for byte; the strict
        # retry check below owns that comparison.
        return
    label = item.step_id or item.title or "<untitled>"
    kept: dict[str, list[str]] = {}
    for key, values in item.required_outputs.items():
        if item.step_id and key == item.step_id:
            notes.append(f"{label}: 忽略指向自身的产物要求 {key}")
            continue
        if key in known_steps:
            kept[key] = values
            if key not in item.depends_on:
                item.depends_on.append(key)
                notes.append(f"{label}: 按产物要求补声明前置 {key}")
            continue
        kept[key] = values
    item.required_outputs = kept


def filter_planning_dependencies(
    proposals: list[PlanningIntent], existing: list[dict], round_limit: int,
) -> tuple[list[PlanningIntent], list[str], list[str]]:
    steps = {item['step_id']: item for item in existing
             if isinstance(item, dict) and item.get('step_id')}
    counts = Counter(item.step_id for item in proposals if item.step_id)
    graph = {key: item.get('depends_on') or [] for key, item in steps.items()}
    graph.update({item.step_id: item.depends_on for item in proposals if item.step_id})
    rejected = []
    notes: list[str] = []
    accepted = []
    retries = set()
    for item in proposals:
        _normalize_output_gates(item, set(graph), notes)
        error = None
        if (item.depends_on or item.required_outputs) and not item.step_id:
            error = '依赖待办必须提供稳定步骤编号'
        elif item.step_id and (not item.step_id.strip() or counts[item.step_id] > 1):
            error = '步骤编号为空或在本轮重复'
        elif item.step_id in steps and not item.retry_intent_id:
            error = '步骤编号已存在于当前任务'
        elif item.retry_intent_id and item.retry_intent_id in retries:
            error = '同一方向不能在一轮重复重试'
        elif item.retry_intent_id and item.step_id:
            prior = steps.get(item.step_id)
            if (not prior or prior.get('id') != item.retry_intent_id
                    or item.depends_on != (prior.get('depends_on') or [])
                    or item.required_outputs != (prior.get('required_outputs') or {})):
                error = '重试必须保留原步骤编号和依赖契约'
        if not error and any(key not in item.depends_on for key in item.required_outputs):
            error = '必需产物必须属于已声明的前置步骤'
        if not error and any(not values or len(values) > 30
                             or any(not value.strip() or len(value) > 120 for value in values)
                             for values in item.required_outputs.values()):
            error = '必需产物编号为空或超过长度限制'
        if not error and any(key not in graph for key in item.depends_on):
            error = '前置步骤不属于当前任务'

        def cyclic(key, path, visited):
            if key in path:
                return True
            if key in visited:
                return False
            if any(cyclic(parent, path | {key}, visited) for parent in graph.get(key, [])):
                return True
            visited.add(key)
            return False

        if not error and item.step_id and cyclic(item.step_id, set(), set()):
            error = '步骤依赖存在环'
        if error:
            rejected.append(f'{item.step_id or item.title}: {error}')
            continue
        accepted.append(item)
        if item.retry_intent_id:
            retries.add(item.retry_intent_id)

    def remove_dangling(items):
        while True:
            known = set(steps) | {item.step_id for item in items if item.step_id}
            remaining = [item for item in items if set(item.depends_on).issubset(known)]
            if len(remaining) == len(items):
                return remaining
            rejected.append('前置步骤被过滤，已移除对应下游待办')
            items = remaining

    accepted = remove_dangling(accepted)
    drafted = {item.step_id for item in accepted if item.step_id}
    bounded: list[PlanningIntent] = []
    independent_count = 0
    for item in accepted:
        independent = not set(item.depends_on).intersection(drafted)
        if independent and independent_count >= round_limit:
            rejected.append('本轮新增独立方向达到配置上限')
            continue
        if item.step_id and item.step_id not in steps and len(steps) + sum(
                bool(p.step_id and p.step_id not in steps) for p in bounded) >= 200:
            rejected.append('任务超过200项规划步骤上限')
            continue
        bounded.append(item)
        independent_count += int(independent)
    return remove_dangling(bounded), rejected, notes
