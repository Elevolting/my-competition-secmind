"""Persistent step dependencies; Runtime remains authoritative for claimability."""

from __future__ import annotations

import json

from fastapi import HTTPException


def _drop_self_output_gates(proposal) -> None:
    """Ignore ``required_outputs`` the Planner keyed by the step itself.

    The field gates a step on a *prerequisite*, but the model often reads it as
    "what this step will produce" and keys it by its own ``step_id``, which made
    the whole direction invalid and stopped the task. Such a self-gate can never
    gate anything, so drop it. Unknown keys stay for the strict check below.
    """
    if not proposal.required_outputs or not proposal.step_id:
        return
    if proposal.step_id in proposal.required_outputs:
        proposal.required_outputs = {
            key: values for key, values in proposal.required_outputs.items()
            if key != proposal.step_id
        }


def validate_graph(conn, project_id, proposals):
    existing = {
        row["step_id"]: row
        for row in conn.execute("SELECT * FROM intents WHERE project_id=? AND step_id IS NOT NULL", (project_id,))
    }
    graph = {key: json.loads(row["depends_on_json"]) for key, row in existing.items()}
    new_keys = set()
    for proposal in proposals:
        _drop_self_output_gates(proposal)
        if (proposal.depends_on or proposal.required_outputs) and not proposal.step_id:
            raise HTTPException(422, "Dependencies require a stable step_id")
        if proposal.step_id:
            if proposal.retry_intent_id:
                prior = existing.get(proposal.step_id)
                if (
                    not prior
                    or prior["id"] != proposal.retry_intent_id
                    or proposal.depends_on != json.loads(prior["depends_on_json"])
                    or proposal.required_outputs != json.loads(prior["required_outputs_json"])
                ):
                    raise HTTPException(422, "Retry must preserve step identity and dependency contract")
            else:
                if proposal.step_id in existing or proposal.step_id in new_keys:
                    raise HTTPException(422, "Duplicate step_id in project")
                new_keys.add(proposal.step_id)
                graph[proposal.step_id] = proposal.depends_on
        elif proposal.retry_intent_id and any(row["id"] == proposal.retry_intent_id for row in existing.values()):
            raise HTTPException(422, "Step retry requires its original step_id")
        if any(key not in proposal.depends_on for key in proposal.required_outputs):
            raise HTTPException(422, "Required outputs must belong to declared dependencies")
        if any(
            not values
            or len(values) > 30
            or any(not isinstance(v, str) or not v.strip() or len(v) > 120 for v in values)
            for values in proposal.required_outputs.values()
        ):
            raise HTTPException(422, "Required output keys must be nonempty and bounded")
    if len(graph) > 200:
        raise HTTPException(422, "Project exceeds the 200-step planning limit")
    visiting, visited = set(), set()

    def visit(key):
        if key in visiting:
            raise HTTPException(422, "Planning dependency cycle")
        if key in visited:
            return
        visiting.add(key)
        for parent in graph[key]:
            if parent not in graph:
                raise HTTPException(422, "Dependency step is not in this project")
            visit(parent)
        visiting.remove(key)
        visited.add(key)

    for key in graph:
        visit(key)


def confirm_outputs(conn, project_id, confirmations):
    if len(confirmations) > 200:
        raise HTTPException(422, "Too many output confirmations")
    for key, outputs in confirmations.items():
        row = conn.execute("SELECT * FROM intents WHERE project_id=? AND step_id=?", (project_id, key)).fetchone()
        if not row or not row["to_fact_id"] or row["execution_status"] != "completed":
            raise HTTPException(422, "Output confirmation requires a completed step in this project")
        fact = conn.execute(
            "SELECT items_json FROM facts WHERE project_id=? AND id=?", (project_id, row["to_fact_id"])
        ).fetchone()
        available = {
            item.get("output_key")
            for item in json.loads(fact["items_json"])
            if item.get("output_key")
            # Any result-item type may carry the named output.  Restricting this
            # to facts and artifacts rejected a Planner confirmation for an
            # observed output reported as an observation or finding, which
            # failed the planning decision and left dependent steps blocked.
            and item.get("type") in {"fact", "artifact", "observation", "finding"}
            and item.get("outcome") == "observed"
            and item.get("evidence_ids")
        }
        if len(outputs) > 30 or any(output not in available for output in outputs):
            raise HTTPException(422, "Output confirmation lacks an observed result and evidence")
        combined = sorted(set(json.loads(row["validated_outputs_json"])) | set(outputs))
        conn.execute(
            "UPDATE intents SET validated_outputs_json=? WHERE project_id=? AND id=?",
            (json.dumps(combined), project_id, row["id"]),
        )


def blocked_reasons(conn, project_id, row):
    reasons = []
    required = json.loads(row["required_outputs_json"])
    for key in json.loads(row["depends_on_json"]):
        parent = conn.execute("SELECT * FROM intents WHERE project_id=? AND step_id=?", (project_id, key)).fetchone()
        if not parent:
            reasons.append(f"{key}: dependency missing")
        elif parent["execution_status"] != "completed" or not parent["to_fact_id"]:
            reasons.append(f"{key}: {parent['execution_status']}")
        else:
            missing = sorted(set(required.get(key, [])) - set(json.loads(parent["validated_outputs_json"])))
            if missing:
                reasons.append(f"{key}: missing verified outputs {', '.join(missing)}")
    return reasons


def inherit_sources(conn, project_id, row):
    """Attach prerequisite result facts before a claim, preserving graph provenance."""
    for key in json.loads(row["depends_on_json"]):
        parent = conn.execute(
            "SELECT to_fact_id FROM intents WHERE project_id=? AND step_id=?", (project_id, key)
        ).fetchone()
        if parent and parent["to_fact_id"]:
            conn.execute(
                "INSERT OR IGNORE INTO intent_sources(intent_id,project_id,fact_id) VALUES (?,?,?)",
                (row["id"], project_id, parent["to_fact_id"]),
            )
