from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from secmind import worker
from secmind.answer_revision import AnswerRevisionError, make_revision, materialize_answer
from secmind.task_contract import AnswerRevisionAction


def _revision(
    anchor: dict[str, Any],
    revision_id: str,
    action: AnswerRevisionAction,
    target: str,
    value: Any,
    *,
    expected: Any = None,
    parents: tuple[str, ...] = (),
):
    return make_revision(
        revision_id=revision_id,
        base_answer=anchor,
        action=action,
        target_path=target,
        value=value,
        evidence_ids=["evidence-b", "evidence-a", "evidence-a"],
        observation_ids=["observation-b", "observation-a", "observation-a"],
        supersedes_revision_ids=parents,
        reason_code="verified_boundary",
        expected_old_value=expected,
    )


def test_revision_metadata_is_canonical_and_nonaccepted_revisions_are_inert() -> None:
    anchor = {"decision": "allow"}
    revision = _revision(
        anchor,
        "revision-1",
        AnswerRevisionAction.REPLACE_FIELD,
        "/decision",
        "deny",
        expected="allow",
    )

    assert revision.evidence_ids == ["evidence-a", "evidence-b"]
    assert revision.observation_ids == ["observation-a", "observation-b"]
    rejected = revision.model_copy(update={"revision_id": "rejected", "verifier_status": "rejected"})
    quarantined = revision.model_copy(update={"revision_id": "quarantined", "verifier_status": "quarantined"})
    assert materialize_answer(anchor, [rejected, quarantined]) == anchor


def test_revision_chain_rejects_duplicate_unknown_parent_and_digest_tampering() -> None:
    anchor = {"decision": "allow"}
    revision = _revision(anchor, "same", AnswerRevisionAction.REPLACE_FIELD, "/decision", "deny")
    with pytest.raises(AnswerRevisionError, match="duplicate"):
        materialize_answer(anchor, [revision, revision])

    orphan = revision.model_copy(update={"revision_id": "orphan", "supersedes_revision_ids": ["missing-parent"]})
    with pytest.raises(AnswerRevisionError, match="unknown revision"):
        materialize_answer(anchor, [orphan])

    tampered = revision.model_copy(update={"value": "review"})
    with pytest.raises(AnswerRevisionError, match="digest mismatch"):
        materialize_answer(anchor, [tampered])


@pytest.mark.parametrize("target", ["", "/", "decision"])
def test_revision_target_must_be_a_non_root_json_pointer(target: str) -> None:
    anchor = {"decision": "allow"}
    revision = _revision(anchor, "bad-target", AnswerRevisionAction.REPLACE_FIELD, target, "deny")
    with pytest.raises(AnswerRevisionError, match="non-root JSON pointer"):
        materialize_answer(anchor, [revision])


def test_revision_paths_use_stable_list_ids_and_json_pointer_unescaping() -> None:
    anchor = {
        "findings": [{"finding_id": "finding-1", "details": {"a/b": "old"}}],
        "escaped~field": "old",
    }
    nested = _revision(
        anchor,
        "nested",
        AnswerRevisionAction.REPLACE_FIELD,
        "/findings/finding-1/details/a~1b",
        "new",
        expected="old",
    )
    escaped = _revision(
        anchor,
        "escaped",
        AnswerRevisionAction.REPLACE_FIELD,
        "/escaped~0field",
        "new",
        expected="old",
    )
    assert materialize_answer(anchor, [nested, escaped]) == {
        "findings": [{"finding_id": "finding-1", "details": {"a/b": "new"}}],
        "escaped~field": "new",
    }

    unknown = _revision(
        anchor,
        "unknown",
        AnswerRevisionAction.REPLACE_FIELD,
        "/findings/missing/details",
        {},
    )
    with pytest.raises(AnswerRevisionError, match="unknown stable list item"):
        materialize_answer(anchor, [unknown])

    scalar = _revision(
        anchor,
        "scalar",
        AnswerRevisionAction.REPLACE_FIELD,
        "/escaped~0field/nested/value",
        "new",
    )
    with pytest.raises(AnswerRevisionError, match="crosses a non-object"):
        materialize_answer(anchor, [scalar])


def test_list_revision_actions_enforce_identity_and_staleness() -> None:
    anchor = {"items": [{"id": "one", "value": 1}]}
    added = _revision(anchor, "add", AnswerRevisionAction.ADD, "/items/two", {"id": "two", "value": 2})
    supplemented = _revision(
        anchor,
        "supplement",
        AnswerRevisionAction.SUPPLEMENT,
        "/items/one",
        {"extra": True},
        expected={"id": "one", "value": 1},
    )
    assert materialize_answer(anchor, [added, supplemented]) == {
        "items": [{"id": "one", "value": 1, "extra": True}, {"id": "two", "value": 2}]
    }

    cases = [
        (AnswerRevisionAction.ADD, "/items/one", {"id": "one"}, "ADD cannot overwrite"),
        (AnswerRevisionAction.REPLACE_FIELD, "/items/missing", {}, "unknown list item"),
        (AnswerRevisionAction.SUPPLEMENT, "/items/missing", {}, "unknown list item"),
    ]
    for index, (action, target, value, message) in enumerate(cases):
        revision = _revision(anchor, f"invalid-{index}", action, target, value)
        with pytest.raises(AnswerRevisionError, match=message):
            materialize_answer(anchor, [revision])

    stale = _revision(
        anchor,
        "stale",
        AnswerRevisionAction.REPLACE_FIELD,
        "/items/one",
        {"id": "one", "value": 2},
        expected={"id": "one", "value": 99},
    )
    with pytest.raises(AnswerRevisionError, match="stale"):
        materialize_answer(anchor, [stale])


def test_mapping_and_supplement_actions_preserve_append_only_semantics() -> None:
    anchor = {"details": {"owner": "alice"}, "tags": ["one"], "same": "value"}
    additions = [
        _revision(anchor, "add", AnswerRevisionAction.ADD, "/new", {"safe": True}),
        _revision(
            anchor,
            "map",
            AnswerRevisionAction.SUPPLEMENT,
            "/details",
            {"owner": "alice", "team": "security"},
            expected={"owner": "alice"},
        ),
        _revision(anchor, "list", AnswerRevisionAction.SUPPLEMENT, "/tags", ["one", "two"]),
        _revision(anchor, "same", AnswerRevisionAction.SUPPLEMENT, "/same", "value"),
        _revision(anchor, "missing", AnswerRevisionAction.SUPPLEMENT, "/missing", ["created"]),
    ]
    active = materialize_answer(anchor, additions)
    assert active["new"] == {"safe": True}
    assert active["details"] == {"owner": "alice", "team": "security"}
    assert active["tags"] == ["one", "two"]
    assert active["same"] == "value"
    assert active["missing"] == ["created"]

    overwrite = _revision(anchor, "overwrite", AnswerRevisionAction.ADD, "/details", {})
    with pytest.raises(AnswerRevisionError, match="ADD cannot overwrite"):
        materialize_answer(anchor, [overwrite])
    incompatible = _revision(anchor, "incompatible", AnswerRevisionAction.SUPPLEMENT, "/same", "different")
    with pytest.raises(AnswerRevisionError, match="compatible list or object"):
        materialize_answer(anchor, [incompatible])


@pytest.mark.asyncio
async def test_worker_rejects_api_role_before_constructing_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker, "get_settings", lambda: SimpleNamespace(runtime_role="api"))
    constructed = False

    def construct(_settings: Any) -> Any:
        nonlocal constructed
        constructed = True
        raise AssertionError("runtime must not be constructed")

    monkeypatch.setattr(worker, "ApplicationRuntime", construct)
    with pytest.raises(RuntimeError, match="RUNTIME_ROLE=worker"):
        await worker.serve()
    assert not constructed


@pytest.mark.asyncio
@pytest.mark.parametrize("unsupported_signals", [False, True])
async def test_worker_lifecycle_always_shuts_down_and_tolerates_signal_limitations(
    monkeypatch: pytest.MonkeyPatch,
    unsupported_signals: bool,
) -> None:
    calls: list[str] = []

    class FakeRuntime:
        def __init__(self, settings: Any) -> None:
            assert settings.runtime_role == "worker"

        async def startup(self) -> None:
            calls.append("startup")

        async def shutdown(self) -> None:
            calls.append("shutdown")

    class FakeEvent:
        def set(self) -> None:
            calls.append("set")

        async def wait(self) -> None:
            calls.append("wait")

    class FakeLoop:
        def add_signal_handler(self, signal_name: Any, callback: Any) -> None:
            calls.append(f"signal:{signal_name.name}")
            if unsupported_signals:
                raise NotImplementedError
            assert callback.__self__.__class__ is FakeEvent

    monkeypatch.setattr(worker, "get_settings", lambda: SimpleNamespace(runtime_role="worker"))
    monkeypatch.setattr(worker, "ApplicationRuntime", FakeRuntime)
    monkeypatch.setattr(worker.asyncio, "Event", FakeEvent)
    monkeypatch.setattr(worker.asyncio, "get_running_loop", lambda: FakeLoop())

    await worker.serve()
    assert calls[0] == "startup"
    assert calls[-2:] == ["wait", "shutdown"]
    assert calls.count("signal:SIGINT") == 1
    assert calls.count("signal:SIGTERM") == 1


def test_worker_run_owns_the_serve_coroutine(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[Any] = []

    def fake_run(coroutine: Any) -> None:
        observed.append(coroutine)
        coroutine.close()

    monkeypatch.setattr(asyncio, "run", fake_run)
    worker.run()
    assert len(observed) == 1
    assert observed[0].cr_code is worker.serve.__code__
