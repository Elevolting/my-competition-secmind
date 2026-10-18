from __future__ import annotations

import json
from uuid import uuid4

import pytest
from security_runtime.dispatcher.config import WorkerConfig
from security_runtime.dispatcher.contracts import (
    parse_json_output,
    validate_explore_payload,
    validate_reason_payload,
)
from security_runtime.dispatcher.runtime.process import ManagedProcess
from security_runtime.dispatcher.workers.adapters.pi import PiDriver


def test_parse_json_output_extracts_object_from_markdown_noise() -> None:
    assert parse_json_output('result:\n```json\n{"accepted": true, "data": {}}\n```') == {
        "accepted": True,
        "data": {},
    }


def test_reason_payload_limits_number_of_intents() -> None:
    kind, intents = validate_reason_payload(
        {
            "accepted": True,
            "data": {
                "intents": [
                    {"from": ["f001"], "description": "one"},
                    {"from": ["f001"], "description": "two"},
                ]
            },
        },
        open_intents_empty=True,
        max_intents=1,
    )

    assert kind == "intents"
    assert intents == [{"from": ["f001"], "description": "one"}]


def test_reason_payload_requires_intent_when_none_are_open() -> None:
    with pytest.raises(ValueError, match="intents is required"):
        validate_reason_payload(
            {"accepted": True, "data": {}},
            open_intents_empty=True,
            max_intents=3,
        )


def test_explore_payload_rejects_planning_text() -> None:
    with pytest.raises(ValueError):
        validate_explore_payload(parse_json_output("Need inspect files and keep working."))


def test_parse_json_output_prefers_the_protocol_object_over_quoted_data() -> None:
    """A decoded payload quoted in prose must not shadow the real answer."""
    message = (
        'The segment `eyJ1c2VybmFtZSI6Imd1ZXN0In0` decodes to `{"username": "guest"}`. '
        'Concluding now.\n```json\n{"accepted": true, "data": {"description": "baseline captured"}}\n```'
    )

    assert parse_json_output(message) == {"accepted": True, "data": {"description": "baseline captured"}}


def test_explore_payload_accepts_fact_level_output_key_and_outcome() -> None:
    """The explore prompt asks for a named output; Workers report it on the fact."""
    kind, fact = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "baseline captured",
                "title": "Baseline",
                "output_key": "baseline",
                "outcome": "observed",
                "items": [
                    {"id": "no-evidence", "type": "observation", "title": "note", "summary": "no receipt"},
                    {"id": "with-evidence", "type": "observation", "title": "response",
                     "summary": "200 OK", "evidence_ids": ["call-1.json"]},
                ],
            },
        }
    )

    assert kind == "fact"
    assert fact["items"][0].get("output_key") is None
    assert fact["items"][1]["output_key"] == "baseline"


def test_explore_payload_accepts_a_bare_fact_bundle() -> None:
    """An unwrapped fact bundle is still a valid answer."""
    kind, fact = validate_explore_payload(
        {
            "description": "offline decode confirmed the field name",
            "output_key": "session_struct",
            "items": [{"id": "cookie", "type": "fact", "title": "cookie",
                       "summary": "{\"username\":\"guest\"}", "evidence_ids": ["call-2.json"]}],
        }
    )

    assert kind == "fact"
    assert fact["items"][0]["output_key"] == "session_struct"


def test_explore_payload_still_rejects_an_unknown_fact_field() -> None:
    with pytest.raises(ValueError, match="unexpected fact fields"):
        validate_explore_payload({"accepted": True, "data": {"description": "d", "bogus": 1, "items": []}})


def test_explore_payload_keeps_a_negative_outcome_on_the_item() -> None:
    _, fact = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "no reachable endpoint",
                "output_key": "routes",
                "outcome": "negative",
                "items": [{"id": "scan", "type": "observation", "title": "scan",
                           "summary": "404 for every candidate", "evidence_ids": ["call-3.json"]}],
            },
        }
    )

    assert fact["items"][0]["outcome"] == "negative"


def test_pi_driver_extracts_session_and_last_assistant_text() -> None:
    driver = PiDriver()
    stdout = "\n".join(
        [
            json.dumps({"type": "session", "id": "session-123"}),
            json.dumps(
                {
                    "type": "turn_end",
                    "message": {
                        "role": "assistant",
                        "content": [{"type": "text", "text": '{"accepted":true,"data":{}}'}],
                    },
                }
            ),
        ]
    )

    assert driver.extract_session(None, stdout, "") == "session-123"
    assert driver.extract_response_text(stdout, "") == '{"accepted":true,"data":{}}'


def test_pi_driver_extracts_final_message_end_from_real_jsonl_shape() -> None:
    driver = PiDriver(local=True)
    answer = '{"accepted":true,"data":{"description":"confirmed observation"}}'
    stdout = "\n".join(json.dumps(event) for event in [
        {"type": "session", "id": "session-123"},
        {"type": "message_end", "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "private"}, {"type": "toolCall", "name": "blackboard_tools"}]}},
        {"type": "message_end", "message": {"role": "toolResult", "content": [
            {"type": "text", "text": "tool result"}]}},
        {"type": "message_end", "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "private"}, {"type": "text", "text": answer}]}},
        {"type": "turn_end"},
        {"type": "agent_end", "messages": []},
    ])

    assert driver.extract_response_text(stdout, "") == answer
    assert validate_explore_payload(parse_json_output(driver.extract_response_text(stdout, "")))[0] == "fact"


def test_pi_driver_extracts_assistant_message_events_without_ndjson_fallback() -> None:
    driver = PiDriver(local=True)
    answer = '{"accepted":true,"data":{"description":"message event"}}'
    stdout = "\n".join(json.dumps(event) for event in [
        {"type": "session", "id": "session-456"},
        {"type": "message", "message": {"role": "assistant", "content": [
            {"type": "text", "text": answer}]}},
    ])
    assert driver.extract_response_text(stdout, "") == answer
    assert driver.extract_response_text(json.dumps({"type": "session", "id": "only"}), "") == ""


def test_pi_driver_reports_terminal_provider_failure_without_reusing_earlier_answer() -> None:
    driver = PiDriver(local=True)
    prior = {"role": "assistant", "content": [{"type": "text", "text": '{"accepted":true}'}],
             "stopReason": "stop"}
    failure = {"role": "assistant", "content": [], "stopReason": "error",
               "errorMessage": "Connection error."}
    stdout = "\n".join(json.dumps(event) for event in [
        {"type": "message_end", "message": prior},
        {"type": "message_end", "message": failure},
        {"type": "agent_end", "messages": [prior, failure]},
    ])
    assert driver.provider_error(stdout, "") == "Connection error."
    assert driver.extract_response_text(stdout, "") == ""
    recovered = stdout + "\n" + json.dumps({"type": "message_end", "message": prior})
    assert driver.provider_error(recovered, "") is None
    assert driver.extract_response_text(recovered, "") == '{"accepted":true}'


def test_pi_recovers_only_completed_answer_for_matching_prompt(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('security_runtime.dispatcher.workers.adapters.pi.Path.home', lambda: tmp_path)
    driver = PiDriver(local=True)
    worker = WorkerConfig(name='pi_test', type='pi', task_types=['explore'], max_running=1, priority=0)
    session = str(uuid4())
    directory = tmp_path / '.security-runtime-pi' / worker.name / 'sessions'
    directory.mkdir(parents=True)
    path = directory / f'2026-10-14T00-00-00Z_{session}.jsonl'
    prompt = 'current exploration prompt'
    answer = '{"accepted":true,"data":{"description":"verified"}}'
    events = [
        {'type': 'message', 'message': {'role': 'user', 'content': [{'type': 'text', 'text': prompt}]}},
        {'type': 'message', 'message': {'role': 'assistant', 'stopReason': 'stop',
                                        'content': [{'type': 'text', 'text': answer}]}},
    ]
    path.write_text('\n'.join(json.dumps(event) for event in events), encoding='utf-8')
    partial = json.dumps({'type': 'session', 'id': session})
    recovered = driver.completed_output(worker, session, prompt, partial)
    assert driver.extract_response_text(recovered, '') == answer
    assert driver.completed_output(worker, session, 'different prompt', partial) == partial
    path.write_text(path.read_text(encoding='utf-8') + '\n' + json.dumps({
        'type': 'message', 'message': {'role': 'user', 'content': [{'type': 'text', 'text': 'new turn'}]},
    }), encoding='utf-8')
    assert driver.completed_output(worker, session, prompt, partial) == partial


def test_close_stream_closes_response_even_when_stream_close_fails() -> None:
    class Response:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class Stream:
        def __init__(self) -> None:
            self._response = Response()

        def close(self) -> None:
            raise ValueError("already closed")

    stream = Stream()
    ManagedProcess._close_stream(stream)

    assert stream._response.closed

