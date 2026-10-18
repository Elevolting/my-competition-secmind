import json

import pytest

from security_agent.tsec_batch import BatchOperator, parse_answers
from security_agent.tsec_benchmark import TSecError


class Platform:
    def __init__(self):
        self.items = [{'unique_code': f'c-0{i}', 'container_status': 'stopped', 'is_completed': False,
                       'container_addr': []} for i in range(1, 6)]
        self.calls = []
        self.start_error = None
        self.submit_error = None
        self.correct_count = 0

    async def list_challenges(self):
        return [dict(item) for item in self.items]

    async def start(self, code):
        self.calls.append(('start', code))
        if self.start_error:
            raise self.start_error
        next(item for item in self.items if item['unique_code'] == code)['container_status'] = 'available'
        return {'container_addr': ['10.0.128.1:80']}

    async def submit(self, code, flag):
        self.calls.append(('submit', code, flag))
        if self.submit_error:
            raise self.submit_error
        if flag == 'wrong':
            return {'correct': False, 'awarded': 0}
        self.correct_count += 1
        if self.correct_count == 2:
            next(item for item in self.items if item['unique_code'] == code)['is_completed'] = True
        return {'correct': True, 'awarded': 50, 'correct_flag_count': self.correct_count, 'total_flag_count': 2}

    async def close(self, code):
        self.calls.append(('close', code))
        next(item for item in self.items if item['unique_code'] == code)['container_status'] = 'stopped'
        return {'closed': True}


async def test_start_respects_global_capacity_and_existing():
    platform = Platform()
    platform.items[0]['container_status'] = 'available'
    platform.items[1]['container_status'] = 'stop_pending'
    op = BatchOperator(platform)
    with pytest.raises(ValueError, match='最多同时'):
        await op.start(['c-03', 'c-04'])
    assert platform.calls == []
    rows = await op.start(['c-01', 'c-03', 'c-03'])
    assert [row['status'] for row in rows] == ['existing', 'started']
    assert platform.calls == [('start', 'c-03')]


async def test_timeout_start_stops_remaining():
    platform = Platform()
    platform.start_error = TSecError(503, 'platform_unavailable', 'timeout')
    rows = await BatchOperator(platform).start(['c-01', 'c-02'])
    assert [row['status'] for row in rows] == ['error', 'not_attempted']
    assert platform.calls == [('start', 'c-01')]


async def test_validate_whole_batch_before_any_write():
    platform = Platform()
    op = BatchOperator(platform)
    for text in ['{"c-01": "valid", "c-02": ""}', '{"c-01": "valid", "unknown": "valid"}']:
        with pytest.raises(ValueError):
            await op.submit(text)
    with pytest.raises(ValueError):
        await op.start(['c-01', 'unknown'])
    assert platform.calls == []


async def test_multiple_flags_duplicates_and_close_only_after_complete():
    platform = Platform()
    platform.items[0]['container_status'] = 'available'
    op = BatchOperator(platform)
    rows = await op.submit('{"c-01": ["first", "first"]}', close_completed=True)
    assert len(rows) == 1
    assert platform.calls == [('submit', 'c-01', 'first')]
    rows = await op.submit('{"c-01": ["second", "third"]}', close_completed=True)
    assert [row['status'] for row in rows] == ['correct', 'skipped', 'closed']
    assert platform.calls[-2:] == [('submit', 'c-01', 'second'), ('close', 'c-01')]
    assert 'second' not in json.dumps(rows)


async def test_incorrect_continues_duplicate_is_visible_and_network_stops():
    platform = Platform()
    op = BatchOperator(platform)
    rows = await op.submit('{"c-01": ["wrong", "good"]}')
    assert [row['status'] for row in rows] == ['incorrect', 'correct']
    platform.submit_error = TSecError(409, 'duplicate', 'already accepted')
    rows = await op.submit('{"c-01": ["good"]}')
    assert rows[0]['status'] == 'duplicate'
    platform.submit_error = TSecError(503, 'platform_unavailable', 'timeout')
    before = len(platform.calls)
    rows = await op.submit('{"c-01": ["a", "b"], "c-02": "c"}', close_completed=True)
    assert [row['status'] for row in rows] == ['error', 'not_attempted', 'not_attempted']
    assert len(platform.calls) == before + 1


async def test_close_only_selected_and_skips_stopped():
    platform = Platform()
    platform.items[0]['container_status'] = 'available'
    platform.items[1]['container_status'] = 'available'
    rows = await BatchOperator(platform).close(['c-01', 'c-03'])
    assert [row['status'] for row in rows] == ['closed', 'skipped']
    assert platform.calls == [('close', 'c-01')]
    assert platform.items[1]['container_status'] == 'available'


def test_preserve_flag_whitespace_and_bom():
    assert parse_answers('\ufeff{"c-01": "  actual flag  "}') == [('c-01', '  actual flag  ')]


@pytest.mark.parametrize('text', ['[]', '{}', '{', '{"c-01": []}', '{"c-01": null}', '{"c-01": [123]}'])
def test_invalid_answer_formats(text):
    with pytest.raises(ValueError):
        parse_answers(text)
