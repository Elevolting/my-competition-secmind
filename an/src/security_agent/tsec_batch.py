"""Batch operations for TSec. No solver, hint calls or automatic retries."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from security_agent.config import Settings
from security_agent.tsec_benchmark import TSecBenchmarkClient, TSecConfig, TSecError


def make_client(env_file: Path) -> TSecBenchmarkClient:
    settings = Settings(_env_file=env_file)
    return TSecBenchmarkClient(TSecConfig(settings.tsec_base_url, settings.tsec_token))


def parse_answers(text: str) -> list[tuple[str, str]]:
    """Validate the entire batch before making any requests; retain flag whitespace."""
    try:
        data = json.loads(text.lstrip('\ufeff'))
    except ValueError as exc:
        raise ValueError('答案必须是 JSON，例如 {"c-01": ["实际 Flag"], "c-02": "实际 Flag"}') from exc
    if not isinstance(data, dict) or not data:
        raise ValueError('答案必须是非空对象：题目编号 → Flag 字符串或字符串数组')
    answers = []
    for code, flags in data.items():
        if not isinstance(code, str) or not code.strip():
            raise ValueError('题目编号不能为空')
        if isinstance(flags, str):
            flags = [flags]
        if not isinstance(flags, list) or not flags:
            raise ValueError(f'{code} 必须包含至少一个 Flag')
        for flag in flags:
            if not isinstance(flag, str) or not 1 <= len(flag) <= 4096:
                raise ValueError(f'{code} 的 Flag 必须是长度 1~4096 的字符串')
            pair = (code.strip(), flag)
            if pair not in answers:
                answers.append(pair)
    return answers


class BatchOperator:
    def __init__(self, client: TSecBenchmarkClient):
        self.client = client

    async def _selected(self, codes: list[str]):
        selected = list(dict.fromkeys(code.strip() for code in codes if code.strip()))
        if not selected:
            raise ValueError('请至少选择一道题目')
        items = await self.client.list_challenges()
        lookup = {item['unique_code']: item for item in items}
        unknown = [code for code in selected if code not in lookup]
        if unknown:
            raise ValueError('当前任务不存在题目：' + ', '.join(unknown))
        return selected, items, lookup

    @staticmethod
    def _error(code: str, exc: TSecError):
        return {'unique_code': code, 'status': 'error', 'code': exc.code, 'message': exc.message,
                'http_status': exc.status_code}

    async def start(self, codes: list[str]) -> list[dict]:
        selected, items, lookup = await self._selected(codes)
        active = sum(item.get('container_status') != 'stopped' for item in items)
        new = [code for code in selected if lookup[code].get('container_status') == 'stopped'
               and not lookup[code].get('is_completed')]
        if active + len(new) > 3:
            raise ValueError(f'平台最多同时启动 3 道题：当前占用 {active} 个，本次需要 {len(new)} 个。'
                             '请减少选择或先关闭已有题目；尚未启动本批次。')
        results = []
        for index, code in enumerate(selected):
            item = lookup[code]
            if item.get('is_completed'):
                results.append({'unique_code': code, 'status': 'skipped', 'message': '已通关，跳过启动'})
                continue
            if item.get('container_status') != 'stopped':
                results.append({'unique_code': code, 'status': 'existing',
                                'container_status': item.get('container_status'),
                                'container_addr': item.get('container_addr', [])})
                continue
            try:
                reply = await self.client.start(code)
                results.append({'unique_code': code, 'status': 'started', 'response': reply})
            except TSecError as exc:
                results.append(self._error(code, exc))
                # A timed-out start may already have consumed a slot. Refresh before retrying.
                results.extend({'unique_code': rest, 'status': 'not_attempted', 'message': '启动失败后停止本批次'}
                               for rest in selected[index + 1:])
                break
        return results

    async def close(self, codes: list[str]) -> list[dict]:
        selected, _, lookup = await self._selected(codes)
        results = []
        for code in selected:
            if lookup[code].get('container_status') == 'stopped':
                results.append({'unique_code': code, 'status': 'skipped', 'message': '容器已关闭'})
                continue
            try:
                reply = await self.client.close(code)
                results.append({'unique_code': code, 'status': 'closed' if reply.get('closed') is True else 'error',
                                'response': reply})
            except TSecError as exc:
                results.append(self._error(code, exc))
        return results

    async def submit(self, text: str, *, close_completed: bool = False) -> list[dict]:
        answers = parse_answers(text)
        _, _, lookup = await self._selected([code for code, _ in answers])
        results = []
        stop_reason = None
        touched = []
        for code, flag in answers:
            if stop_reason:
                results.append({'unique_code': code, 'status': 'not_attempted', 'message': stop_reason})
                continue
            if lookup[code].get('is_completed'):
                results.append({'unique_code': code, 'status': 'skipped', 'message': '题目已通关'})
                continue
            try:
                reply = await self.client.submit(code, flag)
                if not isinstance(reply.get('correct'), bool):
                    raise TSecError(502, 'invalid_response', '提交响应缺少 correct；请刷新进度后核对')
                results.append({'unique_code': code, 'status': 'correct' if reply['correct'] else 'incorrect',
                                'response': reply})
                touched.append(code)
                count, total = reply.get('correct_flag_count'), reply.get('total_flag_count')
                if isinstance(count, int) and isinstance(total, int) and total > 0 and count >= total:
                    lookup[code]['is_completed'] = True
            except TSecError as exc:
                row = self._error(code, exc)
                if exc.code == 'duplicate':
                    row['status'] = 'duplicate'
                    touched.append(code)
                elif exc.code in {'task_not_found', 'invalid_state', 'platform_unavailable', 'invalid_response'}:
                    stop_reason = '平台状态或提交结果不确定，停止后续提交；请刷新题目进度后核对'
                results.append(row)
        if close_completed and touched and not stop_reason:
            # Trust a fresh platform snapshot, never close based only on one correct flag.
            try:
                latest = await self.client.list_challenges()
                completed = [item['unique_code'] for item in latest
                             if item['unique_code'] in touched and item.get('is_completed')
                             and item.get('container_status') != 'stopped']
                if completed:
                    results.extend(await self.close(completed))
            except TSecError as exc:
                results.append(self._error('完成后关闭容器', exc))
        return results


def main() -> int:
    parser = argparse.ArgumentParser(description='TSec 批量启动、提交和关闭；不调用解题 Agent')
    parser.add_argument('--env-file', type=Path, default=Path('.env'))
    parser.add_argument('--output', type=Path, help='保存本次 JSON 结果')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('list', help='查看题目、进度和入口')
    for command in ('start', 'close'):
        commands.add_parser(command).add_argument('codes', nargs='+', help='题目编号，例如 c-01 c-02')
    submit = commands.add_parser('submit', help='从 JSON 文件批量提交 Flag')
    submit.add_argument('answers', type=Path)
    submit.add_argument('--close-completed', action='store_true', help='提交后关闭已全部通关的题目')
    args = parser.parse_args()
    client = make_client(args.env_file)
    operator = BatchOperator(client)

    async def execute():
        if args.command == 'list':
            return await client.list_challenges()
        if args.command == 'submit':
            content = args.answers.read_text(encoding='utf-8-sig')
            return await operator.submit(content, close_completed=args.close_completed)
        return await getattr(operator, args.command)(args.codes)

    try:
        results = asyncio.run(execute())
        output = json.dumps(results, ensure_ascii=False, indent=2)
        print(output)
        if args.output:
            args.output.write_text(output, encoding='utf-8')
        return int(any(item.get('status') in {'error', 'incorrect', 'not_attempted'} for item in results))
    except (TSecError, ValueError, OSError) as exc:
        print(f'失败：{exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
