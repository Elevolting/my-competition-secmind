from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

from security_runtime.dispatcher.config import WorkerConfig
from security_runtime.dispatcher.workers.base import DriverResult, WorkerDriver
from security_runtime.dispatcher.workers.health import (
    HealthResult,
    http_ping,
    proxies_from_env,
)


class PiDriver(WorkerDriver):
    type_name = "pi"

    def __init__(self, local: bool = False):
        self.local = local

    def local_binary(self) -> str | None:
        return "pi"

    def check_health(self, worker: WorkerConfig, *, timeout: float) -> HealthResult:
        env = worker.env
        base = env["PI_BASE_URL"].rstrip("/")
        model = env["PI_MODEL"]
        api = env["PI_PROVIDER_API"]
        proxies = proxies_from_env(env)
        headers = {"Authorization": f"Bearer {env['PI_API_KEY']}", "content-type": "application/json"}
        if "anthropic" in api:
            return http_ping(
                f"{base}/v1/messages",
                headers={**headers, "anthropic-version": "2023-06-01"},
                json_body={"model": model, "max_tokens": 10, "messages": [{"role": "user", "content": "ping"}]},
                timeout=timeout,
                proxies=proxies,
            )
        if "responses" in api:
            return http_ping(
                f"{base}/responses",
                headers=headers,
                json_body={"model": model, "input": [{"role": "user", "content": "ping"}], "stream": False},
                timeout=timeout,
                proxies=proxies,
            )
        # openai-completions and anything else: OpenAI-compatible chat/completions
        return http_ping(
            f"{base}/chat/completions",
            headers=headers,
            json_body={"model": model, "max_tokens": 10, "messages": [{"role": "user", "content": "ping"}]},
            timeout=timeout,
            proxies=proxies,
        )

    def describe_health(self, worker: WorkerConfig) -> str:
        env = worker.env
        return f"POST {env['PI_BASE_URL']} (api={env['PI_PROVIDER_API']}, model={env['PI_MODEL']})"

    def build_execute(self, worker: WorkerConfig, prompt: str, session: str | None) -> DriverResult:
        if self.local:
            return DriverResult(argv=self._local_argv(worker, prompt, session), session=session)
        env = worker.env
        argv = [
            "--provider",
            "security_runtime",
            "--model",
            env["PI_MODEL"],
            "--mode",
            "json",
            "--session-dir",
            self._session_dir(worker),
        ]
        if session:
            argv.extend(["--session", session])
        argv.extend(["-p", prompt])
        return DriverResult(argv=self._wrap_with_models(worker, argv), session=session)

    def build_conclude(self, worker: WorkerConfig, prompt: str, session: str) -> list[str]:
        if self.local:
            return self._local_argv(worker, prompt, session)
        env = worker.env
        argv = [
            "--provider",
            "security_runtime",
            "--model",
            env["PI_MODEL"],
            "--mode",
            "json",
            "--session-dir",
            self._session_dir(worker),
            "--session",
            session,
            "-p",
            prompt,
        ]
        return self._wrap_with_models(worker, argv)

    def _local_argv(self, worker: WorkerConfig, prompt: str, session: str | None) -> list[str]:
        # Give each worker its own Pi state. The model file refers to PI_API_KEY by
        # environment variable, so credentials never enter argv or the file.
        agent_dir = Path.home() / '.security-runtime-pi' / worker.name
        session_dir = agent_dir / 'sessions'
        session_dir.mkdir(parents=True, exist_ok=True)
        worker.env['PI_CODING_AGENT_DIR'] = str(agent_dir)
        configured = all(worker.env.get(key) for key in ('PI_MODEL', 'PI_BASE_URL', 'PI_API_KEY', 'PI_PROVIDER_API'))
        if configured:
            model_file = agent_dir / 'models.json'
            staging = agent_dir / f'models.{os.getpid()}.tmp'
            model = json.loads(self._models_json(worker))
            model['providers']['security_runtime']['apiKey'] = 'PI_API_KEY'
            staging.write_text(json.dumps(model), encoding='utf-8')
            os.replace(staging, model_file)
        pi_argv = [
            "--mode",
            "json",
            "--session-dir",
            str(session_dir),
            "--no-extensions",
            "--no-skills",
            "--no-prompt-templates",
            "--no-themes",
            "--no-context-files",
            "--tools",
            "read",
        ]
        if configured:
            pi_argv.extend(['--provider', 'security_runtime', '--model', worker.env['PI_MODEL']])
        if session:
            pi_argv.extend(["--session", session])
        pi_argv.extend(["-p", prompt])
        # Windows .cmd shims truncate multi-line prompts. The startup script
        # resolves Pi's JS entry point so CreateProcess passes the full prompt.
        cli_js = worker.env.get('PI_CLI_JS') or os.environ.get('PI_CLI_JS')
        if cli_js:
            return ['node', cli_js, *pi_argv]
        return [worker.env.get('PI_CLI_BIN') or os.environ.get('PI_CLI_BIN') or 'pi', *pi_argv]

    def extract_session(self, session: str | None, stdout: str, stderr: str) -> str | None:
        if session:
            return session
        for event in self._iter_events(stdout):
            if event.get("type") != "session":
                continue
            session_id = event.get("id")
            if isinstance(session_id, str) and session_id:
                return session_id
        return None

    def extract_response_text(self, stdout: str, stderr: str) -> str:
        message = self._last_assistant_message(stdout)
        if not message or message.get("stopReason") in {"error", "aborted", "toolUse"}:
            return ""
        content = message.get("content")
        if not isinstance(content, list):
            return ""
        # Never feed the event stream itself or an earlier assistant tool call
        # to the JSON contract parser.
        return "\n".join(
            item["text"] for item in content
            if isinstance(item, dict) and item.get("type") == "text"
            and isinstance(item.get("text"), str) and item["text"]
        ).strip()

    def provider_error(self, stdout: str, stderr: str) -> str | None:
        message = self._last_assistant_message(stdout)
        if message and message.get("stopReason") == "error":
            return str(message.get("errorMessage") or "Pi provider request failed")
        return None

    def completed_output(self, worker: WorkerConfig, session: str | None,
                         prompt: str, stdout: str) -> str:
        if not self.local or not session or self.extract_response_text(stdout, ""):
            return stdout
        try:
            session_id = str(UUID(session))
            directory = Path.home() / '.security-runtime-pi' / worker.name / 'sessions'
            matches = list(directory.glob(f'*_{session_id}.jsonl'))
            if len(matches) != 1 or matches[0].is_symlink() or matches[0].stat().st_size > 8_000_000:
                return stdout
            events = matches[0].read_text(encoding='utf-8').splitlines()
            last_user = -1
            last_assistant = None
            for index, line in enumerate(events):
                event = json.loads(line)
                if event.get('type') != 'message' or not isinstance(event.get('message'), dict):
                    continue
                message = event['message']
                if message.get('role') == 'user':
                    last_user = index if any(
                        item.get('type') == 'text' and item.get('text') == prompt
                        for item in message.get('content', []) if isinstance(item, dict)
                    ) else -1
                    last_assistant = None
                elif last_user >= 0 and message.get('role') == 'assistant':
                    last_assistant = message
            if last_user < 0 or not last_assistant or last_assistant.get('stopReason') != 'stop':
                return stdout
            recovered = json.dumps({'type': 'message_end', 'message': last_assistant})
            return stdout + '\n' + recovered
        except (OSError, ValueError, TypeError, KeyError):
            return stdout

    @classmethod
    def _last_assistant_message(cls, stdout: str) -> dict[str, Any] | None:
        last: dict[str, Any] | None = None
        for event in cls._iter_events(stdout):
            event_type = event.get("type")
            if event_type in {"message", "message_end", "turn_end"}:
                message = event.get("message")
                if isinstance(message, dict) and message.get("role") == "assistant":
                    last = message
            elif event_type == "agent_end" and isinstance(event.get("messages"), list):
                assistants = [message for message in event["messages"]
                              if isinstance(message, dict) and message.get("role") == "assistant"]
                if assistants:
                    last = assistants[-1]
        return last

    def _wrap_with_models(self, worker: WorkerConfig, pi_argv: list[str], *, enable_tools: bool = True) -> list[str]:
        script = (
            'agent_dir="$1"\n'
            'models_json="$2"\n'
            "shift 2\n"
            'mkdir -p "$agent_dir"\n'
            'mkdir -p "$agent_dir/sessions"\n'
            'printf "%s" "$models_json" > "$agent_dir/models.json"\n'
            'exec env PI_CODING_AGENT_DIR="$agent_dir" pi "$@"\n'
        )
        argv = [
            "--no-extensions",
            "--no-skills",
            "--no-prompt-templates",
            "--no-themes",
            "--no-context-files",
        ]
        if enable_tools:
            argv.extend(["--tools", "read,write,edit,bash,grep,find,ls"])
        return [
            "/bin/sh",
            "-lc",
            script,
            "--",
            self._agent_dir(worker),
            self._models_json(worker),
            *argv,
            *pi_argv,
        ]

    @staticmethod
    def _agent_dir(worker: WorkerConfig) -> str:
        return str(PurePosixPath("/tmp/security-runtime-pi") / worker.name)

    @staticmethod
    def _session_dir(worker: WorkerConfig) -> str:
        return str(PurePosixPath(PiDriver._agent_dir(worker)) / "sessions")

    @staticmethod
    def _iter_events(stdout: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                events.append(payload)
        return events

    @staticmethod
    def _models_json(worker: WorkerConfig) -> str:
        env = worker.env
        model: dict[str, Any] = {
            "id": env["PI_MODEL"],
            "name": env["PI_MODEL"],
        }
        context_window = env.get("PI_MODEL_CONTEXT_WINDOW")
        if context_window:
            model["contextWindow"] = int(context_window)

        provider: dict[str, Any] = {
            "baseUrl": env["PI_BASE_URL"],
            "api": env["PI_PROVIDER_API"],
            "apiKey": env["PI_API_KEY"],
            "models": [model],
        }
        payload = {"providers": {"security_runtime": provider}}
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
