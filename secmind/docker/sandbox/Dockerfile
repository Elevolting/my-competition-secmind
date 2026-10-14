FROM python:3.11-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.11.16 /uv /usr/local/bin/uv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY third_party/mukul975-anthropic-cybersecurity-skills ./third_party/mukul975-anthropic-cybersecurity-skills
COPY docker/tools/semgrep/rules/reviewed ./docker/tools/semgrep/rules/reviewed
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8010
CMD ["uvicorn", "secmind.sandbox_api:app", "--host", "0.0.0.0", "--port", "8010"]
