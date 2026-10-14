FROM python:3.11-slim AS runtime

COPY --from=ghcr.io/astral-sh/uv:0.11.16 /uv /usr/local/bin/uv

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN groupadd --system secmind && useradd --system --gid secmind --home /app secmind

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY third_party/mukul975-anthropic-cybersecurity-skills ./third_party/mukul975-anthropic-cybersecurity-skills
COPY docker/tools/semgrep/rules/reviewed ./docker/tools/semgrep/rules/reviewed
COPY alembic.ini ./
COPY migrations ./migrations
COPY scripts/start-api.sh ./scripts/start-api.sh
COPY scripts/start-worker.sh ./scripts/start-worker.sh
# Candidate integrations remain disabled by default, but the standard image
# includes their reviewed clients so activation never needs an ad-hoc build.
RUN uv sync --frozen --no-dev --extra forensics --extra qdrant
RUN chmod 0555 /app/scripts/start-api.sh /app/scripts/start-worker.sh

ENV PATH="/app/.venv/bin:$PATH"

RUN mkdir -p /app/data/inputs /app/data/uploads /app/data/runs /app/data/artifacts \
    && chown -R secmind:secmind /app
USER secmind

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

CMD ["/app/scripts/start-api.sh"]
